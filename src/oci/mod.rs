//! OCI registry ingestion & cosign verification.
//!
//! Pulls SBOM and VEX artifacts associated with an OCI image reference,
//! verifies the image's cosign signature and each attestation's DSSE
//! envelope, and materialises the verified artifacts as local files for the
//! existing parse → enrich → diff/report pipeline.
//!
//! See [`docs/oci-verify-plan.md`](../../docs/oci-verify-plan.md) for the
//! full design.
//!
//! # Status
//!
//! This module is **scaffolded**. The dependency-free layer — reference
//! parsing ([`OciReference`]), verification-policy validation
//! ([`VerificationPolicy`]), the public data model, and the CLI surface — is
//! implemented and tested. The registry client, artifact discovery, DSSE /
//! in-toto attestation handling, and cosign verification land with the
//! `sigstore` / `oci-client` dependencies (gated behind the `oci` feature);
//! until then [`OciResolver::resolve`] returns [`OciError::NotImplemented`].

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::quality::ViolationSeverity;

pub mod attestation;
mod client;
mod verify;

pub use attestation::{
    DsseEnvelope, DsseSignature, InTotoStatement, InTotoSubject, classify_predicate,
    is_known_predicate, parse_dsse_envelope, parse_in_toto_statement, subject_matches_image_digest,
    unwrap_dsse_to_statement,
};

// ============================================================================
// Errors
// ============================================================================

/// Errors produced by the OCI ingestion / verification path.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OciError {
    /// The supplied string is not a parseable OCI reference.
    #[error("invalid OCI reference: {0}")]
    InvalidReference(String),

    /// The verification flags / config do not form a coherent policy.
    #[error("invalid verification policy: {0}")]
    InvalidPolicy(String),

    /// A registry interaction failed (network, auth, manifest shape).
    #[error("registry error: {0}")]
    Registry(String),

    /// Cosign signature / attestation verification failed.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// A code path that has not been wired up yet (pending the
    /// `sigstore` / `oci-client` dependencies — see `docs/oci-verify-plan.md`).
    #[error("not yet implemented: {0}")]
    NotImplemented(String),

    /// An underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A serde/JSON parse failure inside the OCI layer — DSSE envelope,
    /// in-toto Statement, or Referrers index that doesn't match its schema.
    #[error("parse error: {0}")]
    Parse(String),

    /// A content digest didn't match its expected value (cache write
    /// verification, attestation `subject` binding, …).
    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch {
        /// The digest we required (`algorithm:hex`).
        expected: String,
        /// The digest the data actually hashed to (`algorithm:hex`).
        actual: String,
    },
}

// ============================================================================
// OCI reference
// ============================================================================

/// A parsed OCI image reference.
///
/// Accepts the common forms — `registry/repo:tag`,
/// `registry/repo@sha256:<digest>`, `registry/repo:tag@sha256:<digest>`, and
/// an optional `oci://` scheme prefix. A bare name with no registry component
/// resolves against `docker.io` (single-component names gain the `library/`
/// prefix, matching Docker's behaviour); a reference with neither tag nor
/// digest defaults its tag to `latest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciReference {
    /// Registry host (e.g. `ghcr.io`, `docker.io`, `localhost:5000`).
    pub registry: String,
    /// Repository path (e.g. `acme/api`, `library/alpine`).
    pub repository: String,
    /// Tag, if the reference is (or defaults to) tag-based.
    pub tag: Option<String>,
    /// Digest (`algorithm:hex`), if the reference is digest-pinned.
    pub digest: Option<String>,
}

impl OciReference {
    /// Parse an OCI reference string.
    ///
    /// # Errors
    ///
    /// Returns [`OciError::InvalidReference`] if the string is empty or
    /// malformed (bad digest shape, empty repository, invalid tag charset).
    pub fn parse(input: &str) -> Result<Self, OciError> {
        parse_reference(input)
    }

    /// The fully-qualified name `registry/repository` (no tag or digest).
    #[must_use]
    pub fn name(&self) -> String {
        format!("{}/{}", self.registry, self.repository)
    }

    /// Whether this reference is pinned to an immutable digest.
    #[must_use]
    pub const fn is_digest_pinned(&self) -> bool {
        self.digest.is_some()
    }
}

impl FromStr for OciReference {
    type Err = OciError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_reference(s)
    }
}

impl fmt::Display for OciReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        if let Some(ref tag) = self.tag {
            write!(f, ":{tag}")?;
        }
        if let Some(ref digest) = self.digest {
            write!(f, "@{digest}")?;
        }
        Ok(())
    }
}

/// Default registry for references without an explicit registry component.
const DEFAULT_REGISTRY: &str = "docker.io";

fn parse_reference(input: &str) -> Result<OciReference, OciError> {
    let trimmed = input.trim();
    let body = trimmed.strip_prefix("oci://").unwrap_or(trimmed);
    if body.is_empty() {
        return Err(OciError::InvalidReference("reference is empty".to_string()));
    }

    // Split off an optional `@algorithm:hex` digest.
    let (without_digest, digest) = match body.split_once('@') {
        Some((left, right)) => {
            validate_digest(right)?;
            (left, Some(right.to_string()))
        }
        None => (body, None),
    };
    if without_digest.is_empty() {
        return Err(OciError::InvalidReference(
            "reference has a digest but no name".to_string(),
        ));
    }

    // Split off an optional `:tag`. The tag lives in the final path segment,
    // so a `:` that precedes the last `/` (a registry port) is left alone.
    let last_slash = without_digest.rfind('/');
    let last_segment_start = last_slash.map_or(0, |i| i + 1);
    let (name, tag) = match without_digest[last_segment_start..].find(':') {
        Some(rel_colon) => {
            let colon = last_segment_start + rel_colon;
            let tag = &without_digest[colon + 1..];
            validate_tag(tag)?;
            (&without_digest[..colon], Some(tag.to_string()))
        }
        None => (without_digest, None),
    };
    if name.is_empty() {
        return Err(OciError::InvalidReference(
            "reference has a tag but no name".to_string(),
        ));
    }

    // Split the name into registry + repository.
    let (registry, repository) = match name.split_once('/') {
        Some((first, rest)) if looks_like_registry(first) => (first.to_string(), rest.to_string()),
        // A leading component that isn't registry-shaped (e.g. `myuser`) is a
        // Docker Hub namespace, not a registry.
        Some(_) => (DEFAULT_REGISTRY.to_string(), name.to_string()),
        // No `/` at all: a bare image name on Docker Hub gains `library/`.
        None => (DEFAULT_REGISTRY.to_string(), format!("library/{name}")),
    };
    if repository.is_empty() {
        return Err(OciError::InvalidReference(format!(
            "reference `{input}` has an empty repository"
        )));
    }

    // A reference with neither tag nor digest defaults to `:latest`.
    let tag = match (tag, &digest) {
        (Some(t), _) => Some(t),
        (None, Some(_)) => None,
        (None, None) => Some("latest".to_string()),
    };

    Ok(OciReference {
        registry,
        repository,
        tag,
        digest,
    })
}

/// A leading name component is treated as a registry host if it contains a
/// `.` (domain) or `:` (port) or is exactly `localhost`.
fn looks_like_registry(component: &str) -> bool {
    component == "localhost" || component.contains('.') || component.contains(':')
}

fn validate_digest(digest: &str) -> Result<(), OciError> {
    let (algorithm, encoded) = digest.split_once(':').ok_or_else(|| {
        OciError::InvalidReference(format!(
            "digest `{digest}` must have the form `algorithm:hex`"
        ))
    })?;
    if algorithm.is_empty()
        || !algorithm
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(OciError::InvalidReference(format!(
            "digest algorithm `{algorithm}` must be lowercase alphanumeric"
        )));
    }
    if encoded.len() < 32 || !encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(OciError::InvalidReference(format!(
            "digest value `{encoded}` must be at least 32 hex characters"
        )));
    }
    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), OciError> {
    if tag.is_empty() || tag.len() > 128 {
        return Err(OciError::InvalidReference(format!(
            "tag `{tag}` must be 1–128 characters"
        )));
    }
    let valid_first = tag
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let valid_rest = tag
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !valid_first || !valid_rest {
        return Err(OciError::InvalidReference(format!(
            "tag `{tag}` contains characters outside `[A-Za-z0-9_.-]`"
        )));
    }
    Ok(())
}

// ============================================================================
// Verification policy
// ============================================================================

/// How a cosign signature / attestation should be verified.
///
/// Built from CLI flags or the `[oci.verify]` config section via
/// [`VerificationPolicy::from_inputs`], which rejects incoherent combinations
/// up front.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationPolicy {
    /// Verify against a cosign public key.
    KeyBased {
        /// Path to the cosign public key file.
        key_path: PathBuf,
    },
    /// Keyless verification: a Fulcio-issued certificate whose identity and
    /// OIDC issuer must match, anchored to a Sigstore trust root and
    /// (optionally) a Rekor transparency-log inclusion proof.
    Keyless {
        /// Required certificate identity.
        identity: IdentityMatcher,
        /// Required OIDC issuer URL.
        oidc_issuer: String,
        /// Sigstore trust root to anchor the Fulcio chain.
        trust_root: TrustRoot,
        /// Transparency-log policy.
        rekor: RekorPolicy,
    },
    /// Verification explicitly disabled (`--no-verify`). Artifacts are
    /// fetched but every verdict is `Skipped`.
    None,
}

/// How a keyless certificate identity is matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityMatcher {
    /// Exact string match against the certificate SAN.
    Exact(String),
    /// Regular-expression match against the certificate SAN.
    Regexp(String),
}

/// Which Sigstore trust root anchors keyless verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRoot {
    /// The bundled Sigstore public-good trust root.
    BundledPublicGood,
    /// A custom TUF root (private Sigstore deployment).
    Custom(PathBuf),
}

/// Transparency-log (Rekor) policy for keyless verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RekorPolicy {
    /// Require a Rekor inclusion proof from the given endpoint.
    Online(String),
    /// Skip the transparency-log check (air-gapped use).
    IgnoreTlog,
}

/// Raw verification inputs, as gathered from CLI flags or `[oci.verify]`
/// config, before validation into a [`VerificationPolicy`].
#[derive(Debug, Clone, Default)]
pub struct VerificationInputs {
    /// `--no-verify`: fetch without verifying.
    pub no_verify: bool,
    /// `--key`: cosign public key path.
    pub key: Option<PathBuf>,
    /// `--certificate-identity`: exact keyless identity.
    pub certificate_identity: Option<String>,
    /// `--certificate-identity-regexp`: keyless identity regex.
    pub certificate_identity_regexp: Option<String>,
    /// `--certificate-oidc-issuer`: required OIDC issuer.
    pub certificate_oidc_issuer: Option<String>,
    /// `--trust-root`: custom Sigstore TUF root.
    pub trust_root: Option<PathBuf>,
    /// `--rekor-url`: transparency-log endpoint.
    pub rekor_url: String,
    /// `--insecure-ignore-tlog`: skip the Rekor inclusion check.
    pub insecure_ignore_tlog: bool,
}

impl VerificationPolicy {
    /// Validate raw inputs into a coherent [`VerificationPolicy`].
    ///
    /// # Errors
    ///
    /// Returns [`OciError::InvalidPolicy`] when the inputs contradict each
    /// other — e.g. `--no-verify` alongside a key or identity, `--key`
    /// combined with keyless flags, a keyless identity with no issuer (or
    /// vice versa), or no policy at all (which would silently skip
    /// verification — callers must opt in via `--no-verify` instead).
    pub fn from_inputs(inputs: &VerificationInputs) -> Result<Self, OciError> {
        let has_keyless_flag = inputs.certificate_identity.is_some()
            || inputs.certificate_identity_regexp.is_some()
            || inputs.certificate_oidc_issuer.is_some();
        let has_any_policy_flag =
            inputs.key.is_some() || has_keyless_flag || inputs.trust_root.is_some();

        if inputs.no_verify {
            if has_any_policy_flag {
                return Err(OciError::InvalidPolicy(
                    "--no-verify cannot be combined with --key / --certificate-* / --trust-root"
                        .to_string(),
                ));
            }
            return Ok(Self::None);
        }

        if let Some(ref key_path) = inputs.key {
            if has_keyless_flag {
                return Err(OciError::InvalidPolicy(
                    "--key (key-based) cannot be combined with keyless --certificate-* flags"
                        .to_string(),
                ));
            }
            return Ok(Self::KeyBased {
                key_path: key_path.clone(),
            });
        }

        // Keyless path.
        let identity = match (
            &inputs.certificate_identity,
            &inputs.certificate_identity_regexp,
        ) {
            (Some(_), Some(_)) => {
                return Err(OciError::InvalidPolicy(
                    "--certificate-identity and --certificate-identity-regexp are mutually exclusive"
                        .to_string(),
                ));
            }
            (Some(exact), None) => Some(IdentityMatcher::Exact(exact.clone())),
            (None, Some(regex)) => Some(IdentityMatcher::Regexp(regex.clone())),
            (None, None) => None,
        };

        match (identity, &inputs.certificate_oidc_issuer) {
            (None, None) => Err(OciError::InvalidPolicy(
                "no verification policy supplied — pass --key, or \
                 --certificate-identity[-regexp] together with \
                 --certificate-oidc-issuer, or --no-verify to opt out"
                    .to_string(),
            )),
            (Some(_), None) => Err(OciError::InvalidPolicy(
                "keyless verification requires --certificate-oidc-issuer".to_string(),
            )),
            (None, Some(_)) => Err(OciError::InvalidPolicy(
                "keyless verification requires --certificate-identity or \
                 --certificate-identity-regexp"
                    .to_string(),
            )),
            (Some(identity), Some(issuer)) => Ok(Self::Keyless {
                identity,
                oidc_issuer: issuer.clone(),
                trust_root: inputs
                    .trust_root
                    .clone()
                    .map_or(TrustRoot::BundledPublicGood, TrustRoot::Custom),
                rekor: if inputs.insecure_ignore_tlog {
                    RekorPolicy::IgnoreTlog
                } else {
                    RekorPolicy::Online(inputs.rekor_url.clone())
                },
            }),
        }
    }

    /// A short human-readable description for status output.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::KeyBased { key_path } => format!("key-based ({})", key_path.display()),
            Self::Keyless {
                identity,
                oidc_issuer,
                ..
            } => {
                let id = match identity {
                    IdentityMatcher::Exact(s) => format!("identity={s}"),
                    IdentityMatcher::Regexp(s) => format!("identity~={s}"),
                };
                format!("keyless ({id}, issuer={oidc_issuer})")
            }
            Self::None => "disabled (--no-verify)".to_string(),
        }
    }
}

// ============================================================================
// Resolved-artifact data model
// ============================================================================

/// Which discovery mechanism surfaced an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryScheme {
    /// OCI 1.1 Referrers API.
    Referrers,
    /// Legacy cosign tag scheme (`sha256-<digest>.sbom` / `.att` / `.sig`).
    CosignTag,
    /// A plain OCI artifact with an SBOM/VEX media type (no attestation wrapper).
    PlainArtifact,
}

/// The kind of artifact a file represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// A software bill of materials (CycloneDX / SPDX).
    Sbom,
    /// A VEX document (OpenVEX / CycloneDX VEX / CSAF).
    Vex,
    /// An in-toto attestation that is neither SBOM nor VEX.
    Attestation,
}

/// A single materialised artifact file on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactFile {
    /// Local path the artifact was written to.
    pub path: PathBuf,
    /// OCI media type the artifact was stored under.
    pub media_type: String,
    /// in-toto predicate type, when the artifact came from an attestation.
    pub predicate_type: Option<String>,
    /// How the artifact was discovered.
    pub discovered_via: DiscoveryScheme,
}

/// The outcome of verifying a single signature or attestation envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureVerdict {
    /// Signature present and valid against the policy.
    Verified,
    /// Signature present but invalid (reason attached).
    Failed(String),
    /// Verification was not attempted (`--no-verify`).
    Skipped,
}

/// The outcome of verifying one attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationVerdict {
    /// in-toto predicate type, if known.
    pub predicate_type: Option<String>,
    /// DSSE envelope signature verdict.
    pub verdict: SignatureVerdict,
    /// Whether the attestation `subject` digest matched the pulled image.
    pub digest_binding_ok: bool,
}

/// A rule-shaped verification finding, emittable to SARIF.
///
/// Rule IDs follow the project convention `SBOM-OCI-<TIER>-<NNN>` — see
/// `docs/oci-verify-plan.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciVerificationFinding {
    /// e.g. `SBOM-OCI-SIG-002`.
    pub rule_id: String,
    /// Severity, reusing the compliance severity scale.
    pub severity: ViolationSeverity,
    /// Human-readable message.
    pub message: String,
}

/// The verification verdict for a resolved image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Verdict for the image manifest's cosign signature.
    pub image_signature: SignatureVerdict,
    /// Per-attestation verdicts.
    pub attestations: Vec<AttestationVerdict>,
    /// Whether every attestation's `subject` digest matched the image digest.
    pub digest_binding_ok: bool,
    /// Rule-shaped findings (drives SARIF output and the exit code).
    pub findings: Vec<OciVerificationFinding>,
}

impl VerificationReport {
    /// Whether the report represents a clean pass: the image signature
    /// verified, every attestation verified and digest-bound, and no
    /// error-severity findings. A `Skipped` image signature (i.e.
    /// `--no-verify`) is **not** a pass.
    #[must_use]
    pub fn passed(&self) -> bool {
        matches!(self.image_signature, SignatureVerdict::Verified)
            && self.digest_binding_ok
            && self
                .attestations
                .iter()
                .all(|a| matches!(a.verdict, SignatureVerdict::Verified))
            && !self
                .findings
                .iter()
                .any(|f| matches!(f.severity, ViolationSeverity::Error))
    }
}

/// The output of [`OciResolver::resolve`]: local artifact paths plus the
/// verification verdict. This is the boundary between the OCI layer and the
/// rest of sbom-tools — everything downstream consumes ordinary file paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedArtifacts {
    /// The resolved image manifest digest the artifacts are bound to.
    pub image_digest: String,
    /// Discovered + materialised SBOM files.
    pub sboms: Vec<ArtifactFile>,
    /// Discovered + materialised VEX files.
    pub vex_docs: Vec<ArtifactFile>,
    /// The verification verdict.
    pub verification: VerificationReport,
}

// ============================================================================
// Resolver
// ============================================================================

/// Discovery-scheme preference for the resolver (`--prefer`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiscoveryPreference {
    /// Try the OCI 1.1 Referrers API first, fall back to the cosign tag scheme.
    #[default]
    Referrers,
    /// Try the cosign tag scheme first.
    TagScheme,
}

/// Configuration for an [`OciResolver`] run.
#[derive(Debug, Clone)]
pub struct OciResolverConfig {
    /// Directory for the digest-addressed blob cache.
    pub cache_dir: Option<PathBuf>,
    /// Directory to materialise extracted artifacts into.
    pub output_dir: Option<PathBuf>,
    /// Discovery-scheme preference.
    pub prefer: DiscoveryPreference,
    /// Allow plain HTTP / skip registry TLS verification (local registries).
    pub insecure: bool,
    /// Platform selector (`os/arch`) for multi-arch image indexes.
    pub platform: Option<String>,
    /// Which artifact kinds to extract.
    pub artifact_kinds: Vec<ArtifactKind>,
    /// in-toto predicate types that MUST be present and verified.
    pub require_attestations: Vec<String>,
}

impl Default for OciResolverConfig {
    fn default() -> Self {
        Self {
            cache_dir: None,
            output_dir: None,
            prefer: DiscoveryPreference::Referrers,
            insecure: false,
            platform: None,
            artifact_kinds: vec![ArtifactKind::Sbom, ArtifactKind::Vex],
            require_attestations: Vec::new(),
        }
    }
}

/// Registry credentials for [`OciResolver`].
///
/// All three fields are optional; precedence is bearer-token → basic-auth →
/// anonymous.
#[derive(Debug, Clone, Default)]
pub struct AuthInputs {
    /// Bearer token (e.g. a pre-issued registry token).
    pub token: Option<String>,
    /// Basic-auth username.
    pub username: Option<String>,
    /// Basic-auth password.
    pub password: Option<String>,
}

/// Resolves an [`OciReference`] to a set of local artifact files.
///
/// The `--no-verify` path is wired (fetch via OCI Referrers API with cosign
/// tag-scheme fallback). Cosign verification (sigstore) lands in a follow-up
/// commit; any other [`VerificationPolicy`] returns
/// [`OciError::NotImplemented`].
#[derive(Debug, Clone)]
pub struct OciResolver {
    policy: VerificationPolicy,
    config: OciResolverConfig,
    auth: AuthInputs,
}

impl OciResolver {
    /// Construct a resolver with a verification policy, run configuration,
    /// and registry credentials.
    #[must_use]
    pub fn new(policy: VerificationPolicy, config: OciResolverConfig, auth: AuthInputs) -> Self {
        Self {
            policy,
            config,
            auth,
        }
    }

    /// The verification policy this resolver will apply.
    #[must_use]
    pub const fn policy(&self) -> &VerificationPolicy {
        &self.policy
    }

    /// The run configuration.
    #[must_use]
    pub const fn config(&self) -> &OciResolverConfig {
        &self.config
    }

    /// The registry credentials this resolver will use.
    #[must_use]
    pub const fn auth(&self) -> &AuthInputs {
        &self.auth
    }

    /// Resolve a reference to local artifact files.
    ///
    /// # Errors
    ///
    /// - [`OciError::NotImplemented`] if the policy is anything other than
    ///   [`VerificationPolicy::None`] (cosign verification not yet wired).
    /// - [`OciError::InvalidReference`] / [`OciError::Registry`] /
    ///   [`OciError::Io`] for fetch failures.
    pub fn resolve(&self, reference: &OciReference) -> Result<ResolvedArtifacts, OciError> {
        client::fetch_artifacts(reference, &self.auth, &self.policy, &self.config)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- reference parsing -------------------------------------------------

    #[test]
    fn parses_registry_repo_tag() {
        let r = OciReference::parse("ghcr.io/acme/api:v1.4.0").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "acme/api");
        assert_eq!(r.tag.as_deref(), Some("v1.4.0"));
        assert_eq!(r.digest, None);
        assert_eq!(r.to_string(), "ghcr.io/acme/api:v1.4.0");
    }

    #[test]
    fn parses_digest_pinned_reference() {
        let digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let r = OciReference::parse(&format!("ghcr.io/acme/api@{digest}")).unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "acme/api");
        assert_eq!(r.tag, None, "digest-pinned ref must not default a tag");
        assert_eq!(r.digest.as_deref(), Some(digest));
        assert!(r.is_digest_pinned());
    }

    #[test]
    fn parses_tag_and_digest_together() {
        let digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let r = OciReference::parse(&format!("ghcr.io/acme/api:v1.4.0@{digest}")).unwrap();
        assert_eq!(r.tag.as_deref(), Some("v1.4.0"));
        assert_eq!(r.digest.as_deref(), Some(digest));
        assert_eq!(r.to_string(), format!("ghcr.io/acme/api:v1.4.0@{digest}"));
    }

    #[test]
    fn strips_oci_scheme_prefix() {
        let r = OciReference::parse("oci://ghcr.io/acme/api:v1").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "acme/api");
    }

    #[test]
    fn registry_port_is_not_a_tag() {
        let r = OciReference::parse("localhost:5000/test:dev").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "test");
        assert_eq!(r.tag.as_deref(), Some("dev"));
    }

    #[test]
    fn registry_port_without_tag() {
        let r = OciReference::parse("localhost:5000/test").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "test");
        assert_eq!(r.tag.as_deref(), Some("latest"));
    }

    #[test]
    fn bare_name_resolves_against_docker_hub_with_library_prefix() {
        let r = OciReference::parse("alpine:3.20").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag.as_deref(), Some("3.20"));
    }

    #[test]
    fn bare_name_defaults_tag_to_latest() {
        let r = OciReference::parse("alpine").unwrap();
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag.as_deref(), Some("latest"));
    }

    #[test]
    fn docker_hub_namespace_is_not_a_registry() {
        let r = OciReference::parse("myuser/myimage:1.0").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "myuser/myimage");
        assert_eq!(r.tag.as_deref(), Some("1.0"));
    }

    #[test]
    fn name_returns_registry_and_repository() {
        let r = OciReference::parse("ghcr.io/acme/api:v1").unwrap();
        assert_eq!(r.name(), "ghcr.io/acme/api");
    }

    #[test]
    fn rejects_empty_reference() {
        assert!(matches!(
            OciReference::parse("   "),
            Err(OciError::InvalidReference(_))
        ));
        assert!(matches!(
            OciReference::parse("oci://"),
            Err(OciError::InvalidReference(_))
        ));
    }

    #[test]
    fn rejects_malformed_digest() {
        // No `algorithm:` prefix.
        assert!(OciReference::parse("ghcr.io/acme/api@deadbeef").is_err());
        // Too short.
        assert!(OciReference::parse("ghcr.io/acme/api@sha256:abc").is_err());
        // Non-hex value.
        assert!(
            OciReference::parse("ghcr.io/acme/api@sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
                .is_err()
        );
    }

    #[test]
    fn rejects_invalid_tag_charset() {
        assert!(OciReference::parse("ghcr.io/acme/api:bad tag").is_err());
        assert!(OciReference::parse("ghcr.io/acme/api:-leadinghyphen").is_err());
    }

    #[test]
    fn from_str_round_trips_via_display() {
        for input in [
            "ghcr.io/acme/api:v1.4.0",
            "registry.internal:8443/team/app:2.0",
        ] {
            let parsed: OciReference = input.parse().unwrap();
            assert_eq!(parsed.to_string(), input);
        }
    }

    // ---- verification policy ----------------------------------------------

    fn inputs() -> VerificationInputs {
        VerificationInputs {
            rekor_url: "https://rekor.sigstore.dev".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn policy_key_based() {
        let mut i = inputs();
        i.key = Some(PathBuf::from("cosign.pub"));
        let policy = VerificationPolicy::from_inputs(&i).unwrap();
        assert!(matches!(policy, VerificationPolicy::KeyBased { .. }));
    }

    #[test]
    fn policy_keyless_full() {
        let mut i = inputs();
        i.certificate_identity = Some(
            "https://github.com/acme/api/.github/workflows/release.yml@refs/tags/v1".to_string(),
        );
        i.certificate_oidc_issuer = Some("https://token.actions.githubusercontent.com".to_string());
        let policy = VerificationPolicy::from_inputs(&i).unwrap();
        match policy {
            VerificationPolicy::Keyless {
                identity,
                trust_root,
                rekor,
                ..
            } => {
                assert!(matches!(identity, IdentityMatcher::Exact(_)));
                assert_eq!(trust_root, TrustRoot::BundledPublicGood);
                assert!(matches!(rekor, RekorPolicy::Online(_)));
            }
            other => panic!("expected keyless policy, got {other:?}"),
        }
    }

    #[test]
    fn policy_keyless_regexp_and_ignore_tlog_and_custom_root() {
        let mut i = inputs();
        i.certificate_identity_regexp = Some("^https://github.com/acme/.+".to_string());
        i.certificate_oidc_issuer = Some("https://token.actions.githubusercontent.com".to_string());
        i.insecure_ignore_tlog = true;
        i.trust_root = Some(PathBuf::from("/etc/sigstore/root.json"));
        match VerificationPolicy::from_inputs(&i).unwrap() {
            VerificationPolicy::Keyless {
                identity,
                trust_root,
                rekor,
                ..
            } => {
                assert!(matches!(identity, IdentityMatcher::Regexp(_)));
                assert!(matches!(trust_root, TrustRoot::Custom(_)));
                assert_eq!(rekor, RekorPolicy::IgnoreTlog);
            }
            other => panic!("expected keyless policy, got {other:?}"),
        }
    }

    #[test]
    fn policy_no_verify() {
        let mut i = inputs();
        i.no_verify = true;
        assert_eq!(
            VerificationPolicy::from_inputs(&i).unwrap(),
            VerificationPolicy::None
        );
    }

    #[test]
    fn policy_no_verify_conflicts_with_policy_flags() {
        let mut i = inputs();
        i.no_verify = true;
        i.key = Some(PathBuf::from("cosign.pub"));
        assert!(matches!(
            VerificationPolicy::from_inputs(&i),
            Err(OciError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn policy_key_conflicts_with_keyless_flags() {
        let mut i = inputs();
        i.key = Some(PathBuf::from("cosign.pub"));
        i.certificate_identity = Some("id".to_string());
        assert!(matches!(
            VerificationPolicy::from_inputs(&i),
            Err(OciError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn policy_keyless_requires_issuer() {
        let mut i = inputs();
        i.certificate_identity = Some("id".to_string());
        assert!(matches!(
            VerificationPolicy::from_inputs(&i),
            Err(OciError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn policy_keyless_requires_identity() {
        let mut i = inputs();
        i.certificate_oidc_issuer = Some("https://issuer".to_string());
        assert!(matches!(
            VerificationPolicy::from_inputs(&i),
            Err(OciError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn policy_exact_and_regexp_identity_mutually_exclusive() {
        let mut i = inputs();
        i.certificate_identity = Some("id".to_string());
        i.certificate_identity_regexp = Some("re".to_string());
        i.certificate_oidc_issuer = Some("https://issuer".to_string());
        assert!(matches!(
            VerificationPolicy::from_inputs(&i),
            Err(OciError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn policy_empty_is_rejected_not_silently_skipped() {
        // No flags at all must error — never silently skip verification.
        assert!(matches!(
            VerificationPolicy::from_inputs(&inputs()),
            Err(OciError::InvalidPolicy(_))
        ));
    }

    // ---- resolver ----------------------------------------------------------

    // Note: both KeyBased and Keyless policies now drive real fetch + verify
    // flows through the network; there's no hermetic resolve() path that
    // returns NotImplemented up front for them. Policy-validation tests
    // (regex parsing, --trust-root custom, etc.) live in `verify::tests`.

    #[test]
    fn resolver_exposes_auth() {
        let auth = AuthInputs {
            username: Some("u".into()),
            password: Some("p".into()),
            token: None,
        };
        let resolver = OciResolver::new(
            VerificationPolicy::None,
            OciResolverConfig::default(),
            auth.clone(),
        );
        assert_eq!(resolver.auth().username.as_deref(), Some("u"));
    }

    #[test]
    fn verification_report_passed_logic() {
        let clean = VerificationReport {
            image_signature: SignatureVerdict::Verified,
            attestations: vec![],
            digest_binding_ok: true,
            findings: vec![],
        };
        assert!(clean.passed());

        let skipped = VerificationReport {
            image_signature: SignatureVerdict::Skipped,
            ..clean.clone()
        };
        assert!(!skipped.passed(), "--no-verify is not a pass");

        let with_error = VerificationReport {
            findings: vec![OciVerificationFinding {
                rule_id: "SBOM-OCI-SIG-002".to_string(),
                severity: ViolationSeverity::Error,
                message: "bad signature".to_string(),
            }],
            ..clean
        };
        assert!(!with_error.passed());
    }
}
