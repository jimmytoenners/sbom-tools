//! OCI command handler.
//!
//! Implements the `oci` subcommand for pulling and verifying SBOM/VEX
//! artifacts attached to a container image:
//! - `oci pull`   — fetch + verify + materialise artifacts to disk
//! - `oci verify` — verify only; report + exit code
//! - `oci report` — pull + verify + enrich + vulnerability picture
//!
//! # Status
//!
//! The dependency-free layer — reference parsing, verification-policy
//! validation, and this CLI surface — is implemented. The registry client
//! and cosign verification land with the `sigstore` / `oci-client`
//! dependencies; until then the resolver returns
//! [`OciError::NotImplemented`](crate::oci::OciError::NotImplemented) and
//! these handlers print what they *would* do, then exit with
//! [`exit_codes::ERROR`].

use std::path::PathBuf;

use anyhow::Result;

use crate::oci::{
    ArtifactKind, AuthInputs, DiscoveryPreference, OciReference, OciResolver, OciResolverConfig,
    VerificationInputs, VerificationPolicy,
};
use crate::pipeline::exit_codes;
use crate::reports::ReportFormat;

/// Which `oci` operation to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciAction {
    /// Fetch + verify + write SBOM/VEX artifacts to disk.
    Pull,
    /// Verify signatures/attestations only; report + exit code.
    Verify,
    /// Pull + verify + enrich + produce a vulnerability picture.
    Report,
}

impl OciAction {
    const fn label(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Verify => "verify",
            Self::Report => "report",
        }
    }
}

/// Flattened configuration for every `oci` subcommand. `main.rs` populates
/// this from the per-subcommand argument structs.
#[derive(Debug, Clone)]
pub struct OciCliConfig {
    /// The raw image reference string (parsed by the handler).
    pub reference: String,
    /// Raw verification inputs (validated into a policy by the handler).
    pub verification: VerificationInputs,
    /// Registry bearer token.
    pub registry_token: Option<String>,
    /// Registry basic-auth username.
    pub registry_username: Option<String>,
    /// Registry basic-auth password.
    pub registry_password: Option<String>,
    /// Directory to materialise extracted artifacts into (`oci pull`).
    pub output_dir: Option<PathBuf>,
    /// Digest-addressed blob cache directory.
    pub cache_dir: Option<PathBuf>,
    /// Discovery preference: `referrers` or `tag-scheme`.
    pub prefer: String,
    /// Allow plain HTTP / skip registry TLS verification.
    pub insecure: bool,
    /// Platform selector (`os/arch`) for multi-arch image indexes.
    pub platform: Option<String>,
    /// Artifact kinds to extract (`sbom`, `vex`, `attestation`, `all`).
    pub artifact_kinds: Vec<String>,
    /// in-toto predicate types that MUST be present and verified.
    pub require_attestations: Vec<String>,
    /// Output format for the verification report.
    pub output_format: ReportFormat,
    /// Output file (stdout if `None`).
    pub output_file: Option<PathBuf>,
    /// `oci report`: run OSV/KEV enrichment.
    pub enrich_vulns: bool,
    /// `oci report`: also run compliance validation against this standard.
    pub standard: Option<String>,
    /// `oci report`: fail (non-zero) if vulnerabilities are present.
    pub fail_on_vuln: bool,
    /// `oci report`: fail (non-zero) on VEX coverage gaps.
    pub fail_on_vex_gap: bool,
    /// Suppress non-essential output.
    pub quiet: bool,
}

/// Run the `oci` subcommand.
///
/// # Errors
///
/// Returns an error if the image reference is malformed or the verification
/// flags do not form a coherent policy. Fetch/registry errors surface as a
/// non-zero exit code rather than an anyhow error so the caller can route
/// them through the standard CI flow.
pub fn run_oci(config: OciCliConfig, action: OciAction) -> Result<i32> {
    // 1. Parse the image reference.
    let reference = OciReference::parse(&config.reference)
        .map_err(|e| anyhow::anyhow!("invalid image reference: {e}"))?;

    // 2. Validate the verification policy.
    let policy = VerificationPolicy::from_inputs(&config.verification)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // 3. Assemble the resolver configuration + auth.
    let resolver_config = OciResolverConfig {
        cache_dir: config.cache_dir.clone(),
        output_dir: config.output_dir.clone(),
        prefer: parse_prefer(&config.prefer)?,
        insecure: config.insecure,
        platform: config.platform.clone(),
        artifact_kinds: parse_artifact_kinds(&config.artifact_kinds)?,
        require_attestations: config.require_attestations.clone(),
    };
    let auth = AuthInputs {
        token: config.registry_token.clone(),
        username: config.registry_username.clone(),
        password: config.registry_password.clone(),
    };
    let resolver = OciResolver::new(policy.clone(), resolver_config, auth);

    // 4. Show what's about to happen.
    if !config.quiet {
        print_run_intent(action, &reference, &policy, &resolver, &config);
    }

    // 5. Run the resolver. With `--no-verify` this actually fetches; with
    // verification policies it returns NotImplemented until sigstore lands.
    match resolver.resolve(&reference) {
        Ok(resolved) => {
            if !config.quiet {
                print_resolved(&resolved);
            }
            Ok(exit_codes::SUCCESS)
        }
        Err(e) => {
            eprintln!();
            eprintln!("oci {}: {e}", action.label());
            Ok(exit_codes::ERROR)
        }
    }
}

fn parse_prefer(s: &str) -> Result<DiscoveryPreference> {
    match s.to_lowercase().replace('_', "-").as_str() {
        "referrers" => Ok(DiscoveryPreference::Referrers),
        "tag-scheme" | "tag" => Ok(DiscoveryPreference::TagScheme),
        other => {
            anyhow::bail!("unknown discovery preference '{other}' (valid: referrers, tag-scheme)")
        }
    }
}

fn parse_artifact_kinds(kinds: &[String]) -> Result<Vec<ArtifactKind>> {
    if kinds.is_empty() {
        return Ok(vec![ArtifactKind::Sbom, ArtifactKind::Vex]);
    }
    let mut out = Vec::new();
    for kind in kinds {
        match kind.to_lowercase().as_str() {
            "sbom" => push_unique(&mut out, ArtifactKind::Sbom),
            "vex" => push_unique(&mut out, ArtifactKind::Vex),
            "attestation" => push_unique(&mut out, ArtifactKind::Attestation),
            "all" => {
                push_unique(&mut out, ArtifactKind::Sbom);
                push_unique(&mut out, ArtifactKind::Vex);
                push_unique(&mut out, ArtifactKind::Attestation);
            }
            other => anyhow::bail!(
                "unknown artifact kind '{other}' (valid: sbom, vex, attestation, all)"
            ),
        }
    }
    Ok(out)
}

fn push_unique(out: &mut Vec<ArtifactKind>, kind: ArtifactKind) {
    if !out.contains(&kind) {
        out.push(kind);
    }
}

/// Print what the `oci` invocation is about to do — parsed reference,
/// resolved policy, discovery preference, output destination. With
/// `--no-verify` this is followed by an actual fetch; with a verification
/// policy the resolver currently returns `NotImplemented` until sigstore
/// lands.
fn print_run_intent(
    action: OciAction,
    reference: &OciReference,
    policy: &VerificationPolicy,
    resolver: &OciResolver,
    config: &OciCliConfig,
) {
    let title = if matches!(policy, VerificationPolicy::None) {
        format!(
            "oci {} (fetching — verification disabled via --no-verify)",
            action.label()
        )
    } else {
        format!(
            "oci {} (cosign verification not yet wired — see docs/oci-verify-plan.md)",
            action.label()
        )
    };
    println!("{title}");
    println!("  reference:   {reference}");
    println!("    registry   {}", reference.registry);
    println!("    repository {}", reference.repository);
    if let Some(ref tag) = reference.tag {
        println!("    tag        {tag}");
    }
    if let Some(ref digest) = reference.digest {
        println!("    digest     {digest}");
    }
    println!("  policy:      {}", policy.describe());

    let cfg = resolver.config();
    println!("  discovery:   {:?}", cfg.prefer);
    let kinds: Vec<&str> = cfg
        .artifact_kinds
        .iter()
        .map(|k| match k {
            ArtifactKind::Sbom => "sbom",
            ArtifactKind::Vex => "vex",
            ArtifactKind::Attestation => "attestation",
        })
        .collect();
    println!("  artifacts:   {}", kinds.join(", "));
    if !cfg.require_attestations.is_empty() {
        println!("  required:    {}", cfg.require_attestations.join(", "));
    }
    if let Some(ref dir) = cfg.output_dir {
        println!("  output-dir:  {}", dir.display());
    }
    if cfg.insecure {
        println!("  insecure:    true (plain HTTP / TLS verification skipped)");
    }
    if action == OciAction::Report {
        println!(
            "  report:      enrich-vulns={}{}",
            config.enrich_vulns,
            config
                .standard
                .as_ref()
                .map(|s| format!(", standard={s}"))
                .unwrap_or_default()
        );
    }
}

/// Print the artifacts the resolver materialised, post-fetch.
fn print_resolved(resolved: &crate::oci::ResolvedArtifacts) {
    println!();
    println!("resolved image digest: {}", resolved.image_digest);
    println!("  sboms ({}):", resolved.sboms.len());
    for af in &resolved.sboms {
        println!(
            "    - {} ({}, via {:?})",
            af.path.display(),
            af.media_type,
            af.discovered_via
        );
    }
    println!("  vex   ({}):", resolved.vex_docs.len());
    for af in &resolved.vex_docs {
        println!(
            "    - {} ({}, via {:?})",
            af.path.display(),
            af.media_type,
            af.discovered_via
        );
    }
    if matches!(
        resolved.verification.image_signature,
        crate::oci::SignatureVerdict::Skipped
    ) {
        println!("  verification: skipped (--no-verify)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prefer_accepts_known_values() {
        assert_eq!(
            parse_prefer("referrers").unwrap(),
            DiscoveryPreference::Referrers
        );
        assert_eq!(
            parse_prefer("tag-scheme").unwrap(),
            DiscoveryPreference::TagScheme
        );
        assert_eq!(
            parse_prefer("TAG_SCHEME").unwrap(),
            DiscoveryPreference::TagScheme
        );
        assert!(parse_prefer("nonsense").is_err());
    }

    #[test]
    fn parse_artifact_kinds_defaults_to_sbom_and_vex() {
        assert_eq!(
            parse_artifact_kinds(&[]).unwrap(),
            vec![ArtifactKind::Sbom, ArtifactKind::Vex]
        );
    }

    #[test]
    fn parse_artifact_kinds_expands_all_and_dedups() {
        let kinds = parse_artifact_kinds(&["all".to_string(), "sbom".to_string()]).unwrap();
        assert_eq!(
            kinds,
            vec![
                ArtifactKind::Sbom,
                ArtifactKind::Vex,
                ArtifactKind::Attestation
            ]
        );
    }

    #[test]
    fn parse_artifact_kinds_rejects_unknown() {
        assert!(parse_artifact_kinds(&["bogus".to_string()]).is_err());
    }

    fn base_config() -> OciCliConfig {
        // Default uses a key-based policy so resolver tests stay hermetic —
        // verification isn't wired yet, so resolve() returns NotImplemented
        // without touching the network. Tests that need a different policy
        // override the verification field.
        OciCliConfig {
            reference: "ghcr.io/acme/api:v1".to_string(),
            verification: VerificationInputs {
                key: Some(PathBuf::from("cosign.pub")),
                rekor_url: "https://rekor.sigstore.dev".to_string(),
                ..Default::default()
            },
            registry_token: None,
            registry_username: None,
            registry_password: None,
            output_dir: None,
            cache_dir: None,
            prefer: "referrers".to_string(),
            insecure: false,
            platform: None,
            artifact_kinds: vec![],
            require_attestations: vec![],
            output_format: ReportFormat::Auto,
            output_file: None,
            enrich_vulns: true,
            standard: None,
            fail_on_vuln: false,
            fail_on_vex_gap: false,
            quiet: true,
        }
    }

    #[test]
    fn run_oci_returns_error_for_unwired_verification_policy() {
        // Key-based verification is gated on sigstore — the resolver returns
        // NotImplemented, which the handler reports as exit code ERROR.
        let code = run_oci(base_config(), OciAction::Pull).unwrap();
        assert_eq!(code, exit_codes::ERROR);
    }

    #[test]
    fn run_oci_rejects_bad_reference() {
        let mut config = base_config();
        config.reference = "oci://".to_string();
        assert!(run_oci(config, OciAction::Verify).is_err());
    }

    #[test]
    fn run_oci_rejects_incoherent_policy() {
        let mut config = base_config();
        // --no-verify combined with a key is a contradiction.
        config.verification.no_verify = true;
        // base_config already sets `key`; adding no_verify makes it
        // incoherent and policy validation must reject it before the
        // resolver runs.
        assert!(run_oci(config, OciAction::Verify).is_err());
    }
}
