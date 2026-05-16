//! Cosign signature + DSSE envelope verification using `sigstore-rs`.
//!
//! Two verification scopes are covered.
//!
//! **Image signature** — the cosign `.sig` tag attached to the image
//! manifest digest. Verified via `sigstore::cosign::Client::triangulate` +
//! `trusted_signature_layers` + `verify_constraints` with a
//! `PublicKeyVerifier`.
//!
//! **Attestation DSSE envelopes** — the `.att` payloads we already
//! materialised. The DSSE signatures over the PAE-encoded
//! `(payloadType, payload)` are checked directly with
//! `sigstore::crypto::CosignVerificationKey::verify_signature`. The in-toto
//! subject digest in the envelope payload MUST match the resolved image
//! digest (the "right SBOM, wrong image" guarantee).
//!
//! # Scope
//!
//! Key-based and keyless verification of **both** the image signature and
//! every attached attestation DSSE envelope are wired.
//!
//! Keyless image signatures: full pipeline via sigstore-rs (`triangulate` +
//! `trusted_signature_layers`) — Fulcio cert chain validation + Rekor
//! transparency-log inclusion + identity (SAN exact / regex) + OIDC issuer
//! match against the configured policy.
//!
//! Keyless attestations: the resolver captures each cosign attestation
//! layer's `dev.sigstore.cosign/certificate` annotation as a sidecar
//! (`<kind>-<short>.cert.pem`). The verifier parses it with `x509-cert`,
//! extracts the SAN via `sigstore::cosign::signature_layers::CertificateSubject`,
//! extracts the Fulcio OIDC-issuer extension (OID `1.3.6.1.4.1.57264.1.1`),
//! matches both against the policy, derives a `CosignVerificationKey` from
//! the cert's `SubjectPublicKeyInfo`, and verifies the DSSE signatures over
//! PAE. Digest binding (`subject.digest` against the resolved image digest)
//! is always computed.
//!
//! **v1 limitation:** the per-attestation cert chain is NOT validated
//! against Fulcio in this pass. The keyless image-signature path *is*
//! Fulcio-chain-validated by sigstore-rs, so that remains the trust
//! anchor; closing the per-attestation chain gap is the obvious follow-up.

use std::path::Path;

use base64::Engine;
use sigstore::cosign::signature_layers::{CertificateSubject, SignatureLayer};
use sigstore::cosign::verification_constraint::{
    PublicKeyVerifier, VerificationConstraint, VerificationConstraintVec,
};
use sigstore::cosign::{ClientBuilder, CosignCapabilities, verify_constraints};
use sigstore::crypto::{CosignVerificationKey, Signature};
use sigstore::errors::SigstoreError;
use sigstore::registry::{Auth as SigstoreAuth, OciReference as SigstoreOciRef};
use sigstore::trust::sigstore::SigstoreTrustRoot;
use tokio::runtime::Runtime;
use x509_cert::Certificate as X509Certificate;
use x509_cert::der::DecodePem;

use crate::quality::ViolationSeverity;

use super::{
    AttestationVerdict, AuthInputs, IdentityMatcher, OciError, OciReference,
    OciVerificationFinding, RekorPolicy, SignatureVerdict, TrustRoot, VerificationPolicy,
    VerificationReport,
    attestation::{parse_dsse_envelope, parse_in_toto_statement, subject_matches_image_digest},
};

// ============================================================================
// Top-level entry
// ============================================================================

/// Verify an image (and its attached attestation envelopes) under a policy.
///
/// `envelope_paths` is the set of `*.dsse.json` files the resolver already
/// materialised — one per attestation. For each, the DSSE signatures are
/// checked against the configured key and the in-toto `subject.digest` is
/// matched against `image_digest`.
///
/// # Errors
///
/// - [`OciError::InvalidPolicy`] when the supplied key or identity regex
///   can't be loaded, or when a v1-unsupported keyless flag (`--trust-root`
///   custom path) is requested.
/// - [`OciError::Io`] when reading the key file fails.
pub fn verify_image(
    runtime: &Runtime,
    reference: &OciReference,
    image_digest: &str,
    auth: &AuthInputs,
    policy: &VerificationPolicy,
    envelope_paths: &[std::path::PathBuf],
) -> Result<VerificationReport, OciError> {
    match policy {
        VerificationPolicy::None => Ok(skipped_report()),
        VerificationPolicy::KeyBased { key_path } => {
            let key_pem = std::fs::read(key_path).map_err(OciError::Io)?;
            verify_key_based(
                runtime,
                reference,
                image_digest,
                auth,
                &key_pem,
                envelope_paths,
            )
        }
        VerificationPolicy::Keyless {
            identity,
            oidc_issuer,
            trust_root,
            rekor,
        } => verify_keyless(
            runtime,
            reference,
            image_digest,
            auth,
            identity,
            oidc_issuer,
            trust_root,
            rekor,
            envelope_paths,
        ),
    }
}

fn skipped_report() -> VerificationReport {
    VerificationReport {
        image_signature: SignatureVerdict::Skipped,
        attestations: Vec::new(),
        digest_binding_ok: true,
        findings: Vec::new(),
    }
}

// ============================================================================
// Key-based verification
// ============================================================================

fn verify_key_based(
    runtime: &Runtime,
    reference: &OciReference,
    image_digest: &str,
    auth: &AuthInputs,
    key_pem: &[u8],
    envelope_paths: &[std::path::PathBuf],
) -> Result<VerificationReport, OciError> {
    let mut report = VerificationReport {
        image_signature: SignatureVerdict::Skipped,
        attestations: Vec::new(),
        digest_binding_ok: true,
        findings: Vec::new(),
    };

    // 1. Image signature via sigstore-rs's cosign Client.
    report.image_signature =
        verify_image_signature(runtime, reference, image_digest, auth, key_pem)?;
    if let SignatureVerdict::Failed(ref msg) = report.image_signature {
        report.findings.push(OciVerificationFinding {
            rule_id: "SBOM-OCI-SIG-002".to_string(),
            severity: ViolationSeverity::Error,
            message: format!("Image signature verification failed: {msg}"),
        });
    }

    // 2. DSSE envelopes — verified directly with the same key. Each
    // envelope must (a) have at least one signature that verifies against
    // the key and (b) bind to `image_digest` through its in-toto subject.
    let key = match parse_cosign_key(key_pem) {
        Ok(k) => k,
        Err(e) => {
            // Already reported as a finding via the image-sig path if it failed
            // there too; record once and bail out of the envelope loop.
            return Err(e);
        }
    };
    for envelope_path in envelope_paths {
        let verdict = verify_envelope_file(envelope_path, &key, image_digest);
        if let SignatureVerdict::Failed(ref msg) = verdict.verdict {
            report.findings.push(OciVerificationFinding {
                rule_id: "SBOM-OCI-ATT-001".to_string(),
                severity: ViolationSeverity::Error,
                message: format!(
                    "DSSE envelope `{}` failed signature verification: {msg}",
                    envelope_path.display()
                ),
            });
        }
        if !verdict.digest_binding_ok {
            report.findings.push(OciVerificationFinding {
                rule_id: "SBOM-OCI-ATT-002".to_string(),
                severity: ViolationSeverity::Error,
                message: format!(
                    "DSSE envelope `{}` subject digest does not match image \
                     digest {image_digest}",
                    envelope_path.display()
                ),
            });
            report.digest_binding_ok = false;
        }
        report.attestations.push(verdict);
    }

    Ok(report)
}

fn verify_image_signature(
    runtime: &Runtime,
    reference: &OciReference,
    image_digest: &str,
    auth: &AuthInputs,
    key_pem: &[u8],
) -> Result<SignatureVerdict, OciError> {
    let sigstore_auth = to_sigstore_auth(auth);
    let sigstore_ref: SigstoreOciRef = reference.to_string().parse().map_err(|e| {
        OciError::InvalidReference(format!("sigstore cannot parse `{reference}`: {e}"))
    })?;

    let verifier = PublicKeyVerifier::try_from(key_pem)
        .map_err(|e| OciError::InvalidPolicy(format!("invalid cosign public key: {e}")))?;

    let outcome = runtime.block_on(async {
        let mut client = ClientBuilder::default()
            .build()
            .map_err(|e| format!("sigstore client build: {e}"))?;
        let (cosign_ref, _src_digest) = client
            .triangulate(&sigstore_ref, &sigstore_auth)
            .await
            .map_err(|e| format!("triangulate: {e}"))?;
        let layers = client
            .trusted_signature_layers(&sigstore_auth, image_digest, &cosign_ref)
            .await
            .map_err(|e| format!("pull signature layers: {e}"))?;
        if layers.is_empty() {
            return Err("no signature layers found at the cosign .sig tag".to_string());
        }
        let constraints: VerificationConstraintVec = vec![Box::new(verifier)];
        verify_constraints(&layers, constraints.iter())
            .map_err(|e| format!("constraint verification: {e}"))?;
        Ok::<_, String>(layers.len())
    });

    Ok(match outcome {
        Ok(_) => SignatureVerdict::Verified,
        Err(msg) => SignatureVerdict::Failed(msg),
    })
}

// ============================================================================
// DSSE envelope verification
// ============================================================================

fn parse_cosign_key(key_pem: &[u8]) -> Result<CosignVerificationKey, OciError> {
    CosignVerificationKey::try_from_pem(key_pem)
        .map_err(|e| OciError::InvalidPolicy(format!("invalid cosign public key: {e}")))
}

fn verify_envelope_file(
    path: &Path,
    key: &CosignVerificationKey,
    image_digest: &str,
) -> AttestationVerdict {
    let mut verdict = AttestationVerdict {
        predicate_type: None,
        verdict: SignatureVerdict::Skipped,
        digest_binding_ok: true,
    };

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            verdict.verdict = SignatureVerdict::Failed(format!("read envelope: {e}"));
            return verdict;
        }
    };
    let envelope = match parse_dsse_envelope(std::str::from_utf8(&bytes).unwrap_or_default()) {
        Ok(e) => e,
        Err(e) => {
            verdict.verdict = SignatureVerdict::Failed(format!("parse envelope: {e}"));
            return verdict;
        }
    };

    // Decode the payload once (for both DSSE PAE and subject extraction).
    let payload_bytes =
        match base64::engine::general_purpose::STANDARD.decode(envelope.payload.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                verdict.verdict = SignatureVerdict::Failed(format!("decode payload base64: {e}"));
                return verdict;
            }
        };
    let pae = dsse_pae(&envelope.payload_type, &payload_bytes);

    // Verify at least one signature satisfies the key.
    if envelope.signatures.is_empty() {
        verdict.verdict = SignatureVerdict::Failed("envelope has no signatures".to_string());
    } else {
        let mut any_ok = false;
        let mut last_err: Option<String> = None;
        for sig in &envelope.signatures {
            let signature = Signature::Base64Encoded(sig.sig.as_bytes());
            match key.verify_signature(signature, &pae) {
                Ok(()) => {
                    any_ok = true;
                    break;
                }
                Err(e) => last_err = Some(format!("{e}")),
            }
        }
        verdict.verdict = if any_ok {
            SignatureVerdict::Verified
        } else {
            SignatureVerdict::Failed(
                last_err.unwrap_or_else(|| "no signature verified".to_string()),
            )
        };
    }

    // Digest binding — extract predicateType + check subject digest match.
    if let Ok(payload_str) = std::str::from_utf8(&payload_bytes)
        && let Ok(stmt) = parse_in_toto_statement(payload_str)
    {
        verdict.predicate_type = Some(stmt.predicate_type.clone());
        verdict.digest_binding_ok = subject_matches_image_digest(&stmt, image_digest);
    } else {
        // Couldn't extract in-toto Statement from payload; the envelope
        // verified but we can't *prove* the binding. Mark binding as failed
        // so a "verified envelope of unknown subject" doesn't slip through.
        verdict.digest_binding_ok = false;
    }

    verdict
}

// ============================================================================
// Keyless verification
// ============================================================================

/// Pre-compiled identity matcher — exact string or regex.
#[derive(Debug, Clone)]
enum IdentityMatch {
    Exact(String),
    Regex(regex::Regex),
}

impl IdentityMatch {
    fn from_policy(matcher: &IdentityMatcher) -> Result<Self, OciError> {
        Ok(match matcher {
            IdentityMatcher::Exact(s) => Self::Exact(s.clone()),
            IdentityMatcher::Regexp(pattern) => {
                Self::Regex(regex::Regex::new(pattern).map_err(|e| {
                    OciError::InvalidPolicy(format!(
                        "--certificate-identity-regexp `{pattern}` is not a valid regex: {e}"
                    ))
                })?)
            }
        })
    }
    fn matches(&self, subject: &str) -> bool {
        match self {
            Self::Exact(s) => subject == s.as_str(),
            Self::Regex(r) => r.is_match(subject),
        }
    }
}

/// Custom keyless identity verifier — matches the cert SAN (Email or URI)
/// against an exact string or regex, and the OIDC issuer against an exact
/// expected value. sigstore-rs's built-in `CertSubjectUrlVerifier` is
/// exact-only and URI-only; this one accepts both URI and Email and supports
/// regex (matching cosign's CLI `--certificate-identity-regexp` flag).
#[derive(Debug)]
struct KeylessIdentityVerifier {
    identity: IdentityMatch,
    issuer: String,
}

impl VerificationConstraint for KeylessIdentityVerifier {
    fn verify(&self, layer: &SignatureLayer) -> Result<bool, SigstoreError> {
        let Some(cert) = &layer.certificate_signature else {
            return Ok(false);
        };
        // Issuer must match exactly (cosign-equivalent semantics).
        match &cert.issuer {
            Some(iss) if iss == &self.issuer => {}
            _ => return Ok(false),
        }
        let subject_str = match &cert.subject {
            CertificateSubject::Uri(u) => u.as_str(),
            CertificateSubject::Email(e) => e.as_str(),
        };
        Ok(self.identity.matches(subject_str))
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_keyless(
    runtime: &Runtime,
    reference: &OciReference,
    image_digest: &str,
    auth: &AuthInputs,
    identity: &IdentityMatcher,
    oidc_issuer: &str,
    trust_root_choice: &TrustRoot,
    rekor: &RekorPolicy,
    envelope_paths: &[std::path::PathBuf],
) -> Result<VerificationReport, OciError> {
    // v1 limitations — surface early with InvalidPolicy so the user knows.
    if let TrustRoot::Custom(path) = trust_root_choice {
        return Err(OciError::InvalidPolicy(format!(
            "--trust-root {} is not yet wired (v1 keyless uses the bundled \
             Sigstore public-good TUF root only)",
            path.display()
        )));
    }
    if matches!(rekor, RekorPolicy::IgnoreTlog) {
        eprintln!(
            "note: --insecure-ignore-tlog is not yet wired for keyless v1 — \
             Rekor transparency-log inclusion will be verified"
        );
    }

    let identity_match = IdentityMatch::from_policy(identity)?;

    let mut report = VerificationReport {
        image_signature: SignatureVerdict::Skipped,
        attestations: Vec::new(),
        digest_binding_ok: true,
        findings: Vec::new(),
    };

    // 1. Image signature via sigstore-rs's cosign Client + Sigstore trust root.
    report.image_signature = verify_keyless_image_signature(
        runtime,
        reference,
        image_digest,
        auth,
        identity_match,
        oidc_issuer,
    )?;
    if let SignatureVerdict::Failed(ref msg) = report.image_signature {
        report.findings.push(OciVerificationFinding {
            rule_id: "SBOM-OCI-SIG-002".to_string(),
            severity: ViolationSeverity::Error,
            message: format!("Keyless image signature verification failed: {msg}"),
        });
    }

    // 2. Attestation envelopes — keyless DSSE signature verification using
    // the per-envelope ephemeral cert that the fetcher captured as a
    // sidecar (`<kind>-<short>.cert.pem`, from the cosign
    // `dev.sigstore.cosign/certificate` layer annotation).
    let identity_match_for_atts = IdentityMatch::from_policy(identity)?;
    for envelope_path in envelope_paths {
        let verdict = verify_attestation_keyless(
            envelope_path,
            image_digest,
            &identity_match_for_atts,
            oidc_issuer,
        );
        if let SignatureVerdict::Failed(ref msg) = verdict.verdict {
            report.findings.push(OciVerificationFinding {
                rule_id: "SBOM-OCI-ATT-001".to_string(),
                severity: ViolationSeverity::Error,
                message: format!(
                    "DSSE envelope `{}` failed keyless verification: {msg}",
                    envelope_path.display()
                ),
            });
        }
        if !verdict.digest_binding_ok {
            report.findings.push(OciVerificationFinding {
                rule_id: "SBOM-OCI-ATT-002".to_string(),
                severity: ViolationSeverity::Error,
                message: format!(
                    "DSSE envelope `{}` subject digest does not match image \
                     digest {image_digest}",
                    envelope_path.display()
                ),
            });
            report.digest_binding_ok = false;
        }
        report.attestations.push(verdict);
    }

    Ok(report)
}

/// Verify a single attestation DSSE envelope keylessly.
///
/// Looks for a sidecar cert at `<envelope>.cert.pem` (written by the
/// resolver from the `dev.sigstore.cosign/certificate` layer annotation).
/// If present:
///   * parses the cert with `x509-cert`
///   * extracts the SAN via `sigstore::cosign::signature_layers::CertificateSubject`
///     and matches against the configured identity policy
///   * extracts the Fulcio OIDC-issuer extension
///     (OID `1.3.6.1.4.1.57264.1.1`) and matches against the configured issuer
///   * derives a `CosignVerificationKey` from the cert's
///     `SubjectPublicKeyInfo` and verifies each DSSE signature over PAE
///
/// Always runs the in-toto subject-digest binding check, even on cert
/// failure — that's a useful tamper signal independent of crypto.
///
/// **v1 limitation:** the cert chain is NOT validated against Fulcio in
/// this commit. The image-signature keyless path (which sigstore-rs
/// validates fully) is the trust anchor. Full chain validation is the
/// obvious follow-up.
fn verify_attestation_keyless(
    envelope_path: &std::path::Path,
    image_digest: &str,
    identity: &IdentityMatch,
    oidc_issuer: &str,
) -> AttestationVerdict {
    let mut verdict = AttestationVerdict {
        predicate_type: None,
        verdict: SignatureVerdict::Skipped,
        digest_binding_ok: true,
    };

    // Read envelope + decode payload (used for both DSSE PAE and the
    // subject-digest check). Continue past errors so the binding check
    // can still surface a useful finding when we can.
    let envelope_bytes = match std::fs::read(envelope_path) {
        Ok(b) => b,
        Err(e) => {
            verdict.verdict = SignatureVerdict::Failed(format!("read envelope: {e}"));
            return verdict;
        }
    };
    let envelope = match parse_dsse_envelope(std::str::from_utf8(&envelope_bytes).unwrap_or("")) {
        Ok(e) => e,
        Err(e) => {
            verdict.verdict = SignatureVerdict::Failed(format!("parse envelope: {e}"));
            return verdict;
        }
    };
    let payload_bytes =
        match base64::engine::general_purpose::STANDARD.decode(envelope.payload.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                verdict.verdict = SignatureVerdict::Failed(format!("decode payload base64: {e}"));
                return verdict;
            }
        };

    // Digest binding — independent of crypto, always computed.
    if let Ok(payload_str) = std::str::from_utf8(&payload_bytes)
        && let Ok(stmt) = parse_in_toto_statement(payload_str)
    {
        verdict.predicate_type = Some(stmt.predicate_type.clone());
        verdict.digest_binding_ok = subject_matches_image_digest(&stmt, image_digest);
    } else {
        verdict.digest_binding_ok = false;
    }

    // Locate the sidecar cert. Filename convention: replace `.dsse.json`
    // with `.cert.pem` on the envelope path.
    let cert_path = match envelope_path
        .to_str()
        .and_then(|s| s.strip_suffix(".dsse.json"))
    {
        Some(stem) => std::path::PathBuf::from(format!("{stem}.cert.pem")),
        None => {
            verdict.verdict = SignatureVerdict::Failed(
                "envelope file does not have a .dsse.json extension".to_string(),
            );
            return verdict;
        }
    };
    if !cert_path.exists() {
        verdict.verdict = SignatureVerdict::Failed(format!(
            "no cosign cert annotation found on this attestation layer (expected at {}); \
             keyless verification needs a Fulcio-issued ephemeral cert. If this image was \
             signed with `cosign sign --key`, re-run with --key COSIGN_PUB instead",
            cert_path.display()
        ));
        return verdict;
    }
    let cert_pem = match std::fs::read(&cert_path) {
        Ok(b) => b,
        Err(e) => {
            verdict.verdict =
                SignatureVerdict::Failed(format!("read cert sidecar {}: {e}", cert_path.display()));
            return verdict;
        }
    };

    // Parse the cert and run the identity + issuer checks.
    let cert = match X509Certificate::from_pem(&cert_pem) {
        Ok(c) => c,
        Err(e) => {
            verdict.verdict = SignatureVerdict::Failed(format!("parse cert PEM: {e}"));
            return verdict;
        }
    };
    let subject = match CertificateSubject::from_certificate(&cert) {
        Ok(s) => s,
        Err(e) => {
            verdict.verdict = SignatureVerdict::Failed(format!("extract SAN: {e}"));
            return verdict;
        }
    };
    let subject_str = match &subject {
        CertificateSubject::Uri(u) => u.as_str(),
        CertificateSubject::Email(e) => e.as_str(),
    };
    if !identity.matches(subject_str) {
        verdict.verdict = SignatureVerdict::Failed(format!(
            "cert SAN `{subject_str}` does not match the configured identity"
        ));
        return verdict;
    }
    match extract_oidc_issuer_extension(&cert) {
        Some(iss) if iss == oidc_issuer => {}
        Some(iss) => {
            verdict.verdict = SignatureVerdict::Failed(format!(
                "cert OIDC issuer `{iss}` does not match `{oidc_issuer}`"
            ));
            return verdict;
        }
        None => {
            verdict.verdict = SignatureVerdict::Failed(
                "cert missing OIDC issuer extension (OID 1.3.6.1.4.1.57264.1.1)".to_string(),
            );
            return verdict;
        }
    }

    // Verify each DSSE signature against the cert's public key.
    let key = match CosignVerificationKey::try_from(&cert.tbs_certificate.subject_public_key_info) {
        Ok(k) => k,
        Err(e) => {
            verdict.verdict = SignatureVerdict::Failed(format!("extract pubkey from cert: {e}"));
            return verdict;
        }
    };
    if envelope.signatures.is_empty() {
        verdict.verdict = SignatureVerdict::Failed("envelope has no signatures".to_string());
        return verdict;
    }
    let pae = dsse_pae(&envelope.payload_type, &payload_bytes);
    let mut last_err: Option<String> = None;
    let mut any_ok = false;
    for sig in &envelope.signatures {
        match key.verify_signature(Signature::Base64Encoded(sig.sig.as_bytes()), &pae) {
            Ok(()) => {
                any_ok = true;
                break;
            }
            Err(e) => last_err = Some(format!("{e}")),
        }
    }
    verdict.verdict = if any_ok {
        SignatureVerdict::Verified
    } else {
        SignatureVerdict::Failed(last_err.unwrap_or_else(|| "no signature verified".to_string()))
    };
    verdict
}

/// Fulcio "OIDC Issuer" cert extension (legacy OID 1.3.6.1.4.1.57264.1.1).
/// The extension value is a raw UTF-8 string holding the issuer URL.
fn extract_oidc_issuer_extension(cert: &X509Certificate) -> Option<String> {
    use x509_cert::der::asn1::ObjectIdentifier;
    let target = ObjectIdentifier::new("1.3.6.1.4.1.57264.1.1").ok()?;
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    extensions
        .iter()
        .find(|ext| ext.extn_id == target)
        .and_then(|ext| std::str::from_utf8(ext.extn_value.as_bytes()).ok())
        .map(|s| s.to_string())
}

fn verify_keyless_image_signature(
    runtime: &Runtime,
    reference: &OciReference,
    image_digest: &str,
    auth: &AuthInputs,
    identity_match: IdentityMatch,
    oidc_issuer: &str,
) -> Result<SignatureVerdict, OciError> {
    let sigstore_auth = to_sigstore_auth(auth);
    let sigstore_ref: SigstoreOciRef = reference.to_string().parse().map_err(|e| {
        OciError::InvalidReference(format!("sigstore cannot parse `{reference}`: {e}"))
    })?;
    let oidc_issuer = oidc_issuer.to_string();
    // First run fetches the Sigstore TUF root over the network; subsequent
    // runs reuse the cache. Ensure the directory exists so the underlying
    // tough library can write to it.
    let cache_dir = crate::pipeline::dirs::cache_dir().map(|d| d.join("sigstore-tuf"));
    if let Some(ref dir) = cache_dir {
        let _ = std::fs::create_dir_all(dir);
    }

    let outcome = runtime.block_on(async move {
        // Bundled Sigstore public-good TUF root. First run hits the network
        // to fetch the trusted_root.json; subsequent runs reuse the cache.
        let trust_root = SigstoreTrustRoot::new(cache_dir.as_deref())
            .await
            .map_err(|e| format!("fetch Sigstore TUF root: {e}"))?;
        let mut client = ClientBuilder::default()
            .with_trust_repository(&trust_root)
            .map_err(|e| format!("trust repository: {e}"))?
            .build()
            .map_err(|e| format!("sigstore client build: {e}"))?;
        let (cosign_ref, _) = client
            .triangulate(&sigstore_ref, &sigstore_auth)
            .await
            .map_err(|e| format!("triangulate: {e}"))?;
        let layers = client
            .trusted_signature_layers(&sigstore_auth, image_digest, &cosign_ref)
            .await
            .map_err(|e| format!("pull signature layers: {e}"))?;
        if layers.is_empty() {
            return Err("no signature layers found at the cosign .sig tag".to_string());
        }
        let verifier = KeylessIdentityVerifier {
            identity: identity_match,
            issuer: oidc_issuer,
        };
        let constraints: VerificationConstraintVec = vec![Box::new(verifier)];
        verify_constraints(&layers, constraints.iter()).map_err(|e| {
            format!(
                "no signature layer matched identity / issuer — {} cert(s) inspected: {e}",
                layers.len()
            )
        })?;
        Ok::<_, String>(layers.len())
    });

    Ok(match outcome {
        Ok(_) => SignatureVerdict::Verified,
        Err(msg) => SignatureVerdict::Failed(msg),
    })
}

/// DSSE Pre-Authentication Encoding (RFC: secure-systems-lab/dsse v1.0).
///
/// `DSSEv1 <payloadType_len> <payloadType> <payload_len> <payload_bytes>`
///
/// The signature is computed over this byte string, NOT over the base64
/// payload directly.
fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::with_capacity(32 + payload_type.len() + payload.len());
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}

// ============================================================================
// Auth conversion
// ============================================================================

fn to_sigstore_auth(auth: &AuthInputs) -> SigstoreAuth {
    if let Some(token) = &auth.token {
        SigstoreAuth::Bearer(token.clone())
    } else if let (Some(u), Some(p)) = (&auth.username, &auth.password) {
        SigstoreAuth::Basic(u.clone(), p.clone())
    } else {
        SigstoreAuth::Anonymous
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsse_pae_matches_spec() {
        // Per the DSSE spec, PAE("application/vnd.in-toto+json", "hi") is:
        //   "DSSEv1 28 application/vnd.in-toto+json 2 hi"
        let pae = dsse_pae("application/vnd.in-toto+json", b"hi");
        assert_eq!(pae, b"DSSEv1 28 application/vnd.in-toto+json 2 hi");
    }

    #[test]
    fn dsse_pae_handles_binary_payload() {
        let payload: &[u8] = &[0xff, 0x00, 0x7f];
        let pae = dsse_pae("x", payload);
        assert!(pae.starts_with(b"DSSEv1 1 x 3 "));
        assert_eq!(&pae[pae.len() - 3..], payload);
    }

    #[test]
    fn keyless_custom_trust_root_is_rejected_with_invalid_policy() {
        // --trust-root <path> isn't wired in v1; the keyless path must fail
        // up front with InvalidPolicy rather than silently fall back. No
        // network is touched on this path.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let policy = VerificationPolicy::Keyless {
            identity: crate::oci::IdentityMatcher::Exact("x".to_string()),
            oidc_issuer: "https://issuer".to_string(),
            trust_root: crate::oci::TrustRoot::Custom(std::path::PathBuf::from(
                "/etc/sigstore/root.json",
            )),
            rekor: crate::oci::RekorPolicy::IgnoreTlog,
        };
        let reference = OciReference::parse("ghcr.io/acme/api:v1").unwrap();
        let auth = AuthInputs::default();
        let r = verify_image(&runtime, &reference, "sha256:abc", &auth, &policy, &[]);
        assert!(matches!(r, Err(OciError::InvalidPolicy(_))));
    }

    #[test]
    fn keyless_invalid_regex_returns_invalid_policy() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let policy = VerificationPolicy::Keyless {
            identity: crate::oci::IdentityMatcher::Regexp("[invalid-regex".to_string()),
            oidc_issuer: "https://issuer".to_string(),
            trust_root: crate::oci::TrustRoot::BundledPublicGood,
            rekor: crate::oci::RekorPolicy::Online("https://rekor.sigstore.dev".to_string()),
        };
        let reference = OciReference::parse("ghcr.io/acme/api:v1").unwrap();
        let auth = AuthInputs::default();
        let r = verify_image(&runtime, &reference, "sha256:abc", &auth, &policy, &[]);
        assert!(matches!(r, Err(OciError::InvalidPolicy(_))));
    }

    #[test]
    fn identity_match_exact_and_regex() {
        let exact = IdentityMatch::from_policy(&IdentityMatcher::Exact(
            "https://github.com/acme/api/.github/workflows/release.yml@refs/tags/v1".to_string(),
        ))
        .unwrap();
        assert!(
            exact.matches("https://github.com/acme/api/.github/workflows/release.yml@refs/tags/v1")
        );
        assert!(!exact.matches("https://github.com/other/api"));

        let regex = IdentityMatch::from_policy(&IdentityMatcher::Regexp(
            "^https://github\\.com/acme/.+".to_string(),
        ))
        .unwrap();
        assert!(regex.matches("https://github.com/acme/api/whatever"));
        assert!(!regex.matches("https://github.com/other/api"));
    }

    #[test]
    fn none_policy_yields_skipped() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let reference = OciReference::parse("ghcr.io/acme/api:v1").unwrap();
        let auth = AuthInputs::default();
        let r = verify_image(
            &runtime,
            &reference,
            "sha256:abc",
            &auth,
            &VerificationPolicy::None,
            &[],
        )
        .unwrap();
        assert_eq!(r.image_signature, SignatureVerdict::Skipped);
        assert!(r.attestations.is_empty());
        assert!(r.findings.is_empty());
    }

    #[test]
    fn missing_key_file_returns_io_error() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let policy = VerificationPolicy::KeyBased {
            key_path: std::path::PathBuf::from("/nonexistent/cosign.pub"),
        };
        let reference = OciReference::parse("ghcr.io/acme/api:v1").unwrap();
        let auth = AuthInputs::default();
        let err =
            verify_image(&runtime, &reference, "sha256:abc", &auth, &policy, &[]).unwrap_err();
        assert!(matches!(err, OciError::Io(_)));
    }
}
