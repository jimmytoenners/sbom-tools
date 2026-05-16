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
//! Key-based verification only. Keyless (Fulcio + Rekor + OIDC identity
//! matching) is the next increment and returns
//! [`OciError::NotImplemented`] today.

use std::path::Path;

use base64::Engine;
use sigstore::cosign::verification_constraint::{PublicKeyVerifier, VerificationConstraintVec};
use sigstore::cosign::{ClientBuilder, CosignCapabilities, verify_constraints};
use sigstore::crypto::{CosignVerificationKey, Signature};
use sigstore::registry::{Auth as SigstoreAuth, OciReference as SigstoreOciRef};
use tokio::runtime::Runtime;

use crate::quality::ViolationSeverity;

use super::{
    AttestationVerdict, AuthInputs, OciError, OciReference, OciVerificationFinding,
    SignatureVerdict, VerificationPolicy, VerificationReport,
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
/// - [`OciError::NotImplemented`] for keyless policies (not yet wired).
/// - [`OciError::InvalidPolicy`] when the public key can't be loaded.
/// - I/O errors when reading the key or envelope files.
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
        VerificationPolicy::Keyless { .. } => Err(OciError::NotImplemented(
            "keyless cosign verification (Fulcio + Rekor + identity matching) \
             is the next increment — re-run with --key for key-based verification \
             or --no-verify to fetch only"
                .to_string(),
        )),
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
    fn keyless_returns_not_implemented_for_now() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let policy = VerificationPolicy::Keyless {
            identity: crate::oci::IdentityMatcher::Exact("x".to_string()),
            oidc_issuer: "https://issuer".to_string(),
            trust_root: crate::oci::TrustRoot::BundledPublicGood,
            rekor: crate::oci::RekorPolicy::IgnoreTlog,
        };
        let reference = OciReference::parse("ghcr.io/acme/api:v1").unwrap();
        let auth = AuthInputs::default();
        let r = verify_image(&runtime, &reference, "sha256:abc", &auth, &policy, &[]);
        assert!(matches!(r, Err(OciError::NotImplemented(_))));
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
