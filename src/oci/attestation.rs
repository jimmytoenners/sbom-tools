//! DSSE envelope + in-toto Statement parsing and predicate classification.
//!
//! Pulls apart the JSON shapes that wrap an SBOM/VEX attached to an OCI image
//! via cosign attestations:
//!
//! ```text
//! DSSE envelope
//!   { payloadType, payload (base64), signatures: [{ keyid, sig }] }
//!         |
//!         | base64-decoded by the network/crypto glue (in verify.rs)
//!         v
//! in-toto Statement v1
//!   { _type, subject: [{ name, digest: { algo: hex } }], predicateType, predicate }
//!         |
//!         | predicate is the actual SBOM/VEX object
//!         v
//! CycloneDX / SPDX / OpenVEX document (handed to the existing parsers)
//! ```
//!
//! Everything here is dependency-free: serde structs, a predicate-type
//! classifier, and the digest-binding check. The DSSE signature crypto and
//! the base64 payload decode happen in `verify.rs` once the `sigstore`
//! dependency lands; this module only deals with shape and identity.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{ArtifactKind, OciError};

// ============================================================================
// DSSE envelope (https://github.com/secure-systems-lab/dsse)
// ============================================================================

/// A DSSE envelope wrapping an in-toto Statement payload.
///
/// The payload itself is base64-encoded; this struct deliberately does *not*
/// decode it (that requires the `base64` dependency which lands with the
/// crypto glue). Callers who need the decoded payload use `verify.rs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DsseEnvelope {
    /// `payloadType` — typically `application/vnd.in-toto+json`.
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64-encoded payload (the in-toto Statement, when payload_type is in-toto).
    pub payload: String,
    /// One or more DSSE signatures over the PAE(payload_type, payload).
    pub signatures: Vec<DsseSignature>,
}

/// A single DSSE signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DsseSignature {
    /// Optional key identifier — opaque to DSSE itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    /// Base64-encoded signature bytes.
    pub sig: String,
}

impl DsseEnvelope {
    /// Whether the envelope's payload is an in-toto Statement (the only
    /// payload type cosign uses for SBOM/VEX attestations today).
    #[must_use]
    pub fn is_in_toto(&self) -> bool {
        self.payload_type == IN_TOTO_PAYLOAD_TYPE
    }
}

/// DSSE `payloadType` for in-toto Statements.
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Parse a DSSE envelope from a JSON string.
///
/// # Errors
///
/// Returns [`OciError::Parse`] if the JSON is malformed or doesn't match the
/// DSSE shape.
pub fn parse_dsse_envelope(json: &str) -> Result<DsseEnvelope, OciError> {
    let env: DsseEnvelope =
        serde_json::from_str(json).map_err(|e| OciError::Parse(format!("DSSE envelope: {e}")))?;
    if env.payload_type.is_empty() {
        return Err(OciError::Parse(
            "DSSE envelope is missing payloadType".to_string(),
        ));
    }
    if env.signatures.is_empty() {
        return Err(OciError::Parse(
            "DSSE envelope has no signatures".to_string(),
        ));
    }
    Ok(env)
}

// ============================================================================
// in-toto Statement v1
// (https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
// ============================================================================

/// in-toto Statement `_type` value for v1.
pub const IN_TOTO_STATEMENT_TYPE_V1: &str = "https://in-toto.io/Statement/v1";
/// in-toto Statement `_type` value for v0.1 (still seen in the wild).
pub const IN_TOTO_STATEMENT_TYPE_V01: &str = "https://in-toto.io/Statement/v0.1";

/// A decoded in-toto Statement (the payload of a DSSE envelope).
///
/// The `predicate` is left as `serde_json::Value` so the caller can hand it
/// off to the appropriate downstream parser (CycloneDX, SPDX, OpenVEX, …)
/// based on `predicate_type`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InTotoStatement {
    /// `_type` — `https://in-toto.io/Statement/v1` (or v0.1).
    #[serde(rename = "_type")]
    pub r#type: String,
    /// What the statement is about. At least one entry is required.
    pub subject: Vec<InTotoSubject>,
    /// URI naming the predicate schema (drives `classify_predicate`).
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// The predicate body — schema depends on `predicate_type`.
    pub predicate: serde_json::Value,
}

/// One subject of an in-toto Statement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InTotoSubject {
    /// Human-readable name (e.g. image ref) — optional and informational.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Cryptographic digests of the subject. The map key is the algorithm
    /// (`sha256`, `sha512`, …) and the value is the **hex-encoded** digest
    /// **without** the `algorithm:` prefix.
    pub digest: BTreeMap<String, String>,
}

/// Parse an in-toto Statement from a (DSSE-decoded) JSON string.
///
/// # Errors
///
/// Returns [`OciError::Parse`] if the JSON is malformed, the `_type` isn't a
/// recognised in-toto Statement version, or `subject` is empty.
pub fn parse_in_toto_statement(json: &str) -> Result<InTotoStatement, OciError> {
    let stmt: InTotoStatement = serde_json::from_str(json)
        .map_err(|e| OciError::Parse(format!("in-toto Statement: {e}")))?;
    if stmt.r#type != IN_TOTO_STATEMENT_TYPE_V1 && stmt.r#type != IN_TOTO_STATEMENT_TYPE_V01 {
        return Err(OciError::Parse(format!(
            "unexpected in-toto Statement _type `{}` (expected `{}` or `{}`)",
            stmt.r#type, IN_TOTO_STATEMENT_TYPE_V1, IN_TOTO_STATEMENT_TYPE_V01
        )));
    }
    if stmt.subject.is_empty() {
        return Err(OciError::Parse(
            "in-toto Statement has no subjects".to_string(),
        ));
    }
    if stmt.predicate_type.is_empty() {
        return Err(OciError::Parse(
            "in-toto Statement is missing predicateType".to_string(),
        ));
    }
    Ok(stmt)
}

// ============================================================================
// Predicate-type classification
// ============================================================================

/// Map an in-toto `predicateType` to the artifact kind it carries.
///
/// Returns `Some(Sbom)` / `Some(Vex)` for the predicate types this tool
/// natively parses; returns `None` for anything else (cosign signatures,
/// SLSA provenance, vuln-scan attestations, unknowns). Unknown predicates
/// are *not* errors — they're recorded but not extracted as SBOM/VEX.
///
/// Matching is prefix-based to tolerate versioned predicate URIs like
/// `https://openvex.dev/ns/v0.2.0` or `https://cyclonedx.org/bom/v1.6`.
#[must_use]
pub fn classify_predicate(predicate_type: &str) -> Option<ArtifactKind> {
    if predicate_type.starts_with("https://cyclonedx.org/bom")
        || predicate_type.starts_with("https://spdx.dev/Document")
    {
        Some(ArtifactKind::Sbom)
    } else if predicate_type.starts_with("https://openvex.dev/ns") {
        Some(ArtifactKind::Vex)
    } else {
        None
    }
}

/// Whether a predicate is one of the well-known attestation predicates
/// recognised by the OCI layer (SBOM, VEX, in-toto vulns, SLSA provenance).
/// Used to decide whether to *record* an attestation in the report; whether
/// to *extract* it as SBOM/VEX is a separate question — see
/// [`classify_predicate`].
#[must_use]
pub fn is_known_predicate(predicate_type: &str) -> bool {
    classify_predicate(predicate_type).is_some()
        || predicate_type.starts_with("https://in-toto.io/attestation/vulns")
        || predicate_type.starts_with("https://slsa.dev/provenance")
}

// ============================================================================
// Digest binding
// ============================================================================

/// Whether any of the statement's subjects names the given image digest.
///
/// `image_digest` is an OCI-form digest (`algorithm:hex`, e.g.
/// `sha256:abc123…`). in-toto stores digests as `{ algorithm: hex }` so we
/// strip the prefix and look up by algorithm. Any matching subject is enough
/// — an in-toto Statement may have multiple subjects (multi-arch index, etc.)
/// and we only need one to be the image we pulled.
///
/// Returns `false` when `image_digest` doesn't have the `algorithm:hex` shape.
#[must_use]
pub fn subject_matches_image_digest(stmt: &InTotoStatement, image_digest: &str) -> bool {
    let Some((algo, hex)) = image_digest.split_once(':') else {
        return false;
    };
    stmt.subject.iter().any(|s| {
        s.digest
            .get(algo)
            .is_some_and(|v| v.eq_ignore_ascii_case(hex))
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- DSSE -------------------------------------------------------------

    const DSSE_OK: &str = r#"{
        "payloadType": "application/vnd.in-toto+json",
        "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEifQ==",
        "signatures": [{ "keyid": "k1", "sig": "BASE64SIG==" }]
    }"#;

    #[test]
    fn parses_valid_dsse_envelope() {
        let env = parse_dsse_envelope(DSSE_OK).unwrap();
        assert!(env.is_in_toto());
        assert_eq!(env.signatures.len(), 1);
        assert_eq!(env.signatures[0].keyid.as_deref(), Some("k1"));
    }

    #[test]
    fn dsse_rejects_empty_signatures() {
        let bad = r#"{"payloadType":"application/vnd.in-toto+json","payload":"","signatures":[]}"#;
        assert!(matches!(parse_dsse_envelope(bad), Err(OciError::Parse(_))));
    }

    #[test]
    fn dsse_rejects_malformed_json() {
        assert!(matches!(
            parse_dsse_envelope("not json"),
            Err(OciError::Parse(_))
        ));
    }

    #[test]
    fn dsse_is_in_toto_predicate() {
        let env = parse_dsse_envelope(DSSE_OK).unwrap();
        assert!(env.is_in_toto());
    }

    // ---- in-toto Statement -------------------------------------------------

    const STMT_V1_CYCLONEDX: &str = r#"{
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": "ghcr.io/acme/api",
            "digest": { "sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" }
        }],
        "predicateType": "https://cyclonedx.org/bom/v1.6",
        "predicate": { "bomFormat": "CycloneDX", "specVersion": "1.6" }
    }"#;

    #[test]
    fn parses_in_toto_v1_statement() {
        let stmt = parse_in_toto_statement(STMT_V1_CYCLONEDX).unwrap();
        assert_eq!(stmt.r#type, IN_TOTO_STATEMENT_TYPE_V1);
        assert_eq!(stmt.subject.len(), 1);
        assert_eq!(stmt.predicate_type, "https://cyclonedx.org/bom/v1.6");
        assert_eq!(stmt.subject[0].name.as_deref(), Some("ghcr.io/acme/api"));
    }

    #[test]
    fn accepts_in_toto_v0_1_for_compat() {
        let json = STMT_V1_CYCLONEDX.replace(IN_TOTO_STATEMENT_TYPE_V1, IN_TOTO_STATEMENT_TYPE_V01);
        assert!(parse_in_toto_statement(&json).is_ok());
    }

    #[test]
    fn rejects_unknown_statement_type() {
        let bad =
            STMT_V1_CYCLONEDX.replace(IN_TOTO_STATEMENT_TYPE_V1, "https://example.invalid/v9");
        assert!(matches!(
            parse_in_toto_statement(&bad),
            Err(OciError::Parse(_))
        ));
    }

    #[test]
    fn rejects_empty_subject() {
        let bad = r#"{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"x","predicate":{}}"#;
        assert!(matches!(
            parse_in_toto_statement(bad),
            Err(OciError::Parse(_))
        ));
    }

    #[test]
    fn rejects_missing_predicate_type() {
        let bad = r#"{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}],"predicateType":"","predicate":{}}"#;
        assert!(matches!(
            parse_in_toto_statement(bad),
            Err(OciError::Parse(_))
        ));
    }

    // ---- predicate classification ------------------------------------------

    #[test]
    fn classifies_cyclonedx_as_sbom() {
        assert_eq!(
            classify_predicate("https://cyclonedx.org/bom"),
            Some(ArtifactKind::Sbom)
        );
        assert_eq!(
            classify_predicate("https://cyclonedx.org/bom/v1.6"),
            Some(ArtifactKind::Sbom)
        );
    }

    #[test]
    fn classifies_spdx_as_sbom() {
        assert_eq!(
            classify_predicate("https://spdx.dev/Document"),
            Some(ArtifactKind::Sbom)
        );
    }

    #[test]
    fn classifies_openvex_as_vex() {
        assert_eq!(
            classify_predicate("https://openvex.dev/ns"),
            Some(ArtifactKind::Vex)
        );
        assert_eq!(
            classify_predicate("https://openvex.dev/ns/v0.2.0"),
            Some(ArtifactKind::Vex)
        );
    }

    #[test]
    fn unknown_predicate_returns_none() {
        assert_eq!(
            classify_predicate("https://example.invalid/predicate"),
            None
        );
    }

    #[test]
    fn vulns_attestation_is_known_but_unclassified() {
        // Recorded but not auto-extracted as SBOM or VEX.
        let p = "https://in-toto.io/attestation/vulns/v0.1";
        assert!(is_known_predicate(p));
        assert_eq!(classify_predicate(p), None);
    }

    #[test]
    fn slsa_provenance_is_known_but_unclassified() {
        let p = "https://slsa.dev/provenance/v1";
        assert!(is_known_predicate(p));
        assert_eq!(classify_predicate(p), None);
    }

    // ---- digest binding ----------------------------------------------------

    #[test]
    fn subject_matches_when_digest_present() {
        let stmt = parse_in_toto_statement(STMT_V1_CYCLONEDX).unwrap();
        let digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert!(subject_matches_image_digest(&stmt, digest));
    }

    #[test]
    fn subject_match_is_case_insensitive_on_hex() {
        let stmt = parse_in_toto_statement(STMT_V1_CYCLONEDX).unwrap();
        let digest = "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert!(subject_matches_image_digest(&stmt, digest));
    }

    #[test]
    fn subject_mismatch_when_digest_differs() {
        let stmt = parse_in_toto_statement(STMT_V1_CYCLONEDX).unwrap();
        let other = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!subject_matches_image_digest(&stmt, other));
    }

    #[test]
    fn subject_mismatch_on_different_algorithm() {
        let stmt = parse_in_toto_statement(STMT_V1_CYCLONEDX).unwrap();
        // Statement has only sha256; ask about sha512 → no match.
        let sha512 = "sha512:deadbeef".to_string() + &"0".repeat(120);
        assert!(!subject_matches_image_digest(&stmt, &sha512));
    }

    #[test]
    fn subject_match_rejects_malformed_image_digest() {
        let stmt = parse_in_toto_statement(STMT_V1_CYCLONEDX).unwrap();
        assert!(!subject_matches_image_digest(&stmt, "nodigesthere"));
    }

    #[test]
    fn subject_matches_when_any_subject_has_digest() {
        // Multi-arch index: the statement covers two subjects; only one matches.
        let json = r#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                { "digest": { "sha256": "1111111111111111111111111111111111111111111111111111111111111111" } },
                { "digest": { "sha256": "2222222222222222222222222222222222222222222222222222222222222222" } }
            ],
            "predicateType": "https://cyclonedx.org/bom",
            "predicate": {}
        }"#;
        let stmt = parse_in_toto_statement(json).unwrap();
        let target = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        assert!(subject_matches_image_digest(&stmt, target));
    }
}
