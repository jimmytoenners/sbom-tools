//! SARIF 2.1.0 emitter for `oci verify` results.
//!
//! Self-contained — emits a fresh SARIF document per OCI verification
//! run, with a rule index covering every `SBOM-OCI-*` rule the OCI
//! resolver can emit. Findings from [`VerificationReport`] become
//! `runs[0].results` entries; the image reference goes in
//! `runs[0].invocations[0]` as a property so CI can route results back
//! to the artifact.
//!
//! See [`docs/oci-verify-plan.md`](../../docs/oci-verify-plan.md) for
//! the canonical rule catalogue.

use serde::Serialize;

use crate::oci::{OciReference, OciVerificationFinding, VerificationReport};
use crate::quality::ViolationSeverity;

use super::ReportError;

const SCHEMA_URL: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const INFO_URI: &str = "https://github.com/sbom-tool/sbom-tools";
const DRIVER_NAME: &str = "sbom-tools-oci-verify";
const PROPOSAL_URI: &str =
    "https://github.com/sbom-tool/sbom-tools/blob/main/docs/oci-verify-plan.md";

/// Render a [`VerificationReport`] as a SARIF 2.1.0 document.
///
/// # Errors
///
/// Only fails if `serde_json` can't serialise the (purely owned) document
/// — practically never.
pub fn generate_oci_sarif(
    reference: &OciReference,
    image_digest: &str,
    report: &VerificationReport,
) -> Result<String, ReportError> {
    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .map(|f| finding_to_sarif(f, reference, image_digest))
        .collect();

    let doc = SarifReport {
        schema: SCHEMA_URL.to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: DRIVER_NAME.to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: INFO_URI.to_string(),
                    rules: oci_rule_index(),
                },
            },
            invocations: vec![SarifInvocation {
                execution_successful: report.findings.is_empty(),
                properties: SarifInvocationProperties {
                    image_reference: reference.to_string(),
                    image_digest: image_digest.to_string(),
                    image_signature: verdict_label(&report.image_signature),
                    attestations_total: report.attestations.len(),
                    attestations_verified: report
                        .attestations
                        .iter()
                        .filter(|a| matches!(a.verdict, crate::oci::SignatureVerdict::Verified))
                        .count(),
                    attestations_failed: report
                        .attestations
                        .iter()
                        .filter(|a| matches!(a.verdict, crate::oci::SignatureVerdict::Failed(_)))
                        .count(),
                    digest_binding_ok: report.digest_binding_ok,
                },
            }],
            results,
        }],
    };

    serde_json::to_string_pretty(&doc).map_err(|e| ReportError::SerializationError(e.to_string()))
}

fn verdict_label(v: &crate::oci::SignatureVerdict) -> &'static str {
    match v {
        crate::oci::SignatureVerdict::Verified => "verified",
        crate::oci::SignatureVerdict::Failed(_) => "failed",
        crate::oci::SignatureVerdict::Skipped => "skipped",
    }
}

fn finding_to_sarif(
    finding: &OciVerificationFinding,
    reference: &OciReference,
    image_digest: &str,
) -> SarifResult {
    SarifResult {
        rule_id: finding.rule_id.clone(),
        level: match finding.severity {
            ViolationSeverity::Error => SarifLevel::Error,
            ViolationSeverity::Warning => SarifLevel::Warning,
            ViolationSeverity::Info => SarifLevel::Note,
        },
        message: SarifMessage {
            text: finding.message.clone(),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    // The "artifact" is the OCI image. SARIF doesn't have a
                    // first-class registry-URI type, so we use the OCI ref
                    // verbatim and let downstream tooling parse it.
                    uri: format!("oci://{reference}"),
                },
            },
        }],
        properties: SarifResultProperties {
            image_digest: image_digest.to_string(),
        },
    }
}

/// Catalogue of every `SBOM-OCI-*` rule the OCI verifier emits.
///
/// Kept here (rather than dynamically derived from findings) so a SARIF
/// document always lists every reachable rule in the tool's index —
/// matching the convention `quality::compliance` uses.
fn oci_rule_index() -> Vec<SarifRule> {
    let entries: &[(&str, &str, &str, SarifLevel)] = &[
        (
            "SBOM-OCI-SIG-001",
            "image-signature-missing",
            "Image manifest has no cosign signature at the .sig tag",
            SarifLevel::Error,
        ),
        (
            "SBOM-OCI-SIG-002",
            "image-signature-invalid",
            "Image signature was present but failed verification (bad key/identity/Rekor)",
            SarifLevel::Error,
        ),
        (
            "SBOM-OCI-SIG-003",
            "keyless-identity-mismatch",
            "Keyless cert SAN does not match the configured --certificate-identity[-regexp]",
            SarifLevel::Error,
        ),
        (
            "SBOM-OCI-SIG-004",
            "keyless-issuer-mismatch",
            "Keyless cert OIDC issuer does not match --certificate-oidc-issuer",
            SarifLevel::Error,
        ),
        (
            "SBOM-OCI-SIG-005",
            "rekor-inclusion-missing",
            "Rekor transparency-log inclusion proof missing or invalid",
            SarifLevel::Error,
        ),
        (
            "SBOM-OCI-ATT-001",
            "attestation-signature-invalid",
            "Attestation DSSE envelope failed signature verification",
            SarifLevel::Error,
        ),
        (
            "SBOM-OCI-ATT-002",
            "attestation-digest-binding",
            "Attestation in-toto subject digest does not match the resolved image digest",
            SarifLevel::Error,
        ),
        (
            "SBOM-OCI-ATT-003",
            "required-attestation-absent",
            "A `--require-attestation` predicate type was not present in the verified set",
            SarifLevel::Error,
        ),
        (
            "SBOM-OCI-ATT-004",
            "attestation-predicate-unknown",
            "Attestation predicate type unrecognised — recorded but not extracted",
            SarifLevel::Warning,
        ),
        (
            "SBOM-OCI-DISC-001",
            "no-sbom-discovered",
            "No SBOM artifact found via any discovery scheme",
            SarifLevel::Warning,
        ),
        (
            "SBOM-OCI-DISC-002",
            "referrers-api-unavailable",
            "Registry does not implement the OCI 1.1 Referrers API; fell back to the cosign tag scheme",
            SarifLevel::Note,
        ),
        (
            "SBOM-OCI-DISC-003",
            "no-vex-discovered",
            "No VEX artifact attached to the image",
            SarifLevel::Warning,
        ),
    ];

    entries
        .iter()
        .map(|(id, name, desc, level)| SarifRule {
            id: (*id).to_string(),
            name: (*name).to_string(),
            short_description: SarifMessage {
                text: (*desc).to_string(),
            },
            default_configuration: SarifConfiguration { level: *level },
            help_uri: Some(PROPOSAL_URI),
        })
        .collect()
}

// ============================================================================
// SARIF 2.1.0 minimal schema (only the fields we populate)
// ============================================================================

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    tool: SarifTool,
    invocations: Vec<SarifInvocation>,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: String,
    version: String,
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    default_configuration: SarifConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    help_uri: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifConfiguration {
    level: SarifLevel,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifInvocation {
    execution_successful: bool,
    properties: SarifInvocationProperties,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifInvocationProperties {
    image_reference: String,
    image_digest: String,
    image_signature: &'static str,
    attestations_total: usize,
    attestations_verified: usize,
    attestations_failed: usize,
    digest_binding_ok: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: SarifLevel,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    properties: SarifResultProperties,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResultProperties {
    image_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum SarifLevel {
    Note,
    Warning,
    Error,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{AttestationVerdict, SignatureVerdict};

    fn sample_ref() -> OciReference {
        OciReference::parse("ghcr.io/acme/api:v1").unwrap()
    }

    #[test]
    fn empty_report_produces_clean_sarif() {
        let report = VerificationReport {
            image_signature: SignatureVerdict::Verified,
            attestations: vec![AttestationVerdict {
                predicate_type: Some("https://cyclonedx.org/bom".to_string()),
                verdict: SignatureVerdict::Verified,
                digest_binding_ok: true,
            }],
            digest_binding_ok: true,
            findings: vec![],
        };
        let json = generate_oci_sarif(&sample_ref(), "sha256:abc", &report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(
            v["runs"][0]["invocations"][0]["executionSuccessful"], true,
            "no findings → successful invocation"
        );
        assert_eq!(
            v["runs"][0]["invocations"][0]["properties"]["imageSignature"],
            "verified"
        );
        assert_eq!(
            v["runs"][0]["invocations"][0]["properties"]["attestationsVerified"],
            1
        );
    }

    #[test]
    fn findings_become_results_with_rule_ids_and_locations() {
        let report = VerificationReport {
            image_signature: SignatureVerdict::Failed("bad signature".to_string()),
            attestations: vec![],
            digest_binding_ok: false,
            findings: vec![
                OciVerificationFinding {
                    rule_id: "SBOM-OCI-SIG-002".to_string(),
                    severity: ViolationSeverity::Error,
                    message: "Image signature failed".to_string(),
                },
                OciVerificationFinding {
                    rule_id: "SBOM-OCI-ATT-002".to_string(),
                    severity: ViolationSeverity::Error,
                    message: "Subject digest mismatch".to_string(),
                },
            ],
        };
        let json = generate_oci_sarif(&sample_ref(), "sha256:abc", &report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleId"], "SBOM-OCI-SIG-002");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "oci://ghcr.io/acme/api:v1"
        );
        assert_eq!(results[1]["ruleId"], "SBOM-OCI-ATT-002");
        assert_eq!(v["runs"][0]["invocations"][0]["executionSuccessful"], false);
    }

    #[test]
    fn rule_index_covers_every_sbom_oci_rule_used_in_code() {
        // Every rule we emit findings under MUST appear in the index so
        // SARIF consumers can resolve helpUri / description.
        let json = generate_oci_sarif(
            &sample_ref(),
            "sha256:abc",
            &VerificationReport {
                image_signature: SignatureVerdict::Skipped,
                attestations: vec![],
                digest_binding_ok: true,
                findings: vec![],
            },
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let rule_ids: Vec<String> = v["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect();
        // Rules that the code paths currently emit findings under.
        for required in ["SBOM-OCI-SIG-002", "SBOM-OCI-ATT-001", "SBOM-OCI-ATT-002"] {
            assert!(
                rule_ids.iter().any(|r| r == required),
                "rule {required} missing from SARIF rule index"
            );
        }
    }

    #[test]
    fn level_mapping_distinguishes_severities() {
        let report = VerificationReport {
            image_signature: SignatureVerdict::Skipped,
            attestations: vec![],
            digest_binding_ok: true,
            findings: vec![
                OciVerificationFinding {
                    rule_id: "SBOM-OCI-DISC-002".to_string(),
                    severity: ViolationSeverity::Info,
                    message: "Referrers fell back".to_string(),
                },
                OciVerificationFinding {
                    rule_id: "SBOM-OCI-DISC-003".to_string(),
                    severity: ViolationSeverity::Warning,
                    message: "No VEX".to_string(),
                },
            ],
        };
        let json = generate_oci_sarif(&sample_ref(), "sha256:abc", &report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["level"], "note");
        assert_eq!(results[1]["level"], "warning");
    }
}
