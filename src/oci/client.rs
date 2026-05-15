//! Registry client — async→sync bridge over `oci-client`.
//!
//! Owns the tokio current-thread runtime and exposes a synchronous
//! [`fetch_artifacts`] entry point that drives the whole pull. Higher-level
//! orchestration ([`crate::oci::OciResolver::resolve`]) calls this; the rest
//! of the codebase never sees a `Future`.
//!
//! Discovery preference: OCI 1.1 Referrers API first, cosign tag-scheme
//! (`sha256-<HEX>.sbom` / `.att`) as a fallback for registries that don't
//! implement Referrers yet.
//!
//! # Status
//!
//! `VerificationPolicy::None` (i.e. `--no-verify`) is the only policy this
//! function honours today — cosign verification (`sigstore`) lands in a
//! follow-up commit. Any other policy returns
//! [`OciError::NotImplemented`].

use std::path::{Path, PathBuf};

use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::errors::OciDistributionError;
use oci_client::manifest::{OciDescriptor, OciImageManifest};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use tokio::io::AsyncWriteExt;
use tokio::runtime::{Builder, Runtime};

use super::{
    ArtifactFile, ArtifactKind, AuthInputs, DiscoveryScheme, OciError, OciReference,
    OciResolverConfig, ResolvedArtifacts, SignatureVerdict, VerificationPolicy, VerificationReport,
};

// ============================================================================
// Auth conversion
// ============================================================================

/// Convert the user-facing [`AuthInputs`] into the oci-client `RegistryAuth`.
///
/// Precedence: bearer-token → basic-auth (requires both username and
/// password) → anonymous. A bare username without a password silently
/// degrades to anonymous rather than basic-auth with an empty password.
fn to_registry_auth(auth: &AuthInputs) -> RegistryAuth {
    if let Some(token) = &auth.token {
        RegistryAuth::Bearer(token.clone())
    } else if let (Some(u), Some(p)) = (&auth.username, &auth.password) {
        RegistryAuth::Basic(u.clone(), p.clone())
    } else {
        RegistryAuth::Anonymous
    }
}

// ============================================================================
// Entry point
// ============================================================================

/// Pull (and, when supported, verify) the SBOM/VEX artifacts attached to an
/// image.
///
/// # Errors
///
/// - [`OciError::NotImplemented`] when `policy` is anything other than
///   `VerificationPolicy::None` (cosign verification not yet wired).
/// - [`OciError::InvalidReference`] if the OCI reference can't be re-parsed
///   by `oci-client`.
/// - [`OciError::Registry`] for network / auth / manifest failures.
/// - [`OciError::Io`] for filesystem errors when materialising blobs.
pub fn fetch_artifacts(
    reference: &OciReference,
    auth: &AuthInputs,
    policy: &VerificationPolicy,
    config: &OciResolverConfig,
) -> Result<ResolvedArtifacts, OciError> {
    if !matches!(policy, VerificationPolicy::None) {
        return Err(OciError::NotImplemented(
            "cosign verification (sigstore) is not yet wired — re-run with --no-verify \
             to fetch without verifying"
                .to_string(),
        ));
    }

    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| OciError::Registry(format!("tokio runtime build: {e}")))?;

    let client = build_client(config.insecure);
    let registry_auth = to_registry_auth(auth);
    let oci_ref = build_reference(reference)?;

    // Resolve tag → manifest digest so every later request is digest-pinned.
    let image_digest = runtime
        .block_on(client.fetch_manifest_digest(&oci_ref, &registry_auth))
        .map_err(map_err)?;

    let output_dir = config
        .output_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("./oci-artifacts").join(short_digest(&image_digest)));
    std::fs::create_dir_all(&output_dir)?;

    let digest_ref = oci_ref.clone_with_digest(image_digest.clone());

    let mut sboms = Vec::new();
    let mut vex_docs = Vec::new();

    // --- Referrers API (preferred) -----------------------------------------
    let referrers = runtime.block_on(client.pull_referrers(&digest_ref, None));
    let mut referrers_error: Option<String> = None;
    let mut referrers_count = 0usize;
    match referrers {
        Ok(index) => {
            referrers_count = index.manifests.len();
            for entry in &index.manifests {
                let referrer_ref = oci_ref.clone_with_digest(entry.digest.clone());
                let manifest = match runtime
                    .block_on(client.pull_image_manifest(&referrer_ref, &registry_auth))
                {
                    Ok((m, _)) => m,
                    Err(e) => {
                        eprintln!(
                            "warning: failed to pull referrer manifest {}: {e}",
                            entry.digest
                        );
                        continue;
                    }
                };
                let Some(kind) = classify_manifest(&manifest, &entry.media_type) else {
                    continue;
                };
                extract_layers(
                    &runtime,
                    &client,
                    &referrer_ref,
                    &manifest,
                    kind,
                    DiscoveryScheme::Referrers,
                    &output_dir,
                    &mut sboms,
                    &mut vex_docs,
                );
            }
        }
        Err(e) => {
            referrers_error = Some(format!("{e}"));
        }
    }

    // --- Cosign tag-scheme fallback ----------------------------------------
    // Only run if Referrers gave us nothing — keeps the network traffic
    // minimal when Referrers is supported and populated.
    if sboms.is_empty() && vex_docs.is_empty() {
        if let Some(msg) = &referrers_error {
            eprintln!("note: referrers API unavailable ({msg}); trying cosign tag scheme");
        } else if referrers_count == 0 {
            eprintln!("note: referrers API returned 0 manifests; trying cosign tag scheme");
        }
        try_cosign_tag_scheme(
            &runtime,
            &client,
            &oci_ref,
            &registry_auth,
            &image_digest,
            &output_dir,
            &mut sboms,
            &mut vex_docs,
        );
    }

    Ok(ResolvedArtifacts {
        image_digest,
        sboms,
        vex_docs,
        verification: VerificationReport {
            image_signature: SignatureVerdict::Skipped,
            attestations: Vec::new(),
            // Verification deferred; with --no-verify we don't claim binding.
            digest_binding_ok: true,
            findings: Vec::new(),
        },
    })
}

// ============================================================================
// Discovery — Referrers helpers
// ============================================================================

#[allow(clippy::too_many_arguments)]
fn extract_layers(
    runtime: &Runtime,
    client: &Client,
    referrer_ref: &Reference,
    manifest: &OciImageManifest,
    kind: ArtifactKind,
    scheme: DiscoveryScheme,
    output_dir: &Path,
    sboms: &mut Vec<ArtifactFile>,
    vex_docs: &mut Vec<ArtifactFile>,
) {
    for layer in &manifest.layers {
        let path = blob_path(output_dir, kind, &layer.digest, &layer.media_type);
        if let Err(e) = fetch_blob_to_file(runtime, client, referrer_ref, layer, &path) {
            eprintln!("warning: failed to fetch blob {}: {e}", layer.digest);
            continue;
        }
        let af = ArtifactFile {
            path,
            media_type: layer.media_type.clone(),
            predicate_type: manifest.artifact_type.clone(),
            discovered_via: scheme,
        };
        match kind {
            ArtifactKind::Sbom => sboms.push(af),
            ArtifactKind::Vex => vex_docs.push(af),
            // Generic attestations (SLSA provenance, vuln scans, …) are not
            // SBOM/VEX themselves; recorded by future verify.rs as findings,
            // not stored here in v1.
            ArtifactKind::Attestation => {}
        }
    }
}

// ============================================================================
// Discovery — cosign tag-scheme fallback
// ============================================================================

#[allow(clippy::too_many_arguments)]
fn try_cosign_tag_scheme(
    runtime: &Runtime,
    client: &Client,
    base_ref: &Reference,
    auth: &RegistryAuth,
    image_digest: &str,
    output_dir: &Path,
    sboms: &mut Vec<ArtifactFile>,
    vex_docs: &mut Vec<ArtifactFile>,
) {
    let Some(tag_prefix) = cosign_tag_prefix(image_digest) else {
        return;
    };

    // Legacy cosign SBOM tag.
    let sbom_tag = format!("{tag_prefix}.sbom");
    try_fetch_cosign_tag(
        runtime,
        client,
        base_ref,
        auth,
        &sbom_tag,
        ArtifactKind::Sbom,
        output_dir,
        sboms,
    );

    // Modern cosign attestation tag — may carry SBOM or VEX inside a DSSE
    // envelope. Without unwrapping (which lands with verify.rs / base64) we
    // can't classify reliably, so we pessimistically write it under sbom/.
    let att_tag = format!("{tag_prefix}.att");
    try_fetch_cosign_tag(
        runtime,
        client,
        base_ref,
        auth,
        &att_tag,
        ArtifactKind::Sbom,
        output_dir,
        sboms,
    );

    // VEX-via-tag-scheme is rare; left empty deliberately. Future verify.rs
    // will unwrap DSSE-wrapped .att blobs and re-classify as VEX where the
    // in-toto predicateType is `https://openvex.dev/ns/...`.
    let _ = vex_docs;
}

#[allow(clippy::too_many_arguments)]
fn try_fetch_cosign_tag(
    runtime: &Runtime,
    client: &Client,
    base_ref: &Reference,
    auth: &RegistryAuth,
    tag: &str,
    kind: ArtifactKind,
    output_dir: &Path,
    out: &mut Vec<ArtifactFile>,
) {
    let raw = format!(
        "{}/{}:{}",
        base_ref.resolve_registry(),
        base_ref.repository(),
        tag
    );
    let tag_ref = match Reference::try_from(raw.as_str()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("warning: invalid cosign tag ref `{tag}`: {e}");
            return;
        }
    };
    let manifest = match runtime.block_on(client.pull_image_manifest(&tag_ref, auth)) {
        Ok((m, _)) => m,
        // Tag-scheme miss is expected — registry returned 404 / not-found.
        Err(_) => return,
    };
    for layer in &manifest.layers {
        let path = blob_path(output_dir, kind, &layer.digest, &layer.media_type);
        if let Err(e) = fetch_blob_to_file(runtime, client, &tag_ref, layer, &path) {
            eprintln!(
                "warning: failed to fetch cosign-tag blob {}: {e}",
                layer.digest
            );
            continue;
        }
        out.push(ArtifactFile {
            path,
            media_type: layer.media_type.clone(),
            predicate_type: manifest.artifact_type.clone(),
            discovered_via: DiscoveryScheme::CosignTag,
        });
    }
}

/// Cosign tag-prefix for a digest: `sha256:abc...` → `sha256-abc...`.
fn cosign_tag_prefix(image_digest: &str) -> Option<String> {
    let (algo, hex) = image_digest.split_once(':')?;
    if algo.is_empty() || hex.is_empty() {
        return None;
    }
    Some(format!("{algo}-{hex}"))
}

// ============================================================================
// Manifest classification
// ============================================================================

/// Classify an artifact manifest into an [`ArtifactKind`].
///
/// Priority: in-toto predicate URI on `artifactType` (the cosign-attest
/// path) → media-type heuristic on `artifactType` (plain SBOM/VEX artifacts)
/// → media-type heuristic on the descriptor.
fn classify_manifest(
    manifest: &OciImageManifest,
    descriptor_media_type: &str,
) -> Option<ArtifactKind> {
    if let Some(at) = &manifest.artifact_type {
        if let Some(kind) = super::attestation::classify_predicate(at) {
            return Some(kind);
        }
        let at_lc = at.to_lowercase();
        if at_lc.contains("cyclonedx") || at_lc.contains("spdx") {
            return Some(ArtifactKind::Sbom);
        }
        if at_lc.contains("openvex") || at_lc.contains("vex") {
            return Some(ArtifactKind::Vex);
        }
        // Cosign signature artifact / Notary signatures — not SBOM/VEX.
        if at_lc.contains("cosign.artifact.sig") || at_lc.contains("notary.signature") {
            return None;
        }
    }
    let mt = descriptor_media_type.to_lowercase();
    if mt.contains("cyclonedx") || mt.contains("spdx") {
        return Some(ArtifactKind::Sbom);
    }
    if mt.contains("vex") {
        return Some(ArtifactKind::Vex);
    }
    None
}

// ============================================================================
// Blob fetch + filesystem helpers
// ============================================================================

fn fetch_blob_to_file(
    runtime: &Runtime,
    client: &Client,
    image: &Reference,
    layer: &OciDescriptor,
    dest: &Path,
) -> Result<(), OciError> {
    let parent = dest
        .parent()
        .ok_or_else(|| OciError::Registry("blob destination has no parent".to_string()))?;
    std::fs::create_dir_all(parent)?;
    let tmp = dest.with_extension("partial");
    runtime.block_on(async {
        let mut f = tokio::fs::File::create(&tmp).await?;
        client
            .pull_blob(image, layer, &mut f)
            .await
            .map_err(map_err)?;
        f.flush().await?;
        Ok::<_, OciError>(())
    })?;
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

fn blob_path(base: &Path, kind: ArtifactKind, digest: &str, media_type: &str) -> PathBuf {
    let short = short_digest(digest);
    let ext = if media_type.to_lowercase().contains("json") {
        "json"
    } else {
        "bin"
    };
    let kind_prefix = match kind {
        ArtifactKind::Sbom => "sbom",
        ArtifactKind::Vex => "vex",
        ArtifactKind::Attestation => "att",
    };
    base.join(format!("{kind_prefix}-{short}.{ext}"))
}

fn short_digest(digest: &str) -> String {
    digest
        .split_once(':')
        .map(|(_, h)| h.chars().take(12).collect::<String>())
        .unwrap_or_else(|| digest.replace(':', "-"))
}

// ============================================================================
// Client + reference setup
// ============================================================================

fn build_client(insecure: bool) -> Client {
    let mut config = ClientConfig::default();
    if insecure {
        config.protocol = ClientProtocol::Http;
        config.accept_invalid_certificates = true;
    }
    Client::new(config)
}

fn build_reference(reference: &OciReference) -> Result<Reference, OciError> {
    let s = reference.to_string();
    Reference::try_from(s.as_str()).map_err(|e| {
        OciError::InvalidReference(format!("oci-client cannot parse `{reference}`: {e}"))
    })
}

// ============================================================================
// Error mapping
// ============================================================================

fn map_err(err: OciDistributionError) -> OciError {
    match err {
        OciDistributionError::IoError(e) => OciError::Io(e),
        OciDistributionError::JsonError(e) => OciError::Parse(format!("registry json: {e}")),
        OciDistributionError::ManifestParsingError(s) => OciError::Parse(format!("manifest: {s}")),
        OciDistributionError::UnauthorizedError { .. } => OciError::Registry(
            "unauthorized — check --registry-username / --registry-password \
             (or set SBOM_TOOLS_REGISTRY_PASSWORD)"
                .to_string(),
        ),
        OciDistributionError::ImageManifestNotFoundError(s) => {
            OciError::Registry(format!("not found: {s}"))
        }
        other => OciError::Registry(format!("{other}")),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_anonymous_when_empty() {
        let auth = AuthInputs::default();
        assert!(matches!(to_registry_auth(&auth), RegistryAuth::Anonymous));
    }

    #[test]
    fn auth_basic_when_user_and_pass() {
        let auth = AuthInputs {
            username: Some("u".into()),
            password: Some("p".into()),
            token: None,
        };
        assert!(matches!(to_registry_auth(&auth), RegistryAuth::Basic(_, _)));
    }

    #[test]
    fn auth_bearer_wins_over_basic() {
        let auth = AuthInputs {
            token: Some("t".into()),
            username: Some("u".into()),
            password: Some("p".into()),
        };
        assert!(matches!(to_registry_auth(&auth), RegistryAuth::Bearer(_)));
    }

    #[test]
    fn auth_user_without_pass_is_anonymous() {
        let auth = AuthInputs {
            username: Some("u".into()),
            password: None,
            token: None,
        };
        // Basic auth needs both — without a password we fall through.
        assert!(matches!(to_registry_auth(&auth), RegistryAuth::Anonymous));
    }

    #[test]
    fn cosign_tag_prefix_well_formed() {
        assert_eq!(
            cosign_tag_prefix("sha256:abcdef0123456789").unwrap(),
            "sha256-abcdef0123456789"
        );
    }

    #[test]
    fn cosign_tag_prefix_rejects_malformed() {
        assert!(cosign_tag_prefix("nocolonhere").is_none());
        assert!(cosign_tag_prefix(":onlyhex").is_none());
        assert!(cosign_tag_prefix("algoonly:").is_none());
    }

    #[test]
    fn short_digest_truncates_to_twelve() {
        let d = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert_eq!(short_digest(d), "abcdef012345");
    }

    #[test]
    fn short_digest_fallback_when_no_colon() {
        assert_eq!(short_digest("nothing"), "nothing");
    }

    #[test]
    fn blob_path_uses_kind_prefix_and_short_digest() {
        let base = PathBuf::from("/tmp/art");
        let p = blob_path(
            &base,
            ArtifactKind::Sbom,
            "sha256:abcdef0123456789",
            "application/vnd.cyclonedx+json",
        );
        assert_eq!(p, PathBuf::from("/tmp/art/sbom-abcdef012345.json"));

        let p = blob_path(
            &base,
            ArtifactKind::Vex,
            "sha256:abcdef0123456789",
            "application/octet-stream",
        );
        assert_eq!(p, PathBuf::from("/tmp/art/vex-abcdef012345.bin"));
    }

    #[test]
    fn classify_via_in_toto_predicate() {
        let mut m = OciImageManifest::default();
        m.artifact_type = Some("https://cyclonedx.org/bom/v1.6".to_string());
        assert_eq!(
            classify_manifest(&m, "application/vnd.dsse.envelope.v1+json"),
            Some(ArtifactKind::Sbom)
        );
        m.artifact_type = Some("https://openvex.dev/ns/v0.2.0".to_string());
        assert_eq!(classify_manifest(&m, ""), Some(ArtifactKind::Vex));
    }

    #[test]
    fn classify_via_media_type_heuristic() {
        let mut m = OciImageManifest::default();
        m.artifact_type = Some("application/vnd.cyclonedx+json".to_string());
        assert_eq!(classify_manifest(&m, ""), Some(ArtifactKind::Sbom));
    }

    #[test]
    fn cosign_signature_is_not_sbom_or_vex() {
        let mut m = OciImageManifest::default();
        m.artifact_type = Some("application/vnd.dev.cosign.artifact.sig.v1+json".to_string());
        assert_eq!(classify_manifest(&m, ""), None);
    }

    #[test]
    fn fetch_rejects_non_no_verify_policy() {
        let reference = OciReference::parse("ghcr.io/x/y:v1").unwrap();
        let auth = AuthInputs::default();
        let policy = VerificationPolicy::KeyBased {
            key_path: PathBuf::from("cosign.pub"),
        };
        let cfg = OciResolverConfig::default();
        let err = fetch_artifacts(&reference, &auth, &policy, &cfg).unwrap_err();
        assert!(matches!(err, OciError::NotImplemented(_)));
    }
}
