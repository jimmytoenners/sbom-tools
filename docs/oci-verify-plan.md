# OCI Registry Ingestion & Cosign Verification

> Feature proposal. Not yet implemented. Tracking issue: TBD.
> Style follows [`docs/standards-support-plan.md`](standards-support-plan.md),
> [`docs/CRA_COMPLIANCE.md`](CRA_COMPLIANCE.md), and the sibling proposal
> [`docs/vex-validate-plan.md`](vex-validate-plan.md). CLI conventions, exit
> codes, and config layout align with the existing `enrich` / `verify` / `vex`
> commands.

## Executive summary

sbom-tools today is **file-in**: every command takes a local `PathBuf` and
calls `std::fs::read_to_string` (`src/pipeline/parse.rs:78`,
`src/cli/enrich.rs:25`). To analyse the SBOM/VEX attached to a container
image, an operator must first fetch and verify those artifacts themselves
with `cosign` / `oras`, then hand the resulting files to sbom-tools.

This proposal adds a new `sbom-tools oci` command family that:

- **pulls** SBOM and VEX artifacts associated with an OCI image reference —
  both the legacy cosign tag scheme (`sha256-<digest>.sbom`) and the
  OCI 1.1 Referrers API;
- **verifies** the image's cosign signature and each attestation's DSSE
  envelope (key-based and keyless / Fulcio + Rekor), checking that the
  attestation `subject` digest matches the pulled image;
- **materialises** the verified SBOM/VEX as local files and hands them to the
  existing pipeline unchanged — so `diff`, `view`, `quality`, `validate`,
  `vex`, and enrichment all "just work" on registry inputs.

The existing pipeline does not change. The new module sits *in front* of the
parser as an input resolver. Everything heavy (the OCI client, the Sigstore
crypto, an async runtime) lives behind a new **`oci` feature flag, off by
default** — mirroring how `enrichment` already gates `reqwest`. Default
builds, the MSRV job, and the `cargo-deny` / Scorecard surface are unchanged.

Total effort: **~20 days across 4 phases**, each shippable as its own PR.

This is the natural companion to [`vex validate`](vex-validate-plan.md):
that proposal makes VEX a *validated* artifact; this one makes the SBOM/VEX a
*trustworthy* artifact. Together they move sbom-tools from "file differ"
toward "supply-chain verifier."

---

## Motivation

### What goes wrong today

1. **No trust boundary.** sbom-tools analyses whatever file it is given. If a
   CI job pulls an SBOM from a registry with `oras` and that artifact was
   tampered with, sbom-tools reports a clean bill of health on poisoned data.
2. **Manual, error-prone fetch.** The current workaround is a three-tool
   dance:
   ```sh
   cosign verify <image> --certificate-identity ... --certificate-oidc-issuer ...
   cosign download sbom <image> > sbom.json      # or oras pull / referrers
   cosign verify-attestation <image> --type cyclonedx ...
   sbom-tools vex apply sbom.json --vex vex.json --enrich-vulns
   ```
   Each step has its own flags, failure modes, and exit-code semantics. The
   digest the SBOM is *about* is never checked against the image actually
   analysed — a class of bug ("right SBOM, wrong image") that no step catches.
3. **Discovery is fragmented.** SBOM/VEX can be attached as: a cosign tag
   (`sha256-<digest>.sbom`), an OCI 1.1 referrer, a DSSE-wrapped in-toto
   attestation, or a plain OCI artifact with a CycloneDX/SPDX media type.
   Operators rarely know which scheme a given registry uses.
4. **Single-binary ethos broken by workarounds.** sbom-tools ships as one
   self-contained binary (Homebrew, pre-built archives, `cargo binstall`).
   Telling users to also install `cosign` and `oras` undercuts that.

### Why a first-class command, not docs

The fetch+verify+digest-match logic is a real algorithm with real failure
modes. Putting it in the tool means: one exit-code contract, one config
surface, one cache, and — critically — the **digest-binding check** (the
attestation's `subject` must equal the pulled image digest) that the manual
flow omits.

### Why now

The three SBOM/VEX parsers ship (CycloneDX, SPDX, OpenVEX/CSAF). The
[`vex validate`](vex-validate-plan.md) proposal adds VEX conformance. The
missing link is *getting* trustworthy artifacts into the tool in the first
place. This is the front door.

---

## Non-goals (explicit)

To keep the scope bounded — these are NOT part of this feature:

1. **Not a general OCI client.** No `docker pull` replacement, no image
   layer extraction, no running containers. Only SBOM/VEX/signature artifact
   discovery and retrieval.
2. **Not a push path.** `cosign attach` / `cosign attest` equivalents
   (uploading an SBOM/VEX/signature) are out of scope for v1. Possible
   Phase 5; read-and-verify only for now.
3. **Not a reimplementation of Sigstore crypto.** Verification uses the
   `sigstore` crate. We do not hand-roll Fulcio cert-chain validation, Rekor
   inclusion proofs, or SCT verification.
4. **Not a general policy engine.** Verification policy is cosign-flag-shaped
   (key / identity / issuer / trust root), not a Rego/CUE/Kyverno DSL. The
   richer policy surface lives in [`vex validate`](vex-validate-plan.md)'s
   policy sidecar, applied *after* the VEX is fetched.
5. **Not image-content trust.** We verify that the SBOM/VEX is authentic and
   bound to the named image. We do not opine on whether the *image* should be
   trusted to run — that is the CI/admission-controller's job.
6. **Default build unchanged.** Everything is behind `--features oci`. A
   `cargo build` with default features pulls in zero new dependencies.

---

## CLI surface

A new top-level `oci` command with three subcommands. All are compiled only
under `--features oci`; absent the feature, `sbom-tools oci ...` prints a
build-hint error (the same pattern `vex` uses for `enrichment`-gated paths).

```text
sbom-tools oci pull   <REF> [OPTIONS]   # fetch + verify + write artifacts to disk
sbom-tools oci verify <REF> [OPTIONS]   # verify only; report + exit code
sbom-tools oci report <REF> [OPTIONS]   # pull + verify + enrich + vuln picture (one-shot)
```

`<REF>` accepts `registry/repo:tag`, `registry/repo@sha256:<digest>`, or an
`oci://` URL. Digest references are preferred (immutable, cache-friendly);
tag references are resolved to a digest and the digest is reported.

### `oci pull`

| Flag                       | Default                         | Description                                                          |
|----------------------------|---------------------------------|----------------------------------------------------------------------|
| `--output-dir <DIR>`       | `./oci-artifacts/<digest>/`      | Where to write extracted SBOM/VEX files                              |
| `--platform <OS/ARCH>`     | host platform                   | For a multi-arch image index, select the platform manifest           |
| `--artifact <KIND>` (rep.) | `sbom,vex`                      | Which artifact kinds to extract (`sbom`, `vex`, `attestation`, `all`) |
| `--no-verify`              | false                           | Skip cosign verification (Phase 2+: verification is on by default)    |
| `--prefer <SCHEME>`        | `referrers`                     | Discovery preference: `referrers` or `tag-scheme`                     |
| `--insecure`               | false                           | Allow plain HTTP / skip registry TLS verification (local registries) |

### `oci verify`

| Flag                                  | Default                       | Description                                                            |
|---------------------------------------|-------------------------------|------------------------------------------------------------------------|
| `--key <PATH>`                        | none                          | Cosign public key (key-based verification)                             |
| `--certificate-identity <ID>`         | none                          | Keyless: exact SAN identity the Fulcio cert must carry                 |
| `--certificate-identity-regexp <RE>`  | none                          | Keyless: identity regex (mutually exclusive with the exact form)       |
| `--certificate-oidc-issuer <URL>`     | none                          | Keyless: required OIDC issuer                                          |
| `--trust-root <PATH>`                 | bundled Sigstore public-good  | Custom Sigstore TUF root (private Sigstore deployments)                |
| `--rekor-url <URL>`                   | `https://rekor.sigstore.dev`  | Transparency log endpoint                                              |
| `--insecure-ignore-tlog`              | false                         | Air-gapped: skip Rekor inclusion check                                 |
| `--require-attestation <PREDICATE>`   | none (repeatable)             | Fail if no verified attestation of this predicate type is present      |
| `-o, --output <FMT>`                  | `auto`                        | `auto`, `sarif`, `json`, `table`, `summary`                            |
| `-O, --output-file <PATH>`            | stdout                        | Write report to a file                                                 |

### `oci report`

Superset of `pull` + `verify`, then runs the existing enrichment pipeline and
emits a vulnerability picture. Inherits the verification flags above plus:

| Flag                  | Default | Description                                                       |
|-----------------------|---------|-------------------------------------------------------------------|
| `--enrich-vulns`      | true    | OSV + KEV enrichment (on by default for this command)             |
| `--standard <S>`      | none    | Also run compliance validation (`cra`, `ntia`, …) on the SBOM     |
| `--fail-on-vuln`      | false   | Reuse the existing gate — exit non-zero on introduced vulns       |
| `--fail-on-vex-gap`   | false   | Reuse the existing gate — exit code 4 on VEX coverage gaps        |
| `-o, --output <FMT>`  | `auto`  | Any existing report format                                       |

### Registry authentication (all subcommands)

| Flag                      | Description                                                                 |
|---------------------------|-----------------------------------------------------------------------------|
| `--registry-token <TOK>`  | Bearer token                                                                |
| `--registry-username <U>` | Basic auth username (paired with `--registry-password` or `_PASSWORD` env)  |
| `--registry-password <P>` | Basic auth password (prefer the `SBOM_TOOLS_REGISTRY_PASSWORD` env var)     |

Auth resolution order: explicit flags → `SBOM_TOOLS_REGISTRY_*` env →
`~/.docker/config.json` (static `auths` entries only) → anonymous. Docker
credential *helpers* (`credHelpers`, `credsStore`) are deferred to Phase 4.

### Sample invocations

```bash
# Pull + verify the SBOM/VEX attached to an image, keyless policy
sbom-tools oci pull ghcr.io/acme/api@sha256:abc123... \
    --certificate-identity 'https://github.com/acme/api/.github/workflows/release.yml@refs/tags/v1.4.0' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verify only — CI gate, SARIF out, must have a CycloneDX attestation
sbom-tools oci verify ghcr.io/acme/api:v1.4.0 \
    --key cosign.pub \
    --require-attestation https://cyclonedx.org/bom \
    -o sarif -O oci-verify.sarif

# One-shot trustworthy vuln picture
sbom-tools oci report ghcr.io/acme/api@sha256:abc123... \
    --certificate-identity-regexp '^https://github.com/acme/.+' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --standard cra --fail-on-vex-gap -o markdown

# Private / air-gapped Sigstore
sbom-tools oci verify registry.internal/app:1.0 \
    --trust-root /etc/sigstore/root.json \
    --rekor-url https://rekor.internal \
    --key /etc/keys/app.pub

# Local registry over HTTP, no signatures expected
sbom-tools oci pull localhost:5000/test:dev --insecure --no-verify
```

### Exit codes

`pipeline::exit_codes` currently defines `0`–`5` (`SUCCESS`,
`CHANGES_DETECTED`, `VULNS_INTRODUCED`, `ERROR`, `VEX_GAPS_FOUND`,
`LICENSE_VIOLATIONS`). This feature adds one:

| Code | Constant                       | Meaning                                                                    |
|------|--------------------------------|----------------------------------------------------------------------------|
| `0`  | `SUCCESS`                      | Artifacts pulled and (if not `--no-verify`) verified                       |
| `2`  | `VULNS_INTRODUCED` *(reused)*  | `oci report` only — vulns found and `--fail-on-vuln` set                   |
| `3`  | `ERROR` *(reused)*             | Registry / network / parse error: ref not found, manifest malformed, auth  |
| `4`  | `VEX_GAPS_FOUND` *(reused)*    | `oci report` only — VEX coverage gap and `--fail-on-vex-gap` set           |
| `6`  | `OCI_VERIFICATION_FAILED` *(new)* | Signature invalid, identity/issuer mismatch, digest-binding mismatch, or a `--require-attestation` type was absent |

`6` is the next free value and is verification-specific so CI can branch on
"couldn't fetch" (`3`) vs "fetched but untrusted" (`6`).

---

## Architecture

### Data flow

```
   oci://registry/repo:tag
        |
        v
  [ src/oci/ ]  (feature = "oci")
    1. resolve ref -> manifest digest
    2. discover artifacts  (referrers API  ||  cosign tag scheme)
    3. verify cosign sig + attestation DSSE  (sigstore crate)
    4. check attestation subject digest == image digest
    5. extract SBOM / VEX blobs -> temp/cache dir
        |
        v   (local file paths — the boundary)
  parse_sbom_with_context()  ... existing pipeline, UNCHANGED ...
        |
        v
  diff / view / quality / validate / vex / enrich / reports
```

The contract is deliberately narrow: `src/oci/` resolves a reference to a set
of **local file paths plus a verification report**. Everything downstream is
untouched.

### Module layout

```
src/
  oci/                       NEW MODULE — all code gated `#[cfg(feature = "oci")]`
    mod.rs                   OciReference parsing; public API; OciResolver
    client.rs                registry client wrapper; async->sync bridge (block_on)
    discovery.rs             Referrers API + cosign tag-scheme discovery
    attestation.rs           DSSE unwrap, in-toto Statement, predicate -> artifact-kind map
    verify.rs                cosign verification via `sigstore`; VerificationPolicy
    cache.rs                 digest-addressed blob cache (reuses dirs conventions)
  cli/
    oci.rs                   NEW — `oci` subcommand handler (pull/verify/report)
  reports/
    oci_sarif.rs             NEW — SARIF emitter for verification findings
  config/
    types.rs                 + OciConfig struct, + AppConfig.oci field
```

`src/oci/` is a new top-level sibling of `src/enrichment/`, not a child of it,
because:

- It is gated by a *different* feature (`oci`, not `enrichment`) — an operator
  can want registry ingestion without OSV/KEV network enrichment, or vice
  versa.
- It introduces an async runtime; isolating it keeps the rest of the
  (synchronous) codebase free of `async`/`await`.

### Public types

```rust
// src/oci/mod.rs   — all #[cfg(feature = "oci")]

/// A parsed OCI reference. Always resolved to a digest before use.
pub struct OciReference {
    pub registry: String,
    pub repository: String,
    pub digest: Option<String>,    // sha256:...
    pub tag: Option<String>,
}

/// What the resolver produces — local paths + a verification verdict.
pub struct ResolvedArtifacts {
    pub image_digest: String,
    pub sboms: Vec<ArtifactFile>,   // path + media type + discovery scheme
    pub vex_docs: Vec<ArtifactFile>,
    pub verification: VerificationReport,
}

pub struct ArtifactFile {
    pub path: PathBuf,                 // materialised local file
    pub media_type: String,
    pub predicate_type: Option<String>, // set when it came from an attestation
    pub discovered_via: DiscoveryScheme, // Referrers | CosignTag | PlainArtifact
}

pub struct VerificationReport {
    pub image_signature: SignatureVerdict,        // Verified | Failed(reason) | Skipped
    pub attestations: Vec<AttestationVerdict>,
    pub digest_binding_ok: bool,                  // subject == image_digest
    pub findings: Vec<OciVerificationFinding>,    // rule-shaped, SARIF-emittable
}

/// Verification policy — cosign-flag-shaped. Built from CLI flags or `[oci.verify]` config.
pub enum VerificationPolicy {
    KeyBased { key_path: PathBuf },
    Keyless {
        identity: IdentityMatcher,        // Exact(String) | Regexp(String)
        oidc_issuer: String,
        trust_root: TrustRoot,            // BundledPublicGood | Custom(PathBuf)
        rekor: RekorPolicy,               // Online(url) | IgnoreTlog
    },
    None,                                 // --no-verify
}

pub struct OciResolver { /* client, cache, policy */ }
impl OciResolver {
    pub fn resolve(&self, reference: &OciReference) -> Result<ResolvedArtifacts, OciError>;
}
```

`OciVerificationFinding` reuses `ViolationSeverity` and `StandardRef` from
`src/quality/compliance.rs`, so the SARIF emitter inherits the existing
`helpUri` machinery (see
[CRA_COMPLIANCE.md](CRA_COMPLIANCE.md#where-this-map-lives-in-the-code)).

### Artifact discovery matrix

`discovery.rs` handles every common attachment scheme; `--prefer` picks the
order, with automatic fallback:

| Scheme              | How it's found                                                              | Notes                                                |
|---------------------|-----------------------------------------------------------------------------|------------------------------------------------------|
| OCI 1.1 Referrers   | `GET /v2/<repo>/referrers/<digest>`, filter by `artifactType`               | Preferred. Not all registries implement it yet.      |
| Cosign tag scheme   | Pull tags `sha256-<digest>.sbom`, `.att`, `.sig`                            | Legacy but ubiquitous. Fallback when Referrers is 404.|
| Plain OCI artifact  | Manifest config `mediaType` is `application/vnd.cyclonedx+json` / SPDX      | Direct artifact, no attestation wrapper.             |
| In-toto attestation | DSSE envelope → in-toto Statement → `predicateType`                         | Unwrapped in `attestation.rs`; see mapping below.    |

### Attestation predicate → artifact-kind mapping

```
https://cyclonedx.org/bom              -> SBOM  (CycloneDX parser)
https://spdx.dev/Document              -> SBOM  (SPDX parser)
application/vnd.cyclonedx+json         -> SBOM  (plain artifact)
text/spdx+json  /  application/spdx+json -> SBOM
https://openvex.dev/ns                 -> VEX   (OpenVEX enricher path)
csaf media types                       -> VEX   (CSAF enricher path)
https://in-toto.io/attestation/vulns/* -> recorded in report, NOT auto-ingested in v1 (see Open questions)
unknown predicate                      -> recorded in report as Info, not extracted
```

### The async/sync boundary

`sbom-tools` is synchronous and uses `reqwest`'s `blocking` API. The
`sigstore` crate and the OCI client (`oci-client`) are async (tokio). To
avoid spreading `async` through the codebase:

- `client.rs` owns a `tokio` current-thread runtime, created once per
  `OciResolver`.
- All async calls are confined to `client.rs` / `verify.rs` and exposed
  through **synchronous** methods that `runtime.block_on(...)` internally.
- The CLI handler, the pipeline, and every other module stay synchronous and
  never see a `Future`.

This is the same shape `reqwest::blocking` already uses internally — tokio is
*already* in the dependency tree under the `enrichment` feature; this feature
makes a small, contained, *direct* use of it.

### Dependency choice — recommendation and the rejected alternative

**Recommended: the `sigstore` crate + `oci-client`, behind `--features oci`.**

`sigstore` (sigstore-rs, the official Rust SDK) is the only mature option for
cosign verification in Rust: key-based and keyless, Fulcio cert-chain
validation, Rekor inclusion proofs, bundled TUF trust root. It re-exports an
OCI client. The cost is a sizeable transitive tree (TLS, tokio, crypto) and a
pre-1.0 API.

**Rejected: shelling out to `cosign` / `oras` binaries.** Zero new Rust deps,
but it breaks the single-self-contained-binary ethos (Homebrew / pre-built
archives / `cargo binstall` all assume one file), pushes version-skew bugs
onto users, and makes exit-code/error handling brittle. Not worth it.

**Mitigations for the recommended path** (see also the risk register):

- Feature-gated: default builds and the default `cargo-deny` run are
  unaffected. CI gains one job: `cargo deny check --features oci` and a build
  of the `oci` feature.
- `sigstore`'s churny API is wrapped behind the thin internal `verify.rs`
  surface, so an upgrade touches one file.
- Versions are pinned exactly (`=x.y.z`) given the pre-1.0 status.
- **MSRV — decided:** `sigstore` / `oci-client` will likely require a Rust
  newer than the project's current 1.88. A **whole-project MSRV bump is
  acceptable** (maintainer decision, 2026-05-14) — the project does not need
  to keep a split MSRV. The exact new floor is whatever the pinned
  `sigstore` / `oci-client` versions require; it is set in the same change
  that adds the dependencies (`rust-toolchain.toml`, `Cargo.toml`
  `rust-version`, the README badge, and the MSRV CI job all move together).
  Until the dependencies are added, the skeleton builds on 1.88 unchanged.

### Config

A new `[oci]` section in `.sbom-tools.yaml`, so CI sets the verification
policy once instead of repeating flags. New `OciConfig` struct in
`src/config/types.rs`, added as `AppConfig.oci`, schema-generated like the
rest (`schemars`).

```yaml
oci:
  cache_dir: ~/.cache/sbom-tools/oci      # digest-addressed blob cache
  prefer: referrers                       # referrers | tag-scheme
  insecure: false
  verify:
    # exactly one of: key, or keyless (identity + oidc_issuer)
    key: cosign.pub
    certificate_identity_regexp: '^https://github.com/acme/.+'
    certificate_oidc_issuer: https://token.actions.githubusercontent.com
    trust_root: bundled                   # bundled | /path/to/root.json
    rekor_url: https://rekor.sigstore.dev
    ignore_tlog: false
    require_attestations:
      - https://cyclonedx.org/bom
      - https://openvex.dev/ns
```

Flags override config; config overrides defaults — the precedence rule the
rest of the tool already follows.

### Caching

OCI blobs are content-addressed by digest and therefore immutable — an ideal
cache key. `cache.rs` reuses the `dirs`-based cache-directory conventions
already used by the enrichment caches (`crate::pipeline::dirs::*`). A pulled
blob keyed `sha256:<digest>` is reused indefinitely; tag→digest resolution is
*not* cached (tags are mutable). `--no-cache` and a TTL are wired for
symmetry with the enrichment cache, though digest content never expires.

---

## Verification semantics

What "verified" means, precisely — this is the core contract:

1. **Image signature.** The image manifest digest has a cosign signature
   that validates against the policy (key, or keyless identity+issuer with a
   valid Fulcio cert chain and — unless `--insecure-ignore-tlog` — a Rekor
   inclusion proof).
2. **Attestation envelopes.** Each discovered attestation is a DSSE envelope
   whose signature validates against the *same* policy.
3. **Digest binding.** Each attestation's in-toto `subject[].digest` MUST
   equal the resolved image digest. This is the check the manual
   `cosign download` flow skips, and the reason this belongs in the tool.
4. **Required attestations.** If `--require-attestation <T>` is given, a
   verified attestation of predicate type `T` MUST be present.

If any of 1–4 fails, the run exits `6` (`OCI_VERIFICATION_FAILED`) and the
report enumerates the failures as findings. `--no-verify` skips 1–4 entirely
and marks every verdict `Skipped` (exit `0` still possible, but the report
header is unambiguous about the lack of trust).

### Verification findings (SARIF-emittable)

Rule IDs follow the project convention `SBOM-<FAMILY>-<TIER>-<NNN>`:

| Rule ID            | Severity | Description                                                                  |
|--------------------|----------|------------------------------------------------------------------------------|
| `SBOM-OCI-SIG-001` | Error    | Image signature missing                                                      |
| `SBOM-OCI-SIG-002` | Error    | Image signature present but fails verification against the policy            |
| `SBOM-OCI-SIG-003` | Error    | Keyless: certificate identity does not match `--certificate-identity[-regexp]`|
| `SBOM-OCI-SIG-004` | Error    | Keyless: OIDC issuer does not match `--certificate-oidc-issuer`               |
| `SBOM-OCI-SIG-005` | Error    | Rekor transparency-log inclusion proof missing or invalid                    |
| `SBOM-OCI-ATT-001` | Error    | Attestation DSSE envelope fails signature verification                       |
| `SBOM-OCI-ATT-002` | Error    | Attestation `subject` digest does not match the pulled image digest          |
| `SBOM-OCI-ATT-003` | Error    | `--require-attestation <T>` given but no verified attestation of type `T`     |
| `SBOM-OCI-ATT-004` | Warning  | Attestation predicate type unrecognised — recorded but not extracted         |
| `SBOM-OCI-DISC-001`| Warning  | No SBOM artifact found via any discovery scheme                               |
| `SBOM-OCI-DISC-002`| Info     | Registry does not implement the Referrers API; fell back to the tag scheme    |
| `SBOM-OCI-DISC-003`| Warning  | No VEX artifact found for the image                                           |

---

## Standards mapping

(To be appended to the [`CRA_COMPLIANCE.md`](CRA_COMPLIANCE.md) reverse map
when Phase 2 lands.)

| Capability                                   | Standard / framework reference                                  | CRA reference            |
|-----------------------------------------------|------------------------------------------------------------------|--------------------------|
| Image cosign signature verified               | Sigstore; SLSA provenance (build integrity)                      | Annex III (integrity)    |
| SBOM attestation present + DSSE-verified      | in-toto Attestation Framework; SLSA                              | Art. 13(4) machine-readable SBOM |
| SBOM digest-bound to the analysed image       | in-toto Statement `subject`                                      | Annex I Part II 1        |
| VEX attestation present + verified            | OpenVEX; CSAF v2.0                                               | Art. 13(9)               |
| Keyless identity + OIDC issuer matched        | Fulcio; SLSA Build L2+ (provenance authenticity)                 | Annex III                |
| Rekor transparency-log inclusion              | Sigstore Rekor                                                   | Annex III                |

Canonical URLs for `properties.standardHelpUris`:
Sigstore `https://www.sigstore.dev/`,
in-toto `https://in-toto.io/`,
SLSA `https://slsa.dev/spec/`,
plus the existing CRA / OpenVEX / CSAF URLs already in the bibliography.

---

## Implementation plan

### Phase 1 — Pull & discovery, no verification (~6 days). Ship as PR #1.

1. **Day 1 — Feature flag + module skeleton.**
   Add `oci = ["dep:sigstore", "dep:oci-client", "dep:tokio"]` to
   `Cargo.toml` `[features]`. Create `src/oci/` with `mod.rs` (gated). Add
   `OciReference` parser + tests (`oci://`, tag, digest forms). Wire a
   stub `oci` subcommand into `main.rs` that errors without the feature.
2. **Day 2 — Registry client + async bridge.**
   `client.rs`: wrap `oci-client`, own a current-thread tokio runtime,
   expose synchronous `pull_manifest` / `pull_blob`. Anonymous + bearer +
   basic auth; `~/.docker/config.json` static `auths`.
3. **Day 3 — Discovery.**
   `discovery.rs`: Referrers API query + cosign tag-scheme fallback +
   plain-artifact detection. `--prefer` ordering.
4. **Day 4 — Attestation unwrap + extraction.**
   `attestation.rs`: DSSE → in-toto Statement → predicate map. Materialise
   SBOM/VEX blobs to `--output-dir`. `ResolvedArtifacts` assembled.
5. **Day 5 — `oci pull` CLI + cache.**
   `cli/oci.rs` pull path; `cache.rs` digest-addressed blob cache.
6. **Day 6 — Tests + docs.**
   Integration tests against a local registry fixture (`registry:2` via a
   test harness, or recorded fixtures). README "Features" bullet.

### Phase 2 — Cosign verification (~7 days). Ship as PR #2.

1. **Days 7–8 — Key-based verification.**
   `verify.rs`: `sigstore` integration for `--key`. Image signature + DSSE
   envelope verification. `VerificationReport` populated.
2. **Days 9–10 — Keyless verification.**
   Fulcio cert-chain validation, identity/issuer matching, Rekor inclusion.
   `--trust-root`, `--rekor-url`, `--insecure-ignore-tlog`.
3. **Day 11 — Digest binding + required attestations.**
   `subject` digest check; `--require-attestation`. The `SBOM-OCI-*`
   finding catalogue.
4. **Day 12 — `oci verify` CLI + exit code.**
   `cli/oci.rs` verify path. Add `OCI_VERIFICATION_FAILED = 6` to
   `pipeline::exit_codes`. Verification on-by-default for `pull`.
5. **Day 13 — Tests.**
   Fixtures: validly-signed image, tampered SBOM, identity mismatch,
   missing attestation, wrong-subject-digest. Each maps to a `SBOM-OCI-*`
   rule.

### Phase 3 — `oci report` + SARIF (~4 days). Ship as PR #3.

1. **Day 14 — `oci report` one-shot.**
   Chain resolver → `parse_sbom_with_context` → `enrich_sbom` →
   `enrich_vex` → existing report generators. Reuse `--fail-on-vuln` /
   `--fail-on-vex-gap` gates.
2. **Day 15 — `[oci]` config section.**
   `OciConfig` in `config/types.rs`; `AppConfig.oci`; `schemars` schema;
   flag/config precedence.
3. **Day 16 — SARIF emitter.**
   `reports/oci_sarif.rs`; `rule_help_uri` entries for the `SBOM-OCI-*`
   prefix; standard refs.
4. **Day 17 — Tests + golden SARIF fixture.**

### Phase 4 — Polish & ergonomics (~3 days). Ship as PR #4.

1. **Day 18 — `--from-oci` ambient input mode.**
   Let `diff` / `view` / `enrich` / `vex` accept an OCI ref where they take
   a path, routed through the same resolver. (Deferred from Phase 1 until
   the resolver is proven.)
2. **Day 19 — Docker credential helpers.**
   `credHelpers` / `credsStore` support in auth resolution.
3. **Day 20 — Docs.**
   `README.md` CLI cheat sheet + MSRV note for the `oci` feature;
   `ARCHITECTURE.md` resolver section; append `SBOM-OCI-*` rows to
   `CRA_COMPLIANCE.md`; `ARCHITECTURE.md` feature-flag table.

### Feature flags

```toml
[features]
default = ["enrichment"]
enrichment = ["reqwest"]
oci = ["dep:sigstore", "dep:oci-client", "dep:tokio"]   # NEW, off by default
ffi = []
```

`oci` is independent of `enrichment`: you can pull+verify without OSV/KEV
enrichment, or enrich local files without OCI. `oci report` naturally wants
both, but only *runs* the enrichment step if `enrichment` is also enabled
(graceful degradation, same pattern as the `vex` command today).

### Public API additions

```rust
// src/lib.rs — #[cfg(feature = "oci")]
pub use oci::{
    OciReference, OciResolver, ResolvedArtifacts, ArtifactFile,
    VerificationPolicy, VerificationReport, OciError,
};
```

`VerificationPolicy` and the verdict enums are `#[non_exhaustive]` so new
policy modes (e.g. a future bundled-attestation format) don't break
downstream.

---

## Test plan

### Unit tests

- `OciReference` parsing: `oci://`, tag, digest, registry-with-port,
  malformed refs.
- Discovery: Referrers JSON → artifact list; tag-scheme name derivation;
  predicate-type → artifact-kind mapping.
- DSSE unwrap: valid envelope, tampered payload, unknown predicate.
- `VerificationPolicy` construction from flags and from `[oci]` config;
  precedence.

### Integration tests (`tests/oci_tests.rs`, gated `#[cfg(feature = "oci")]`)

Use a local OCI registry (`registry:2` spun up by the test harness) or
recorded HTTP fixtures:

- Pull an SBOM attached via the Referrers API.
- Pull an SBOM attached via the cosign tag scheme; assert fallback fired
  (`SBOM-OCI-DISC-002`).
- Verify a validly key-signed image → exit `0`, all verdicts `Verified`.
- Tampered SBOM blob → `SBOM-OCI-ATT-001`, exit `6`.
- Attestation `subject` digest ≠ image digest → `SBOM-OCI-ATT-002`, exit `6`.
- Keyless identity mismatch → `SBOM-OCI-SIG-003`, exit `6`.
- `--require-attestation` for an absent type → `SBOM-OCI-ATT-003`, exit `6`.
- `--no-verify` → verdicts `Skipped`, exit `0`.
- `oci report` end-to-end: pull → verify → enrich → markdown report contains
  the vuln table.
- Round-trip with the sibling features: `oci pull` a VEX attestation, then
  `vex validate` the extracted file (once that feature lands).

### Property tests (`proptest`)

- Random DSSE envelopes (valid + mutated): no panic; signature check fails
  iff the payload or signature was mutated.
- Random in-toto `subject` digest sets: digest-binding passes iff the image
  digest is present.

### Fuzz target

`fuzz/fuzz_targets/oci_attestation.rs` — arbitrary bytes into the DSSE/in-toto
unwrap path; assert no panic, no unbounded allocation. Same harness shape as
the existing parser fuzz targets.

### CI

- New job: `cargo build --features oci` + `cargo test --features oci`.
- New job: `cargo deny check --features oci` (the dependency surface is
  reviewed separately from the default build).
- The MSRV job continues to run **without** `--features oci`.

---

## Risk register

| Risk                                                                 | Likelihood | Impact | Mitigation                                                                                              |
|----------------------------------------------------------------------|------------|--------|---------------------------------------------------------------------------------------------------------|
| `sigstore` crate is pre-1.0; API churns between releases             | High       | Medium | Pin exact versions (`=x.y.z`); isolate behind the thin `verify.rs` surface so upgrades touch one file   |
| `sigstore` / `oci-client` raise the effective MSRV above 1.88        | Resolved   | Low    | Whole-project MSRV bump approved (2026-05-14); new floor set when the deps are pinned. No split-MSRV complexity. |
| Large transitive dependency tree vs OpenSSF Scorecard / `cargo-deny` | High       | Medium | Off by default; dedicated `cargo deny --features oci` CI job; dependency review in the Phase 1 PR        |
| async (tokio) leaking into the synchronous codebase                  | Medium     | Medium | `block_on` bridge confined to `client.rs` / `verify.rs`; no `async` in any signature outside `src/oci/` |
| Registry doesn't implement the Referrers API                         | High       | Low    | Cosign tag-scheme fallback; `SBOM-OCI-DISC-002` Info finding records which scheme was used              |
| Keyless verification needs network egress to Fulcio/Rekor            | Medium     | Medium | `--insecure-ignore-tlog` + `--trust-root` + `--key` for air-gapped; documented air-gapped recipe        |
| Registry auth variety (cloud cred helpers, OIDC, anonymous)          | Medium     | Low    | Phase 1 covers anonymous + token + basic + static `~/.docker/config.json`; cred helpers in Phase 4      |
| Multi-arch image index: which manifest is the SBOM about?            | Medium     | Medium | `--platform` selects; default to host platform; report records the resolved per-platform digest        |
| Test flakiness pulling from public registries                       | Medium     | Low    | Tests use a local `registry:2` or recorded fixtures — never the public internet                         |

---

## What this enables

- **A real trust boundary.** `sbom-tools oci verify <image> --certificate-identity ...`
  is a drop-in CI gate that fails closed (exit `6`) on an unsigned or
  tampered SBOM — something no current command can do.
- **One-command trustworthy vuln picture.** `sbom-tools oci report <image>`
  replaces the cosign + oras + sbom-tools dance with a single invocation that
  *also* performs the digest-binding check the manual flow omits.
- **Closes the supply-chain loop.** Today the tool trusts whatever file it is
  handed. With this, the file's provenance is checked before a single
  component is parsed.
- **Composes with the sibling proposals.** `oci pull` fetches the VEX;
  [`vex validate`](vex-validate-plan.md) lints it; `oci verify` proves it is
  authentic and bound to the image. Three commands, one verified pipeline.
- **Keeps the single-binary promise.** No `cosign` / `oras` prerequisite —
  `--features oci` builds it in for those who want it, costs nothing for
  those who don't.

## Future work (separate proposals)

| Feature                       | Sketch                                                                              |
|-------------------------------|-------------------------------------------------------------------------------------|
| `oci attach` / `oci attest`   | Push an SBOM/VEX/signature back to a registry (the write path; Phase 5)              |
| `https://in-toto.io/attestation/vulns` ingestion | Map verified vuln-scan attestations into the enrichment model    |
| Admission-controller mode     | Long-running `--serve` that answers verify queries (pairs with `watch`)             |
| Docker credential helpers     | Promoted out of Phase 4 if cloud-registry demand is high                            |
| Bundle format (`.sigstore`)   | Support the newer Sigstore bundle alongside the tag/referrer schemes                |

---

## Status (as of the merge into this branch)

| Increment | Status |
|---|---|
| Skeleton (reference parsing, policy validation, CLI surface, exit codes) | ✅ shipped — `9fababb` |
| Attestation module (DSSE + in-toto Statement + digest binding) | ✅ shipped — `edbc06d` |
| Registry fetch via `oci-client` + `tokio` (`--no-verify` path) | ✅ shipped — `6ae624c` |
| `oci report` end-to-end (DSSE unwrap, re-classify, enrich, summary) | ✅ shipped — `e99ea88` (rewritten to `5f8e150` after a commit-message scrub) |
| Cosign **key-based** verification (image sig + DSSE envelopes + digest binding) | ✅ shipped — `0272208` |
| Cosign **keyless** verification (Fulcio + Rekor + identity match) for image sig | ✅ shipped — `5f08150` |
| Keyless DSSE attestation verification (per-envelope cert, SAN, issuer ext, DSSE sig) | ✅ shipped — `7fd8118` |
| Per-attestation Fulcio chain validation | ✅ shipped — `028fa20` |
| `--trust-root <PEM>` + `--insecure-ignore-tlog` | ✅ shipped — `72169a0` |
| SARIF 2.1.0 emitter for `oci verify` | ✅ shipped — `b3ae4c9` |
| MSRV | ✅ stayed on **Rust 1.88** — no bump needed |

## Known remaining gaps (not blocking the feature)

- **Custom Rekor URL.** `--rekor-url <URL>` is parsed and honoured against the
  bundled Rekor key, but `sigstore-rs 0.13` doesn't surface a way to swap the
  Rekor *endpoint* without rebuilding internals. Practically, this affects
  private Sigstore Rekor deployments. Workaround today: use the bundled
  Rekor or pair with `--insecure-ignore-tlog` for air-gapped use.
- **`https://in-toto.io/attestation/vulns` ingestion.** Verified vuln-scan
  attestations are recorded in the SARIF index but not auto-merged into the
  OSV/KEV enrichment model. Deferred to a dedicated proposal.
- **Multi-arch image index.** For a multi-arch index, we currently verify the
  resolved platform manifest's signature/attestations but not the index
  digest's own signature. Index-level verification is an additive follow-up.
- **Sigstore Bundle format.** The modern `.sigstore` bundle format (with
  embedded TUF/Rekor data) isn't read directly. The cosign tag-scheme and
  Referrers API cover all observed registries today; bundle support is a
  drop-in addition when adoption demands it.

## Decisions made along the way

1. ~~**MSRV split.**~~ **Resolved (2026-05-14):** no split needed.
   `sigstore = 0.13` + `oci-client = 0.15` + `tokio` compile clean on the
   existing Rust 1.88 toolchain.
2. **Verification default.** ~~Open.~~ **Implemented (b3ae4c9 era):**
   `oci pull` / `oci verify` / `oci report` all require an explicit
   verification policy or `--no-verify`. No silent skipping.
3. **`vulns` attestation ingestion.** **Decision: record only.** The cosign
   vuln-attestation surfaces in the SARIF report but doesn't replace OSV/KEV.
4. **TUF root.** **Decision: fetch + cache.** `SigstoreTrustRoot::new` is
   given a cache path under `~/.cache/sbom-tools/sigstore-tuf`. First run
   fetches the bundled public-good root; subsequent runs reuse the cache.
   Custom TUF roots: see `--trust-root <PEM>` for Fulcio CA substitution.
5. **Multi-arch.** **Decision (interim):** verify the resolved platform
   manifest; index-level verification is the documented follow-up.

---

## Where this lives in the code (after implementation)

- `src/oci/mod.rs` — `OciReference`, `OciResolver`, public API
- `src/oci/client.rs` — registry client wrapper + async→sync bridge
- `src/oci/discovery.rs` — Referrers API + cosign tag-scheme discovery
- `src/oci/attestation.rs` — DSSE/in-toto unwrap + predicate mapping
- `src/oci/verify.rs` — cosign verification (`sigstore`) + `VerificationPolicy`
- `src/oci/cache.rs` — digest-addressed blob cache
- `src/cli/oci.rs` — `oci pull|verify|report` command handler
- `src/reports/oci_sarif.rs` — SARIF emitter for `SBOM-OCI-*` findings
- `src/config/types.rs` — `OciConfig` + `AppConfig.oci`
- `src/pipeline/mod.rs` — `exit_codes::OCI_VERIFICATION_FAILED = 6`
- `src/main.rs` — new `Command::Oci { action: OciAction }` arm
- `src/lib.rs` — feature-gated public re-exports
- `tests/oci_tests.rs` — integration tests (gated `#[cfg(feature = "oci")]`)
- `tests/fixtures/oci/` — registry fixtures, signed/tampered samples
- `fuzz/fuzz_targets/oci_attestation.rs` — DSSE/in-toto fuzz target
- `Cargo.toml` — `oci` feature + `sigstore` / `oci-client` / `tokio` deps
- `docs/CRA_COMPLIANCE.md` — append `SBOM-OCI-*` rows to the reverse map
- `README.md` — Features bullet, CLI cheat sheet, `oci`-feature MSRV note
