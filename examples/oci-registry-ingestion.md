# OCI Registry Ingestion — Worked Examples

Pull and cosign-verify the SBOM/VEX artifacts attached to a container image,
then feed them straight into the sbom-tools pipeline.

> **Status (preview).** The command surface, image-reference parsing, and
> verification-policy validation are implemented and tested. The registry
> client and cosign verification — the `sigstore` / `oci-client` dependencies
> — are in progress. Until they land, the `oci` commands parse and validate
> their inputs, print what they *would* fetch and verify, and exit with code
> `3`. See [`docs/oci-verify-plan.md`](../docs/oci-verify-plan.md) for the
> full design and phased plan.

## Building

The feature is **off by default**. A default `cargo build` pulls in none of
the OCI dependencies.

```sh
cargo build --release --features oci
```

## `oci pull` — fetch + verify + materialise

Pulls the SBOM/VEX artifacts attached to an image, verifies them, and writes
them to disk as ordinary files.

```sh
# Digest-pinned image, keyless cosign policy (GitHub Actions OIDC)
sbom-tools oci pull ghcr.io/acme/api@sha256:abc123... \
    --certificate-identity-regexp '^https://github.com/acme/.+' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --output-dir ./oci-artifacts

# Key-based policy, only extract the SBOM
sbom-tools oci pull ghcr.io/acme/api:v1.4.0 \
    --key cosign.pub \
    --artifact sbom

# Local registry over plain HTTP, no signatures expected
sbom-tools oci pull localhost:5000/test:dev --insecure --no-verify
```

## `oci verify` — verify only

Verifies the image signature and attestations and reports the verdict — no
artifacts are written. Intended as a CI gate.

```sh
# Fail the build unless a verified CycloneDX attestation is present
sbom-tools oci verify ghcr.io/acme/api:v1.4.0 \
    --key cosign.pub \
    --require-attestation https://cyclonedx.org/bom \
    -o sarif -O oci-verify.sarif

# Private / air-gapped Sigstore deployment
sbom-tools oci verify registry.internal/app:1.0 \
    --key /etc/keys/app.pub \
    --trust-root /etc/sigstore/root.json \
    --rekor-url https://rekor.internal
```

Exit codes: `0` verified · `3` registry/parse error · `6` verification failed
(bad signature, identity/issuer mismatch, digest-binding mismatch, or a
required attestation was absent).

## `oci report` — one-shot trustworthy vuln picture

Pulls + verifies + enriches, then produces a vulnerability report — the
single-command replacement for the `cosign` + `oras` + `sbom-tools` dance.

```sh
sbom-tools oci report ghcr.io/acme/api:v1.4.0 \
    --certificate-identity-regexp '^https://github.com/acme/.+' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --standard cra \
    --fail-on-vex-gap \
    -o markdown
```

## Verification policies

Exactly one policy must be supplied — the tool never silently skips
verification:

| Policy        | Flags                                                                                          |
|---------------|------------------------------------------------------------------------------------------------|
| Key-based     | `--key cosign.pub`                                                                             |
| Keyless       | `--certificate-identity[-regexp] <id>` **and** `--certificate-oidc-issuer <url>`               |
| None (opt-in) | `--no-verify` — fetch only; every verdict is `Skipped`                                         |

Keyless verification also accepts `--trust-root` (custom Sigstore TUF root),
`--rekor-url`, and `--insecure-ignore-tlog` (air-gapped).

## Registry authentication

Resolution order: explicit flags → `SBOM_TOOLS_REGISTRY_*` env →
`~/.docker/config.json` (static `auths`) → anonymous.

```sh
sbom-tools oci pull ghcr.io/acme/api:v1.4.0 \
    --registry-username acme-ci \
    --no-verify
# password read from SBOM_TOOLS_REGISTRY_PASSWORD
```

## Config file — the `[oci]` section

CI can pin the verification policy and discovery preferences once in
`.sbom-tools.yaml` instead of repeating flags. CLI flags override the file.

```yaml
oci:
  cache_dir: ~/.cache/sbom-tools/oci   # digest-addressed blob cache
  prefer: referrers                     # referrers | tag-scheme
  insecure: false
  verify:
    # exactly one of: key, or keyless (certificate_identity* + issuer)
    key: cosign.pub
    certificate_identity_regexp: '^https://github.com/acme/.+'
    certificate_oidc_issuer: https://token.actions.githubusercontent.com
    trust_root: bundled                 # bundled | /path/to/root.json
    rekor_url: https://rekor.sigstore.dev
    ignore_tlog: false
    require_attestations:
      - https://cyclonedx.org/bom
      - https://openvex.dev/ns
```

## How it fits the pipeline

`oci pull` writes ordinary SBOM/VEX files, so the rest of sbom-tools works
on registry inputs with no changes:

```sh
sbom-tools oci pull ghcr.io/acme/api:v1.4.0 --key cosign.pub --output-dir ./art
sbom-tools vex apply ./art/sbom.json --vex ./art/vex.json --enrich-vulns
sbom-tools validate ./art/sbom.json --standard cra
```

`oci report` chains all of that into one invocation.
