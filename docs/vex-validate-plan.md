# VEX Validate — Standalone VEX Document Linter & Conformance Checker

> Feature proposal. Not yet implemented. Tracking issue: TBD.
> Style follows [`docs/standards-support-plan.md`](standards-support-plan.md) and
> [`docs/CRA_COMPLIANCE.md`](CRA_COMPLIANCE.md). All rule IDs, exit codes, and
> CLI conventions are aligned with the existing `sbom-tools validate` and
> `sbom-tools vex` commands.

## Executive summary

sbom-tools today **consumes** VEX documents (OpenVEX / CycloneDX VEX / CSAF
v2.0) via `vex apply`, `vex status`, `vex filter`, `diff --vex …`, and the
shared `VexEnricher`. It also **emits** CSAF v2.0 via `vex export --format
csaf`. What is missing is a way to **validate the VEX documents themselves**:
to check that an advisory is well-formed, that its statements satisfy the
MUST/SHOULD rules of its format spec, and that it carries the evidence a
regulator (CRA Art. 13(9), CSAF profile MUSTs) expects.

The proposal: a new subcommand `sbom-tools vex validate <vex-doc>...` that
- parses each input as OpenVEX, CycloneDX VEX, or CSAF v2.0 (re-using the
  detection plumbing in `src/enrichment/vex/mod.rs`);
- runs a tiered catalogue of rules (structural → semantic → standards →
  policy);
- emits findings in SARIF / JSON / table / summary (consistent with
  `validate`, `quality`, `query`);
- exits non-zero on any `Error`-severity violation, configurable via
  `--fail-on-warning` / `--fail-on-info`.

Effort: **~6–8 days** for Phase 1 (rules + CLI + SARIF + tests). Phase 2
(policy sidecar + cross-document conflict detection) is an optional follow-up.

This feature elevates VEX from "enrichment input" to "first-class validated
artifact" so the supply-chain pipeline can gate on `vex validate` the same
way it already gates on `sbom-tools validate --standard cra`.

---

## Motivation

### What goes wrong today

1. **`Not Affected` without justification.** OpenVEX `not_affected` statements
   MUST carry a `justification`. The current ingest path silently accepts
   missing justifications and assigns `VexJustification::None`, so CRA
   Art. 13(9) ("Known vulnerabilities statement") can be cleared by an
   advisory that would be rejected by an auditor.
2. **CSAF without product identifiers.** A CSAF advisory whose
   `product_tree` entries lack a `purl` (and lack a CPE) cannot be matched to
   any SBOM component. `VexEnricher` skips them, so the SBOM's VEX coverage
   silently drops without an error.
3. **Stale advisories.** OpenVEX and CSAF both carry a timestamp, but no
   sbom-tools command flags advisories older than a configurable freshness
   window.
4. **Cross-document conflicts.** `VexEnricher` uses last-file-wins semantics
   for overlapping `(vuln_id, purl)` keys (see
   `src/enrichment/vex/mod.rs:38` — the doc comment is explicit). In
   multi-team setups (vendor advisory + downstream override) this can mask a
   regression. Phase 2 surfaces these as findings.
5. **Conflicting status within one document.** A CSAF v2.0 advisory can list
   the same product under both `known_affected` and `known_not_affected`.
   The current parser accepts this and the last bucket wins. A regulator
   reading the file would call this a defect.
6. **`Affected` with `Fixed`-only response.** OpenVEX semantics: an
   `affected` statement should carry an `action_statement` (CRA Art. 13(9)
   "vulnerability handling"). The current parser doesn't require it.

### Why a separate command, not an extension of `validate`

`sbom-tools validate` validates an **SBOM** against compliance standards.
`vex validate` validates a **VEX document** against the VEX-format specs and
VEX-relevant standards. The inputs are different artifacts. Mirroring the
existing `verify` (file integrity) / `validate` (SBOM compliance) split keeps
each command's input contract clean.

### Why now

The project already ships:

- the three parsers (P4.1: OpenVEX, CycloneDX VEX, CSAF v2.0)
- the CSAF emitter (P4.2)
- standards-watch coverage for CRA / prEN 40000-1-3 / BSI / CSAF / EUCC

The natural P4.3 deliverable is conformance: prove that the VEX flowing into
the pipeline meets the standards that the project already catalogues.

---

## Non-goals (explicit)

To avoid scope creep — these are NOT part of `vex validate`:

1. **No signing or signature verification.** That belongs in a future
   `vex verify` (sigstore / X.509) and is intentionally separated from
   document linting.
2. **No JSON-schema-only validation.** The OpenVEX schema is published but
   real-world advisories are loose; semantic rules are where the value is.
   Schema checks run as one tier of rule, not the whole feature.
3. **No automatic fix.** Findings carry a human-readable `message` and (when
   applicable) a `suggested_fix` string, but the file on disk is never
   modified. Operators can write a follow-up `vex fix` PR.
4. **No CVE / OSV cross-validation.** That belongs in the enrichment
   pipeline (`sbom-tools enrich`). `vex validate` operates only on the VEX
   document and its self-consistency.
5. **No bypass for `vex apply` / `vex status`.** Those keep their current
   lenient ingest behaviour; only `vex validate` is strict. This preserves
   backwards-compatible enrichment.

---

## CLI surface

```text
sbom-tools vex validate <PATH>... [OPTIONS]
```

| Flag                           | Default              | Description                                                                                  |
|--------------------------------|----------------------|----------------------------------------------------------------------------------------------|
| `--profile <NAME>`             | `default`            | Rule profile: `default`, `strict`, `openvex`, `cyclonedx-vex`, `csaf`, `cra`                 |
| `--max-age <DURATION>`         | none                 | Fail (or warn under `--fail-on-warning`) if timestamp older than this (e.g., `90d`, `12mo`)  |
| `--policy <PATH>`              | auto-discover        | YAML/JSON policy sidecar (Phase 2). See [Policy sidecar](#policy-sidecar-phase-2)             |
| `-o, --output <FMT>`           | `auto`               | `auto`, `sarif`, `json`, `table`, `summary`, `markdown`                                       |
| `-O, --output-file <PATH>`     | stdout               | Write to a file                                                                              |
| `--fail-on-warning`            | false                | Exit non-zero on Warning findings too                                                        |
| `--fail-on-info`               | false                | Exit non-zero on any finding                                                                 |
| `--summary`                    | false                | Suppress per-finding output; print only counts                                               |
| `--quiet`                      | false                | Suppress non-essential stderr                                                                |
| `--rule <ID>` (repeatable)     | none                 | Run only these rules (`SBOM-VEX-…`)                                                          |
| `--ignore <ID>` (repeatable)   | none                 | Skip these rules                                                                             |
| `--strict-format`              | false                | Reject the file if its declared format doesn't match the auto-detected format                |

### Sample invocations

```bash
# Lint a single OpenVEX document with default profile
sbom-tools vex validate advisory.openvex.json

# Strict mode, fail on warnings, emit SARIF for CI
sbom-tools vex validate advisory.csaf.json \
    --profile strict --fail-on-warning -o sarif -O vex.sarif

# Multi-document validation (typical PR review of vendor + downstream override)
sbom-tools vex validate vendor.csaf.json downstream.openvex.json \
    --profile cra --max-age 12mo

# Skip a noisy rule
sbom-tools vex validate advisory.json --ignore SBOM-VEX-INFO-004

# Phase 2 — policy-driven validation
sbom-tools vex validate advisory.csaf.json --policy vex-policy.yaml
```

### Exit codes (consistent with `pipeline::exit_codes`)

| Code | Meaning                                                                                  |
|------|------------------------------------------------------------------------------------------|
| `0`  | No findings, or only findings below the configured fail threshold                        |
| `1`  | One or more `Error`-severity findings (or, with `--fail-on-warning`, any Warning)        |
| `2`  | I/O / parse error (file not found, malformed JSON, unknown format)                       |
| `4`  | Multi-document conflict detected (Phase 2 only)                                          |

These mirror `validate` (`0`/`1`/`2`) and add `4` for conflicts, paralleling
the existing `diff --fail-on-vex-gap` semantics.

---

## Architecture

### Module layout

```
src/
  cli/
    vex_validate.rs        NEW — command handler, dispatch by detected format
  validation/              NEW MODULE — sibling of enrichment/vex/
    vex/
      mod.rs               Rule trait + registry + ValidationFinding type
      structural.rs        Schema / required-field rules
      semantic.rs          Cross-field consistency, format-specific MUSTs
      standards.rs         CRA / CSAF profile / OpenVEX MUST rules
      conflicts.rs         Phase 2 — multi-doc and intra-doc conflicts
      policy.rs            Phase 2 — sidecar policy DSL
  reports/
    vex_sarif.rs           NEW — SARIF emitter for VEX findings (mirrors compliance SARIF)
```

`validation/vex/` is a new top-level module under `src/`. It sits alongside
`enrichment/vex/` (which parses) rather than inside it, because:

- `enrichment/vex/` is feature-gated under `enrichment`; `vex validate`
  should work in builds without that flag (it doesn't need network).
- A new module keeps the public API surface stable. The enricher's
  `from_files` / `enrich_sbom` stays unchanged.

### Public types

```rust
// src/validation/vex/mod.rs

pub struct VexValidationFinding {
    pub rule_id: String,          // e.g. "SBOM-VEX-MUST-001"
    pub severity: ViolationSeverity, // reuse the enum from src/quality/compliance.rs
    pub category: VexFindingCategory,
    pub message: String,
    pub document_path: PathBuf,
    pub statement_index: Option<usize>, // OpenVEX statement[i], CSAF vulnerabilities[i]
    pub product_id: Option<String>,
    pub suggested_fix: Option<String>,
    pub standard_refs: Vec<StandardRef>, // reuse from src/quality/compliance.rs
}

pub enum VexFindingCategory {
    Structure,     // missing required field, bad type
    Semantic,      // contradictions, missing justification, etc.
    Standards,     // CRA / CSAF / OpenVEX MUST / SHOULD
    Freshness,     // stale timestamp
    Conflict,      // Phase 2 — overlapping statements
    Policy,        // Phase 2 — user policy rule
}

pub struct VexValidator {
    profile: VexProfile,
    rules: Vec<Box<dyn VexRule>>,
    max_age: Option<chrono::Duration>,
}

pub trait VexRule: Send + Sync {
    fn id(&self) -> &'static str;
    fn category(&self) -> VexFindingCategory;
    fn default_severity(&self) -> ViolationSeverity;
    fn check(&self, doc: &ParsedVexDoc, sink: &mut Vec<VexValidationFinding>);
}
```

Reusing `ViolationSeverity` and `StandardRef` from `src/quality/compliance.rs`
means SARIF output already has the canonical `helpUri` machinery — see
[CRA_COMPLIANCE.md](CRA_COMPLIANCE.md#where-this-map-lives-in-the-code).

### Parser reuse

`src/enrichment/vex/{openvex,cyclonedx_vex,csaf}.rs` already detect and parse
all three formats. Phase 1 extracts the **format detection** logic
(`is_csaf`, `is_cyclonedx_vex`, fall-through OpenVEX) into a small public
helper so `vex validate` can dispatch without depending on enricher internals.
The parsers themselves stay private to the enrichment module; the validator
gets a new `ParsedVexDoc` enum that wraps the three parser outputs.

### Format detection contract

Detection priority is unchanged from the enricher: CSAF (top-level
`document.csaf_version` starts with `2.`) → CycloneDX VEX (`bomFormat:
CycloneDX` + empty `components`) → OpenVEX (catch-all on `@context:
*openvex.dev*`). Under `--strict-format` a file that fails detection is
reported as `SBOM-VEX-STR-000` (unknown format) instead of falling through.

---

## Rule catalogue

Rule IDs follow `SBOM-VEX-<TIER>-<NNN>` where `<TIER>` is one of
`STR` (structural), `SEM` (semantic), `STD` (standards), `FRSH` (freshness),
`CONF` (conflicts — Phase 2), `POL` (policy — Phase 2). The prefix
`SBOM-VEX-*` matches the SARIF rule-ID convention already used by
`SBOM-BSI-TR-03183-2-*` etc.

### Tier 1 — Structural (always run)

| Rule ID            | Severity | Description                                                                                  |
|--------------------|----------|----------------------------------------------------------------------------------------------|
| `SBOM-VEX-STR-000` | Error    | Document parses as none of OpenVEX / CycloneDX VEX / CSAF v2.0 (under `--strict-format`)     |
| `SBOM-VEX-STR-001` | Error    | OpenVEX statement missing `vulnerability.name`                                               |
| `SBOM-VEX-STR-002` | Error    | OpenVEX `@context` missing or doesn't match `openvex.dev/ns/v*`                              |
| `SBOM-VEX-STR-003` | Error    | OpenVEX document has zero statements                                                         |
| `SBOM-VEX-STR-004` | Error    | CSAF document missing `document.csaf_version` or value not `2.x`                             |
| `SBOM-VEX-STR-005` | Error    | CSAF document has no `vulnerabilities[]`                                                     |
| `SBOM-VEX-STR-006` | Error    | CycloneDX VEX missing `bomFormat: "CycloneDX"`                                               |
| `SBOM-VEX-STR-007` | Error    | CycloneDX VEX `vulnerabilities[].id` missing                                                 |
| `SBOM-VEX-STR-008` | Warning  | CSAF `product_tree.full_product_names[]` entry has no `purl` and no `cpe`                    |
| `SBOM-VEX-STR-009` | Warning  | OpenVEX product has no `@id` (PURL) and no `identifiers.purl`                                |

### Tier 2 — Semantic (always run)

| Rule ID            | Severity | Description                                                                                                                              |
|--------------------|----------|------------------------------------------------------------------------------------------------------------------------------------------|
| `SBOM-VEX-SEM-001` | Error    | `not_affected` statement has no `justification` (OpenVEX MUST; CycloneDX `analysis.justification` SHOULD elevated to MUST under strict)  |
| `SBOM-VEX-SEM-002` | Warning  | `affected` statement has no `action_statement` / `analysis.response`                                                                     |
| `SBOM-VEX-SEM-003` | Error    | Same `(vuln_id, product_id)` appears in two contradictory CSAF buckets (`known_affected` AND `known_not_affected`)                        |
| `SBOM-VEX-SEM-004` | Warning  | CSAF product status `recommended` used without `known_affected` for the same vulnerability                                               |
| `SBOM-VEX-SEM-005` | Warning  | OpenVEX statement claims `fixed` but `products[]` PURL has no version pin                                                                |
| `SBOM-VEX-SEM-006` | Info     | OpenVEX `aliases` array contains a duplicate of `vulnerability.name`                                                                     |
| `SBOM-VEX-SEM-007` | Warning  | OpenVEX statement uses an unrecognised `justification` value (not one of the five OpenVEX-defined values)                                |
| `SBOM-VEX-SEM-008` | Warning  | CycloneDX `analysis.state` uses non-spec value (only `not_affected`, `affected`, `fixed`, `in_triage`, `false_positive`, `resolved` allowed) |
| `SBOM-VEX-SEM-009` | Info     | Statement has both `impact_statement` and `action_statement` empty (low-information VEX)                                                 |
| `SBOM-VEX-SEM-010` | Warning  | OpenVEX `products[]` mixes PURLs and non-PURL `@id` URIs in a single statement (matching will be inconsistent)                           |

### Tier 3 — Standards (profile-gated)

`--profile cra` adds:

| Rule ID            | Severity | Standard ref          | Description                                                                                                       |
|--------------------|----------|-----------------------|-------------------------------------------------------------------------------------------------------------------|
| `SBOM-VEX-STD-001` | Error    | CRA Art. 13(9)        | Document declares no statements with `status: affected` or `under_investigation` (a "VEX" with no risk is sus)    |
| `SBOM-VEX-STD-002` | Warning  | CRA Art. 13(7)        | Document has no contact / publisher namespace (CSAF `document.publisher.namespace` / OpenVEX `author`)            |
| `SBOM-VEX-STD-003` | Warning  | CRA Art. 13(9) / CSAF | CSAF `document.tracking.status` is `draft` but advisory carries actionable statements                             |
| `SBOM-VEX-STD-004` | Warning  | CSAF v2.0 §3.1.1      | CSAF `document.tracking.revision_history[]` is empty                                                              |
| `SBOM-VEX-STD-005` | Info     | CSAF v2.0 §3.2.4      | Advisory has no `notes[]` entries describing the response                                                         |

`--profile openvex` / `--profile csaf` / `--profile cyclonedx-vex` activate
only the rules native to that format (others reported as `not applicable`).

`--profile strict` activates everything above plus elevates several Warnings
to Errors (controlled by a per-profile severity map, not hard-coded).

### Tier 4 — Freshness

| Rule ID             | Severity | Description                                                                              |
|---------------------|----------|------------------------------------------------------------------------------------------|
| `SBOM-VEX-FRSH-001` | Warning  | Document's most-recent timestamp older than `--max-age` (default disabled)                |
| `SBOM-VEX-FRSH-002` | Info     | Document has no timestamp at all (OpenVEX `timestamp`, CSAF `current_release_date`)       |

### Tier 5 — Phase 2: Conflicts & policy

Documented here for completeness; implementation deferred.

| Rule ID            | Severity | Description                                                                                                                  |
|--------------------|----------|------------------------------------------------------------------------------------------------------------------------------|
| `SBOM-VEX-CONF-001`| Warning  | Two input files assert different `status` for the same `(vuln_id, purl)` — last-file-wins would mask this in `vex apply`     |
| `SBOM-VEX-CONF-002`| Info     | Two input files assert the same `status` with different `justification` values                                               |
| `SBOM-VEX-POL-001` | per-policy | User-defined: e.g. "any `Critical` CVE marked `NotAffected` MUST carry an `impact_statement`"                              |

---

## Standards mapping table

(Mirrors the reverse-map in [`CRA_COMPLIANCE.md`](CRA_COMPLIANCE.md). New
entries to be added there once Phase 1 lands.)

| Rule ID            | OpenVEX spec       | CycloneDX VEX                | CSAF v2.0                                           | CRA / prEN reference     |
|--------------------|--------------------|------------------------------|-----------------------------------------------------|--------------------------|
| `SBOM-VEX-STR-001` | §2.3 (Statement)   | n/a                          | n/a                                                 | —                        |
| `SBOM-VEX-STR-002` | §1.2 (@context)    | n/a                          | n/a                                                 | —                        |
| `SBOM-VEX-STR-004` | n/a                | n/a                          | §3.1.1 (csaf_version)                                | RLS-2-RQ-03-RE           |
| `SBOM-VEX-STR-008` | n/a                | n/a                          | §3.2.1 (product_identification_helper)              | PRE-7-RQ-07              |
| `SBOM-VEX-SEM-001` | §2.5 (Statuses)    | §4.4 (analysis.justification) | §3.2.3 (product_status)                              | Art. 13(9), RLS-2-RQ-04  |
| `SBOM-VEX-SEM-002` | §2.5 (action)      | §4.4 (analysis.response)      | §3.2.4 (remediations)                                | Art. 13(9)               |
| `SBOM-VEX-SEM-003` | n/a                | n/a                          | §3.2.3 (product_status mutually exclusive)           | Art. 13(9)               |
| `SBOM-VEX-STD-001` | n/a                | n/a                          | n/a                                                 | Art. 13(9)               |
| `SBOM-VEX-STD-002` | §2.2 (Author)      | n/a                          | §3.1.3 (publisher)                                  | Art. 13(7)               |
| `SBOM-VEX-FRSH-001`| §2.4 (timestamp)   | n/a                          | §3.1.4 (current_release_date)                       | —                        |

Canonical URLs land in SARIF `properties.standardHelpUris` via the existing
`StandardKind::canonical_help_uri()` mechanism. CSAF URIs use
`https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#$ANCHOR`.

---

## SARIF output

The validator emits SARIF 2.1.0 using a new tool driver
`sbom-tools-vex-validate`. Each finding becomes one `result` with:

- `ruleId` = `SBOM-VEX-…`
- `level` = `error` / `warning` / `note`
- `message.text` = human-readable
- `locations[0].physicalLocation.artifactLocation.uri` = document path
- `locations[0].logicalLocations[0].name` = statement-level pointer
  (e.g., `statements[2].justification` / `vulnerabilities[0].product_status.known_affected[1]`)
- `properties.standardIds` / `properties.standardHelpUris` populated via
  `StandardRef::canonical_help_uri()`

The rule index is generated once per run from the active profile, so
`runs[0].tool.driver.rules[]` lists every rule that was enabled (not just the
ones that fired) — matching how `validate` emits its rule index today.

---

## Policy sidecar (Phase 2)

A YAML/JSON file (`vex-policy.yaml`) that augments the built-in rule
catalogue. Auto-discovered next to the VEX document at
`<stem>.vex-policy.{yaml,yml,json}`. Schema sketch:

```yaml
fail_on:
  - error
  - warning
ignore:
  - SBOM-VEX-INFO-009
require_justification_for_severities:
  - critical
  - high
require_action_statement_for_status:
  - affected
max_age: 12mo
require_publisher_namespace: true
forbid_status:
  draft:
    - affected
custom_rules:
  - id: ORG-VEX-001
    description: "Critical CVE NotAffected requires impact_statement"
    severity: error
    when:
      status: not_affected
      vuln_severity: critical
    require:
      impact_statement_non_empty: true
```

Reuses the policy-loading patterns already in `src/license/policy.rs`.

---

## Implementation plan

### Phase 1 — Core validator (target: ~6–8 days)

1. **Day 1 — Module skeleton**
   - Add `src/validation/vex/mod.rs` with `VexRule` trait, `VexValidator`,
     `VexValidationFinding`, `VexFindingCategory`
   - Lift `is_csaf` / `is_cyclonedx_vex` into `enrichment::vex::detect`
     (small refactor; keep current detection precedence)
   - Wire `validation` into `src/lib.rs` (default-on, no feature gate)
2. **Day 2 — Structural rules**
   - Implement Tier 1 rules (`SBOM-VEX-STR-*`) against the three parsers
   - Tests: round-trip the fixture files, verify zero structural findings;
     mutate fixtures to drop required fields, verify each rule fires
3. **Day 3 — Semantic rules**
   - Implement Tier 2 rules (`SBOM-VEX-SEM-*`)
   - Tests: positive + negative fixture per rule
4. **Day 4 — Standards rules + profile machinery**
   - Implement Tier 3 (`SBOM-VEX-STD-*`)
   - Wire `--profile`, `--rule`, `--ignore`, per-profile severity overrides
   - Reuse `ViolationSeverity` and `StandardRef` from
     `src/quality/compliance.rs`
5. **Day 5 — Freshness + CLI**
   - Tier 4 (`SBOM-VEX-FRSH-*`) with `--max-age` parser
   - New `cli/vex_validate.rs` command handler; wire into
     `main.rs::VexAction` as `VexAction::Validate`
   - Output: table (default), JSON, summary
6. **Day 6 — SARIF emitter**
   - `reports/vex_sarif.rs`; mirror the existing compliance SARIF in
     `reports/sarif.rs`
   - Add `rule_help_uri` entries for `SBOM-VEX-*` prefix
7. **Day 7 — Documentation + golden fixtures**
   - Update `README.md` (Features section + CLI cheat sheet)
   - Update `CRA_COMPLIANCE.md` (add `SBOM-VEX-*` rule rows)
   - Add golden SARIF fixture per profile to `tests/fixtures/vex_validate/`
8. **Day 8 — Polish**
   - Exit-code wiring (1 for findings, 2 for I/O, 4 reserved for Phase 2)
   - `clap_complete` shell completions regenerate
   - Final clippy / fmt pass

### Phase 2 — Conflicts + policy (~5 days, optional)

1. Multi-doc conflict detection (`SBOM-VEX-CONF-*`)
2. Policy sidecar loader (`src/validation/vex/policy.rs`)
3. Custom rule DSL
4. Exit code `4` wired up

### Feature flags

No new feature flags. `vex validate` works in builds without the `enrichment`
flag because it only needs the (already-feature-free) parsers — the
enrichment flag gates the *network* enrichment pipeline, not the VEX
document parsers themselves. (If parser code is currently gated, Phase 1
day 1 includes the small refactor to expose the parsers
unconditionally.)

### Public API additions

```rust
// src/lib.rs additions
pub use validation::vex::{
    VexValidator, VexValidationFinding, VexFindingCategory, VexProfile, VexRule,
};
```

`VexProfile` is a `#[non_exhaustive]` enum so adding new profiles later
(`fda`, `nis2`, …) doesn't break downstream.

---

## Test plan

### Unit tests (per rule)

For each rule in the catalogue:

- Positive fixture (rule does NOT fire)
- Negative fixture (rule DOES fire, finding has expected
  `rule_id`/`severity`/`document_path`/`statement_index`)

These live in `src/validation/vex/{structural,semantic,standards,freshness}.rs`
under `#[cfg(test)]`.

### Integration tests (`tests/vex_validate_tests.rs`)

- Validate each of the three existing fixtures:
  - `tests/fixtures/vex/openvex-sample.json`
  - `tests/fixtures/vex/cyclonedx-vex-sample.json`
  - (new) `tests/fixtures/vex/csaf-sample.json`
- Round-trip: `vex export --format csaf <sbom>` → `vex validate <csaf>` must
  produce zero `Error` findings (closes the loop already established by the
  CSAF emitter)
- Profile gating: same fixture under `--profile default` vs `--profile cra`
  produces different finding counts (snapshot test)
- Exit code matrix: `0` / `1` / `2` for the expected scenarios
- SARIF golden fixture (snapshot, regenerable with
  `cargo test --features ffi -- --ignored update_golden`)

### Property tests (`proptest`)

- Generate random OpenVEX documents with valid + invalid mutations; assert
  no panic, structural rule fires iff expected
- Generate random CSAF `product_status` buckets with random overlaps; assert
  `SBOM-VEX-SEM-003` (contradiction) fires iff a product appears in two
  mutually-exclusive buckets

### CLI tests (`tests/showcase_cli_tests.rs`)

Add a `test_vex_validate_cli_runs` that asserts `vex validate
fixtures/vex/openvex-sample.json` exits `0` and prints a non-empty summary.

### Fuzz target

`fuzz/fuzz_targets/vex_validate.rs` — feed arbitrary JSON into the validator;
asserts no panics, no infinite loops. Same harness shape as the existing
parser fuzz targets.

---

## Risk register

| Risk                                                                  | Likelihood | Impact | Mitigation                                                                                                  |
|-----------------------------------------------------------------------|------------|--------|-------------------------------------------------------------------------------------------------------------|
| Spec ambiguity: OpenVEX SHOULDs vs MUSTs in `not_affected` rules      | Medium     | Medium | Map each rule to the exact spec section in the catalogue; profile gates SHOULDs                             |
| Real-world advisories fail trivial rules and overwhelm users          | High       | Low    | Default profile is permissive; `--profile strict` for the picky pass; SARIF helpUri explains each finding   |
| `--max-age` clock drift between CI and document timezone              | Low        | Low    | All comparisons in UTC; document timestamps are required to be RFC 3339 already                             |
| CSAF parser doesn't expose enough fields to validate (e.g., revision history) | Medium     | Medium | Phase 1 day 0 audit of `enrichment/vex/csaf.rs`; extend the parser struct with `#[allow(dead_code)]` fields |
| Duplicate logic between `vex validate` and `vex apply` parsing        | Low        | Low    | Lift detection into `enrichment::vex::detect`; share a `ParsedVexDoc` wrapper                                |
| Rule catalogue churns once users start filing bugs                    | High       | Low    | Rule IDs are stable contracts; deprecations marked `#[deprecated]` not removed, mirroring SARIF convention  |

---

## What this enables

Once `vex validate` lands:

- **CI gates**: `sbom-tools vex validate vex/*.json --profile cra
  --fail-on-warning -o sarif -O vex.sarif` is a drop-in PR check that runs
  alongside the existing `validate --standard cra` job
- **Cross-format authoring confidence**: round-trip
  `vex export --format csaf` → `vex validate` confirms the emitter's output
  is itself spec-conformant — a regression test the project doesn't have today
- **Standards-watch coverage**: CRA Art. 13(9) gets an actionable rule path
  for the VEX document side (today only the SBOM side is gated)
- **Foundation for OpenVEX / CycloneDX VEX emit**: the validator becomes the
  acceptance test for those emitters in their respective Phase 4.x PRs

## Future work (separate proposals)

| Feature                | Sketch                                                                                          |
|------------------------|-------------------------------------------------------------------------------------------------|
| `vex export --format openvex` | Mirror existing CSAF emitter; validated by `vex validate --profile openvex`              |
| `vex export --format cyclonedx-vex` | Same shape; validated by `--profile cyclonedx-vex`                                |
| `vex merge`            | Consolidate multiple VEX docs deterministically; surface `SBOM-VEX-CONF-*` during the merge      |
| `vex diff <a> <b>`     | PR-review tool for two VEX documents; emits a structured changeset                              |
| `vex verify`           | Sigstore / X.509 signature verification (separate from this proposal)                            |

---

## Open questions

1. Should `vex validate` participate in `sbom-tools watch` so a long-running
   process re-validates VEX docs when they change on disk? Lean: yes, but
   wire it in a follow-up PR after Phase 1.
2. Do we want a `--baseline <previous-sarif>` flag to suppress findings
   already known to the project (matches the existing baseline pattern in
   `validate`)? Lean: yes, Phase 1.5.
3. JSON-schema check (against the published OpenVEX / CSAF schemas) as an
   optional rule (`SBOM-VEX-STR-099` perhaps) — adds a `jsonschema` crate
   dependency. Defer until a user asks; semantic rules cover most real bugs.

---

## Where this lives in the code (after implementation)

- `src/validation/vex/mod.rs` — rule trait + registry
- `src/validation/vex/{structural,semantic,standards,freshness,conflicts,policy}.rs` — rules
- `src/enrichment/vex/detect.rs` — format detection (lifted from `mod.rs`)
- `src/cli/vex_validate.rs` — command handler
- `src/main.rs` — new `VexAction::Validate(VexValidateArgs)` arm
- `src/reports/vex_sarif.rs` — SARIF emitter
- `tests/vex_validate_tests.rs` — integration tests
- `tests/fixtures/vex_validate/` — positive + negative fixtures per rule
- `fuzz/fuzz_targets/vex_validate.rs` — fuzz target
- `docs/CRA_COMPLIANCE.md` — append `SBOM-VEX-*` rule rows to the reverse map
- `README.md` — Features bullet + CLI cheat sheet entry
