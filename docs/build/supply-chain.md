# Supply-chain gates (RLS6)

Status date: 2026-09-06. This document records the dependency vulnerability,
license, provenance/SBOM, and reproducible-build gates for the workspace, how
to run them locally, and what is honestly in place versus not yet.

## Gates

| Gate | Tool | Where it runs | Failure policy |
|---|---|---|---|
| Vulnerability advisories | `cargo deny check advisories` (RustSec DB) | CI `deny` job + local | Vulnerable/unsound/yanked crates fail; unmaintained warns; no vulnerability exceptions |
| License compliance | `cargo deny check licenses` | CI `deny` job + local | Any license outside the allowlist fails |
| Banned crates / duplicate versions | `cargo deny check bans` | CI `deny` job + local | openssl/native-tls/git2/curl fail; duplicate versions and path wildcards warn |
| Source provenance | `cargo deny check sources` | CI `deny` job + local | Anything not from crates.io fails (no git deps, no alternate registries) |
| SBOM (Rust) | `cargo cyclonedx --format json` | CI `sbom` job (uploaded artifact) | Generation failure fails the job |
| SBOM (desktop app) | `npm sbom --sbom-format cyclonedx` | CI `sbom` job (uploaded artifact) | Generation failure fails the job |
| Toolchain evidence | `rustc --version --verbose` printed in CI log | CI `rust` and `sbom` jobs | Informational (required by docs/build/toolchain.md) |

Configuration lives in `deny.toml` at the repo root. CI is
`.github/workflows/ci.yml` (jobs: `rust`, `deny`, `web`, `sbom`).

## Running the gates locally

All commands from the repo root. On this Windows dev box, anything that
compiles against Npcap or invokes gcc needs the msys64/Npcap environment
first (the GStreamer bin directory shadows `libwinpthread-1.dll`, which makes
gcc fail silently otherwise):

```powershell
$env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH
$env:RUSTFLAGS = "-L C:\Windows\System32\Npcap"
```

Then:

```powershell
cargo install cargo-deny --locked        # once
cargo install cargo-cyclonedx --locked   # once
cargo deny check                         # advisories + licenses + bans + sources
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo cyclonedx --format json            # writes <crate>.cdx.json next to each Cargo.toml
cd apps/desktop
npm ci
npm sbom --sbom-format cyclonedx --package-lock-only > desktop.cdx.json
```

SBOM files (`*.cdx.json`) are build artifacts, not repo files: CI uploads them
as the `sbom-cyclonedx` artifact; locally, delete them after inspection (they
are not committed).

## License allowlist rationale

The shipped product is proprietary; strong copyleft in third-party
dependencies is a defect. Policy encoded in `deny.toml`:

- **Allowed (permissive):** MIT, Apache-2.0 (incl. `WITH LLVM-exception`),
  BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0. Standard permissive
  set; every entry is present in the actual dependency tree (the allowlist was
  built by iterating `cargo deny check licenses` against this workspace, not
  copied from a template).
- **CDLA-Permissive-2.0 — allowed:** the Mozilla CA certificate data embedded
  in `webpki-roots`. Permissive data license, no copyleft obligations.
- **MPL-2.0 — not currently allowed** because nothing in the tree uses it
  (cargo-deny warns on unused allowances, and the allowlist is kept exact).
  Policy if a dependency introduces it: MPL-2.0 is file-level copyleft —
  obligations attach to the MPL-licensed files themselves, not the combined
  work — so an *unmodified* MPL crate is acceptable in a proprietary binary;
  add it to the allowlist with a comment naming the crate.
- **GPL family (GPL/LGPL/AGPL) — NOT allowed for dependencies.** The
  workspace's own crates carry `license = "AGPL-3.0-or-later"` in
  `Cargo.toml`; they are permitted via per-crate `exceptions` entries in
  `deny.toml` so that AGPL can never silently enter through a third-party
  crate. (Note: the eventual outbound licensing of the product is a business
  decision outside this gate's scope; the gate's job is that no *third-party*
  copyleft obligations attach to the shipped binaries.)

Adding a new license to the allowlist requires: identifying which crate needs
it, confirming the license text's obligations are compatible with proprietary
distribution, and recording the rationale here in the same commit.

## Security dependency updates (2026-09-06)

The home-hub branch removes all 20 historical advisory exceptions. The gate
passes with an empty `[advisories].ignore` list. Resolved versions:

| Dependency | Version | Relevant remediation |
|---|---|---|
| Wasmtime | 36.0.14 | Maintained LTS patches, including RUSTSEC-2026-0269; the audit host now uses a bounded scoped request channel for the updated owned Store API |
| hickory-proto | 0.26.2 | DNS encoding fix and removal of the affected DNSSEC handle from this crate |
| quick-xml | 0.41.0 | Bounded namespace declarations and linear duplicate-attribute checks |
| chacha20 | 0.10.2 | Replaces yanked 0.10.1 pulled by the new DNS dependency |

Upstream sources:
[Wasmtime advisory](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-vqjp-4c8c-hfgg),
[Hickory NSEC3](https://rustsec.org/advisories/RUSTSEC-2026-0118.html),
[Hickory encoder](https://rustsec.org/advisories/RUSTSEC-2026-0119.html),
[XML attributes](https://rustsec.org/advisories/RUSTSEC-2026-0194.html),
[XML namespaces](https://rustsec.org/advisories/RUSTSEC-2026-0195.html).

The new local audit returned `advisories ok, bans ok, licenses ok, sources ok`.
This is a dependency gate, not proof of absence of application vulnerabilities.
Fresh native runtime and browser evidence belongs in
[home-hub verification](../owner/home-hub-verification.md).

Also pending (warnings, not errors):

- **Wildcard path dependencies:** `[bans].wildcards` is `"warn"` instead of
  `"deny"` because workspace crates use versionless path dependencies and do
  not declare `publish = false` (`allow-wildcard-paths` only exempts
  unpublished crates). Once every workspace crate sets `publish = false`,
  flip `wildcards` back to `"deny"`.
- **Duplicate versions:** 28 crates resolve at 2–3 versions (transitive
  skew: `getrandom`, `hashbrown`, `syn`, `windows-sys`, `thiserror`, crypto
  stack, etc.). Warn-only; reduce opportunistically with `cargo update`.

## Provenance

- `[sources]` in `deny.toml` denies unknown registries and all git
  dependencies; crates.io is the only allowed source. `Cargo.lock` currently
  contains only `registry+https://github.com/rust-lang/crates.io-index`
  entries (verified 2026-08-24).
- npm dependencies resolve through the default npm registry and are pinned by
  `apps/desktop/package-lock.json`; CI uses `npm ci` so the lockfile is
  authoritative and drift fails the install.

## Reproducible-build status (honest assessment)

In place:

- `Cargo.lock` and `apps/desktop/package-lock.json` are committed; CI builds
  from lockfiles (`npm ci`; cargo uses the lockfile by default).
- `rust-toolchain.toml` pins the `stable` channel with pinned components, and
  CI prints `rustc --version --verbose` so every run records the exact
  resolved compiler (per `docs/build/toolchain.md`).
- Node major version is pinned to 22 in CI, matching the recorded baseline.

NOT yet in place — do not claim reproducibility beyond this:

- **Bit-for-bit reproducibility is unverified.** No two independent builds
  have been compared. Rust binaries embed absolute paths and other host
  details by default; no `--remap-path-prefix`/`trim-paths`, `SOURCE_DATE_EPOCH`,
  or normalized-environment work has been done.
- The `stable` channel pin resolves to *different* compiler versions over
  time; exact-version reproduction requires reading the recorded version from
  the CI log or release evidence and installing that toolchain explicitly.
- Vite/npm build output has not been checked for determinism (hashing,
  timestamps).
- SBOMs are generated per build but are not yet signed, and no attestation
  (SLSA provenance) is produced. Artifact signing is tracked separately as
  RLS7.

## Historical verification evidence (2026-08-24, Windows 11 dev box)

`cargo deny check` (cargo-deny 0.20.2), final output:

```text
advisories ok, bans ok, licenses ok, sources ok
```

Exit code 0; 0 errors, 34 warnings (28 `duplicate` + 6 `wildcard`, both
justified above).

`cargo cyclonedx --format json` (exit 0) wrote one CycloneDX JSON per crate,
e.g.:

```text
crates\lattice-service\lattice-service.cdx.json   (390,918 bytes)
crates\lattice-sensor\lattice-sensor.cdx.json     (230,052 bytes)
crates\lattice-audit-wasm\lattice-audit-wasm.cdx.json (218,210 bytes)
... 14 files total, one per workspace crate
```

`npm sbom --sbom-format cyclonedx --package-lock-only` in `apps/desktop`
(exit 0) produced a 170,481-byte CycloneDX 1.5 document:

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  ...
}
```

The generated `*.cdx.json` files were deleted after verification — SBOMs are
CI artifacts, not repo files.

## Historical local-run caveats (2026-08-24; not the current branch)

- `cargo fmt --all -- --check` currently fails on in-flight files owned by
  concurrent work lanes (`crates/lattice-service/src/home.rs`,
  `crates/lattice-service/tests/home_api.rs`, `crates/lattice-store/src/{lib,audit_log,maintenance_db}.rs`)
  and errors on the incomplete `crates/lattice-doctor` crate (missing
  `src/diagnosis.rs`). These are not formatting-gate defects; they will pass
  once those lanes land formatted code. CI enforces the gate on merge.
