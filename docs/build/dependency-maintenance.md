# Security dependency maintenance — 2026-11-14

The shipping review's 18 Rust advisory findings and one yanked crate were
addressed without adding advisory exceptions. Compatible updates select
ctutils 0.4.4, rustls 0.23.46, rustls-webpki 0.103.16, Tokio 1.53.3,
webpki-roots 1.0.10, Wasmtime LTS 36.0.20 and its matching Cranelift packages,
zstd 0.13.4/zstd-safe 7.4.1/zstd-sys 2.1.3, and async-executor 1.14.1.
Review the lockfile, not only direct manifest requirements.

## Fixed SQLite with the existing SQLx API

Released SQLx 0.8.6 pins libsqlite3-sys 0.30.1, bundling SQLite 3.46.0.
The WAL page-size disclosure fix requires SQLite >=3.54.0. To avoid an unrelated
database API migration, `vendor/sqlx-sqlite` is the checksum-verified upstream
0.8.6 crate with one manifest-only dependency change to libsqlite3-sys 0.39.1
(bundled SQLite 3.54.1). Its original manifest, source licenses, upstream
checksum, exact patch and removal condition are retained in that directory.
It is a local compatibility backport, not a claim of an upstream SQLx release.

`crates/lattice-store/tests/sqlite_runtime.rs` failed against actual SQLite
3.46.0 and passed after selecting the fixed engine. Existing migration files
must remain byte-identical. Run the complete store, backup/restore, API and
workspace regressions before accepting this binding change.

Sources: [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0459.html),
[upstream driver range](https://github.com/transact-rs/sqlx/blob/main/sqlx-sqlite/Cargo.toml).

## Build-only JavaScript dependencies

Vite stays on the 8.2 security patch line (`~8.2.6`), Vitest updates to 4.1.12,
and compatible patched devalue, source-map-js and undici versions are locked.
The production-only npm dependency audit was already clean; development
toolchain findings must not be presented as eight installed-app vulnerabilities.

Upstream deepmerge 4.3.1 has no patched npm release for GHSA-gcqx-w48m-w2h4.
`vendor/deepmerge` is an explicitly named private local fork of its verified
official archive, retaining its MIT license and original SRI metadata. The
only logic change defines own destination data properties instead of invoking
the inherited `__proto__` setter. No advisory is ignored or version falsely
represented as a patched upstream release. `PATCH.md` documents provenance and
replacement criteria. The Svelte build plugin uses this development dependency;
it is not application runtime logic.

Two target/null-prototype-source reproduction tests failed against upstream
and pass against the patch; normal nested, symbol and custom-array config
behavior remains tested. npm's registry matching alone cannot establish the
safety of a local fork. Keep these regressions and review the source patch.

## Required checks

```text
cargo deny check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
npm --prefix apps/desktop ci
npm --prefix apps/desktop run test:dependencies
npm --prefix apps/desktop audit
npm --prefix apps/desktop test -- --run
npm --prefix apps/desktop run check
npm --prefix apps/desktop run build
npm --prefix apps/desktop run test:e2e
```

Clean advisory results are a dated snapshot, not a security guarantee. Remove
each local backport when a compatible fixed upstream release is available and
the same regression gates pass.
