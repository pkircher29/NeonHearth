# SQLx SQLite compatibility backport

Exact upstream sqlx-sqlite 0.8.6 registry source, SHA-256 `c2d12fe70b2c1b4401038055f90f151b78208de1f9f89a7dbfd41587a10c3eea`.
Source: https://crates.io/crates/sqlx-sqlite/0.8.6
The source and MIT/Apache licenses are preserved. The only driver change is the
libsqlite3-sys dependency pin from 0.30.1 to 0.39.1 in Cargo.toml; Cargo.toml.orig
records upstream's original manifest. No migration files change.

This selects bundled SQLite 3.54.1, fixing RUSTSEC-2026-0459, while preserving
SQLx 0.8's public API. Upstream main now accepts libsqlite3-sys <0.40 but no
released SQLx 0.8/0.9 driver includes that range. Remove this patch when a
compatible upstream release permits the fixed binding and all storage tests pass.
https://rustsec.org/advisories/RUSTSEC-2026-0459.html
https://github.com/transact-rs/sqlx/blob/main/sqlx-sqlite/Cargo.toml

Verification: the store runtime-version regression must select SQLite >=3.54.0;
run full storage, API, migration, backup/restore and workspace tests. cargo-deny
must pass without advisory exceptions.
