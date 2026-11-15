# Build toolchain

Baseline recorded on 2026-08-23 in WSL2 before the first implementation task:

| Tool | Version |
|---|---|
| Cargo | 1.95.0 |
| rustc | 1.95.0 stable |
| Node.js | 22.23.0 |
| npm | 10.9.8 |
| Git | 2.34.1 |

Pin update on 2026-09-03 (audit remediation): `rust-toolchain.toml` now pins
the exact release `1.96.0` instead of the floating `stable` channel. The
floating pin had already cost a clippy-drift fix (commit `bf568b1`, "keep
clippy 1.98 green") and made "which compiler built this" answerable only by
reading a CI log. The full local gate (`cargo fmt --check`, `cargo clippy
--workspace --all-targets -D warnings`, `cargo test --workspace`: 837 tests)
was verified green on 1.96.0 the day the pin landed.

| Tool | Pinned version | Where |
|---|---|---|
| rustc / cargo | 1.96.0 | `rust-toolchain.toml`; CI passes the same version to `dtolnay/rust-toolchain` via `with.toolchain` |
| Node.js | 22 (major) | CI `setup-node`; local baseline 22.23.0 |
| cargo-cyclonedx | 0.5.9 | CI `sbom` job (`cargo install --version 0.5.9 --locked`) |

Bumping the toolchain is a deliberate change: edit `rust-toolchain.toml` and
the two `toolchain:` inputs in `.github/workflows/ci.yml` in the same commit,
and run the full gate locally first. CI and release evidence must still record
the resolved compiler version (`rustc --version --verbose` is printed in the
`rust` and `sbom` jobs). Windows 11 and a mainstream systemd Linux distribution
are the release targets. WSL2 is the development host, not a substitute for
clean-machine acceptance on either target.
