# Build toolchain

Baseline recorded on 2026-08-23 in WSL2 before the first implementation task:

| Tool | Version |
|---|---|
| Cargo | 1.95.0 |
| rustc | 1.95.0 stable |
| Node.js | 22.23.0 |
| npm | 10.9.8 |
| Git | 2.34.1 |

The Rust workspace pins the `stable` channel in `rust-toolchain.toml`; CI and release evidence must record the resolved compiler version. Windows 11 and a mainstream systemd Linux distribution are the release targets. WSL2 is the development host, not a substitute for clean-machine acceptance on either target.

