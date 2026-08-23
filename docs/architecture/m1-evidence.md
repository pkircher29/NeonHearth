# M1 evidence

Evidence recorded 2026-08-23 at commit `ef71911a679d714550c3fc06997ca16423b44f7e`, the code commit containing the platform tests. Counts and statuses below are from commands run for this gate; this corrected evidence document is a subsequent fix commit.

| Invariant | Exact command | Observed result |
|---|---|---|
| Install invariant | `cargo test --workspace --locked` | PASS: 33 passed, 0 failed |
| API auth | `cargo test -p lattice-service --test api_contract --locked` | PASS: 7 passed, 0 failed |
| WS resume/tickets | `cargo test -p lattice-service --test websocket_resume --locked` | PASS: 5 passed, 0 failed |
| Platform paths | `cargo test -p lattice-service --test platform_contract --locked` | PASS: 3 passed, 0 failed |
| Frontend unprivileged scan | `rg -n "(pcap|Npcap|CAP_NET_RAW|CAP_NET_ADMIN|std::process|Command::new|TcpStream|UdpSocket)" apps/desktop/src` | PASS: 0 matches |
| Loopback live smoke | `ss -ltnp` plus valid-token health/state requests against `127.0.0.1` | PASS: health 200; state without token 401; authorized state 200; `127.0.0.1:58120` LISTEN |

## Full M1 gate command set

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
npm --prefix apps/desktop run check
npm --prefix apps/desktop run test -- --run
npm --prefix apps/desktop run build
```

The live smoke used an ephemeral in-memory test token supplied only to the local test process. The evidence table is updated with the observed date, commit, counts, and status from the same run.
