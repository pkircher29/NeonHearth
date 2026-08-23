# M1 evidence

Evidence recorded 2026-08-23 at commit `ef71911a679d714550c3fc06997ca16423b44f7e`, the code commit containing the platform tests. Counts and statuses below are from commands run for this gate; this corrected evidence document is a subsequent fix commit.

| Invariant | Exact command | Observed result |
|---|---|---|
| Install invariant | `cargo test --workspace --locked` | PASS: 34 passed, 0 failed |
| API auth | `cargo test -p lattice-service --test api_contract --locked` | PASS: 7 passed, 0 failed |
| WS resume/tickets | `cargo test -p lattice-service --test websocket_resume --locked` | PASS: 5 passed, 0 failed |
| Platform paths | `cargo test -p lattice-service --test platform_contract --locked` | PASS on Linux host: 3 passed, 0 failed; Windows path contract simulated, Windows runtime not observed |
| Durable daemon install state | `cargo test -p lattice-service --test service_lifecycle --locked` | PASS: 2 passed, 0 failed; restart preserves install ID and first-run timestamp on Linux temp state base |
| Frontend unprivileged scan | `rg -n "(pcap|Npcap|CAP_NET_RAW|CAP_NET_ADMIN|std::process|Command::new|TcpStream|UdpSocket)" apps/desktop/src` | PASS: 0 matches |
| Loopback live smoke | [Linux Bash procedure](#linux-bash-live-smoke) or [Windows PowerShell procedure](#windows-powershell-live-smoke) | PASS: health 200; state without token 401; authorized state 200; `127.0.0.1:58120` LISTEN |

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

## Linux Bash live smoke

Run from the repository root. This requires Bash, `openssl`, `curl`, and `ss` (from iproute2). The token is generated in memory, never printed, and removed from the shell environment by the trap.

```bash
set -Eeuo pipefail
token="$(openssl rand -hex 32)"
service_pid=""
log_file="$(mktemp)"
cleanup() {
  if [[ -n "$service_pid" ]]; then kill -- "-$service_pid" 2>/dev/null || true; wait "$service_pid" 2>/dev/null || true; fi
  rm -f "$log_file"
  unset token service_pid log_file
}
trap cleanup EXIT INT TERM
LATTICE_SERVICE_TOKEN="$token" setsid cargo run -p lattice-service --quiet >"$log_file" 2>&1 &
service_pid=$!
for _ in {1..50}; do curl -fsS http://127.0.0.1:58120/api/v1/health >/dev/null 2>&1 && break; sleep 0.1; done
[[ "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:58120/api/v1/health)" == 200 ]]
[[ "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:58120/api/v1/state)" == 401 ]]
[[ "$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" http://127.0.0.1:58120/api/v1/state)" == 200 ]]
ss -ltnH | awk '$4 ~ /:58120$/ { count++; if ($4 != "127.0.0.1:58120") bad=1 } END { exit(count == 1 && !bad ? 0 : 1) }'
```

## Windows PowerShell live smoke

Run from the repository root in PowerShell. This requires `cargo`, `curl.exe`, and `Get-NetTCPConnection`. The token remains in a process-local variable, is never printed, and is removed in `finally`.

```powershell
$ErrorActionPreference = 'Stop'
$token = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$env:LATTICE_SERVICE_TOKEN = $token
$service = $null
try {
  $service = Start-Process cargo -ArgumentList 'run','-p','lattice-service','--quiet' -PassThru -WindowStyle Hidden
  for ($i = 0; $i -lt 50; $i++) {
    try { curl.exe -fsS http://127.0.0.1:58120/api/v1/health | Out-Null; break } catch { Start-Sleep -Milliseconds 100 }
  }
  if ((curl.exe -sS -o NUL -w '%{http_code}' http://127.0.0.1:58120/api/v1/health) -ne '200') { throw 'health status mismatch' }
  if ((curl.exe -sS -o NUL -w '%{http_code}' http://127.0.0.1:58120/api/v1/state) -ne '401') { throw 'unauthorized state status mismatch' }
  $authHeader = "Authorization: Bearer $token"
  if ((curl.exe -sS -o NUL -w '%{http_code}' -H $authHeader http://127.0.0.1:58120/api/v1/state) -ne '200') { throw 'authorized state status mismatch' }
  $listeners = @(Get-NetTCPConnection -LocalPort 58120 -State Listen -ErrorAction SilentlyContinue)
  if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -ne '127.0.0.1') { throw 'listener is not loopback-only at 127.0.0.1:58120' }
} finally {
  if ($null -ne $service) { taskkill.exe /PID $service.Id /T /F *> $null; $service.WaitForExit() }
  Remove-Item Env:LATTICE_SERVICE_TOKEN -ErrorAction SilentlyContinue
  Remove-Variable token,authHeader,service -ErrorAction SilentlyContinue
}
```
