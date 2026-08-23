# M1 evidence

Evidence recorded 2026-08-23 at commit `237fd311dc1fe1739011d350eb9c53e2da71c997`, plus this documentation correction. Counts and statuses below are from commands run for this gate.

| Invariant | Exact command | Observed result |
|---|---|---|
| Install invariant | `cargo test --workspace --locked` | PASS: 34 passed, 0 failed |
| API auth | `cargo test -p lattice-service --test api_contract --locked` | PASS: 7 passed, 0 failed |
| WS resume/tickets | `cargo test -p lattice-service --test websocket_resume --locked` | PASS: 5 passed, 0 failed |
| Platform paths | `cargo test -p lattice-service --test platform_contract --locked` | PASS: Linux contract 3/3; Windows runtime path observed by temp-base `NeonHearth\\lattice.db` creation |
| Durable daemon install state | `cargo test -p lattice-service --test service_lifecycle --locked` | PASS: 2 passed, 0 failed; restart preserves install ID and first-run timestamp on Linux temp state base |
| Frontend unprivileged scan | `rg -n "(pcap|Npcap|CAP_NET_RAW|CAP_NET_ADMIN|std::process|Command::new|TcpStream|UdpSocket)" apps/desktop/src` | PASS: 0 matches |
| Loopback live smoke | [Linux Bash procedure](#linux-bash-live-smoke) or [Windows PowerShell procedure](#windows-powershell-live-smoke) | Linux observed: health 200; state without token 401; authorized state 200; `127.0.0.1:58120` LISTEN. Windows observed 2026-08-23: native MSVC build, same statuses, exactly one loopback listener, temp-base `NeonHearth\lattice.db`, zero listeners after cleanup. |

## Full M1 gate command set

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +stable-x86_64-pc-windows-msvc build -p lattice-service --locked  # VS Developer PowerShell
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
state_base="$(mktemp -d)"
cleanup() {
  if [[ -n "$service_pid" ]]; then kill -- "-$service_pid" 2>/dev/null || true; wait "$service_pid" 2>/dev/null || true; fi
  rm -f "$log_file"; rm -rf "$state_base"
  unset token service_pid log_file state_base
}
trap cleanup EXIT INT TERM
LATTICE_SERVICE_TOKEN="$token" LATTICE_STATE_BASE="$state_base" setsid cargo run -p lattice-service --quiet >"$log_file" 2>&1 &
service_pid=$!
for _ in {1..50}; do curl -fsS http://127.0.0.1:58120/api/v1/health >/dev/null 2>&1 && break; sleep 0.1; done
[[ "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:58120/api/v1/health)" == 200 ]]
[[ "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:58120/api/v1/state)" == 401 ]]
[[ "$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" http://127.0.0.1:58120/api/v1/state)" == 200 ]]
ss -ltnH | awk '$4 ~ /:58120$/ { count++; if ($4 != "127.0.0.1:58120") bad=1 } END { exit(count == 1 && !bad ? 0 : 1) }'
```

## Windows PowerShell live smoke

Run from the repository root in Windows PowerShell 5.1 in a VS Developer environment. First run `cargo +stable-x86_64-pc-windows-msvc build -p lattice-service --locked`, then run the block. The token remains in process-local variables, is never printed, and is removed in `finally`.

```powershell
$ErrorActionPreference = 'Stop'
$bytes = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
$rng = $null
$token = (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
$stateBase = Join-Path $env:TEMP ("neonhearth-smoke-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stateBase | Out-Null
$env:LATTICE_SERVICE_TOKEN = $token
$env:LATTICE_STATE_BASE = $stateBase
$service = $null
try {
  $service = Start-Process (Join-Path (Get-Location) 'target\debug\lattice-service.exe') -PassThru -WindowStyle Hidden
  for ($i = 0; $i -lt 50; $i++) {
    try {
      $health = Invoke-WebRequest -UseBasicParsing http://127.0.0.1:58120/api/v1/health
      if ([int]$health.StatusCode -eq 200) { break }
    } catch { if ($i -eq 49) { throw } }
    Start-Sleep -Milliseconds 100
  }
  if ([int]$health.StatusCode -ne 200) { throw 'health status mismatch' }
  try { Invoke-WebRequest -UseBasicParsing http://127.0.0.1:58120/api/v1/state | Out-Null; throw 'unauthorized state unexpectedly succeeded' }
  catch [Net.WebException] { if ([int]$_.Exception.Response.StatusCode -ne 401) { throw 'unauthorized state status mismatch' } }
  $authHeader = @{ Authorization = "Bearer $token" }
  $authorized = Invoke-WebRequest -UseBasicParsing -Headers $authHeader http://127.0.0.1:58120/api/v1/state
  if ([int]$authorized.StatusCode -ne 200) { throw 'authorized state status mismatch' }
  $listeners = @(Get-NetTCPConnection -LocalPort 58120 -State Listen -ErrorAction SilentlyContinue)
  if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -ne '127.0.0.1') { throw 'listener is not loopback-only at 127.0.0.1:58120' }
  if (-not (Test-Path -LiteralPath (Join-Path $stateBase 'NeonHearth\lattice.db') -PathType Leaf)) { throw 'service database was not created under the temp state base' }
} finally {
  if ($null -ne $service) { taskkill.exe /PID $service.Id /T /F *> $null; $service.WaitForExit() }
  $remaining = @(Get-NetTCPConnection -LocalPort 58120 -State Listen -ErrorAction SilentlyContinue)
  if ($remaining.Count -ne 0) { throw 'listener remained after service cleanup' }
  Remove-Item Env:LATTICE_SERVICE_TOKEN -ErrorAction SilentlyContinue
  Remove-Item Env:LATTICE_STATE_BASE -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $stateBase -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Variable token,bytes,rng,authHeader,service,stateBase,remaining -ErrorAction SilentlyContinue
}
```
