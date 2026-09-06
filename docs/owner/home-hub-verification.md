# Home hub verification — 2026-09-06

## Continued source validation

The `codex/network-home-hub` branch now includes upstream `faf7455`, preserving
its authentication, history, settings, editor persistence, and security fixes.
It adds numeric IP sorting, metric/imperial editing, independent footprint
copies, bounded device scans, mDNS/Bonjour, ICMP, SMB, NetBIOS, credentialed
SNMP, Linux Avahi integration, and CDP/LLDP PCAP import. A native Windows
launcher and portable package builder replace the development-only startup path.

Current local checks: **914 Rust tests passed, one opt-in MQTT test ignored**;
**266 desktop tests and seven Playwright tests passed**; Svelte checking and
the production web build passed. Rust dependency advisories, licenses, bans,
and sources passed without advisory exceptions. Workspace Clippy passed with
warnings denied. The new Windows backup/restore regression from upstream was
observed failing with an access error and passed after correcting the file
handle's flush access. Existing SQL migration bytes were preserved.

Current logs use the `artifacts/final-*` prefix. The native package and current
live discovery acceptance are recorded separately from the earlier evidence
below. CI and merge status belong to the linked GitHub pull request.

## Earlier development-runtime acceptance

The remaining measurements document the earlier development executable, before
the continued changes above. Its dependency and startup limitations are historical.

This is a working local Windows development release in
`C:\Users\Paul\GITHUB\neonhearth-home-hub`, based on NeonHearth `a7f8883`,
on the isolated branch `codex/network-home-hub`. Open `Start-NeonHearth.cmd`.
At that earlier acceptance, source changes were local and no production deployment was made.

The optimized service executable is
`artifacts/NeonHearth-home-hub-release/lattice-service.exe` (33,757,185 bytes).
Its SHA-256 is:

```text
ec29872d6d4652f51acb3c80d3ac8602d5918f90dd4ac6e574b1a69b939d914a
```

## Verified behavior

| Check | Evidence and scope |
|---|---|
| Actual Windows network discovery | 73 persisted devices; 73 had observed MAC and current neighbor-cache IP addresses. Collector ready. Counts describe what this host observed, not a complete network census. |
| Browser pairing and access control | Native service returned 401 without authentication and 403 for a foreign browser origin. Pairing removed the token fragment from the browser URL. |
| Home Assistant integration | Three clearly labeled simulated devices imported through a real local WebSocket connection. Token input cleared after connection. Permission, cancel, confirm, observed power state, and disconnect/replay protections verified by browser and Rust tests. No household appliance was switched. |
| Home map | Three rooms and three device placements saved, survived reload, and rendered in the native app's 3D canvas. Existing editor workflows also passed. |
| Desktop and mobile UI | Chrome checked at 1500-pixel desktop and 390-pixel mobile widths. No page exceptions and no horizontal mobile overflow. Screenshots inspected. |
| Real MQTT broker | Mosquitto 2.1.2 running locally with authentication and topic ACLs. Anonymous connections and prohibited topic writes rejected. Service inventory publishing verified. |
| Combined runtime | Both native service instances stayed ready for 12 samples at five-second intervals during the browser/control/map workflow. Observation timestamps advanced in both. |
| Competing database writes | A disposable database copy completed three full discovery/policy passes while HA inventory writes competed. Every pass committed and ended ready; about 20 seconds per pass while multiple native instances and checks shared this host. |
| Integration contract | All six automation routes documented by the authenticated OpenAPI document. Local-owner checks include the new address/identity endpoint. Scoped integration credentials do not inherit power permissions. |
| Listener scope | Service, broker, and QA fixture listeners verified on literal `127.0.0.1`; no public or LAN listener configured. |

The user's instance contains no simulated Home Assistant devices or demonstration
floorplan. Its private data is under `.local/runtime/`; QA state, controls, home
layout, and broker credentials use separate directories and ports.

At handoff (14:21 UTC), the visible Chrome dashboard and the same tested
executable were still running. Discovery had advanced to 74 observed devices,
the collector was ready, and MQTT was connected. The three QA listeners were
closed. `handoff.json` records this final check without credentials.

## Automated checks

| Check | Result |
|---|---|
| Full Rust workspace after dependency upgrades | 843 passed, zero failures; one opt-in broker test ignored by default. |
| Final store and service suites after address and concurrency fixes | 373 passed, zero failures; the same opt-in broker test ignored. This is focused final coverage, not a claim that the entire workspace suite ran again afterward. |
| Opt-in test against actual Mosquitto | One passed, including authentication, ACLs, bridge output, and credential exclusion. |
| Desktop tests | 196 passed across 19 files. |
| Existing browser/editor workflows | Seven passed. Legacy fixtures log requests for optional new automation routes they do not mock; native acceptance supplies and verifies those routes. |
| Desktop checking and production build | Passed; zero Svelte errors or warnings. |
| Rust formatting and Clippy | Workspace checks passed; Clippy uses `-D warnings`. |
| Rust dependency policy | Advisories, licenses, bans, and sources passed, with zero advisory exceptions. Duplicate dependency/path-policy warnings remain visible in the log. |
| npm audit and provenance | Zero reported vulnerabilities; 146 registry signatures and 64 attestations verified. |
| Git whitespace validation | Passed. |

Logs are under `artifacts/`. Machine-readable results and screenshots are under
`artifacts/home-hub-verification/`, particularly `checks.json`, `result.json`,
`live-result.json`, `stability.json`, and `release-binary.json`.

Both contention regressions were observed failing before their fixes. Discovery
checkpoint commits and the affected policy transactions now reserve the SQLite
writer before reading. Durable sequence checks, checksums, atomic publication
ordering, and the existing database journaling/durability settings remain in
place. This resolves immediate read-to-write lock-upgrade failures; it does not
remove finite timeouts or promise operation under arbitrary disk contention.

## Security and compatibility limits

No software can be guaranteed 100% secure. This build has local-only defaults,
owner authentication, browser-origin checks, bounded upstream input, restrictive
browser headers, TLS validation, explicit entity permissions, command auditing,
durable deduplication, and authenticated MQTT topic isolation. The dependency
results are a snapshot of known advisories, not an independent security audit.

The HA token stays in service memory and must be supplied again after restart.
Real HA connectivity, reported rooms and identities, physical power behavior,
radios, Linux runtime, remote phone access, and a clean-machine installer have
not been verified in this run. First observed is not an exact Wi-Fi join time.
An unobserved sleeping device can be absent from the inventory.

HA supplies access to its configured protocols and hardware. This build does
not implement every radio or vendor protocol, arbitrary appliance power control,
Wake-on-LAN, PoE control, or an incoming MQTT power-command bridge. LAN MQTT
requires an explicitly configured TLS listener and client credentials.

This Windows executable is unsigned and uses this machine's Python, Npcap,
and built desktop assets. The official Mosquitto installer was downloaded over
HTTPS and extracted without running its installer; its SHA-256 was recorded as
`58008ad7a22ada0b4073afa415801746e027c5f583e4fa52d0f4e9193b98d6aa`.
It did not provide a Windows Authenticode publisher signature. Artifact hashes
record the tested files; they do not replace publisher signature verification.

Before a customer release, validate the intended physical devices, test Linux
and clean Windows installations, provide signed packaging, complete longer
operation and recovery testing, and obtain independent security review.
See [the setup and integration guide](home-automation.md).
