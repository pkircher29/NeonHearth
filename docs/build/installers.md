# Installer and packaging scaffolding (Stage 7: RLS4 / RLS5)

Status date: 2026-08-24. This document separates, per the project honesty
rule, what was **verified on the build machine** (Windows 11 Pro, the machine
that produced this scaffolding) from what is **authored but unverified**.
RLS4 and RLS5 remain UNCHECKED: nothing here is a substitute for building the
actual installer artifacts and clean-machine acceptance.

## What exists

```
packaging/
  stage.ps1                       Windows staging: release service build + UI build -> dist/windows/
  stage.sh                        Linux staging (same layout) -> dist/linux/   [authored, not executed]
  windows/
    NeonHearth.wxs                WiX v4 installer definition (MSI, x64, perMachine)
    scripts/configure-service.ps1 Post-install: token, ACL, Npcap detect/limited mode, recovery
  linux/
    neonhearth.service            Hardened systemd unit
    neonhearth.sysusers.conf      sysusers.d fragment (dedicated `neonhearth` user)
    full-capture.conf.example     Drop-in raising AmbientCapabilities for future capture mode
    nfpm.yaml                     nfpm config producing .deb and .rpm
    scripts/{postinstall,preremove,postremove}.sh
  dist/                           Staging output (generated; not committed)
```

## Ground truth the packaging is built on (verified by reading source and by running the binary)

- `lattice-service` binds **127.0.0.1:58120 only** (`crates/lattice-service/src/main.rs`)
  and requires `LATTICE_SERVICE_TOKEN` (>= 32 chars) at start; state base is
  `%ProgramData%` on Windows / `/var/lib` on Linux with a `NeonHearth` /
  `neonhearth` subdirectory (`platform.rs`).
- **No firewall rule is authored anywhere.** The listener is loopback-only,
  and Windows Firewall does not filter loopback traffic; an inbound rule
  would be dishonest surface. If a LAN/Tailscale listener is ever added,
  firewall authoring must be revisited then.
- The service has **no built-in service-install mechanism**; MSI
  `ServiceInstall` / systemd own registration.
- The service serves the **loopback API only** — it does not serve the UI
  bundle over HTTP in this build (no static file routes exist in
  `lattice-service`). The Vite bundle from `apps/desktop` is installed as
  data (`ui\` / `/usr/share/neonhearth/ui`) so the future desktop shell has
  its assets; opening `ui/index.html` directly does not constitute a working
  app because API calls need the bearer token (dev uses the Vite proxy in
  `apps/desktop/vite.proxy-auth.ts`).
- **Npcap on Windows is a load-time dependency, not a graceful runtime one.**
  Verified empirically: `objdump -p` on the built `lattice-service.exe`
  lists `packet.dll` in the import table (via `pnet_datalink`). Without
  Npcap the process cannot load, so the code's in-process `Degraded` mode
  (`runtime.rs`, which handles interface-snapshot failure *after* load)
  cannot be reached. The installer's limited mode is therefore: install
  completes, service stays registered but **Manual and stopped**, and
  `%ProgramData%\NeonHearth\NPCAP-REQUIRED.txt` explains recovery
  (install Npcap, re-run `configure-service.ps1 -Start`).
- Linux discovery in this build reads the kernel neighbor table via
  rtnetlink (`RTM_GETNEIGH`, an unprivileged read) and enumerates interfaces
  via `pnet_datalink`; it opens no raw sockets, and `lattice-service` does
  not link the Wasmtime audit crate. Hence the unit grants **no ambient
  capabilities** by default; `CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN`
  is retained only as the documented ceiling for future full-capture mode,
  enabled via the shipped drop-in example (AmbientCapabilities on the unit,
  deliberately not `setcap` on the binary).

## Verified on this machine (2026-08-24)

1. **`packaging\stage.ps1` ran end-to-end, exit 0.**
   - `cargo build --release -p lattice-service`: `Finished 'release' profile [optimized] target(s) in 2m 46s`
     (windows-gnu toolchain, `PATH` prefixed with `C:\msys64\mingw64\bin`,
     `RUSTFLAGS=-L C:\Windows\System32\Npcap` — both set by the script).
   - `vite v8.2.2 ... built in 1.53s`.
   - `Staged 7 files into ...\packaging\dist\windows` with SHA-256 manifest:
     `bin\lattice-service.exe` (30,495,280 bytes), `scripts\configure-service.ps1`,
     `ui\index.html` + 3 hashed assets, `STAGING-MANIFEST.txt`.
2. **Smoke run of the staged binary** (temp `LATTICE_STATE_BASE`, throwaway token):
   - `GET http://127.0.0.1:58120/api/v1/health` -> `{"status":"ok","api_version":"v1"}`.
   - `Get-NetTCPConnection -LocalPort 58120` -> `127.0.0.1  58120  Listen` (loopback only).
   - `GET /api/v1/state` without token -> HTTP 401.
   - State dir created as `<base>\NeonHearth\{lattice.db, backups\}` as platform.rs promises.
3. **Import-table check**: `objdump -p lattice-service.exe` shows `packet.dll`
   as a load-time import (the basis of the limited-mode design above).
4. **Syntax-level validation of authored definitions**:
   - `NeonHearth.wxs`: well-formed XML (loaded with .NET `XmlDocument`).
   - `nfpm.yaml`: parsed by PyYAML (5 contents entries, 3 scripts).
   - `stage.sh`: `bash -n` clean; the three Linux package scripts: `sh -n` clean.
   - `stage.ps1`, `configure-service.ps1`: PowerShell language parser reports zero errors.

## Authored but NOT verified on this machine

- **`wix build` was not run.** No WiX/Inno/NSIS toolchain exists here
  (`where wix|iscc|makensis` all empty), and the fallback failed:
  `dotnet.exe` exists but has **no .NET SDK**, so
  `dotnet tool install --global wix` fails with "No .NET SDKs were found".
  Consequences: the `.wxs` is validated as XML only — WiX v4 schema
  correctness, the `Files Include` wildcard harvesting, the
  `util:ServiceConfig` recovery element, the `NT SERVICE\NeonHearth`
  virtual-account `ServiceInstall`, and the deferred
  `WixQuietExec64` custom action are all unproven until `wix build`
  and a real install run.
- **No MSI has been installed/uninstalled anywhere**, so service
  registration, recovery settings, limited mode, and clean uninstall
  (service removed, files removed, `%ProgramData%\NeonHearth` left with
  `README-UNINSTALL.txt`) are design intent, not evidence.
- **nfpm was not run** (no `nfpm` binary here; downloading one was out of
  scope), so no `.deb`/`.rpm` exists and the contents mapping is untested.
- **`stage.sh` has not been executed** (authored on Windows; syntax-checked only).
- **The systemd unit has never started the service.** The hardening set
  (`ProtectSystem=strict`, `MemoryDenyWriteExecute`, `SystemCallFilter`,
  `RestrictAddressFamilies` etc.) is reasoned from source, not proven under
  systemd; keyring/secret-service interaction on Linux is a known
  possible friction point to test.
- MSI `UpgradeCode`/component GUIDs are freshly generated and become
  contractual only once a first real release ships.

## Build commands (per platform)

Windows (this repo, elevated not required for staging):

```powershell
pwsh -File packaging\stage.ps1              # build + stage into packaging\dist\windows
# Requires WiX v4 CLI (needs a .NET SDK: dotnet tool install --global wix):
wix extension add -g WixToolset.Util.wixext
wix build packaging\windows\NeonHearth.wxs `
    -ext WixToolset.Util.wixext `
    -bindpath dist=packaging\dist\windows `
    -arch x64 `
    -o packaging\dist\NeonHearth-0.1.0-x64.msi
```

Linux (from a systemd distro or WSL2 with the pinned toolchain):

```bash
packaging/stage.sh                          # build + stage into packaging/dist/linux
cd packaging/linux
nfpm package --config nfpm.yaml --packager deb --target ../dist/
nfpm package --config nfpm.yaml --packager rpm --target ../dist/
```

## Install model summary

Windows: MSI installs `lattice-service.exe`, `ui\`, and `scripts\` under
`Program Files\NeonHearth`, registers the `NeonHearth` service under the
dedicated virtual account `NT SERVICE\NeonHearth` with restart-on-failure
recovery (5s/5s/30s, 24h reset — both via `util:ServiceConfig` and mirrored
with `sc.exe failure` in the configure script), then runs
`configure-service.ps1` which generates the pairing token into the
service-private `Environment` registry value, grants the state-dir ACL,
detects Npcap (adding a service-local `PATH` entry when Npcap lacks
WinPcap-compat DLLs in System32), and starts the service — or engages
limited mode when Npcap is absent. Uninstall stops/deletes the service and
removes program files; the state directory survives with a note.

Linux: deb/rpm install the binary to `/usr/libexec/neonhearth/`, the
hardened unit, the sysusers fragment, and UI assets;
`postinstall.sh` creates the user, generates
`/etc/neonhearth/service.env` (root:neonhearth 0640) on first install,
and enables/starts the unit. `StateDirectory=neonhearth` owns
`/var/lib/neonhearth`; package removal never deletes it (note file written
at install).

## What remains before RLS4 / RLS5 can be checked

1. Run `wix build` on a machine with a .NET SDK; fix schema errors; produce the MSI.
2. Install/upgrade/uninstall the MSI on a **clean Windows 11 x64 machine**,
   both with and without Npcap, and record: service running under
   `NT SERVICE\NeonHearth`, recovery settings present, loopback-only bind,
   limited-mode notice without Npcap, state dir surviving uninstall.
3. Run `stage.sh` + `nfpm` on Linux; install the `.deb` and `.rpm` on clean
   machines; verify unit hardening doesn't break the service
   (`systemd-analyze security neonhearth`), token generation, and
   state survival on package removal.
4. Signing (RLS7) and SBOM/provenance (RLS6) are separate items and untouched here.

Honest status lines for the evidence ledger:

- RLS4: **not complete** — Windows installer definition + staged inputs exist
  and the staged binary was smoke-verified locally; no MSI has been built
  (no WiX toolchain/.NET SDK on the build machine) and no clean-machine
  install has occurred.
- RLS5: **not complete** — systemd unit, sysusers fragment, scripts, and
  nfpm config authored with capabilities matched to actual code behavior;
  nothing has been packaged or installed on any Linux machine.
