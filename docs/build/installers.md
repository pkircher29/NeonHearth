# Installer and packaging scaffolding (Stage 7: RLS4 / RLS5)

Status date: 2026-08-25. This document separates, per the project honesty
rule, what is **verified** (and where: build machine vs CI) from what is
**authored but unverified**. RLS4 and RLS5 remain UNCHECKED: installer
artifacts now build and are payload-validated in CI, but no real
install/uninstall has happened on any machine, clean or otherwise.

## What exists

```
packaging/
  stage.ps1                       Windows staging: release service build + UI build -> dist/windows/
  stage.sh                        Linux staging (same layout) -> dist/linux/
  windows/
    NeonHearth.wxs                WiX installer definition (MSI, x64, perMachine) - requires WiX v5
    Bundle.wxs                    Burn bundle: NeonHearth-Setup-<ver>-x64.exe chaining the MSI
    scripts/configure-service.ps1 Post-install: token, ACL, Npcap detect/limited mode, recovery
  linux/
    neonhearth.service            Hardened systemd unit
    neonhearth.sysusers.conf      sysusers.d fragment (dedicated `neonhearth` user)
    full-capture.conf.example     Drop-in raising AmbientCapabilities for future capture mode
    nfpm.yaml                     nfpm config producing .deb and .rpm (version from NEONHEARTH_VERSION)
    scripts/{postinstall,preremove,postremove}.sh
  dist/                           Staging output (generated; not committed)
.github/workflows/release.yml     Tagged-release pipeline (v* tags) building MSI + exe + deb + rpm
                                  and publishing a GitHub pre-release with SHA256SUMS
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
  `ServiceInstall` / systemd own registration. It DOES have a built-in SCM
  entry point: `lattice-service.exe --service` connects the Windows service
  dispatcher (`win_service.rs`); without the flag it is a plain console app.
  `ServiceInstall` passes `Arguments="--service"` accordingly.
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

## Verified on this machine (2026-08-25): real service start under the SCM

The first real MSI installs on this (non-clean) machine surfaced two start
blockers, both now fixed and re-verified against a live service:

1. **The binary never spoke the SCM protocol.** `Start-Service NeonHearth`
   timed out with System events 7009 ("timeout waiting for the service to
   connect") + 7000: the exe was a plain console app with no
   `StartServiceCtrlDispatcher`. Fix: `--service` flag →
   `win_service.rs` dispatcher (StartPending → Running-after-bind →
   StopPending → Stopped, Stop/Shutdown accepted, startup errors reported
   as Stopped/1066 instead of hanging), and
   `ServiceInstall Arguments="--service"` in `NeonHearth.wxs`.
2. **The generated token used the wrong alphabet.** `configure-service.ps1`
   wrote standard base64 (`+`, `/`), but `AppState::new` (state.rs) only
   accepts `[A-Za-z0-9._-]` tokens ≥ 32 chars, so the service rejected its
   own installer-generated token ("invalid service token configuration",
   observed in `service.log`). Fix: URL-safe alphabet (`+`→`-`, `/`→`_`).

Proof (throwaway `NeonHearthTest` service registered with `sc.exe create
... binPath= '"<release exe>" --service' obj= LocalSystem`, token +
`LATTICE_STATE_BASE` in the service-private `Environment` registry value,
fully deleted afterwards): start reached RUNNING in **0.28 s**,
`GET /api/v1/health` → 200, `sc.exe stop` showed STOP_PENDING and reached
STOPPED with exit code 0 in **0.02 s**, `sc.exe delete` clean. Service-mode
tracing goes to `<state dir>\service.log` (the SCM gives the process no
console); the console dev flow is unchanged and was re-smoked (health 200,
state dir layout intact). A clean-machine MSI acceptance run (RLS4) is
still outstanding.

## Verified in CI (2026-08-25, tagged-release pipeline)

The `v0.1.0-alpha.1` tag ran `.github/workflows/release.yml` to green
(after one iteration; see the WIX8601 note below) and published a
pre-release at https://github.com/pkircher29/NeonHearth/releases/tag/v0.1.0-alpha.1
with `NeonHearth-0.1.0-alpha.1-x64.msi`, `neonhearth_0.1.0~alpha.1_amd64.deb`,
`neonhearth-0.1.0~alpha.1-1.x86_64.rpm`, and `SHA256SUMS`.

1. **`wix build` (WiX 5.0.2) builds the MSI**, locally and on
   windows-latest. Two findings from actually running it:
   - The `<Files>` wildcard-harvesting element **does not exist in WiX
     4.x** (4.0.6 fails with WIX0005); WiX v5 is required and the pipeline
     pins 5.0.2.
   - The `-bindpath` **must be absolute**: `<Files>` resolves a relative
     bindpath against the `.wxs` file's own directory and a miss is only a
     warning (WIX8601), which shipped an MSI with an empty `ui\` tree on
     the first tag run. The workflow now passes an absolute bindpath and
     `-wx` (warnings-as-errors), and validates the payload by
     `msiexec /a` administrative extract (exe, configure script, UI
     bundle asserted present).
2. **The Burn bundle (`Bundle.wxs`) builds** with
   `WixToolset.BootstrapperApplications.wixext/5.0.2`, producing
   `NeonHearth-Setup-<ver>-x64.exe` (WixStdBA hyperlinkLicense theme, no
   license step). Validated without installing via `wix burn extract`: the
   embedded payload is byte-identical (SHA-256) to the input MSI. Note
   `/layout` is not a meaningful check for this bundle (compressed bundle
   layout just copies the exe), and `wix burn extract` silently no-ops
   with WIX8503 unless its output/intermediate folders already exist.
3. **`stage.sh` executed end-to-end on ubuntu-latest** (its first real
   execution) with no fixes needed beyond marking it executable in the git
   index (it was committed 100644).
4. **nfpm 2.47.0 produced the .deb and .rpm**, first exercised locally
   (Windows nfpm binary against a dummy staged tree) and then in CI
   against the real one. Payload paths verified by `dpkg-deb --contents`
   and `rpm2cpio | cpio -t` (binary, unit, sysusers fragment, UI tree).
   `version: ${NEONHEARTH_VERSION}` env expansion works; nfpm's semver
   schema turns `0.1.0-alpha.1` into deb `0.1.0~alpha.1` and rpm
   `0.1.0~alpha.1-1` as expected. Build inputs (Npcap SDK 1.13 zip, nfpm
   deb) are downloaded pinned with SHA-256 verification.
5. On hosted Windows runners (no Npcap installed) the workspace links
   against the **Npcap SDK 1.13 import libraries** (`RUSTFLAGS=-L
   <sdk>\Lib\x64`); `stage.ps1` now respects a caller-supplied
   `RUSTFLAGS` and only prepends the dev machine's msys64 path when it
   exists. Only `Packet.lib` (SDK) and `iphlpapi` (Windows SDK) are
   needed (`pnet_datalink` link attributes).

## Authored but NOT verified anywhere

- **No MSI, setup exe, deb, or rpm has been installed/uninstalled on any
  machine**, so service registration, recovery settings, limited mode,
  token generation, and clean uninstall (service removed, files removed,
  `%ProgramData%\NeonHearth` left with `README-UNINSTALL.txt`) are still
  design intent, not evidence. The `util:ServiceConfig` element, the
  `NT SERVICE\NeonHearth` virtual-account `ServiceInstall`, and the
  deferred `WixQuietExec64` custom action compile, but only a real install
  exercises them.
- **The systemd unit has never started the service.** The hardening set
  (`ProtectSystem=strict`, `MemoryDenyWriteExecute`, `SystemCallFilter`,
  `RestrictAddressFamilies` etc.) is reasoned from source, not proven under
  systemd; keyring/secret-service interaction on Linux is a known
  possible friction point to test. CI packages the unit but never runs it.
- **Nothing is signed** (RLS7): SmartScreen will flag the exe/MSI and the
  deb/rpm carry no repository signatures; releases are therefore marked
  pre-release with that warning in the notes.
- MSI `UpgradeCode`/component GUIDs and the bundle `UpgradeCode` are now
  published in a (pre-)release and must be treated as contractual.

## Build commands (per platform)

The release workflow (`.github/workflows/release.yml`, on `v*` tags) runs
all of the below; tag base version must equal the Cargo workspace version.

Windows (this repo, elevated not required for staging; WiX v5 CLI via
`dotnet tool install --global wix --version 5.0.2`):

```powershell
pwsh -File packaging\stage.ps1              # build + stage into packaging\dist\windows
wix extension add -g WixToolset.Util.wixext/5.0.2
wix extension add -g WixToolset.BootstrapperApplications.wixext/5.0.2
# bindpaths MUST be absolute (see WIX8601 note above); -wx enforces it
wix build packaging\windows\NeonHearth.wxs `
    -ext WixToolset.Util.wixext `
    -bindpath dist=$PWD\packaging\dist\windows `
    -arch x64 -d MsiVersion=0.1.0 -wx `
    -o NeonHearth-0.1.0-x64.msi
wix build packaging\windows\Bundle.wxs `
    -ext WixToolset.BootstrapperApplications.wixext `
    -bindpath msi=$PWD `
    -arch x64 -d MsiVersion=0.1.0 -d FullVersion=0.1.0 -wx `
    -o NeonHearth-Setup-0.1.0-x64.exe
```

Linux (from a systemd distro or WSL2 with the pinned toolchain):

```bash
packaging/stage.sh                          # build + stage into packaging/dist/linux
cd packaging/linux
export NEONHEARTH_VERSION=0.1.0             # tag version without the leading v
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

1. Install/upgrade/uninstall the MSI (and the setup exe wrapping it) on a
   **clean Windows 11 x64 machine**, both with and without Npcap, and
   record: service running under `NT SERVICE\NeonHearth`, recovery settings
   present, loopback-only bind, limited-mode notice without Npcap, state
   dir surviving uninstall.
2. Install the `.deb` and `.rpm` on clean machines; verify unit hardening
   doesn't break the service (`systemd-analyze security neonhearth`),
   token generation, and state survival on package removal.
3. Signing (RLS7) and SBOM/provenance (RLS6) are separate items and untouched here.

Honest status lines for the evidence ledger:

- RLS4: **not complete** — the MSI and setup-exe bundle now build and are
  payload-validated in CI on every `v*` tag (administrative extract /
  burn extract; published as pre-release assets with SHA-256s), but they
  are unsigned and no install of either has occurred on any machine.
- RLS5: **not complete** — deb and rpm now build in CI from the first real
  `stage.sh` + nfpm execution with payload listings verified, but neither
  package has been installed on any Linux machine and the systemd unit has
  never run the service.
