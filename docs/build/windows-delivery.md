# Windows delivery and upgrades

The recommended beta download is **NeonHearth-Home-Hub-<version>-windows-x64.zip**.
On Windows 11 on ARM use **NeonHearth-Home-Hub-<version>-windows-arm64.zip**: its
launcher and collector are native ARM64 programs, and its broker is the same x64
build, which Windows runs through its built-in x64 emulation (so it needs the
same x64 runtime described below).
Extract the entire ZIP to a new folder, then open `NeonHearth.exe`. It includes
the native launcher, collector, UI, authenticated MQTT broker, license notices,
build information and a file manifest. Running it needs no Python, Node,
administrator rights or Npcap. The broker needs Microsoft's Visual C++ v14
Redistributable (x64). If startup reports a missing DLL (`0xC0000135`), install
or repair the [official x64 runtime](https://aka.ms/vc14/vc_redist.x64.exe), then
open NeonHearth again. Windows may request administrator approval to install
this prerequisite. Existing NeonHearth data is preserved. See
[Microsoft's instructions](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist).
If the error persists, extract the complete ZIP again; avoid individual DLL downloads.

The candidate remains unsigned unless its release explicitly says otherwise.
Hashes detect changed bytes; they are not publisher signatures. Clean-machine
acceptance, signing and a completed soak must be recorded before a general
release claim. Linux acceptance is separate.

## What the launcher checks before it starts anything

`NeonHearth.exe` refuses to start the collector or broker, with a message that
says what to fix, when:

- **It is running as administrator.** The collector and broker would inherit
  administrator rights and the data folder would belong to the elevated account.
  Open it normally. `--allow-elevated` exists only for automated tests (hosted CI
  runners are always elevated).
- **The package folder can be changed by another account.** The root, every
  directory, and every `.exe`/`.dll` must be writable only by you, SYSTEM,
  Administrators and TrustedInstaller. Extract into a new folder under your
  profile. Drive roots such as `D:\` often grant "Authenticated Users" modify
  rights and will be refused. `--allow-shared-package` overrides this knowingly.
- **A file is present that the manifest does not list** (for example a DLL
  dropped next to `mosquitto.exe`), or a listed file's size or SHA-256 differs.
- **The launcher is Authenticode-signed but the collector is not signed by the
  same publisher.** The collector receives the owner credential. An unsigned
  development launcher skips this check, so it is not a security boundary for
  unsigned builds. The third-party broker is covered by its pinned hash only.
- **The data folder is inside a known cloud-sync folder** (OneDrive, Dropbox,
  Google Drive, iCloud, Box, Nextcloud, pCloud, MEGA): this is a warning
  (stderr and the `warnings` field of the JSON status), not a refusal, because
  the folder holds the device history and plain-text MQTT passwords.

The launcher also removes the current directory from its DLL search path,
restricts later dynamic loads to System32, and is linked with
`/DEPENDENTLOADFLAG:0x800` so its own imports resolve only from System32.

The manifest is an integrity record shipped inside the package, not a trust
anchor: someone who can rewrite the package can rewrite the manifest. The
permission check and the signature check are what limit that.

## Threat model for the owner credential

The owner credential is 48 random bytes (96 hex characters) from the OS
generator. It is stored as `owner.dpapi`, sealed with Windows DPAPI in the
current user's scope plus fixed application entropy (format 2). Older
credentials sealed without entropy still open and are re-sealed on first use.

What this protects against: other Windows accounts, and a copy of the disk or
the file without the user's Windows credentials. What it does **not** protect
against: any program running as the same Windows user. Such a program can
decrypt the file, read the collector's environment (the credential is handed to
the collector as `LATTICE_SERVICE_TOKEN`), and read the browser command line
while the dashboard is being opened. The entropy only defeats generic
credential stealers that call DPAPI with no entropy; it is deliberately a
constant, because a per-install file beside the blob would not stop the same
account and would make a lost file an unrecoverable credential. The MQTT
passwords in `mqtt\client.json` and `mqtt\accounts.json` are plain text inside
the private (current user, SYSTEM) data folder.

The private data folder is created with an explicit owner and a protected DACL
(current user and SYSTEM only). Reparse points are refused.

## Planned: one-time pairing code (not implemented)

Today the launcher opens the browser at `http://127.0.0.1:<port>/#token=<owner
credential>`. The URL fragment is never sent over the network, but the whole URL
is visible on the browser's command line to same-user programs and administrators,
and may be recorded in browser history or sync even though the page removes the
fragment afterwards. The credential never rotates.

Planned replacement (needs service and UI changes, so it is not done here):

1. The launcher calls an authenticated loopback endpoint on the collector
   (`POST /api/v1/pairing`), which creates a random single-use code with a
   60-second lifetime and returns it.
2. The launcher opens `http://127.0.0.1:<port>/#pair=<code>`.
3. The page exchanges the code once (`POST /api/v1/pairing/exchange`, no bearer
   token) for a short-lived session token kept only in `sessionStorage`, then
   removes the fragment. Used, expired or repeated codes are rejected.
4. The long-lived owner credential then never appears in a URL or on a command
   line, and a `--rotate-credential` command can change it safely.

Follow-up: `crates/lattice-service` (endpoints, expiry, single-use storage, rate
limit) and `apps/desktop` (pairing exchange) must land first; the launcher side
is a small change to `windows_launcher.rs` once they exist. The Start-menu
shortcut of the MSI service package has the same limitation and the same fix.

## Updating a Home Hub

1. Keep the previous package and a database backup.
2. From the old folder run `NeonHearth.exe --stop`; it stops only its verified
   processes and preserves `%LOCALAPPDATA%\NeonHearthHomeHub`.
3. Extract the new ZIP into a new folder and keep every package file together.
4. Open the new `NeonHearth.exe`; it reuses the protected owner credential,
   saved ports and per-user data. Check `--status`, inventory and history.
5. Do not run both versions. If an upgrade fails, stop it, retain its data for
   diagnosis, and restore a compatible pre-upgrade database backup before using
   an older binary. Older binaries may not read a newer database schema.

Deleting an extracted program folder does not delete private data. Stop the hub
before removing its folder; removing private data requires an owner decision.

## Existing MSI/service installations

The MSI and Setup EXE remain service-installation compatibility downloads. They
use `%ProgramData%\NeonHearth`, the `NeonHearth` Windows service and port 58120.
The portable hub uses per-user state and ports 58121/58183. These are different
data stores and launch models, not interchangeable shortcuts.

Keep using the installed service's Start-menu dashboard until you deliberately
plan a switch. Back up its SQLite database using the online backup mechanism,
then stop and disable the installed service through an administrator. Do not
run two collectors or copy a live SQLite database and WAL by hand. There is no
automatic service-to-hub data migration; retain the ProgramData store and backup.
Migration requires separate integrity, record-count and permission checks.

The service installer uses native Windows discovery without Npcap. Its absence
must not leave the service stopped. Uninstall preserves ProgramData state;
upgrades preserve its token. MSI install/upgrade/uninstall acceptance still
needs to be recorded on a clean machine.

## Building the payload locally and in CI

From a clean checkout, build both Rust executables with the pinned toolchain
and lockfile and build the UI with `npm ci` and `npm run build`:

```text
python packaging/windows/prepare-mosquitto.py --output <new-broker-folder>
cargo build --locked --release -p lattice-service -p lattice-launcher
python scripts/package-home-hub.py --target <cargo-target>/release --mosquitto <new-broker-folder> --output <new-package-folder> --version 0.1.0-beta.1
```

For a signed release the same script runs in two halves, so the half that
follows signing needs neither cargo nor `node_modules`: `--emit-notices <new
folder>` (in the unprivileged build job) writes the third-party notices, and
`--notices <folder>` plus `--ui <built dashboard>` (after signing) assembles the
package around the signed programs.

7-Zip extracts the checksum-verified broker installer without executing it.
`--archive` accepts an already downloaded installer but still checks its hash.
Expected source URL, version, digest and selected files live in
`packaging/windows/mosquitto-source.json`. The package builder verifies the
extracted broker hashes and refuses missing inputs or existing outputs/ZIPs.

`BUILD-INFO.json` records the source commit, dirty-tree status and version; the
manifest covers it with the runtime payload. Release CI builds the exact tagged
checkout, validates the candidate and waits for the reusable quality workflow.
A dirty local candidate is labeled as such; it is not a clean tagged release.

## Release pipeline and signing

See the job graph at the top of `.github/workflows/release.yml`. In short:
build jobs (cargo, npm, WiX, pip) have no signing identity and publish unsigned
artifacts with a `SHA256SUMS` list whose hash travels as a job output;
`.github/workflows/sign.yml` is the only job that holds the Azure identity, runs
no build tooling, verifies the artifact against that output, signs only named
files and checks the signatures; the ZIPs, MSI and setup EXE are assembled
after signing so every manifest describes the signed programs. Signing happens
only for `main` and `v*` tags; a candidate from another branch is unsigned and
says so; a tag fails if signing is not configured or the tagged commit is not
on `main`. WiX is installed from SHA-256 pinned NuGet packages
(`.github/actions/install-wix`). Build-provenance attestation is not yet wired
(see the TODO in `release.yml`).
