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

7-Zip extracts the checksum-verified broker installer without executing it.
`--archive` accepts an already downloaded installer but still checks its hash.
Expected source URL, version, digest and selected files live in
`packaging/windows/mosquitto-source.json`. The package builder verifies the
extracted broker hashes and refuses missing inputs or existing outputs/ZIPs.

`BUILD-INFO.json` records the source commit, dirty-tree status and version; the
manifest covers it with the runtime payload. Release CI builds the exact tagged
checkout, validates the candidate and waits for the reusable quality workflow.
A dirty local candidate is labeled as such; it is not a clean tagged release.
