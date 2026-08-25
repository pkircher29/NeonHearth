# Privacy and data

## The stance

NeonHearth is local-first. Evidence about your network stays on the
collector machine. There is no cloud account, no telemetry, and no public
listener — the service accepts connections only from the same computer.

## What is stored

- **Metadata and evidence, not packet bodies.** Observations keep the
  interface, time, subject addresses, protocol, and normalized facts (with
  confidence and expiry). No frame bytes or payloads survive normalization,
  and the traffic model has no payload field at all — there is nowhere to
  put packet contents even by mistake.
- **Bandwidth rollups.** Byte counts per device/protocol/interface at
  one-second, one-minute, and one-hour resolution, each labeled with its
  honest coverage.
- **Destination privacy.** Destination IP/domain metadata is irreversibly
  stripped before storage unless you enable that option.
- **Device, presence, and policy history.** Identity facts, presence
  transitions with their triggering evidence, policy decisions and their
  enforcement results.
- **Camera inventory and cached advisories** (with source provenance).
- **Secrets are not in the database.** Camera credentials live in Windows
  Credential Manager / Linux Secret Service; the database stores only
  opaque references.

## Where it is stored

A local SQLite database (`lattice.db`) under the service's state directory,
owned by the service account — not by your desktop login:

- Windows: `%ProgramData%\NeonHearth`
- Linux: `/var/lib/neonhearth`

The desktop app owns no service data.

## What leaves the machine

Nothing, by default. The only designed exceptions are:

- **Advisory lookups** — fetching vendor advisory / NVD / CISA KEV data so
  findings can be matched locally. Fetched data is cached with its source
  and provenance; your device details are matched locally against the cache.
- **Optional private Tailscale access** (future) — a private tailnet proxy
  of the same loopback API for your own phone. Public exposure (Tailscale
  Funnel or any public listener) is prohibited by design.

## Retention

- One-second bandwidth rows are compacted after 24 hours into minute rows.
- Minute rows are compacted after 90 days into hour rows.
- Hour rows are **never deleted automatically** — removing them is an
  explicit owner action by design (not yet exposed in the app).
- Evidence facts expire individually (lease/TTL-driven where the protocol
  provides one); expired facts stop participating in identity.
- Owner-confirmed values never expire; only your explicit clearing removes
  them.

## Removing NeonHearth and its data

1. Stop the service (and disable whatever mechanism you used to start it).
2. Delete the state directory for your platform —
   `%ProgramData%\NeonHearth` on Windows, `/var/lib/neonhearth` on Linux.
   This removes the database and the (currently empty) `backups`
   subdirectory with it.
3. Remove any NeonHearth entries from your OS credential store (Credential
   Manager on Windows, your keyring on Linux) if you stored camera
   credentials.
4. Uninstall/delete the desktop app; it holds no service data.

## Not yet available

- Backup and restore. The service reserves a `backups` directory but no
  backup is written yet; do not rely on one existing.
- A guided uninstaller (removal is the manual procedure above).
- Retention and destination-metadata settings in the app (the underlying
  policies exist in the service; the Settings view is not built).
- Support-export redaction tooling (no export feature exists yet).
- Tailscale phone access (see above; not implemented).
