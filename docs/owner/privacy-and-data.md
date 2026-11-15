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
- **Bandwidth rollups (storage only, not fed in this build).** The database
  can hold byte counts per device/protocol/interface at one-second,
  one-minute, and one-hour resolution, each labeled with its honest coverage.
  Nothing in the running service produces per-device counts today, because
  there is no traffic source with per-device counters, so these tables stay
  empty. The router feed and the Traffic view's computer-level numbers are
  stored separately.
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

The service runs a cleanup pass in the background: the first one about two
minutes after it starts, then every 15 minutes. It uses fixed defaults; there
is no setting to change them yet. What it removes:

- **Audit log:** entries older than 365 days, and anything beyond the newest
  1,000,000 entries.
- **Evidence:** older non-identity evidence is removed after 90 days. The
  newest value for each fact is always kept, and link-layer and
  owner-confirmed evidence is never removed.
- **Presence history:** transitions older than 365 days. Each device's latest
  transition is always kept.
- **Discovery commit records:** 30 days.
- **Camera evidence:** 90 days.
- **Advisory fetch records:** 30 days (the newest per source is kept).
- **Phone sessions** that expired or were revoked, and **revoked integration
  tokens:** 30 days after they ended.
- **Home-plan drafts** left over from a different home plan: 30 days.
- **Bandwidth rollups** (if any exist; see below): one-second rows are
  compacted into minute rows after 24 hours, minute rows into hour rows after
  90 days, and hour rows are deleted after 2 years.
- Evidence facts also expire individually (lease/TTL-driven where the
  protocol provides one); expired facts stop participating in identity.
- Owner-confirmed values never expire; only your explicit clearing removes
  them.

## Restoring a backup

Restoring replaces the whole database with a backup file, so it is done
offline:

1. Stop the NeonHearth service.
2. Run `lattice-service restore --from <backup-file>` with the same
   environment the service uses (`LATTICE_STATE_BASE`, and `LATTICE_BIND` if
   you changed it). The command refuses to run while the service is
   listening, checks the backup (integrity, foreign keys, migration history)
   and refuses one written by a newer NeonHearth than the one you are
   running. If anything fails it exits with an error and your current
   database is left as it was.
3. On success your previous database is kept next to the restored one as
   `lattice.db.pre-restore` until the next restore replaces it. Start the
   service.

On that first start the service reconciles before it trusts anything. A
restore rewinds more than your device list: the record of what NeonHearth had
already blocked at the router, pending decisions, and the audit log all go
back to the moment of the backup. So the service treats its enforcement state
as unknown, re-evaluates every device from the restored data, and writes a
`restore.reconciled` entry to the audit log (entries made after the backup
was taken are gone from the log; this entry says so). Controls that cannot be
proven stay pending and ask for your attention instead of being repeated
blindly. Until that finishes, a small marker file
(`restore-reconcile.pending` in the state directory) stays in place; if
reconciliation fails the service reports itself degraded and tries again on
the next start. Check your router for blocks NeonHearth applied after the
backup was taken: the restored database no longer knows about them.

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

- Scheduled backups. The service reserves a `backups` directory but no
  backup is written yet; do not rely on one existing. Restoring a SQLite
  backup file (for example one made with `VACUUM INTO`) is supported; see
  "Restoring a backup".
- A guided uninstaller (removal is the manual procedure above).
- Retention and destination-metadata settings in the app. Retention uses
  the fixed defaults listed above; the Settings view has no control for it.
- Support-export redaction tooling (no export feature exists yet).
- Tailscale phone access (see above; not implemented).
