# Getting started

## What NeonHearth is

NeonHearth is a local-first home-network monitor for Windows and Linux. It
discovers the devices on your network, learns what they are from evidence,
tracks when they appear and disappear, shows live traffic, and applies an
approval policy you control. Everything it learns stays on the computer that
runs it (the "collector"). The customer-facing name is NeonHearth; internal
software components use the `lattice-` prefix, which you may see in file and
process names.

## The safety boundary

NeonHearth is for private networks that you administer. It never:

- scans public or third-party targets,
- uses ARP poisoning or Wi-Fi deauthentication,
- exposes its administrator interface to the public internet,
- flashes device firmware automatically,
- runs exploit checks without your explicit, per-target approval.

The service accepts connections only on the local machine (loopback address
`127.0.0.1`, port 58120). There is no public listener of any kind.

## The two parts

1. **The service** (`lattice-service`) is the only privileged part. It owns
   discovery, evidence, the database, and — once enabled — router actions and
   camera access. Its data lives under `%ProgramData%\NeonHearth` on Windows
   or `/var/lib/neonhearth` on Linux, in a local SQLite database
   (`lattice.db`).
2. **The desktop app** is an ordinary, unprivileged window. It never captures
   traffic, opens raw sockets, or handles router or camera secrets. It talks
   to the service over the loopback API only.

## Pairing

Every request to the service (except a plain health check) must carry a
bearer pairing token. The token is at least 32 characters, is supplied to the
service at start through the `LATTICE_SERVICE_TOKEN` secret, and is checked
with constant-time comparison. Without the token the service answers
`401 Unauthorized` and reveals nothing. Live event streams use short-lived
one-time tickets issued from the same token, so the token itself never
appears in a URL.

In this build the desktop app does not yet obtain the token automatically.
Until pairing is wired, views that need protected data show honest
placeholders such as "Unavailable until paired" and "Pair NeonHearth to
begin building a private device list" — they never invent readings.

## Your first 48 hours: the baseline

The first time the service successfully starts, it permanently records that
moment. Every device first seen within the next 48 hours joins the
**baseline cohort** and is marked exempt from age-based deadlines.

Why: when NeonHearth arrives, your network is already full of devices you own.
Rather than threatening to quarantine your own television, the baseline
window treats everything present at move-in as "yours until you say
otherwise." Baseline devices stay fully visible for naming and approval —
exemption skips the countdown, not the record. One thing baseline never
skips: a device showing high-confidence dangerous behavior is still
quarantined immediately (see [Guard and policy](guard-and-policy.md)).

Devices that first appear *after* the 48-hour window get real deadlines.
The baseline start time is immutable in the database; it does not reset on
restart or clock changes.

## What you will see

The app opens on **Pulse** (live throughput, protocol mix, coverage, and an
event thread), with **Devices**, **Guard**, and **Cameras** views alongside.
A collector status card in the side rail tells you plainly whether the local
service is reachable, checking, or unavailable. Views that are not built yet
say so on screen instead of pretending.

## Not yet available

- Production installers and automatic service installation (the service is
  currently started manually with its token and paths supplied at launch).
- Automatic pairing between the desktop app and the service.
- Phone access over Tailscale (planned as private Tailscale Serve only; not
  yet implemented — and public exposure will remain prohibited).
- The Home, Doctor, History, and Settings navigation destinations show a
  "still being wired" notice in this build.
- Automated router enforcement (see [Guard and policy](guard-and-policy.md)
  for what happens instead today).
