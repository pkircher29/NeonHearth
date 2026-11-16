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

### Where the token lives, and rotating it

The owner can replace the token at any time (`POST /api/v1/service/token/rotate`,
owner only; the old token stops working immediately). The service saves the new
token in a file named `owner-token` in its state directory, and **that file wins
over the `LATTICE_SERVICE_TOKEN` value at every start**, so a rotation survives
restarts and upgrades.

| Install | Token file | Who can read it |
| --- | --- | --- |
| Windows installer (MSI) | `%ProgramData%\NeonHearth\owner-token` | SYSTEM, Administrators and the `NT SERVICE\NeonHearth` account only. The Start-menu shortcut reads it after one UAC prompt. |
| Windows portable `NeonHearth.exe` | `<data folder>\data\NeonHearth\owner-token` | You (the data folder is private to your account). The launcher reads it before its own saved credential, on every launch. |
| Linux deb/rpm | `/var/lib/neonhearth/owner-token` (mode 0600, service account) | The service account and root. Run `sudo neonhearth-token` to print the current token. |

What each installer writes at install time:

- **Windows MSI:** the installer generates the token straight into
  `owner-token` and removes the older copy in the service's registry
  `Environment` value (an upgrade from an older build migrates that copy once).
  Upgrades and repairs never overwrite an existing token file, so a rotated
  token is kept. A full uninstall deletes the file (collected data stays).
- **Linux:** `/etc/neonhearth/service.env` (root only) holds the install-time
  seed. Once the owner rotates, the token file takes over. Upgrades keep both;
  removing the package deletes the token file, a fresh install replaces any
  stale one.

If the desktop app or launcher answers `401` after a rotation, it is still
holding the previous token: relaunch from the Start menu (Windows) or read the
current token with `sudo neonhearth-token` (Linux). A token file that is empty
is ignored; one that is malformed (fewer than 32 characters, or characters
outside `A-Z a-z 0-9 . _ -`) stops the service from starting; delete the file
to fall back to the install-time value. Never paste a token into chat, tickets
or logs.

The desktop app shows a sign-in screen where the owner pastes the token (with
an option to remember it on this computer). Until you sign in, protected
views show nothing rather than invented readings. There is no button in the
app to rotate the token: rotation is an owner-only service call
(`POST /api/v1/service/token/rotate`), and after it the app needs the new
token pasted in.

### Private phone access

Your phone can reach NeonHearth over your own Tailscale network, with no
public exposure. All of these steps are owner-only and are done from the
desktop app, in **Settings**:

1. **Turn on private access** (card "Private phone access"). NeonHearth
   checks that Tailscale is running on this computer and points Tailscale
   Serve (private HTTPS inside your tailnet) at the service, which itself
   keeps listening on this computer only. The button is disabled if
   Tailscale is not running.
2. **Pair a phone** (card "Pair a phone"). Enter a name and choose a
   six-digit PIN, then press "Create pairing code". The code is shown once.
   Enter it on the phone's sign-in screen.
3. **Revoke** a phone at any time from the "Paired phones" list. It stops
   working immediately.

**Funnel is refused.** If Tailscale Funnel is exposing NeonHearth to the
public internet, NeonHearth will not turn private access on and the card
shows a warning until you turn Funnel off in Tailscale. There is no override.

**What a paired phone can do.**

- *Without the PIN* (read only): see device state, cameras and their health
  and inventory, device advisories, your home plan and drafts, the Doctor
  report, remote-access status, and live events.
- *Only after entering the PIN* (high impact, needs a fresh PIN entry; it
  stays valid for 5 minutes): Guard decisions (approve, reject, quarantine),
  running Doctor checks and repairs, changing the home plan and device
  placements, and reading the audit log.
- *Never from a phone*: everything else, including pairing other phones,
  revoking phones, turning private access on, rotating the token, and
  settings. Those need the owner token on the desktop.

Five wrong PINs within 15 minutes lock that phone's PIN entry for 15 minutes;
failed attempts are written to the audit log. A phone session lasts 30 days
and renews while the phone is used, but never lives longer than 180 days
in total; after that, pair the phone again.

Not verified here: this was checked against the service code and tests with a
simulated Tailscale. It has not been confirmed on a real tailnet and phone,
so treat the first real pairing as a test and tell us what you see.

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
service is reachable, checking, or unavailable. The rest of the navigation
is working views:

- **Home** — draw your home and see devices on a 3D plan; see
  [Home Twin](home-twin.md).
- **Doctor** — runs diagnostics; see [Network Doctor](network-doctor.md).
- **History** — the audit log of approvals, scans, enforcement and repairs,
  with a check that the log's hash chain is intact.
- **Settings** — your sign-in session, appearance, phone pairing and
  access, integrations, and the targets the Doctor checks.

## Not yet available

- Production installers and automatic service installation (the service is
  currently started manually with its token and paths supplied at launch).
- Automatic sign-in of the desktop app: you paste the owner token yourself.
- An in-app way to rotate the owner token.
- Confirmation of phone access on a real tailnet and phone (see "Private
  phone access"; tested against a simulated Tailscale only).
- Automated router enforcement (see [Guard and policy](guard-and-policy.md)
  for what happens instead today). Blocking a device is a manual step in
  your router's own app.
