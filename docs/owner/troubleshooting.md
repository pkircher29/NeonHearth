# Troubleshooting

Each entry below is a failure mode the current software can actually
produce, and what it means.

## "Collector unavailable" in the status card

The app's plain health check to the local service
(`http://127.0.0.1:58120/api/v1/health`) is not answering. The service is
not running, exited at startup, or is still starting. The card also tells
you the truth about scope: "Protected live data has not been requested" —
the health probe carries no token and exposes nothing.

Check that the `lattice-service` process is running. It refuses to start if
its pairing token is missing or malformed ("LATTICE_SERVICE_TOKEN must be
supplied by platform secret provider" / "invalid service token
configuration") or if it cannot create its state directory
(`%ProgramData%\NeonHearth` on Windows, `/var/lib/neonhearth` on Linux).

## The UI reaches the service but cannot pair

Symptoms: the collector card says reachable, but the app shows its sign-in
screen, or views stay empty or report that the service refused the request.

Protected requests are answered `401 Unauthorized` when the bearer token is
absent or wrong. The service requires exactly one `Authorization: Bearer …`
header whose value matches its configured token (at least 32 characters).
The desktop app asks you to paste the owner service token on its sign-in
screen (see [Getting started](getting-started.md#where-the-token-lives-and-rotating-it)
for where to find it). A phone signs in with a pairing code instead; see
[Private phone access](getting-started.md#private-phone-access).

After the owner rotates the token the old one is rejected at once. The
service keeps the new token in its `owner-token` file (see
[Getting started](getting-started.md#where-the-token-lives-and-rotating-it));
relaunch NeonHearth from the Start menu, or on Linux read the current token
with `sudo neonhearth-token`. If the service will not start after someone
edited that file by hand, delete the file: the install-time value is used
again.

## No devices appear

The service only watches network interfaces that are up and confidently
physical (wired or Wi-Fi). Loopback, Tailscale, VPN/tunnel, container,
virtual-machine, corporate-role, down, and unclassifiable adapters are all
excluded by default. If no eligible interface exists — for example, the
collector is connected only through a VPN — startup finds "no eligible
network interfaces" and the service reports itself **degraded** instead of
inventing data. Connect the collector to your home network with a real
wired or Wi-Fi adapter.

Also remember: discovery evidence in this build comes from the operating
system's neighbor table (ARP/NDP), so only devices your collector's subnet
actually exchanges traffic with will surface.

## Bandwidth shows "local-only" or "estimated"

This is a coverage label, not an error. *Local-only* means the numbers come
solely from the collector machine's own vantage point — traffic switched
between other devices is invisible to it. *Estimated* means inference or
mixed-quality sources; whenever sources of different quality overlap, the
label is conservatively downgraded. "Complete" appears only when a verified
gateway/bridge/mirror source observes the traffic; no such source is
configured in this build, so any figure you do see is local-only or
estimated. A device with no bandwidth figure at all is expected: this build
has no source of per-device traffic counters, so per-device bandwidth is
unavailable for every device.

## Camera live view will not open

- **"Live view needs a stream selected"** — the collector has not shared a
  stream selection for that camera; snapshot capture still works.
- Session start can fail when the target is no longer approved, the vault
  cannot supply the camera credential, or the local media process cannot
  start; the app reports the error rather than showing a frozen player.
- A working live view that ends by itself is expected: sessions expire
  after about 30 seconds idle (and have an overall time limit), then clean
  up their files. Start it again when you want to watch.

## Guard actions stuck at "manual required"

Expected in this build: automated router enforcement is intentionally
disabled until the real router interface is verified from an
owner-authorized capture. "Manual required" is the truthful status — the
device is *not* blocked at the router, and NeonHearth is telling you so
instead of pretending. See [Guard and policy](guard-and-policy.md).

## Where the logs are

The service writes structured logs to its process output (standard
output/error), filtered by the `RUST_LOG` environment variable. Where that
output lands depends on how you started the service: the terminal you
launched it from, or the systemd journal (`journalctl`) if you run it as a
Linux unit. Logs are sanitized by design — no tokens, credentials, or raw
capture contents appear in them. The state directory holds the database,
not log files.

## Not yet available

- The Network Doctor (guided diagnostics and repairs) — no automated
  diagnosis or repair exists in this build; this page is the manual.
- Automatic UI pairing (see above).
- In-app surfacing of the degraded/no-interface state beyond the collector
  status and service status events.
- An interface-override screen for deliberately enabling an excluded
  (non-loopback) adapter — the rule exists in the service; the setting UI
  does not.
