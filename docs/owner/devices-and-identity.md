# Devices and identity

## Identity is earned from evidence

NeonHearth never trusts a single clue about what a device is. Every fact it
collects — a MAC address, a DHCP client ID, a TLS key, an ONVIF UUID, a
hostname — is stored with its evidence family, its source, when it was seen,
when it expires, a confidence value, and whether you confirmed it. Expired
facts stop counting.

Your router's own device labels are deliberately weak evidence: they are
stored only as hints, capped at 0.49 confidence, and can never create,
merge, or confirm an identity on their own. NeonHearth owns identity; the
router does not.

## The two-family rule

Before NeonHearth automatically concludes that two observations are the same
physical device, it requires strong matches from **at least two independent
evidence families**. Repeated facts from one family count once. Weak
identifiers — IP address, vendor prefix, router label, hostname, device
class, open ports — are never merge anchors. A device using a private
(randomized) MAC needs two other stable anchors, such as a TLS key plus an
ONVIF UUID, before its identity survives the rotation. A conflicting
high-confidence stable identifier blocks the merge entirely.

The same bar applies to naming a device: automatic vendor + device-class
identification requires both values at 0.85 confidence or higher, supported
by at least two independent non-router families. Model and firmware are
allowed to stay "unknown" — NeonHearth says less rather than guessing.

## Your word wins

Anything you confirm — a name, a type, an identity — is authoritative over
every automatic inference, regardless of the machine's confidence, until you
explicitly clear it. Owner-confirmed values never expire on their own.

## Merge proposals

When evidence points toward a merge but does not meet the automatic bar, or
points at multiple candidates, NeonHearth creates a review proposal instead
of choosing for you. Each proposal records the candidates, score, and
reasons; accepting, rejecting, or undoing one is an audited, reversible
decision that never moves or deletes the underlying facts. This engine is
conservative on purpose: one physical device may temporarily appear as two
records rather than two devices being wrongly fused into one.

## Presence states

Each device shows one of five presence states:

- **online** — recent trusted traffic was actually seen.
- **quiet** — no recent traffic, but a still-valid lease, router
  association, or successful probe says it is likely still there. A probe
  alone never establishes presence.
- **offline** — all protocol evidence has expired *and* the configured
  number of confirmation checks failed afterward. NeonHearth does not
  declare departure from silence alone.
- **blocked** — enforcement was verified at the router. This state has the
  highest precedence and only a verified release clears it; discovery
  evidence cannot overwrite it.
- **unknown** — evidence is contradictory or the sensor is impaired. The UI
  shows this as "Presence unavailable" rather than pretending.

Joins and departures use hysteresis so a flaky device does not flap, and a
recent departure is corrected if late evidence proves the device was
actually present.

## Bandwidth coverage labels

Every bandwidth figure carries a coverage label, because a single collector
PC cannot see everything a router sees:

- **complete** — a verified gateway, bridge, or mirror source observed the
  traffic. This label is never inferred; it exists only when such a source
  is configured and verified.
- **router-reported** — verified router counters.
- **local-only** — only the collector machine's own vantage point.
- **estimated** — inferred, or mixed sources. When sources of different
  quality overlap, the combined view is conservatively labeled *estimated*,
  never upgraded.

"Complete" honestly means the label says complete — nothing else. The Pulse
coverage badge is explicitly "evidence quality, not a heat score," and a mix
of coverages across devices is shown as *mixed*.

## Not yet available

- On-screen controls to confirm or correct a device's identity (the Devices
  view shows "Needs your confirmation" but the confirm action is not wired
  into the app yet).
- A merge-proposal review screen (proposals exist inside the identity
  engine; there is no owner-facing surface for them yet).
- Real-hardware departure/rejoin acceptance is still pending: the join and
  departure machinery is fixture-verified, and physical-device evidence is
  deliberately not claimed until observed.
- Verified gateway/mirror/router bandwidth sources are not configured in
  this build, so live figures are local-only or estimated in practice.
