# NeonHearth

**Your network. Under control.**

NeonHearth is a local-first Windows and Linux home-network monitor. It discovers and identifies devices independently of the router, shows live traffic and presence, enforces owner approval policies through verified router capabilities, detects cameras, assesses device security, renders a live 3D Home Twin, and provides a private phone interface through Tailscale.

The customer-facing name is NeonHearth. Rust crates use the internal `lattice-*` prefix.

## Safety boundary

NeonHearth is for private networks the owner administers. It does not scan public targets, use ARP poisoning or Wi-Fi deauthentication, expose its administrator UI publicly, automatically flash firmware, or execute exploit checks without explicit target-bound approval.

## Current status

The current Windows Home Hub combines native device discovery, owner-confirmed
names, local-computer traffic/history, a home editor and 3D view, and optional
Home Assistant/MQTT integration. It uses a native launcher, a local collector,
and a browser dashboard. The recommended Windows delivery is the portable Home
Hub ZIP; the service MSI remains a compatibility path. See
[Windows delivery and upgrades](docs/build/windows-delivery.md).

Measurement and control depend on the connected source:

- This computer's interface totals are separate from sampled TCP application
  counters. Short connections and UDP usage are not fully attributed.
- The optional Predator Connect W6 feed supplies household internet totals,
  not per-device traffic or all LAN traffic. Pulse labels it separately from
  device counters. Other routers do not gain this integration automatically.
- Guard records owner policy; the default router actuator requires manual
  enforcement. Application firewall controls and explicitly permitted Home
  Assistant appliance controls are separate capabilities.

[Network coverage](docs/owner/network-monitor.md),
[traffic and permissions](docs/owner/traffic-monitor.md), and
[home automation](docs/owner/home-automation.md) explain setup and limits.

Release-candidate work includes refreshed dependency gates and documented
security backports, protected local credentials, reproducible package manifests,
and isolated smoke/soak tooling. Historical tests and fixture proofs are not a
substitute for fresh-machine installation, physical-hardware compatibility,
remote-phone acceptance, trusted signing or the actual 72-hour soak. These
remain explicit release gates until their evidence is recorded. See
[candidate acceptance](docs/build/acceptance.md),
[dependency maintenance](docs/build/dependency-maintenance.md), and
[installer status](docs/build/installers.md). The current candidate is unsigned.
