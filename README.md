# NeonHearth

**See your network breathe.**

NeonHearth is a local-first Windows and Linux home-network monitor. It discovers and identifies devices independently of the router, shows live traffic and presence, enforces owner approval policies through verified router capabilities, detects cameras, assesses device security, renders a live 3D Home Twin, and provides a private phone interface through Tailscale.

The customer-facing name is NeonHearth. Rust crates use the internal `lattice-*` prefix.

## Safety boundary

NeonHearth is for private networks the owner administers. It does not scan public targets, use ARP poisoning or Wi-Fi deauthentication, expose its administrator UI publicly, automatically flash firmware, or execute exploit checks without explicit target-bound approval.

## Current status

Implementation follows the approved M1–M7 build checklist in the parent workspace. The first deliverable is the loopback-only service foundation and unprivileged UI shell.

