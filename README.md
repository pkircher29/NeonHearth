# NeonHearth

**See your network breathe.**

NeonHearth is a local-first Windows and Linux home-network monitor. It discovers and identifies devices independently of the router, shows live traffic and presence, enforces owner approval policies through verified router capabilities, detects cameras, assesses device security, renders a live 3D Home Twin, and provides a private phone interface through Tailscale.

The customer-facing name is NeonHearth. Rust crates use the internal `lattice-*` prefix.

## Safety boundary

NeonHearth is for private networks the owner administers. It does not scan public targets, use ARP poisoning or Wi-Fi deauthentication, expose its administrator UI publicly, automatically flash firmware, or execute exploit checks without explicit target-bound approval.

## Current status

Implementation follows the approved M1–M7 build checklist in the parent
workspace. M1 is complete, the automated M2 discovery/identity/presence work is
complete with real departure/rejoin acceptance still pending, and the simulated
M3 live UI, approval policy, and W6 enforcement gate is complete.

The W6 adapter is fixture-verified but intentionally not enabled in the main
runtime until an owner-authorized, sanitized compatibility capture identifies
the real interface. Cameras/security assessment, Home Twin, Network Doctor,
Tailscale access, and production installers follow in M4–M7.
