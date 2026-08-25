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
the real interface.

Camera fixture and real-host acceptance gate: [M4 camera evidence](docs/protocols/m4-camera-evidence.md).

M5 (Home editor + 3D Home Twin) is complete with a browser-level gate proof:
[M5 evidence](docs/architecture/m5-evidence.md). M6 software is in place —
Network Doctor (diagnostic DAG, typed repairs with enforced approval tokens,
snapshot/verify/rollback execution, service routes and UI), private Tailscale
Serve phone access with PIN step-up and command-replay dedup, and scoped
read-only integration tokens — with the away-from-home tailnet acceptance
pending real hardware. M7 hardening so far: a hash-chained append-only audit
log with anchor-based retention, DB integrity/backup/restore maintenance,
cargo-deny/license/SBOM/CI gates ([supply chain](docs/build/supply-chain.md)),
owner documentation ([docs/owner](docs/owner/index.md)), and installer
packaging scaffolding with a smoke-verified staged build
([installers](docs/build/installers.md)). Real-hardware acceptance, signed
installers, performance budgets, and the 72-hour soak remain open before an
M7 release claim.
