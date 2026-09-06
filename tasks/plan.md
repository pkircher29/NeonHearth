# Network and home automation hub

Requested 2026-09-06. Base: NeonHearth a7f8883, isolated from the existing home-editor and W6 work. Windows and Linux remain the targets; existing discovery, first/last-seen history, plan editing, Three.js home rendering, and scoped integration API are retained.

## Architecture and security boundaries

- The owner UI and API bind to loopback. External software uses explicitly scoped credentials. No public deployment is part of this build.
- A Home Assistant adapter imports areas, devices, entities, and live states over its authenticated WebSocket API. A reported area is a location hint, never an invented physical coordinate. Owners place devices on their plan.
- Home Assistant credentials stay in the service, are excluded from responses/logs, and are not persisted in browser storage. TLS certificate validation stays enabled; plaintext is only permitted for loopback testing.
- Control is disabled until an owner enables exact entities. Only explicit turn_on/turn_off actions on approved light/switch entities are accepted. No arbitrary services, broadcast targets, locks, alarms, or scripts. A successful command submission is distinguished from an observed device state.
- Mosquitto supplies the MQTT hub with anonymous access disabled, authenticated clients, topic ACLs, bounded packets, and a local listener. Network listeners require TLS. MQTT does not gain unrestricted control authority.
- Integration boundaries are versioned JSON APIs and explicit adapters. Home Assistant can bridge protocols such as Zigbee, Z-Wave, Matter, Bluetooth and vendor integrations when its required hardware/integrations exist. Universal compatibility and perfect security cannot be promised.
- Threats: malicious websites calling a local service, stolen tokens, hostile discovery/HA/MQTT metadata, spoofed identity and locations, broad or replayed control commands, credential leakage, unsafe broker defaults, and unbounded upstream data. Tests target denied requests as well as successful flows.

## Ordered implementation

1. Add a bounded Home Assistant adapter and tests using a local protocol fixture. Verify authentication, state/registry import, disconnects, bounds, and exact control requests.
2. Add authenticated service routes and sanitized snapshots, explicit per-entity control permission, command deduplication, and auditable results. Test unauthenticated and scoped-token refusal, stale/disconnected control, and replays.
3. Add an understandable Automation view: connect, status, areas, device identity, observed state, and confirmation before power actions. Run UI type checks and build.
4. Connect imported devices to the existing 2D/3D placement interface with durable identity and honest location hints. Verify plan save/reload and device placement in browser.
5. Add an authenticated MQTT broker setup/launch workflow and protocol/API integration documentation. Verify broker anonymous rejection, ACLs, publish/subscribe, and listener binding where a broker binary is available.
6. Verify the combined app: targeted Rust security and integration tests, desktop tests/check/build, dependency audits, and a local executable/browser run. Record exact evidence and remaining hardware acceptance.

Each step must produce a working feature path. Existing databases and installed services are not test fixtures. New local test state is isolated. Public publishing, production installation, and live power/router mutations require a concrete owner-approved target.

## Completion limits

A local build or simulated device control is not proof of a physical switch, radio protocol, router, or remote phone path. The evidence report must identify which checks ran against fixtures and which ran live. Independent security review, physical acceptance, signing, and sustained operation remain release gates.

## Runtime findings from real execution

- Switched the deliverable from debug to an optimized release executable. The 73-device checkpoint workload fell from about 63 seconds per pass to about 7 seconds in the disposable-copy benchmark.
- A concurrent writer could make a deferred discovery transaction fail its read-to-write upgrade immediately. Added a deterministic regression and reserve the write transaction with BEGIN IMMEDIATE before reading the checkpoint. Checksums, sequence checks, full durability, and commit-before-publication remain in place.
- Follow-up native testing exposed the same read-to-write upgrade failure in policy enrollment. Added a competing-writer regression for enrollment, decision publication, actuation reservation, and baseline initialization, and acquire their writer reservations before reading. Final store/service tests and combined discovery/control/map runtime acceptance passed. Results and release limits are in docs/owner/home-hub-verification.md.
