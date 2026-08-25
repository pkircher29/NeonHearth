# NeonHearth privilege boundary

`lattice-service` is the only privileged component. It owns capture, probes, the vault, target-bound audits, and router mutation. The Svelte/Tauri UI may use authenticated service REST/WebSocket APIs, but never performs raw capture, opens raw or arbitrary sockets, handles router secrets, or launches arbitrary processes.

On Windows, the service runs under a dedicated service identity and uses Npcap. On Linux, the service receives only `CAP_NET_RAW` and `CAP_NET_ADMIN` when full mode is enabled. The UI runs as the signed-in user.

Service state is owned by `%ProgramData%\NeonHearth` on Windows or `/var/lib/neonhearth` on Linux. The UI bundle never owns service state.

The API listens on loopback only. The listener address is configurable (`LATTICE_BIND`) solely so test instances can coexist with an installed service; the service refuses to start on any non-loopback address. Tailscale Serve may be added later; Tailscale Funnel and any public listener are prohibited.

The service may also serve the built UI bundle (static files from `LATTICE_UI_DIR`) on the same loopback listener. Static assets are public build output, not secrets, and require no bearer; every API and WebSocket route keeps its authentication. The UI authenticates via a token handed over locally in a URL fragment (never transmitted on the network) by the installed launcher.

Audit and scan operations are private and owner-approved only. No scan may target an unapproved external or public destination.
