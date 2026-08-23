# NeonHearth privilege boundary

`lattice-service` is the only privileged component. It owns capture, probes, the vault, target-bound audits, and router mutation. The Svelte/Tauri UI never performs raw capture, opens sockets, handles router secrets, or launches arbitrary processes.

On Windows, the service runs under a dedicated service identity and uses Npcap. On Linux, the service receives only `CAP_NET_RAW` and `CAP_NET_ADMIN` when full mode is enabled. The UI runs as the signed-in user.

Service state is owned by `%ProgramData%\NeonHearth` on Windows or `/var/lib/neonhearth` on Linux. The UI bundle never owns service state.

The API listens on loopback only. Tailscale Serve may be added later; Tailscale Funnel and any public listener are prohibited.

Audit and scan operations are private and owner-approved only. No scan may target an unapproved external or public destination.
