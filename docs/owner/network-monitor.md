# Entire-network traffic and discovery

**Traffic** opens on **Entire network**. It lists all saved and actively discovered devices, including devices that are sleeping or no longer responding. Search by name, address, manufacturer, or room; sort numerically by IP or by name/last observation. Device details lead to identification, web links, confirmed names, and Guard controls.

**This computer · applications** opens the existing application, connection, firewall, and host-history view. Its counters are never substituted for household traffic.

## Predator Connect W6

In **Network preferences**, enter the W6's numeric LAN IPv4 address and web port. The firmware inspected for this implementation serves its dashboard at port 8080. NeonHearth reads the router's live WAN feed; no router login, configuration change, or firmware installation is performed. Clear the address to disconnect.

The graph shows router-reported download/upload rates for household internet traffic. Its device count is labeled as a router report and can differ from the observed inventory, especially with downstream switches, access points, sleeping devices, or isolated networks. Graph gaps indicate missing measurements. A stale feed loses its live rates and device count after ten seconds. Averages are available for 5 minutes, 1 hour, and 24 hours; raw rates are retained locally for one day, up to 50,000 samples. Pausing freezes the graph while collection continues.

The inspected W6 feed supplies aggregate WAN rates and connected-client counts. **It does not supply per-device byte counts or traffic between LAN devices.** Those measurements remain unavailable. Measuring them requires counters from a suitable gateway or collection at a mirrored switch port. This build does not claim to capture that traffic.

## Finding previously unseen devices

Choose **Discover devices now**, or enable automatic discovery every 1–15 minutes. Windows uses source-bound native ARP resolution without Npcap or administrator permission. Linux uses its system `ping` on the selected interface and correlates the resulting neighbor entries; the OS must permit ping. Failure to use the native mechanism remains visible.

Sweeps include private IPv4 subnets on up physical Ethernet/Wi-Fi adapters. VPN, Tailscale, loopback, virtual, and corporate-role adapters are excluded. Network/broadcast addresses and the collector's own addresses are excluded. Each sweep is limited to 1,024 targets and 16 simultaneous probes. Subnets broader than /22 are reported as skipped; IPv6 continues through existing passive observations. This does not enumerate unreachable VLANs or guest networks behind client isolation.

Active responses populate the OS neighbor table, so the existing discovery pipeline can assign durable device records. Response history keeps the interface/MAC identity, latest IP, first/last observation, and recent discovery events. Confirmed names, Guard decisions, and prior web-scan findings are preserved. The existing port/protocol scan remains available in **Devices** for deeper identification after discovery.

Two completed sweeps without a response produce **Not responding**. This is not proof the device disconnected; a sleeping or isolated device can miss probes. Failed, cancelled, or partially failed sweeps cannot create departure events. Old responses lose their current-response label. A returning device is recorded separately. History retains up to 4,096 response identities and 2,000 events, with the latest 200 events shown.

## Integration and boundaries

The owner-authenticated API exposes:

- `GET /api/v1/network/monitor?minutes=5` — settings, live W6 rates, rate history, discovery status, response identities, and events.
- `GET` / `PUT /api/v1/network/monitor/settings` — `router_ip`, `router_port`, `discovery_enabled`, and `interval_seconds` (60–3600).
- `POST /api/v1/network/discover` and `/api/v1/network/discover/cancel` — bounded sweep controls.

Schemas are included in OpenAPI. Existing restricted integration credentials do not gain owner authority. Network collection defaults to disconnected/manual until configured.

Router requests use an exact read endpoint on an explicitly selected directly connected private address, omit credentials/cookies and proxy settings, reject redirects, and bound response parsing. Only WAN rates and counts enter the router projection; other router event fields are discarded. The firmware feed uses HTTP on the local LAN. Treat reported network information as advisory, never as permission to control a device.

The W6 adapter was derived from the owner's live firmware's observable interface, checked September 6, 2026, alongside [Acer's W6 manual](https://global-download.acer.com/GDFiles/Document/User%20Manual/User%20Manual_Acer_2.3_A_A.pdf). Firmware changes can make the adapter unavailable; no fallback guesses measurements or administrative endpoints.
