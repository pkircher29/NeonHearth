# Network and home automation hub

Open **NeonHearth.exe** in the Windows portable package. It starts the collector
and authenticated MQTT hub and pairs your browser. The native launcher needs no
Python, Node, administrator account, or packet-capture driver. Mosquitto needs
the Microsoft Visual C++ x64 runtime; see the package's `Read me.txt`.
The package is unsigned. Developers can still use **Start-NeonHearth.cmd**
with Python and a locally built service and desktop bundle.

The dashboard uses `http://127.0.0.1:58121`. The launcher pairs the browser;
opening that address in an unpaired browser does not grant access to device
data. The native launcher stores private configuration and observations under
`%LOCALAPPDATA%/NeonHearthHomeHub`, protects the owner credential with Windows
DPAPI, and restricts directory access to the current user and SYSTEM. Development
launchers use `.local/`, excluded from Git. Existing installed services keep
their separate state. `NeonHearth.exe --status` checks this instance; `--stop`
stops its verified processes while preserving data.

## Use the dashboard

1. **Devices** shows IP/MAC addresses, discoveries, identity evidence, presence, and first/last
   observations. First seen means this monitor's first observation. Exact
   Wi-Fi association times require access-point telemetry. A host cannot see
   every packet on a switched network or discover an unobserved sleeping device.
   Unambiguous Home Assistant MAC matches supply name/model/room hints. They
   never merge ownership records or enable control automatically. **Sort devices**
   offers numeric IP order in either direction, or discovery order; devices
   without an address appear last.
2. **Automation** connects to Home Assistant. Enter its HTTPS address and a
   token from a dedicated account in the password field. Names, manufacturers,
   models, MAC addresses when reported, rooms, entities, and state changes are
   imported. The token stays in service memory; reconnect after a service restart.
3. For an eligible individual light or switch, choose **Allow power control**,
   then **Turn on/off**, and confirm the named device. Permissions clear after
   a disconnect or reconnect. An accepted command means Home Assistant accepted
   it; the displayed state changes only after Home Assistant reports a state.
4. In **Home**, draw the floors, walls, and rooms, save the plan, and place
   discovered or imported devices from the tray. Open **3D view** to orbit the
   home and isolate floors. Home Assistant room names help placement; they do
   not supply physical coordinates. HA imports retain stable IDs across
   reconnects to the same server, so saved placements survive.
5. Select **Measurement units** in Home to use metric or imperial measurements.
   Length inputs show meters or decimal feet; imperial drawing snaps to one inch.
   Changing units preserves the geometry and saves your display preference.
   **Copy footprint** copies walls, openings, and rooms to a new floor above
   or an existing empty floor. Devices stay on their original floor. Copies
   have independent identifiers, can be edited separately, and support Undo.
6. In **Devices**, expand **Identify devices with a network scan**. Choose common
   ports, all TCP ports, specific ports, or protocol discovery only, then
   **Scan all devices**. Progress and partial findings remain visible if you
   cancel. Results are saved with timestamps. Timeouts do not prove absence;
   service names inferred from port numbers are hints.
   **Identify open web ports with HTTP / HTTPS** is enabled by default. When a
   common web port is open, the scanner reads its root page and adds searchable
   titles, server metadata, and conservative product clues to its device card.
   Confirmed device names and control permissions remain owner-managed.

Web identification sends only an unauthenticated `GET /`, using the scanned
numeric address and pinned local interface. It does not follow redirects, resolve
advertised names, use proxies, send credentials or cookies, execute page scripts,
or fetch images or links. Both HTTP and HTTPS can be tried, at most twice per open
web port; the attempts share the scan's rate limit, cancellation and deadline.
HTTP responses are capped at 16 KiB with an 8 KiB/64-header limit, a 1.5-second response
read limit, and a 3-second overall probe timeout. Compressed bodies are skipped.
Raw page bodies, cookies, redirect locations and authentication challenge tokens
are not retained. Only bounded identification fields are saved.

HTTPS discovery accepts private/self-signed certificates solely for this
credential-free probe, verifies TLS handshake signatures, and marks certificate
identity **unverified**. A reported title, product clue or certificate is not
proof of the physical device's identity. Devices requiring a redirect, sign-in,
JavaScript, an unsupported TLS version, or an unrecognized web port may supply
only partial clues. Raw printer and other non-web ports receive no HTTP request.
The root-page request follows the [HTTP safe-method semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.1).

Home Assistant must be reachable using a private LAN or Tailscale address
with a certificate trusted by Windows. Certificate verification cannot be
disabled. HTTPS hostnames are resolved, checked, and pinned for each connection;
public, link-local, multicast, and IPv4-mapped IPv6 destinations are rejected.
Plain HTTP/WebSocket connections are allowed only to literal loopback addresses
for local instances or protocol testing. Configure trusted HTTPS on an existing
HTTP-only HA installation before connecting it here.

## What the protocols support

| Connection | Implemented behavior | Boundary |
|---|---|---|
| Local IP network | Bounded native neighbor discovery, persisted observations, live presence events | Visibility depends on this host and network topology; not an access-point join feed |
| TCP identification | Owner-started common, custom, or all-port connection checks across observed local devices | Only unambiguous neighbor-backed addresses on eligible physical links; 12 devices concurrent, one request per device, 40 starts/second, 24-hour limit |
| HTTP / HTTPS identification | Root-page title, Server, X-Powered-By, generator, authentication realm, product clues and certificate metadata on open web ports | No credentials, scripts, redirects or additional resources; reported hints and certificate identity are unverified |
| Multicast DNS / Bonjour | Local IPv4 service discovery with correlated, bounded replies | Uses the observed local links; advertised identities are untrusted hints |
| Avahi | Linux adapter uses avahi-daemon through the fixed avahi-browse utility | Debian packages depend on avahi-daemon/avahi-utils; RPM packages use avahi/avahi-tools; daemon must be running |
| ICMP | Echo reachability; native IPv4 on Windows | Other platforms and IPv6 depend on socket permissions |
| SNMP | Read-only v2c or v3 SHA-256/AES-128 inventory | Requires credentials supplied for that scan; v2c sends its community unencrypted |
| SMB / NetBIOS | SMB 2/3 negotiation and UDP node-status names | No sign-in, share access, or SMB1; SMB 3.1.1-only servers are not yet supported |
| CDP / LLDP | Validated Ethernet PCAP import with captured timestamps and withdrawal/expiry status | Requires a capture from the relevant link; imported advertisements do not create trusted device identities |
| Home Assistant WebSocket API | Device/entity/area registry import, live state subscription, reconnects | Requires a reachable HA instance and user-supplied credentials |
| HA light/switch control | Explicit individual turn-on/off commands with permission, confirmation, stale-state check, durable deduplication, and audit | Groups, arbitrary services, locks, alarms, scripts, and broadcast targets are excluded |
| Zigbee, Z-Wave, Matter/Thread, Bluetooth, ESPHome, vendor protocols | Devices already integrated into HA can appear and expose supported entities | HA's integrations, radios, bridges, and device capabilities determine support; no universal native radio implementation |
| MQTT | Real Mosquitto broker with accounts, topic ACLs, bounded queues and messages; inventory publishing | Local listener by default; no incoming MQTT-to-power execution |
| Other software | Versioned HTTP API, existing scoped inventory/event API, and MQTT output | Third-party credentials do not inherit local-owner power permission |

Internet blocking, Wake-on-LAN, operating-system shutdown, PoE switching, and
protocol-specific commissioning need their own compatible adapters. Removing
internet access is different from removing electrical power. This build does
not claim those operations work on arbitrary devices.

## MQTT hub

The launcher authenticates to an existing configured hub or starts the local
broker. It refuses to replace an occupied listener that rejects its credentials.
The default listener is `127.0.0.1:58183`, with anonymous access disabled.
Credentials are generated randomly and stored in the private state's `mqtt/`
directory (`.local/mqtt/` for the development launcher). Never put them in command
arguments, Git, screenshots, or chat.

Advanced setup with an official Mosquitto installation:

```sh
python scripts/mqtt-hub.py setup --binary /path/to/mosquitto
python scripts/mqtt-hub.py ensure --binary /path/to/mosquitto
```

`setup` refuses to overwrite existing data. The service reads the bridge
credential file selected by `LATTICE_MQTT_CREDENTIAL_FILE`. Account passwords
for configuring other clients are in `accounts.json`; the broker's separate
password file contains hashes. Files inherit a user/SYSTEM-only Windows ACL
or sit inside a mode-700 Unix directory.

| Topic | Payload and access |
|---|---|
| `neonhearth/status` | Retained online/offline status with Last Will |
| `neonhearth/network/status` | Collector health, separate from automation connectivity |
| `neonhearth/network/inventory` | Up to 256 devices per snapshot, first/last observations and presence; `more_may_be_available` signals use of the paginated HTTP API |
| `neonhearth/automation/inventory` | Sanitized HA device/entity snapshot and connection status |
| `neonhearth/devices/<username>/state` and `/availability` | A provisioned device account may publish only its own topic subtree |
| `neonhearth/devices/<username>/set` | That device may subscribe; NeonHearth does not currently publish power commands here |

Inventory is not retained or persisted by the broker, preventing old data from
appearing current after restart. It is published about every three seconds
while connected. Consumers must observe connection/collector status and timestamps.
The `homeassistant` account can read `neonhearth/#`; it cannot write the bridge's
inventory. Provision distinct credentials and ACLs for additional clients.

A Home Assistant server or device on another computer cannot use this loopback
listener. A LAN MQTT listener needs deliberate TLS configuration, a trusted
certificate, a specific LAN/tailnet bind address, per-client authentication and
ACLs, and a firewall restriction. Follow the
[Mosquitto listener and TLS documentation](https://mosquitto.org/man/mosquitto-conf-5.html).
No LAN listener, firewall opening, public exposure, or router change is made
by this launcher.

## Integration API

The service exposes its OpenAPI document at `/api/v1/openapi.json` and versioned JSON routes. The
automation routes require the actual local-owner bearer credential:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/automation/network` | Saved hardware addresses, current neighbor-cache IP addresses, and unambiguous HA identity hints |
| GET | `/api/v1/automation` | Connection status, sanitized inventory, rooms, MQTT health |
| POST | `/api/v1/automation/connect` | Supply `url` and write-only `access_token` |
| POST | `/api/v1/automation/disconnect` | Revoke permissions and close the HA session |
| PUT | `/api/v1/automation/permissions` | Replace the exact `entity_ids` control allowlist |
| POST | `/api/v1/automation/commands` | Confirm one power action with a unique command ID and observed state timestamp |
| GET / POST | `/api/v1/network/scan` | Inspect or start a scan of observed device IDs; an empty selection scans all eligible devices |
| POST | `/api/v1/network/scan/cancel` | Cancel the current scan and retain partial results |
| GET | `/api/v1/network/capabilities` | Explain protocol and platform support |
| GET / POST | `/api/v1/network/capture` | Read the last import or import an Ethernet PCAP up to 4 MiB |

Command requests carry `command_id` (UUID), `entity_id`, `action`
(`turn_on` or `turn_off`), `expected_last_changed`, `issued_at` (RFC3339), and
`confirmed: true`. While connected and authorized, reuse the same command ID and intent with
a fresh `issued_at` to retrieve the existing receipt; do not generate a new
ID to retry an uncertain outcome. Reusing an ID with
different intent is rejected. Queue capacity and timeouts are bounded.

Use MQTT or existing scoped read credentials for software that only needs
inventory. The local-owner credential grants broad local authority and must
not be embedded into a distributed application. Home layouts contain private
information; export only what the receiving application needs.

## Security and release status

The API and broker bind to loopback. Owner authentication, browser-origin
checks, a restrictive content security policy, request/frame bounds, explicit
device permissions, command auditing, and credential exclusion are implemented.
Rust advisory exceptions have been removed, dependencies patched, and local
dependency scans run. These controls reduce risk; no software can honestly
promise 100% security.

A compromised owner account, operating system, HA server, broker, or physical
device remains a trust boundary. A dedicated HA token can still have more HA
authority than this adapter exposes. TLS does not establish that a device's
reported identity or room is true. Test hardware, review the threat model,
sign release artifacts, and arrange independent security assessment before
shipping this as a production control system. See the accompanying
[verification report](home-hub-verification.md) for measured results and limits.
