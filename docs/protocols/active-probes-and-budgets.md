# Active probes and budgets

NeonHearth active discovery is a bounded, homeowner-authorized supplement to passive
discovery. `ActiveEngine` is the only network-send boundary. Immediately before each
attempt it authorizes the immutable `(InterfaceId, numeric IP)` pair through the shared
`TargetGuard`. Names are never resolved, redirects are never followed, and multicast,
broadcast, loopback, CGNAT/Tailscale, public, and cross-interface destinations remain
rejected by that guard.

## Catalog

Every descriptor has a stable ID/version, transport, exact port, privilege, side-effect
notice, timeout, request/response caps, evidence families, and owner/credential flags.
IDs are unique and plans are sorted deterministically.

| Family | Default curated targets | Privilege / side effects |
| --- | --- | --- |
| Reachability | ICMPv4, ICMPv6 | Real cross-platform raw echo through `surge-ping`; typed permission/unavailable/network outcomes |
| Link layer | ARP, NDP | Raw privilege; descriptor only until capture backend supplies a guarded send path; never fakes success |
| TCP | FTP 21, SSH 22, Telnet 23, SMTP 25, DNS 53, HTTP 80, HTTPS 443, SMB 445, RTSP 554, IPP 631, camera/web 8000/8080, printer 9100, RDP 3389, VNC 5900, MQTT 1883/8883, AMQP 5672/5671, CoAP/TCP 5683, common databases | Normal connect; bounded read; no login or authentication attempts |
| UDP unicast | DNS 53, DHCP 67, NTP 123, NBNS 137, SNMP 161, SSDP 1900, WS-Discovery/ONVIF 3702, SIP 5060, mDNS 5353, CoAP 5683, common IoT 6666 | One tiny deterministic unicast request; passive-only for multicast discovery |
| SNMP inventory | 161 | Owner-started and credential-required; no default/community guessing |
| Full-port | TCP 1–65535 conceptually; the catalog exposes bounded owner-started chunks | Explicit owner start only, lower priority, never scheduled by the default plan |

HTTP uses a raw numeric-target request with a numeric `Host`, connection close, bounded
status/header extraction, and no redirect handling. TLS certificate collection uses
pure-Rust rustls and exposes only a bounded SHA-256 fingerprint, subject, SAN and validity.
The fingerprint-only handshake is always labeled **unverified**, never trusted, and never
downgrades to plaintext.

SNMP credentials are borrowed only for the execution call. They are never stored,
logged, included in errors, or returned in evidence. ONVIF authentication is deferred to
M4. Successful protocol metadata is capped at 32 facts and 512 bytes per value, source
stamped as `active.<probe-id>.v<version>`, confidence-clamped by construction, and expires
after ten minutes. Refusal and timeout are metadata-only outcomes; raw bodies,
certificates, and secrets never leave the adapter.

## Scheduler defaults and ceilings

| Budget | Default | Valid ceiling |
| --- | ---: | ---: |
| Global in-flight | 32 | 256 |
| Per-host in-flight | 2 | 16 and no greater than global |
| Per-host burst | 4 × per-host concurrency | 64 |
| Per-/24 IPv4 or /64 IPv6 subnet burst | 64 | 1024 |
| Token refill | 1 token/second | 1–3600 seconds |
| Queue | 2048 coalesced items | 4096 |
| Backoff | 1, 2, 4… seconds | capped at 60 seconds; exponent bounded |
| Jitter | deterministic 0–10% positive delay | configurable through 25% |

Budgets and backoff use monotonic time. Wall time is used only for evidence
`observed_at`/expiry. A wall-clock correction cannot refill a budget. Resume after sleep
may refill tokens, but never above bucket capacity, preventing a wake-up burst.

The high-priority queue round-robins hosts, coalesces identical
interface/target/probe/mode work, and always drains presence/discovery before lower-priority
owner full-port work. A noisy or offline host therefore cannot starve another host.

`stop()` rejects new work, clears queued work, and wakes every in-flight engine attempt.
Cancellation is returned as `Cancelled` and is not recorded as a target failure. Transport
timeouts are descriptor-specific. Result amplification is rejected rather than truncated
silently.

## Limitations

- No vulnerability scanning, exploit behavior, credential guessing, router mutation, or
  public-target mode exists in this milestone.
- ARP/NDP require the later signed privileged capture backend. ICMP works where the OS grants raw-echo access and otherwise returns a typed permission result.
- Authenticated ONVIF inventory is intentionally unavailable until M4; no insecure fallback is used.
- DHCP, SSDP, mDNS, and WS-Discovery default discovery remains passive because normal use
  is broadcast/multicast and `TargetGuard` correctly rejects those destinations.
- Persistence, service routes, and UI controls are separate milestones.
