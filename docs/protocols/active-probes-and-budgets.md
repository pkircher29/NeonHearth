# Active probes and budgets

NeonHearth active discovery is a bounded, homeowner-authorized supplement to passive
discovery. `ActiveEngine` is the only network-send boundary. Immediately before each
attempt it authorizes the immutable `(InterfaceId, numeric IP)` pair through the shared
`TargetGuard`. Names are never resolved, redirects are never followed, and multicast,
broadcast, loopback, CGNAT/Tailscale, public, and cross-interface destinations remain
rejected by that guard.

Authorization also resolves an immutable source address and interface index from the
approved inventory. TCP, TLS, UDP, SNMP, and ICMP bind that source before connecting;
every TCP/TLS/UDP/SNMP connect or send is also pinned and read-back verified with Linux
`SO_BINDTOIFINDEX` or Windows `IP_UNICAST_IF`/`IPV6_UNICAST_IF`. ICMP uses the same
platform interface-index boundary through its raw-socket backend. IPv6 link-local
destinations carry the selected interface as their scope ID. The local binding and
interface pin are verified before each send and there is no unbound fallback, including
when routes overlap. A kernel that rejects interface pinning returns a typed
permission/unavailable result and sends nothing. Linux kernels or security policies may
require `CAP_NET_RAW`/`CAP_NET_ADMIN` for the relevant raw or device-binding option;
NeonHearth never retries without the pin.

## Catalog

Every descriptor has a stable ID/version, transport, exact port, privilege, side-effect
notice, timeout, request/response caps, evidence families, and owner/credential flags.
IDs are unique and plans are sorted deterministically.

| Family | Default curated targets | Privilege / side effects |
| --- | --- | --- |
| Reachability | ICMPv4, ICMPv6 | Real cross-platform raw echo through `surge-ping`; typed permission/unavailable/network outcomes |
| Link layer | ARP, NDP | Raw privilege; descriptor only until capture backend supplies a guarded send path; never fakes success |
| TCP | FTP 21, SSH 22, Telnet 23, SMTP 25, DNS 53, HTTP 80, HTTPS 443, SMB 445, RTSP 554, IPP 631, camera/web 8000/8080, printer 9100, RDP 3389, VNC 5900, MQTT 1883/8883, AMQP 5672/5671, CoAP/TCP 5683, common databases | Normal connect; bounded read; no login or authentication attempts |
| UDP unicast | DNS 53, DHCPINFORM 67, NTP 123, NBNS 137, SNMP 161, RTSP OPTIONS 554, SSDP 1900, WS-Discovery/ONVIF 3702, SIP 5060, mDNS 5353, CoAP 5683, LIFX LAN 56700 | One tiny deterministic unicast request; passive-only for multicast discovery |
| SNMP inventory | 161 | Owner-started v1/v2c/v3 read-only GET for sysDescr.0 and sysObjectID.0; no default/community guessing |
| Full-port | TCP 1–65535 conceptually; the catalog exposes bounded owner-started chunks | Explicit owner start only, lower priority, never scheduled by the default plan |

The mDNS adapter is distinct from conventional DNS: its unicast DNS-SD query uses
message ID zero and requests a unicast reply in the question class. Replies must echo
the exact question name and type and return a matching PTR owner name; peer address is
always correlated separately. WS-Discovery and ONVIF replies are parsed as bounded XML
with exact SOAP, WS-Addressing, and WS-Discovery namespaces and document containment.
SIP and RTSP replies require syntactically valid status/header blocks with unique, exact
Call-ID/CSeq correlation fields; bodies and unrelated headers cannot satisfy correlation.
Transaction IDs, nonces, WS-Addressing message IDs, SIP/RTSP correlation values, CoAP
tokens, and LIFX source/sequence values are generated independently per attempt by the
operating-system CSPRNG. Tests inject a deterministic nonce source; production does not.

HTTP uses a raw numeric-target request with a numeric `Host`, connection close, bounded
status/header extraction, and no redirect handling. TLS certificate collection uses
pure-Rust rustls and exposes only a bounded SHA-256 fingerprint, subject, SAN and validity.
The fingerprint-only handshake is always labeled **unverified**, never trusted, and never
downgrades to plaintext.

SNMP credentials are typed and borrowed only for the execution call. V1/v2c community,
v3 username-only, SHA-1/SHA-256/SHA-512 authentication, and AES-128/AES-256 privacy are
supported through a bounded custom transport. That transport re-authorizes the exact
interface and numeric peer before every v3 discovery/retry send, and the protocol library
validates version, community or USM security, request/message ID, and response shape.
Credentials are redacted by `Debug`, never logged, included in errors, or returned in
evidence. ONVIF authentication is deferred to M4. Successful protocol metadata is capped at 32 facts and 512 bytes per value, source
stamped as `active.<probe-id>.v<version>`, confidence-clamped by construction, and expires
after ten minutes. Refusal and timeout are metadata-only outcomes; raw bodies,
certificates, and secrets never leave the adapter.

Every UDP receive path, including community SNMP and SNMPv3, allocates one byte beyond
its declared cap. A cap-plus-one datagram is rejected as amplification instead of being
silently accepted after operating-system truncation.

## Scheduler defaults and ceilings

| Budget | Default | Valid ceiling |
| --- | ---: | ---: |
| Global in-flight | 32 | 256 |
| Per-host in-flight | 2 | 16 and no greater than global |
| Global rate burst | 128 cost tokens | 4096 |
| Per-host burst | 4 × per-host concurrency | 64 |
| Per-/24 IPv4 or /64 IPv6 subnet burst | 64 | 1024 |
| Token refill | 1 token/second | 1–3600 seconds |
| Queue | 2048 coalesced items | 4096 |
| Backoff | 1, 2, 4… seconds | capped at 60 seconds; exponent bounded |
| Jitter | deterministic 0–10% positive delay | configurable through 25% |

Descriptors also declare an explicit cost class: presence (ICMP/neighbor checks),
discovery (normal TCP/UDP), inventory (credentialed SNMP, cost 4), or owner full-port
(cost 2 per handshake). The scheduler consumes those costs when the D6 runner dispatches
work atomically from global, host, and subnet buckets; denial cannot partially consume
another bucket. Credentialed inventory uses the explicit `OwnerInventory` authorization
mode and remains normal priority. Only `OwnerFullPort` work enters the low-priority queue.
The curated catalog exposes the same separation: `Default` excludes all owner-started
descriptors, `OwnerInventory` contains only credentialed inventory descriptors, and
`OwnerFullPort` contains only full-port descriptors.

Budgets and backoff use monotonic time. Wall time is used only for evidence
`observed_at`/expiry. A wall-clock correction cannot refill a budget. Resume after sleep
may refill tokens, but never above bucket capacity, preventing a wake-up burst.

The high-priority queue round-robins hosts, coalesces identical
interface/target/probe/mode work, and prefers presence/discovery over lower-priority owner
full-port work. To prevent indefinite low-priority starvation under sustained arrivals,
one full-port item becomes eligible after at most 32 consecutive high-priority admissions,
then preference resets. A noisy or offline host therefore cannot starve another host.

`SchedulerRunner` is the asynchronous execution boundary joining this queue to
`ActiveEngine`. Dispatch atomically consumes each descriptor's declared `rate_cost` and
holds global and per-host concurrency through a panic-safe RAII reservation. Before any
budget is consumed or task admitted, dispatch reserves a bounded result-channel slot, so
completion, typed error, cancellation, and retry status can be published synchronously.
Backpressure therefore pauses admission and cannot deadlock global stop. Admission and
stop transition share one lifecycle gate: stop prevents late task registration and awaits
every task admitted before the transition. Concurrent and later stop callers observe one
retained `Running` → `Draining` → `Drained` completion and cannot return before that shared
drain finishes.
Credentialed inventory obtains an owned credential from an execution-time provider only
after dispatch. Retrieval is an asynchronous, typed-error boundary with a default two-second
timeout (maximum 30 seconds) and is selected directly against global stop; cancellation drops
the pending future and never retries it. Implementations must move blocking OS/keyring calls
to a blocking worker rather than executing them on Tokio. Provider failures cross a closed,
payload-free `CredentialSourceError` boundary and map only to terminal sanitized outcomes;
arbitrary strings and source errors cannot cross it. The runner neither queues nor retains
credentials.

`catch_unwind` exists only so runner reservations and pending state are cleaned up and an
opaque `Internal` outcome remains observable. It does **not** suppress Rust's process-global
panic hook, which runs before unwinding is caught. Credential providers are trusted code and
must never panic with credential material; they must return a typed redacted error instead.

Denied admission reports either concurrency pressure or the earliest monotonic rate/state
deadline. Each wake scans at most the queue length observed at its start, then the coordinator
parks until that deadline, the next retry, enqueue/completion/stop, result capacity, or result
receiver closure. There is no fixed-interval queue polling. Dropping the result receiver
initiates shared stop, and `start()` returns a joinable coordinator handle.

Only timeout outcomes and typed transient network failures retry. Unauthorized targets,
missing approval or credentials, invalid configuration/protocol data, correlation and
response-limit failures are terminal. Retry state is keyed by interface, numeric target,
and probe ID; exponential delay is capped at 60 seconds, jitter is bounded by policy, and
the default permits at most five retries. Successful, refused, and terminal attempts reset
their failure state. Host, subnet, retry, and failure maps have explicit capacities and a
30-minute monotonic TTL; when safe capacity is unavailable, dispatch fails closed rather
than creating unbounded state. Suspend can refill a bucket only to its configured cap.

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
