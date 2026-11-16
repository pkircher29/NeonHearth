# Network Doctor

The Doctor runs a short, bounded set of checks against the computer NeonHearth runs on and tells you what it found. Each check is either **passed**, **failed**, or **not available** — never a guess. A check that the operating system cannot measure is labelled *Not available* and produces no finding; it is not counted as a fault in your network.

The Doctor does not run `ping`, `ipconfig`, `netsh` or any other program. It asks the operating system directly. Repairs are described under [What NeonHearth can repair itself](#what-neonhearth-can-repair-itself): in this build only one repair is something NeonHearth does for you; every other plan is guidance for you to follow.

## What each check measures

| Check | What is measured | Windows | Linux |
| --- | --- | --- | --- |
| Collector health | Whether the NeonHearth service is running and ready. | Yes | Yes |
| Adapter link | Whether the primary adapter has a link, and its negotiated speed when the OS reports one. | Yes (IP Helper interface table) | Yes (`/sys/class/net`: carrier state and speed; speed is often unknown for Wi-Fi and virtual adapters) |
| Address / DHCP | The adapter's IPv4 address and whether it is a valid lease, a static address, expired, or missing. A `169.254.x.x` self-assigned address is reported as *missing*: it is what the computer falls back to when DHCP fails. | Yes (address lifetimes and origin) | Yes (kernel address lifetimes over netlink) |
| Duplicate IP | Sends ARP probes for this computer's own address and lists the hardware addresses of any other device that answers. | Not available | Yes, but needs the `CAP_NET_RAW` capability; without it the check fails with that explanation |
| Wi-Fi quality | Signal strength in dBm for a wireless adapter. A wired adapter is reported as "not wireless". The retry rate is never measured. | Not available for Wi-Fi adapters (the Windows WLAN API is not enabled in this build) | Yes, when the driver reports dBm in `/proc/net/wireless`; otherwise not available |
| Gateway | Four ICMP echoes to the default gateway. | Yes | Yes (needs the account's group to be allowed by `net.ipv4.ping_group_range`, the default on common distributions) |
| Router health | Would ask the router for its own status. NeonHearth has no router API to ask. | Not available | Not available |
| Loss / latency | Packet loss and median round-trip time to the gateway. | Yes | Yes |
| MTU | Don't-fragment echoes at several sizes to the internet probe address, to find a path that silently drops large packets. | Yes. When a router says a packet is too big, Windows does not report the router's MTU, so this build reports the MTU of the adapter that owns the default route | Yes |
| DNS | Asks each configured resolver, and one independent resolver, for the probe name over UDP port 53. Reports the answer and delay, or the failure (timeout, refused, server failure, no answer). | Yes | Yes |
| Route / VPN | Lists the IPv4 default routes and marks routes that belong to a VPN or tunnel adapter. More than one default route is reported as a conflict. | Yes | Yes |
| Internet reachability | A TCP connection to the internet probe address and port (no names are resolved). | Yes | Yes |

Details that apply everywhere:

- **IPv4 only.** Echo, default routes and address checks cover IPv4. IPv6 targets are not probed; they show as not available.
- **The primary adapter** is the one that owns the best IPv4 default route unless you choose another in the Doctor settings.
- **Probes follow the normal routing table.** They are not forced out of one adapter, so on a computer with a VPN the path measured is the path the VPN setup gives.
- **Every probe has a hard time limit.** A probe that cannot finish in time is reported as a timeout or a probe error, never as success. A missing echo reply counts as loss; a failure to send at all is a probe error and does not count as loss.
- **Nothing is invented.** When the operating system gives no value (for example link speed), the value is simply absent.

## What needs your confirmation

Probes to your own network (the gateway, your own resolvers, anything on a private address) run whenever you run the Doctor. Probes that leave your network go to public internet addresses and are refused until you turn on **external probes** in the Doctor settings. That covers:

- the **independent resolver** in the DNS check (default `9.9.9.9`), and any configured resolver that is a public address;
- the **MTU** echoes to the internet probe address (default `1.1.1.1`);
- the **internet reachability** connection to that address and port (default `1.1.1.1` port 443).

Without confirmation these checks do not run their probe. They report that the target is not confirmed by the owner, so you can see why they say nothing about your internet connection. If your computer is configured to use a public DNS server, the DNS check counts that resolver as unanswered until you confirm external probes.

A target that is not set (for example no default gateway could be found) is never probed at all; the check reports that the target is not configured.

## What is not available, and why

- **Router health**: there is no router interface NeonHearth can ask on either system.
- **Duplicate IP on Windows**: finding other devices that claim your address needs raw link-layer access, which Windows only provides through a packet-capture driver. NeonHearth does not install one for the Doctor.
- **Wi-Fi quality on Windows**: reading signal strength needs the Windows WLAN API, which this build does not use. Wired adapters are still reported correctly as not wireless.
- **Wi-Fi retry rate** on both systems: the operating systems expose counters, not a rate over the test interval.
- **IPv6** checks on both systems.
- **Other operating systems**: only Windows and Linux are supported; every probe that needs the operating system is not available elsewhere.

## What NeonHearth can repair itself

Each finding comes with a proposed fix. The Doctor only offers a button for a fix NeonHearth can really carry out on this computer. A fix it cannot carry out is shown as guidance with the steps for you to follow, and it has no Approve or Repair button: you are never asked to approve something that would then fail.

| Fix | NeonHearth does it? | Why |
| --- | --- | --- |
| Restart the discovery worker (collector fault) | **Yes**, while the worker is running | NeonHearth rebuilds its own discovery worker in place, without restarting the service. It then re-runs the collector-health check and tells you whether the symptom improved. A restart that changes nothing is reported as "no measurable change". It cannot revive a worker that has already died; restart the service for that. |
| Refresh app caches | No | No finding proposes it and no check can measure its effect. |
| Repair Tailscale remote access | No | No finding proposes it and no check can measure its effect. Use the remote-access settings. |
| Renew the collector's address lease | No | Renewing a lease needs administrator rights on the operating system, which NeonHearth does not hold. |
| Retry the router session | No | NeonHearth has no router interface to retry. |
| Reset the network adapter | No | Needs administrator rights on the operating system. |
| Change DNS servers | No | Needs administrator rights on the operating system. |
| Renew the DHCP lease | No | Needs administrator rights on the operating system. |
| Lower the interface MTU | No | Needs administrator rights on the operating system. |
| Block or unblock a device | No | Needs administrator rights on the operating system. |
| Reserve an address for one of two devices that share it (duplicate IP) | No | Needs the router's DHCP settings, and NeonHearth has no router interface. |
| Reboot the router | No | NeonHearth has no router interface. |
| Move the access point, check cables, contact your provider | No | Physical or outside NeonHearth; the Doctor lists the steps. |

For every "No" the finding still tells you what is wrong, with the evidence and a plain-language "To fix it yourself" step. For the duplicate address the Doctor no longer asks which device should keep it, because it cannot apply your answer; make that choice in your router's DHCP settings.

## Not yet available

- Repairs that change the operating system's network settings or the router (see the table above). They need administrator rights or a router interface that this build does not have.
- Choosing which adapter a probe leaves from.
