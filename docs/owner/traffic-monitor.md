# Traffic, device recognition, and Guard

Open **NeonHearth.exe**, then choose **Traffic**. The collector observes this computer every two seconds. It continues to collect while you use other pages.

The graph shows upload and download separately. Choose a time range or application, click a reading (or use the reading selector), and pause/resume the graph. Pausing freezes the view; collection continues. CSV export is available for traffic, application usage, and connection history. The compact graph stays visible within the Traffic page.

**Applications** lists programs with observed TCP or UDP sockets, executable paths when the OS permits access, sampled TCP usage when available, memory, and first/last observation times. **Connections** shows local and remote addresses/ports, current state, and saved observations. UDP listeners usually do not report a remote peer.

**Alerts** records newly observed applications and TCP connections using the standard RDP port. A port observation is a clue, not proof of an authenticated remote-desktop session. Mark alerts reviewed or snooze their badges while keeping the history. Preferences control recording, retention, and a monthly host-traffic target. Monthly totals use retained data in the UTC calendar month and include local-network traffic; they do not estimate missing data or an ISP bill.

## What is measured

- Physical-interface totals cover this computer's traffic across active wired and Wi-Fi adapters, including local-network traffic. Virtual/VPN adapter totals are excluded from the combined total to avoid double counting.
- Application byte counters use Windows TCP extended statistics when available. They cover sampled TCP payload bytes. Short connections between samples and UDP bytes are not attributed. A complete per-application packet/event collector is still needed for full GlassWire-style attribution.
- A sleep, counter reset, missing permission, or unavailable source produces a gap or an unavailable label. Zero is used only when a valid measurement reports zero.
- This computer's application activity is distinct from the Devices inventory of the home network. Measuring all other devices' bandwidth requires router or network capture coverage.
- Linux reads interface counters and socket ownership from `/proc`; process visibility depends on OS permissions. Application byte counters and application firewall changes are unavailable in this Linux adapter.

Windows administrator permission is required to enable TCP extended counters and modify firewall rules. Ordinary launches still show connection ownership and physical-interface totals. The app never elevates silently.

For the portable Windows package, stop its current instance with `NeonHearth.exe --stop`, then right-click the same `NeonHearth.exe` and choose **Run as administrator**. Approve the Windows prompt only if you intend to enable those capabilities. Starting another copy while the ordinary collector is already running does not elevate that collector.

## Application firewall

Choose an application, select **Block inbound** or **Block outbound**, and review the executable and direction. The service resolves the executable from observed inventory. Windows confirms the rule state; the UI reports that confirmation separately from observed traffic. If Windows Firewall profiles are disabled, the rule may not enforce on those networks.

**Release** removes only the corresponding NeonHearth block. Other Windows firewall policy still applies. Monitoring, MQTT, critical system programs, and remote-access helpers are protected. Owner authority is required, stale rule states are rejected, and each attempt is audited. A failure or timeout should be followed by refreshing the actual Windows rules before retrying. Rule verification is not a packet-level proof that an established flow was terminated.

## Recognizing devices

Devices combines Home Assistant matches, Bonjour/mDNS metadata, web-page clues, and other discovery results. Icons indicate a reported device category. The interface-maker field uses 58,412 bundled [IEEE address assignments](https://standards.ieee.org/products-programs/regauth/), retrieved September 6, 2026. This identifies the registered network-interface organization; it does not prove the finished product's manufacturer or model. Private/randomized MAC addresses and conflicting public assignments remain unassigned.

Discovered names ask **Is this the right name?** Confirm the label, edit it, or choose Later. Confirmed names survive discovery and restarts. **Confirm name** does not approve the device's network access or enable appliance controls.

Bonjour service types are excluded from name suggestions. NetBIOS suggestions require an active unique node name; workgroup/domain names and conflicting names are excluded using the [RFC 1002 node-status flags](https://www.rfc-editor.org/rfc/rfc1002#section-4.2.18). Older NetBIOS results need a new scan before they can supply a name suggestion.

Guard shows the device's IP and MAC addresses beside its policy. **Open HTTP/HTTPS** opens the numeric address and port observed in the scan in a separate window/tab with no NeonHearth credentials or referrer. Device-provided redirects are never used to construct those links. Check the device and any certificate warning in the browser, especially if the address has changed since scanning.

## Privacy and present limits

Storage stays local. No device inventory, process list, application file, or destination list is uploaded to a recognition/reputation service. Disabling history stops subsequent history writes while preserving existing history and live readings. Retention removes expired records, with hard limits of 500,000 minute buckets, 20,000 endpoints, and 2,000 alerts.

This implements the core local-monitoring workflow inspired by [GlassWire](https://www.glasswire.com/features/). It does not yet provide full packet/event attribution, ask-before-connect enforcement, global lockdown, firewall profiles, geolocation, reputation scanning, Wi-Fi evil-twin detection, remote-collector management, or system-wide CPU/disk/GPU instrumentation. Existing NeonHearth Home Assistant, MQTT, Guard, and 3D home-map features remain separate capabilities.

No software can guarantee 100% security. The current package is unsigned; the validation report describes the checks performed and the limits of those checks.
