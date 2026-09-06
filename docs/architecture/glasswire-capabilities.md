# Network and application visibility

NeonHearth is implementing the capabilities described in the [GlassWire feature list](https://www.glasswire.com/features/) and [user guide](https://www.glasswire.com/userguide/) using its own local collector and interface. These references describe behavior, not code or licensed recognition data.

## Acceptance criteria

- Device discovery combines observed addresses, IEEE assignments, Home Assistant, protocol discovery, and bounded web identification. Identity remains advisory until the owner confirms a name.
- Guard shows IP/MAC addresses, suggested-name confirmation, and credential-free links to observed HTTP/HTTPS endpoints. Naming cannot alter policy or appliance permissions.
- Traffic monitoring separates this computer's interface counters, application connections, and home-network measurements. Missing counters and sampling gaps remain visible.
- Time ranges, upload/download graphs, usage totals, application/host filters, CSV export, and connection history use persisted observations.
- New application/network access and remote-desktop observations appear in a bounded local alert history. Alert dismissal/snoozing must not disable collection.
- Application firewall actions resolve a previously observed executable on the server, require owner authority and OS privilege, and affect only NeonHearth-owned rules. Direction, pending outcome, errors, and release remain visible.
- Advanced capabilities (geolocation, reputation feeds, prevention of all new connections, Wi-Fi impersonation detection, remote collectors, resource counters) must report their actual data source and coverage; unavailable integrations must not be represented as working.

No program can guarantee 100% security. The implementation uses least privilege, local storage, bounded parsers, authenticated control, explicit results, and regression checks. It does not transmit application files, addresses, or inventory to third parties by default.

## Offline manufacturer facts

The bundled address-assignment data contains prefixes and organization names from the [IEEE Registration Authority public listings](https://standards.ieee.org/products-programs/regauth/). MA-L, MA-M, MA-S, and IAB are matched longest prefix first. Conflicting public entries remain ambiguous. Locally administered or multicast addresses do not receive an organization guess. This is the registered network-interface organization, which can differ from the finished product's brand.

`scripts/update-mac-registry.py` refreshes these public facts explicitly at build-maintenance time, records source hashes and retrieval time, and excludes postal addresses. Runtime lookup is offline. The source listings remain attributed to IEEE; no endorsement is implied.
