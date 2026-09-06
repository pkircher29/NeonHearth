# Network home hub tasks

- [x] Compare existing checkouts and isolate the runnable base.
- [x] Document architecture, trust boundaries, acceptance criteria, and verification order.
- [x] Home Assistant adapter with protocol and abuse-case tests.
- [x] Authenticated automation API with bounded control permissions and audit.
- [x] Automation interface with connection and control flows.
- [x] Home map placement for automation devices and location hints.
- [x] MQTT hub setup and authenticated broker verification.
- [x] Build, security checks, browser verification, and evidence report.

- [x] Show observed network IP/MAC addresses and conservative Home Assistant name/room matches.
- [x] Diagnose the collector warning in the restarted QA instance before final handoff.

## Continued delivery

- [ ] Remove the unnecessary Windows packet-driver dependency from interface inventory.
- [ ] Add a native launcher with protected per-user state and authenticated startup.
- [ ] Build a portable package containing the UI, service, launcher, MQTT hub, and license notices.
- [ ] Verify relocated startup, missing components, occupied ports, repeat launch, private files, and actual browser use.
- [ ] Preserve the development instance's observations in the runnable package and record the handoff.
- [ ] Recheck reachable Home Assistant configuration without changing household devices.
- [x] Add numeric IP sorting in both directions, with unknown addresses last; verify in the running UI.
- [ ] Add Avahi integration for Linux and bounded mDNS/Bonjour discovery for Windows.
- [ ] Expose bounded discovery jobs for mDNS/Bonjour, ICMP, SNMP, SMB, and NetBIOS; require explicit owner selection and supplied SNMP credentials.
- [ ] Add validated CDP/LLDP parsing and capture import with truthful local-link visibility.
- [ ] Scan ports across all observed devices with bounded jobs, cancellation, and identification results.
- [ ] Add metric/imperial house-editor units and copy footprints between floors; verify saved geometry, undo, and browser use.
