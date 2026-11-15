# Traffic and device recognition validation

The native Windows service and production UI were exercised together on September 6, 2026. A protected copy of the household database isolated name and preference changes from the live home.

## Verified locally

- Rust workspace suite: 940 tests passed. After the final collector/privacy changes, the affected service suite passed 52 tests; the NetBIOS parser suite passed 12 tests after its unique-name correction.
- Desktop suite: 276 tests passed, followed by the expanded Traffic and recognition checks. Svelte validation reports zero errors and warnings. The production bundle builds; Vite retains its existing large-chunk warning.
- Existing browser regression suite: seven tests passed, covering Guard, home editing, and the 3D twin paths.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo deny check`, and `npm audit --audit-level=moderate` passed. The npm audit reported zero known vulnerabilities.
- Native Windows sampling identified 92 process rows and 461 endpoints in the captured QA snapshot. These are a point-in-time observation, not an expected inventory count.
- Real-browser checks passed at 1500 px and 390 px widths: Guard IP/MAC addresses; name confirmation and reload; unchanged Guard policy; offline interface-maker search; live graph updates; pause/resume; time range selection; CSV download; application and connection views; recording preferences; and a traffic target.
- A real native-service restart preserved confirmed names, traffic history, and monitoring settings in the QA database. SQLite integrity passed.
- An intercepted device-page fixture verified that a web link opens a separate browser window without an opener, Authorization header, or referrer. It did not navigate to or control a household device.
- The firewall review dialog was tested with an explicit simulated OS response: Cancel is focused initially, cancellation sends no change, and confirmation sends the observed application ID and selected direction. Browser and console error lists were empty.

## Limits of this evidence

This Windows session did not have administrator authority. Actual privileged TCP extended-counter activation and packet-level firewall blocking were not tested. The interface correctly disables firewall actions when that authority is absent. Linux compilation and regression checks run in GitHub CI; no claim is made of physical Linux-host validation here.

The owner guide records measurement coverage and the GlassWire features still requiring additional collectors or implementations. This is a local monitoring implementation, not a claim of complete GlassWire feature parity or guaranteed security. The portable package is unsigned.

GitHub delivery requires the pull request's checks to pass before merge. Native package activation and its preserved live inventory are checked separately from CI.

## Activated Windows package

`NeonHearth Traffic and Devices/NeonHearth.exe` was activated with an integrity-checked online database backup and the previous package retained. All 76 existing device records were preserved; the authenticated MQTT broker reconnected. Browser verification of the actual instance refreshed 66 addressable devices with 911 bounded checks: 47 open ports, 41 web responses, 18 reported page titles, and five HTTPS responses. Some probes timed out or failed; they do not establish device absence.

A second native restart preserved the discovery results, device labels, and host history. The actual Devices, Guard, and Traffic pages were checked, with no browser errors or horizontal overflow at 390 px width. No household names were confirmed and no firewall or appliance controls were actuated during this live check.

The package contains 1,101 manifested files. ZIP SHA-256: `91b9d67b6a4fbc7ac51d8a876b65a3a474f62ce89f8b01a316d09514d39c5bac`. It includes the owner guide and third-party dependency/source notices, with no runtime database or owner credential.
