# Cameras and security

## Camera detection

NeonHearth identifies camera candidates from network evidence (ONVIF and
WS-Discovery announcements, RTSP and related services) and shows each
verified camera with a **detection confidence percentage** and its
classification. Confidence is shown, not hidden — a camera card says, for
example, "92% confident," and inventory fields that are not known say
"Unavailable."

## Inventory

Selecting a camera shows what the collector was able to inventory:
manufacturer, model, owner serial, firmware, and an inventory health state
(healthy / degraded / unknown). Inventory requests are bounded and run only
against explicitly approved private targets on your own network.

## Credentials stay in the operating-system vault

Camera credentials live in the platform secret store — Windows Credential
Manager on Windows, the Secret Service keyring on Linux — and nowhere else.
The database holds only opaque references. Credentials are never displayed,
never logged, never included in errors or exports, and never sent to the
desktop app. When a stream needs authentication, a local loopback proxy
inside the privileged service injects the credential; the raw camera URL and
password never reach your browser window.

## Live view and snapshots

- **Snapshot** captures a still image on demand.
- **Start live view** opens a short-lived local streaming session: the
  service transcodes the camera's stream to HLS on your machine and the app
  plays it. Playlist and segment requests are authenticated like everything
  else.
- Sessions are deliberately temporary: closing the view, or about 30
  seconds of idle, ends the session, stops the media process, and removes
  its temporary files. Nothing is recorded by default.

## Advisory findings

Security findings come from cached advisory data (vendor advisories, NVD,
and the CISA Known Exploited Vulnerabilities list) matched against a
device's inventoried identity, and are served per device from the local
store. Two things keep findings honest:

1. **Match labels.** Every finding is labeled **exact** (vendor, model, and
   firmware all matched at high confidence), **possible**, **contradicted**,
   or **unknown** — with a plain-language explanation of which fields
   matched. An "exact" label cannot exist without all three fields.
2. **Five separate risk dimensions.** Risk is never one scary number. Each
   finding carries independent values for **severity**, **exploitability**,
   **exposure**, **confidence**, and **remediation**. A critical-severity
   advisory with unknown exposure and low confidence reads exactly that
   way.

## Confined audit modules

Deeper security checks run inside a locked-down sandbox with hard rules
enforced by the service, not by the module:

- **Owner approval is mandatory** — a module without your approval is
  refused before it starts.
- **One private target only** — each run is bound to a single approved
  target (exact address, interface, and port, re-verified on every
  exchange). It cannot talk to anything else.
- **Budgets** — byte, compute, and memory limits plus a hard deadline; a
  module that exhausts any budget is stopped, and results are evidence, not
  permission to scan further.

## Firmware research is research only

NeonHearth's standing rule: it never downloads or flashes replacement
firmware automatically, and never will. Any future firmware research feature
presents information for you to act on yourself.

## Not yet available

- Real-camera acceptance is still pending: the whole camera pipeline
  (detection, inventory, vault, streaming, cleanup) is verified end-to-end
  against fixtures, but no owner-supplied physical camera has been through
  the documented acceptance procedure yet.
- An in-app flow for entering camera credentials (credentials are supplied
  through the operating-system vault; a guided prompt is planned).
- A findings/advisories panel in the app (findings are served by the
  authenticated per-device advisory API; the on-screen surface is pending),
  and scheduled advisory-feed refresh with staleness labeling.
- Launching confined audit modules from the app (the sandbox and its rules
  exist in the service; there is no owner-facing trigger yet).
- Alternative-firmware research (not implemented in this build).
- Authenticated ONVIF operations beyond the bounded inventory shown, and
  camera recording (live view is not recorded by default and no recorder
  exists yet).
