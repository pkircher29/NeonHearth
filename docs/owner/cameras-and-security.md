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
(The Linux service runs as a system user with no desktop session, so there it
normally uses an encrypted file in its own state directory instead; Windows
never falls back to a file.) The database holds only opaque references. Credentials are never displayed,
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

### What this machine needs

Live view and snapshots start with the service and are on only when every one
of these holds. If one does not, the rest of NeonHearth is unaffected, and the
Cameras view says in plain words which one failed and what to do (the same
answer is at `GET /api/v1/camera-media`).

- **Windows or Linux.** Other systems cannot verify which process is reading
  the local stream, so camera media stays off there (`unsupported_platform`).
- **ffmpeg at one exact place.** NeonHearth never searches `PATH` for it. It
  looks at the absolute path in the `NEONHEARTH_FFMPEG` setting of the
  service, otherwise at `C:\Program Files\NeonHearth\ffmpeg.exe` on Windows
  or `/usr/bin/ffmpeg` on Linux. The Linux packages install ffmpeg as a
  dependency. The Windows installer includes ffmpeg only when it was built
  with the optional bundled-ffmpeg component; if yours was not, install an
  `ffmpeg.exe` at that path (or set `NEONHEARTH_FFMPEG`) and restart the
  service (`ffmpeg_not_found`, or `ffmpeg_not_executable` on Linux when the
  file lacks the executable bit).
- **A usable credential store** (`vault_unavailable` otherwise).
- **A writable service state directory**, where the temporary video folder
  `camera-media` lives (`output_dir_unavailable` otherwise). Anything left in
  it by a crash or power loss is deleted at every service start, and a single
  live session is closed if it grows beyond its disk budget.

Camera passwords are only ever sent over the network to a camera address that
you have approved, on the interface you approved it for. Loopback, unspecified
and multicast addresses are always refused. HTTP-style Basic login to a camera
is refused unless explicitly allowed per camera.

### Supported camera types

Only cameras that speak RTSP (most IP cameras, including ONVIF cameras that
publish an RTSP stream) can be viewed. The video must be one ffmpeg can remux
(H.264 or MJPEG). There is no support for cloud-only cameras, USB or
doorbell-app cameras, or encrypted RTSP.

### Adding a camera is not possible yet

The viewing half of the pipeline is built and runs when the list above holds,
but this build has **no way to add a camera**: no screen or route for entering
a camera's address and password, for approving that address as a stream
target, or for reading the camera's ONVIF profiles. Cameras the network
monitor recognizes are not turned into viewable cameras automatically.
Until that is built, the Cameras view stays empty and says so. It is not a
setup you can finish by hand.

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

**No audit module can be run in this build.** The module host (a WebAssembly
sandbox) is built and tested as a separate component, but it is not part of
the service: the service cannot load or run a module, and nothing records
audit-module activity. The rules below are what the host enforces and what
the service is meant to enforce once it is connected. They describe the
design, not something you can use today.

The planned rules:

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

- Real-camera acceptance is still pending: the viewing pipeline (vault,
  streaming, snapshots, cleanup) is verified end-to-end against fixtures and
  is now built into the running service, but no owner-supplied physical
  camera has been through the documented acceptance procedure yet.
- Any way to add a camera: entering its address and credentials, approving it
  as a stream target, ONVIF profile discovery, and turning a recognized
  camera into a viewable one (see "Adding a camera is not possible yet").
- A findings/advisories panel in the app (findings are served by the
  authenticated per-device advisory API; the on-screen surface is pending),
  and scheduled advisory-feed refresh with staleness labeling.
- Confined audit modules. The sandbox is built and tested as a separate
  component, not part of the service; no module can be run in this build, from
  the app or otherwise.
- Alternative-firmware research (not implemented in this build).
- Authenticated ONVIF operations beyond the bounded inventory shown, and
  camera recording (live view is not recorded by default and no recorder
  exists yet).
