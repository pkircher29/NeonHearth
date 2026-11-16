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
(The store is tested with a throwaway write, read and delete first. A service
account usually has no keyring session, on Linux or on Windows, where the
Credential Manager refuses a service logon; in that case the service uses an
encrypted file in its own state directory instead, readable only by the
service and administrators.) The database holds only opaque references. (See "Where the password is kept" below for what happens to a password you type into the add-camera form.) Credentials are never displayed,
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
is refused unless explicitly allowed for that camera when you add it.

### Supported camera types

Only cameras that speak RTSP (most IP cameras, including ONVIF cameras that
publish an RTSP stream) can be viewed. The video must be one ffmpeg can remux
(H.264 or MJPEG). There is no support for cloud-only cameras, USB or
doorbell-app cameras, or encrypted RTSP.

## Adding and removing a camera

Open **Cameras** as the owner and use **Add a camera**. The form only appears
when camera media is running on this machine (see "What this machine needs"
above) and only to the owner: a paired phone cannot add or remove a camera, and
neither can an integration token.

You enter the camera's **address**, the **user name and password** you use to
sign in to the camera, and optionally a name. The address must be an IPv4
address such as `192.168.1.50`, not a hostname. Leave **Allow less secure
sign-in (Basic)** off unless the camera cannot sign in any other way; Basic
sends the camera's password without protection on your home network.

### What is checked

Before anything is sent to the camera, the address must be:

- a private IPv4 address (`10.x.x.x`, `172.16.x.x` to `172.31.x.x`, or
  `192.168.x.x`), never a public, loopback, link-local, multicast, broadcast,
  unspecified or IPv6 address, and never a hostname (so there is no name lookup
  an attacker could change later);
- inside the subnet of a network adapter that is up and is a real wired or
  Wi-Fi adapter (not a VPN or tunnel, virtual machine or container adapter, or
  one you marked as a corporate connection);
- not one of this computer's own addresses, and not the network or broadcast
  address of that subnet.

Then, in this order:

1. At most six attempts per minute are accepted, so the form cannot be used to
   try passwords against devices on your network.
2. The attempt is written to the audit log (`camera_add_requested`) before any
   packet is sent. The log records the address and the adapter, never the user
   name or the password.
3. NeonHearth asks the camera for its details and its video streams over
   ONVIF (a few cameras answer with an empty SOAP header and no
   WS-Addressing; that is accepted, while a header that is present but wrong is
   not), at exactly that address and port (80 unless you change it), through
   the adapter the address was approved on. It follows no redirects and ignores
   proxy settings, signs in with a one-time digest so the password itself is
   not sent, and refuses answers larger than a fixed limit.
4. **Every video address the camera reports must point at the same host you
   entered**, and so must any service address it advertises. A camera that
   points its video somewhere else is refused.
5. Only then is anything kept: the password and the stream addresses go to the
   credential store, and one database transaction records the camera, its
   streams and your approval of that one address. If a step after the
   credential was written fails, what was written is removed again.

Each failure has its own plain message: the address is not on your network, the
camera could not be reached, it refused the user name or password, it points its
video somewhere else, ONVIF does not appear to be enabled on it (the camera
answered "no such page" to the first ONVIF request, which is what a camera does
when ONVIF is switched off in its settings), it did not answer like a camera, it has no video stream,
a camera is already added at that address, or video support is not available on
this machine (with the reason).

### Where the password is kept

The password is not stored in the NeonHearth database or in any log, audit
entry, error or response. It is held in memory only while the camera is being
added, and is then kept in the same place as every other camera secret: the
operating-system credential store (Windows Credential Manager, or the Secret
Service keyring on Linux), or, where the service has no keyring session, an
encrypted file in the service's own state directory. It is kept inside each
stream's saved address, which only the local media proxy reads when a live view
starts; the browser never receives it. The app clears the password field as
soon as you submit the form.

### Your approval is re-checked every time

The approval of one address for one camera is stored with the camera. At every
service start the list of approved cameras is rebuilt from it, and every live
view or snapshot re-checks the address against the network adapters as they are
at that moment. If the adapter went down, was renamed or moved to another
subnet, or the address now belongs to this computer, the camera simply cannot be
viewed until the network matches again. Nothing falls back to another adapter.

### Removing a camera

Select the camera and choose **Remove camera**, then confirm. Because removing
is a revocation, it acts first: open live views are closed and the approval is
withdrawn before anything else, then the stored password and streams and the
database records are deleted, and the removal is written to the audit log. If
the credential store cannot delete something, the camera stays switched off and
the app says the removal is not finished; removing it again retries.

### What has been proven on real hardware

One camera family has been tried end to end: a FLIR PE133F (Dahua-family
firmware) on a home network, with NeonHearth on Windows and ffmpeg 8.1. Adding
it over ONVIF, reading its details, taking snapshots and watching live view
through ffmpeg all work. Two things that camera does are handled because of
it: it answers ONVIF with an empty SOAP header, and it gives its stream address
with a query string (`...?channel=1&subtype=1...`) that is kept exactly.

Cameras whose RTSP stream needs no login are supported. If the camera never
asks for credentials, none are ever sent to it (this is safer than sending them
unasked); the stored address still carries them for the cameras that do ask,
and only answers a challenge the camera itself makes. HTTP Basic login stays
off unless you allowed it for that camera.

Only that one camera family has been tried. Other makes differ in how they
speak ONVIF and RTSP, so expect some to need fixes; if adding or viewing fails,
the service log now says which step failed and why, and for a failed ffmpeg run
it includes a short excerpt of ffmpeg's own message with every address, token
and credential masked.

### What adding a camera does not do

- It does not detect cameras for you. Cameras the network monitor recognizes are
  not turned into viewable cameras automatically; you add each one yourself.
- It does not bundle ffmpeg on Windows (see "What this machine needs").
- It does not set up a camera's Wi-Fi or any other setting on the camera.
- The camera's names, models and other details come from the camera and are
  shown as the camera reports them; the optional name you type is stored but is
  not yet shown in the list.
- It speaks plain-HTTP ONVIF only (no encrypted ONVIF). It starts at
  `/onvif/device_service` on the address and port you gave. If the camera then
  names its media service on that same address and port (for example
  `/onvif/media_service`), the profile and stream steps are sent there; a
  service address on any other host, port or scheme is never contacted, and a
  camera advertising one is refused.
- The camera's user name may be 1 to 128 characters and may contain only
  letters, digits, dot, underscore and hyphen, so a plain `admin` works but an
  email-style user name (with `@`) or one with a space cannot be used yet. The
  password may contain anything, up to 256 bytes.

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
  streaming, snapshots, cleanup) and adding and removing a camera are verified
  end-to-end against fixtures and a stand-in device on this computer, and are
  built into the running service. Adding, snapshots and live view have been
  proven on one real camera (see "What has been proven on real hardware"); the
  documented acceptance procedure has not been run across other makes, and
  cameras differ in how they answer ONVIF and RTSP, so expect some to need
  fixes.
- Automatic camera detection that creates a viewable camera: you add each
  camera yourself (see "Adding and removing a camera"), and nothing the network
  monitor recognizes becomes a camera on its own.
- ffmpeg bundled with the Windows installer, camera Wi-Fi setup, encrypted
  (HTTPS) ONVIF, and showing the name you give a camera in the list.
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
