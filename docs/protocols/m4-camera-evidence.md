# M4 camera evidence gate

Status: **PENDING — no owner device has been observed.**

This gate is the only path from fixture verification to a real camera. It may be
run only by the owner on an owner-approved private subnet and interface. The
service must retain `TargetGuard` approval for the exact numeric target before
each ONVIF or media operation. Public, CGNAT/Tailscale, loopback, multicast,
cross-interface, and guessed endpoints remain out of scope.

## Fixture gate

The automated gate uses no network or camera hardware:

```sh
cargo test -p lattice-service --test camera_end_to_end
cargo test --workspace
cd apps/desktop && npm test && npm run check && npm run build
```

It composes normalized passive and active evidence, bounded ONVIF inventory,
the fake vault, fake HLS process, authenticated API projections, snapshot, and
idle cleanup. The fixture stores the stream source only behind an opaque vault
reference; no credential, raw RTSP URI, SOAP, header, target address, or MAC
may appear in JSON, support export/debug output, diagnostics, media arguments,
or temporary artifacts.

## Owner real-host procedure

1. Confirm the owner-administered interface and a narrow private subnet are
   explicitly approved in the UI; record the approval decision without copying
   an address or hardware identifier into this document.
2. Supply a camera credential through the operating-system vault prompt. Never
   place it in a command line, environment variable, ticket, log, fixture, or
   inventory export.
3. Run the service locally and use the authenticated Cameras view to request
   inventory, a snapshot, and a short HLS session. Observe that session close or
   idle expiry removes its artifacts and terminates the process/proxy.
4. Capture only sanitized evidence in this format:

   ```text
   observed_at=<UTC>; approved_private_target=true; family=<onvif|ws_discovery|rtsp|http|tls>;
   fact=<allow-listed normalized fact>; confidence=<0.0..1.0>; result=<pass|fail>
   ```

   Do not record raw IP or MAC values, usernames, passwords, RTSP URIs, SOAP,
   raw headers, serials, source references, FFmpeg arguments, or screenshots
   containing them.

Windows PowerShell:

```powershell
cargo test -p lattice-service --test camera_end_to_end
cargo check --workspace --target x86_64-pc-windows-msvc
Set-Location apps/desktop; npm test; npm run check; npm run build
```

Linux:

```sh
cargo test -p lattice-service --test camera_end_to_end
cargo check --workspace --target x86_64-unknown-linux-gnu
cd apps/desktop && npm test && npm run check && npm run build
```

Tailscale may provide the private phone UI path, but it is not a camera probing
network and must never be approved as a discovery or ONVIF target.

## Acceptance record

Real-camera acceptance remains **PENDING** until the owner performs the above
procedure with an approved device and supplies a sanitized observation. This
document deliberately contains no invented hardware result.
