# Web device identification verification

Verified on Windows on 2026-09-06. An owner-started TCP scan now follows open
recognized web ports with bounded, credential-free HTTP/HTTPS root-page reads.
Reported clues appear on device cards, can be searched, and persist with the
scan. They do not change owner-confirmed identities or grant control permission.

## Local checks

- Full Rust workspace: 931 tests passed, no failures; one existing opt-in broker
  test ignored. This includes 14 new web-identification tests.
- Desktop: 268 tests passed, including plain-text rendering of hostile page
  titles, searching reported clues, preserving owner names and the opt-out.
- Seven Playwright browser regression tests passed.
- Workspace Clippy with warnings denied, rustfmt, Svelte check (zero errors or
  warnings) and production desktop build passed. The existing bundle-size
  advisory remains.
- cargo-deny passed advisories, licenses, bans and sources. npm audit reported
  zero vulnerabilities. The HTTP parser is the already-locked `httparse` crate;
  the lockfile adds a direct dependency edge without adding a package version.

Protocol tests cover fragmented and chunked responses, malformed framing,
header/body size limits, response deadlines, secret-bearing headers, redirect
refusal, non-HTML/compressed bodies, self-signed TLS, owner authorization,
scheme fallback, cancellation, and persistence. Synthetic certificate/key
fixtures are public test material, never production credentials.

## Native package and live scan

The new Windows package was built and run against the existing per-user hub.
The prior service and broker paths were checked before the native launcher
stopped them. A SQLite online backup passed integrity checking; all 75 existing
device records were preserved. MQTT reconnected.

The actual device-screen scan selected ports 80, 81, 443, 5000, 5001, 8006, 8080,
8123 and 8443, with web identification enabled and other protocol probes off:

- 63 devices had eligible local addresses; 12 were skipped.
- 621 connection/follow-up checks completed; 48 TCP ports were open.
- 42 HTTP/HTTPS responses supplied metadata, including 18 page titles and six
  HTTPS responses. The conservative signature rules reported Tasmota clues.
- 519 checks had no response and 11 failed or were unavailable, including
  unsuccessful web-scheme attempts. These do not prove device absence.
- Failed web identification did not erase open-port findings.
- Results survived browser reload and a real native-service restart.
- The real UI was checked at 1500-pixel desktop and 390-pixel mobile widths:
  visible web clues, working search, no horizontal overflow or page errors.

The portable package is `NeonHearth Home Hub Web ID`, with a verified manifest
containing 1099 files. ZIP SHA-256:
`2c7a7fb82157d36d95944da5d4ceabbbc5a5b2eb93a041af8b21d20625243966`.
The previous package and database backup remain available for rollback.

## Limits

Network responses and product signatures are unverified clues. This does not
authenticate a device or guarantee its make/model. No real appliance control was
performed. Web discovery does not sign in, follow redirects, run JavaScript,
decompress bodies, fetch other resources, or send HTTP to unrecognized web ports.
Devices requiring those operations may provide only partial metadata. HTTPS
certificate trust is explicitly unverified; the credentialed Home Assistant
connection continues to require its normal certificate verification.

This package remains unsigned. This run does not establish clean-machine
installation, all physical hardware, all TLS versions, or long-term soak results.
GitHub check results are available on the associated pull request.
