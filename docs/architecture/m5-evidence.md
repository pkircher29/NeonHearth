# M5 Home Editor and 3D Home Twin — evidence record

Recorded 2026-08-24 on the Windows 11 development workstation (branch
`claude/neonhearth-m5-home-twin`). Built by parallel implementation lanes
against the locked contract (`m5-home-twin-contracts.md`), each lane gated
before commit; the M5 gate is proven in a real browser.

## Commits

| Commit | Lane |
|---|---|
| `38e7038` | Contract lock |
| `0eb80e2` | 3D Home Twin (pure geometry + three.js component) |
| `a3f2e75` | 2D snap-to-grid multi-floor editor |
| `6eed143` | Domain + migration 021 + HomeRepository |
| `6c30199` | Home tab integration (HomeView + App wiring) |
| `b79fd8e` | Home service API + HomeChanged events |
| `70d8ad7` | M5 gate browser proof (Playwright) |

## Checklist mapping

- **H1** versioned storage — migration 021 (`home_plans`, `home_plan_history`
  append-only pruned to 100, `home_drafts` 512 KiB cap, `owner_placements`,
  `location_estimates`); optimistic-concurrency saves with typed version
  conflicts; service routes expose it (`/api/v1/home*`).
- **H2** snap-to-grid multi-floor 2D editor — 0.1 m snapping, floor tabs,
  wall/room/opening/place tools, inspector, calibration dimension labels,
  keyboard operation.
- **H3** undo/redo, autosave, schema migration, corrupt-draft recovery —
  bounded 200-entry undo/redo; 2 s draft autosave with resume/discard;
  corrupt current plan recovers from newest valid history row (surfaced as
  `recovered: true`); corrupt drafts discarded and reported, never merged.
- **H4** manual placement + owner precedence — owner placements in their own
  table; estimate upserts leave owner rows byte-identical (tested);
  `effective_location` always prefers the owner.
- **H5** location confidence + evidence stored — `location_estimates` carries
  confidence + evidence list; estimates below 0.6 render only as
  "Estimated only — not confirmed", never as pins.
- **H6** multiple collectors / calibrated inference — the estimate store and
  honest labeling are in place; **calibrated multi-sensor inference itself is
  NOT implemented** (hardware-dependent; remains unchecked).
- **H7** Three.js extrusion — pure plan→scene assembly (slabs, extruded
  walls with real door/window/stair openings, stacked floors), rendered with
  orbit/pan/zoom/reset, floor isolation, hide walls, raycast selection.
- **H8** animation — presence pulses, bandwidth heat, camera view cones,
  selected-device focus animation; live maps derived from LiveState.
- **H9** risk independent from heat — separate ramp/badge channels with
  explicit independence tests.
- **H10** reduced-motion, low-power, WebGL fallback, device-list parity —
  reduced-motion prop OR media query; WebGL-unavailable falls back to the 2D
  editor with a notice; always-present hidden device list mirrors pins.
- **H11** uncertain-device prompt — "Place these devices" banner from the
  <0.6 rule; clears when the owner places the device.
- **M5 gate** — Playwright against the shipped UI (`e2e/home.spec.ts`):
  draw a two-floor home, save (`expected_version` captured), reload and see
  it persist, rotate the real-WebGL twin (drag changes the rendered frame;
  Reset view restores it byte-identically under reduced motion), floor
  isolation, truthful low-confidence labeling, 409 honesty, draft resume.
  Full e2e suite: **7 passed**.

## Verification outputs (final lines)

- `cargo test -p lattice-domain -p lattice-store` — all suites ok (0 failed).
- `cargo test -p lattice-service --test home_api` — ok, 16 passed.
- `cargo test -p lattice-service` — every binary green on Windows
  (after `271404c` fixed two pre-existing Windows-only test defects).
- `cargo clippy -p lattice-service --all-targets -- -D warnings` — clean.
- `npm test -- --run` (apps/desktop) — 17 files, 177 tests passed.
- `npm run check` — 0 errors, 0 warnings. `npm run build` — success.
- `npx playwright test` — 7 passed (home + guard specs), real WebGL path.

## Accepted follow-ups (recorded, not claimed complete)

- Editor→twin selection sync is one-way (twin→editor chip); two-way needs
  optional selection props on `HomeEditorView`.
- `HomeTwin3D` exposes no DOM-observable orbit state (pixel-diff assertions
  used); a `data-camera` attribute would simplify future tests.
- Placement PUTs are fire-and-forget (no 409 semantics like plan saves).
- A draft autosaved before the first committed save is keyed under the
  placeholder home id and is not re-offered after that first commit.
- Conflict-resolution reload does not re-offer an existing draft.

## Home tools v2 (2026-11-15)

Implements `m5-home-tools-v2-spec.md` sections A–F and replaces the Pulse
hearth with a Flow Map (the hearth stays available behind a Flow / Hearth
switch).

Verified on the integration branch `feat/home-tools-v2`:

- `npm run check` — 0 errors, 0 warnings.
- `npx vitest run --exclude 'e2e/**'` — 48 files, 579 tests passed.
- `npx playwright test` — 21 passed, 9 skipped (the Flow Map screenshot and
  live-service scenarios only run with `FLOW_SHOTS=1` / `FLOW_REAL=1`), real
  WebGL path. Includes pinch zoom and two-finger pan driven by real touch
  events through the Chrome DevTools Protocol.
- A release `lattice-service` built from this branch, run isolated with
  `scripts/run-local.py` on a real home network (89 discovered devices, no
  router feed, so no device types, names or per-device counters):
  - Plan editor: rectangle room, a partition landing on two wall bodies
    (both split), Detect rooms → Add all, save. The service stored version 1
    with seven walls carrying `thickness_m` and the two half rooms, and it
    reloaded. The 3D view rendered it with room labels.
  - Device tray: "Unplaced devices · 89" with maker labels and addresses;
    the Inspector stays inside its column and in view.
  - Flow Map: sectors grouped by maker (Home & IoT 41, Unclassified 14,
    Computers 13, Media 8, Cameras 7, Network 4, Private address 2),
    presence visible, this computer's live traffic in the core and history
    ring, application streams. Average frame 16.67 ms, worst 16.8 ms.
  - The 20 s quiet-socket resync no longer flashes "unavailable" (two
    resyncs observed, no flip).
- Flow Map with a 150-device synthetic fixture in headless Chromium:
  average frame 16.67 ms, worst 16.8 ms over 10 s.

Not verified (recorded, not claimed):

- A physical touchscreen, mobile Safari or Android Chrome (touch was
  emulated in desktop Chromium).
- Browsers other than Chromium; the twin detail card on a narrow screen.
- The Flow Map with real per-device counters (no router feed was
  connected), or on an integrated GPU.
- Maker grouping is a hand-made keyword table; 14 of 89 real devices stayed
  Unclassified.
- Ctrl+D on a room copies the room outline, not its walls.
