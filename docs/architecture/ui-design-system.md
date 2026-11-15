# NeonHearth visual design system

Revised 2026-11-15 to describe the app as it is. The earlier "glass, chrome and fire" v3 (2026-08-25) was never
implemented as written: the shipped UI is a matte blue-black instrument with one cyan accent, and this document now
follows the code (`apps/desktop/src/app.css`, `ui.css`). The principles that still hold are kept below.

## Principles (unchanged)

1. **Honesty first.** Missing data is never drawn or written as zero or as real. A value the collector did not report
   is shown as "unavailable" or an em-dash; a one-sided reading (upload without download) is shown as one-sided and is
   never summed into a total. Anything last-known (collector offline) is labelled as last-known, rate figures are
   withheld, and owner actions are disabled. The single derived signal is `liveStatus()` in `stores/live.ts`.
2. **Risk never uses the traffic ramps.** Orange to gold (download) and violet to magenta (upload) mean traffic only.
   Blocked, quarantined and failed states use the flat risk colour (`--risk`) with a ring or an icon, never a gradient.
3. **Motion is decoration.** Every animation honours `prefers-reduced-motion` and the in-app switch (Settings,
   `data-motion="reduced"`). Canvas and WebGL loops pause when the tab is hidden or off-screen and stop painting when
   nothing moves. Readings never depend on motion.
4. **Colour is never the only cue.** Presence, risk and health also differ by shape (filled, hollow, dashed, ringed) and text.
5. **Offline first.** Fonts and scripts are bundled; the page makes no third-party request (see CSP in `index.html`).

## Tokens (defined in `app.css`; components use these, never raw hex)

| Token | Value | Role |
|---|---|---|
| `--bg` | `#061019` | page ground (blue-black, cyan bias) |
| `--surface`, `--surface-raised` | `#0b1c26`, `#102a35` | panels and raised controls |
| `--line`, `--line-mid`, `--line-strong` | `#17323d`, `#20424b`, `#28505a` | borders, three steps |
| `--ink` | `#e9fbfc` | primary text |
| `--muted-strong`, `--muted`, `--faint` | `#9bb7bb`, `#77959d`, `#64838b` | secondary text, three steps (`--ink-mute` is an alias of `--muted-strong`) |
| `--accent`, `--accent-ink` | `#63f3f0`, `#063a3c` | brand accent, text on it |
| `--blue`, `--gold`, `--pink` | `#548cff`, `#ffcd66`, `#ff5c9b` | palette colours; `--gold` is the focus ring |
| `--tier-blue/cyan/gold/pink` | blue, accent, gold, pink | the four bandwidth tiers, shared with `twin/heat.ts` |
| `--ok`, `--watch`, `--risk`, `--info` | accent, gold, pink, blue | semantic status, separate from the tier ramp |
| `--risk-ink` | `#ffb4cc` | text on a risk-tinted surface |
| `--fire-blue/violet/magenta/orange/gold`, `--alert` | `#3d5afe`, `#7c4dff`, `#e040fb`, `#ff6d3b`, `#ffc53d`, `#ff4757` | Flow Map ramps and its blocked ring; read by `FlowMap.svelte` |
| `--radius-sm`, `--radius`, `--radius-lg` | 5, 8, 12 px | shape |
| `--focus` | `3px solid var(--gold)` | focus ring (non-gradient) |

A vitest scan (`src/css-tokens.test.ts`) fails on any `var(--name)` that nothing defines and on hex alpha glued to a
`var()`; use `color-mix(in srgb, var(--x) N%, transparent)` for translucency.

## Type (bundled with `@fontsource`, zero external requests)

- **Instrument Sans (variable)**: UI text and display (`--font-body`, `--font-display`).
- **IBM Plex Mono** (400, 500): readings, ids, timestamps, eyebrows and anything that lines up (`--font-mono`).

## Structure

- **Left rail** (170 px) with the wordmark and the ten destinations; a **right events rail** (260 px) with the Live
  thread and the collector status; the main column between them. Below 850 px the rails collapse to a top bar and a
  bottom navigation with a "More" drawer.
- Destinations: Pulse, Devices, Traffic, Guard, Cameras, Home, Automation, Doctor, History, Settings.
- Panels are flat `--surface` with a 1 px `--line` border. There are no glass or blur surfaces in the design; the few
  overlays that blur (`backdrop-filter`) are cosmetic and not relied on for legibility.
- Sign-in is a full-page state, not a modal: after a 401 with no credential the app shows the sign-in view (owner token
  or phone pairing code). The PIN step-up is a modal dialog that traps focus and closes on Escape.

## Pulse

The **Flow Map** is the default Pulse hero and the **Hearth** is the alternative (switch in the panel, remembered per
browser). Both are canvas drawings fed by per-device counters; neither invents data.

- Flow Map: the gateway sits in the centre; devices are grouped into sectors by confirmed type, then by MAC maker
  (inferred sectors are drawn with a dashed rail and a trailing `~`, never like a confirmed type), then "Unclassified".
  Download particles run orange to gold, upload violet to magenta. A 60 s ring around the core shows complete readings
  only and breaks across gaps. Without per-device counters it can show this computer's traffic, labelled as such.
- Nodes: online is a filled disc, quiet a violet ember, offline a hollow ring, blocked a flat `--alert` ring, unknown a
  dashed ring, online-without-counters a dim disc with no stream.
- When the collector is offline every node is last-known: no rate, no stream, and tooltips and the screen-reader list say
  "last known".
- Hearth: arcs for download and upload, one spark per device.
- Below the hero: throughput, coverage, the throughput curve (breaks across time gaps), top devices, recent events.

## Home

A plan editor (walls, rooms, openings, floors, owner-confirmed device placement) and a 3D twin that shares one
snapshot. The editor enforces the storage limits (2048 walls, 256 rooms, 256 corners, 64 openings, 64 floors) and keeps
ids unique; a draft is flushed on leaving the view; keyboard shortcuts act only while the editor tab is visible and the
single-letter ones can be switched off in Settings. The plan canvas has one tab stop and arrow keys move between items.
The twin shows pins as "unknown" and says so while the collector is offline.

## Accessibility floor

- Responsive down to 390 px with no horizontal page scroll.
- Focus ring is always visible (`--focus`); tab lists use roving tabindex with arrow, Home and End keys.
- Text on `--bg` and `--surface` meets WCAG AA at the sizes used; the faint step is for non-essential captions.
- Reduced motion is honoured in CSS and in every canvas loop.
