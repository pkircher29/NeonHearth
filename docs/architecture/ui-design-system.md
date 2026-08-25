# NeonHearth visual design system v2 — "daylight hearth"

Locked 2026-08-25 (v2, supersedes the dark v1 — the owner pointed at
GlassWire as the inspiration). Reference screenshot:
`C:\Users\Paul\AppData\Local\Temp\claude\C--Users-Paul\7c79c6d0-64cc-4e19-a048-0888fbfdb358\scratchpad\gw-graph.png`
— study it before styling anything. What we take from GlassWire: light,
airy, consumer-grade softness; top tab navigation as icon+label pills; the
hero visualization fills the view edge-to-edge with white pill controls
floating OVER it; a bottom stat band with big bold numbers, an arc gauge,
and a mini stacked-area timeline; a two-color down/up data language used
consistently everywhere. What stays NeonHearth's own: a warm paper tint
instead of GlassWire's cool white, ember/rose instead of yellow/pink, the
Fraunces display voice, mono readings, and the coals presence language.
Inspired, never cloned: no world map, no GlassWire iconography.

## Palette (tokens in app.css; never hardcode hex in components)

| Token | Hex | Role |
|---|---|---|
| `--ground` | `#FAF6EF` | page ground — warm paper, never grey-blue |
| `--surface` | `#FFFFFF` | cards, floating pills, nav |
| `--surface-2` | `#F2ECE1` | wells, hover, segmented-control track |
| `--line` | `#E7DECF` | hairlines |
| `--ink` | `#2E261C` | primary text (warm near-black) |
| `--ink-mute` | `#93836E` | secondary text, small labels |
| `--down` | `#F0AD2D` | download / inbound — amber (data duo #1) |
| `--up` | `#E4688C` | upload / outbound — rose (data duo #2) |
| `--ember` | `#E8853C` | brand accent: active tab, links, selection, focus |
| `--sage` | `#3F9C7B` | OK/verified/enabled toggles |
| `--alert` | `#D9534A` | danger/quarantine/blocked only |

Rules: `--down`/`--up` are the ONLY colors for traffic data (areas,
gauges, WAN/LAN bars) — used everywhere traffic appears, never for chrome.
Security risk uses `--alert` badges/outlines only (H9 discipline). The
product-spec'd twin data ramp in `twin/heat.ts` stays untouched.

## Type (bundled @fontsource, zero external requests)

- **Display — Fraunces** (600/900): one hero line per view, big stat
  numbers in the stat band (it has lovely numerals). NeonHearth's voice.
- **Body — IBM Plex Sans** (400/500/600): everything readable, nav labels.
- **Data — IBM Plex Mono** (400/500): timestamps, ids, rates, eyebrow
  labels (small, `--ink-mute`, +0.12em caps).

Scale: eyebrow 11px mono caps / body 14.5px / h2 18px sans 600 / display
28–40px Fraunces / stat-band numbers 26px Fraunces 600.

## Structure (the GlassWire lesson)

- **Top tab bar** (replaces the left sidebar): white bar, wordmark left,
  tabs as icon+label; the active tab is a `--surface-2` rounded pill with
  `--ember` icon+text. Mobile: same tabs collapse to the existing bottom
  nav.
- **Hero fills the view**: each view's primary surface (Pulse hearth graph,
  Devices list, Home twin) runs edge-to-edge on `--ground`; controls float
  over it as white pills with the soft shadow (`0 2px 12px rgb(46 38 28 /
  0.10)`), fully rounded (999px) for single controls, 14px radius for
  cards.
- **Pulse stat band** (signature layout moment, straight from the
  reference): bottom band with download big-number + rate (amber arrow),
  an arc gauge in `--down`→`--up` sweep with the total centered, upload
  big-number + rate (rose arrow), WAN/LAN mini bars — then a full-width
  stacked soft-area mini timeline (amber under rose, 60% opacity fills,
  smooth curves) with a time scrubber. Honesty rule: when coverage is
  unavailable the band shows an em-dash and the coverage label — never a
  fake zero line.
- Density: whitespace is a feature — 24px card padding, 16px gaps, let it
  breathe like the reference.

## Signature: coals, in daylight

Presence dots stay the coals language, tuned for light ground: **online** =
`--ember` dot with a soft warm halo (the only glow); **quiet** = solid
`--ink-mute` dot; **offline** = hollow ring; **blocked** = hollow ring in
`--alert`; **unknown** = dashed ring. The Pulse hearth visualization
becomes a soft amber/rose breathing area — daylight fire, not neon.

## Voice

Unchanged from v1: honest instrument copy, sentence case, empty states
invite action, mono eyebrows for wayfinding.

## Floor

Responsive to 390px; `--ember` 2px focus rings; prefers-reduced-motion =
no breathing/pulse, static states; AA contrast (`--ink-mute` on
`--surface` and `--ground` must pass 4.5:1 — darken if needed; `--down`
amber is never used for text smaller than 18px).
