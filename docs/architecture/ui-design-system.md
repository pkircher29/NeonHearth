# NeonHearth visual design system v3 — "glass, chrome, and fire"

Locked 2026-08-25 (v3, supersedes v2). Owner's brief, verbatim intent: make
it look like **glass and chrome and fire of all colors — make it cool.**
This is a dark, premium, glassmorphic instrument: frosted panels floating
over a near-black void, chrome-metal accents, and a full-spectrum flame —
blue through violet, magenta, orange, gold — as the living element. Think
high-end audio/gaming software, not a dashboard. The GlassWire lessons that
survive: the hero fills the view, controls float over it, a bottom stat
band with big numbers and a stacked-area timeline, one consistent two-ramp
traffic language.

## Palette (tokens in app.css; never hardcode in components)

| Token | Value | Role |
|---|---|---|
| `--void` | `#0B0B10` | page ground — near-black with a violet breath |
| `--void-glow` | radial washes of `#1A1030`/`#241137` at ~40% | ambient aurora behind everything, fixed, subtle |
| `--glass` | `rgba(255,255,255,0.07)` + `backdrop-filter: blur(22px) saturate(1.5)` | every panel/card |
| `--glass-strong` | `rgba(255,255,255,0.12)` | hover, active pill, inputs |
| `--glass-line` | `rgba(255,255,255,0.16)` | 1px panel borders; top edge highlight `rgba(255,255,255,0.28)` |
| `--chrome` | `linear-gradient(160deg,#E9EDF4 0%,#98A1B3 32%,#F5F8FD 50%,#7C8698 68%,#DADFE9 100%)` | metallic: wordmark, key bezels, gauge ring, slider thumbs |
| `--fire-blue` | `#3D5AFE` | flame spectrum 1 |
| `--fire-violet` | `#7C4DFF` | flame spectrum 2 |
| `--fire-magenta` | `#E040FB` | flame spectrum 3 |
| `--fire-orange` | `#FF6D3B` | flame spectrum 4 |
| `--fire-gold` | `#FFC53D` | flame spectrum 5 |
| `--ink` | `#F2F4F8` | primary text |
| `--ink-mute` | `#9BA3B0` | secondary text (AA on --void and glass) |
| `--alert` | `#FF4757` | danger/quarantine/blocked ONLY — flat, never gradient |
| `--safe` | `#39E6B0` | verified/OK/enabled |

**The fire** is the identity: `--flame-ramp` =
`linear-gradient(90deg, var(--fire-blue), var(--fire-violet),
var(--fire-magenta), var(--fire-orange), var(--fire-gold))`. It appears as:
the Pulse hearth (layered animated radial flames cycling through the
spectrum), the active-tab underline, the gauge sweep, focus rings, and the
primary-button edge. Traffic keeps two distinguishable ramps drawn FROM the
fire: `--down-ramp` = orange→gold, `--up-ramp` = violet→magenta. Risk never
touches fire (H9): flat `--alert` badges/outlines. `twin/heat.ts` data
values untouched.

## Type (bundled @fontsource, zero external requests)

- **Display — Space Grotesk** (500/700): view titles, stat numbers, the
  wordmark (wordmark gets the chrome gradient via background-clip). Cool,
  technical, characterful.
- **Body — IBM Plex Sans** (400/500/600).
- **Data — IBM Plex Mono** (400/500): readings, ids, timestamps, eyebrows
  (11px caps +0.12em, `--ink-mute`).
Drop Fraunces (remove the dependency).

## Structure

- Top glass nav bar (blur over the aurora), chrome wordmark, tab pills:
  inactive = ghost text; active = `--glass-strong` pill with a 2px
  `--flame-ramp` underline and `--ink` text. Mobile bottom nav same
  treatment.
- Heroes fill the view over the aurora void; controls are floating glass
  pills. Panels: 16px radius, glass + line + top-edge highlight + soft
  black ambient shadow (`0 8px 32px rgb(0 0 0 / 0.45)`).
- Pulse stat band: glass slab; big Space Grotesk numbers; arc gauge with a
  chrome outer ring and flame-ramp sweep; stacked soft-area timeline using
  the down/up ramps at 65% opacity with glow; scrubber thumb = chrome.
  Honesty rule stands: unavailable coverage = em-dash + label, never fake
  zeros.
- Empty states: cool, not dead — the flame idles low (small dim animated
  ember) with the inviting copy; never a blank grey box.

## Signature: flames of all colors

Presence language = flame dots: **online** = live flame dot (orange-gold
gradient, soft glow); **quiet** = blue-violet ember, faint glow; **offline**
= glass ring, no fill; **blocked** = glass ring in flat `--alert`;
**unknown** = dashed glass ring. The Pulse hearth is the showpiece: layered
radial gradients of all five fire colors slowly breathing and drifting hue
(CSS only, GPU-cheap), intensity tied to activity tier; paused/reduced
motion = static flame at current tier.

## Resilience copy (part of this pass — the "not working" fix)

When stored pairing is rejected (401/auth-failed on API or WS), the app
must clear the stored token and show a single glass panel action state:
"This window's pairing expired. Open NeonHearth from the Start menu to
re-pair." — no dead spinners, no silent QUIET state while broken.

## Floor

Responsive to 390px; `--flame-ramp` focus ring (2px) with a non-gradient
fallback; `prefers-reduced-motion` = no flame drift/breathing (static);
`prefers-reduced-transparency`/no-backdrop-filter fallback = solid
`#15151D` panels; AA contrast for all text on glass-over-void; fire colors
never used for body text.
