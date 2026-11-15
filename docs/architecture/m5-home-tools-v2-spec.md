# Home tools v2 — making the plan editor and Home Twin real

Locked 2026-08-28 after the owner's verdict: "the 3D house drawing tools
needs quite a bit of work." v1 (shipped in M5) proved the data model, the
save/version/draft pipeline, and the 3D extrusion. It is not yet a tool
someone can comfortably draw a house with. This spec is the authority for
v2; it extends the locked wire contract in `m5-home-twin-contracts.md`
(plan JSON is compatible — every addition is optional with a default) and
follows the v3 visual system.

## What v1 lacks (assessed against the shipped code)

Editor: no viewport control at all (fixed 18 m × 12 m at 40 px/m — a real
house does not fit), no snapping to existing wall endpoints so drawn rooms
never truly close, no chained wall drawing (tool resets after every wall),
no rectangle-room shortcut, no live length/angle readout while drawing, no
endpoint dragging, no orthogonal constraint, no room area, no wall
thickness, no alignment guides, no duplicate-floor. Twin: walls are
zero-thickness planes, flat lighting, no room floors or ceilings, no camera
presets, no click-through from 3D to a device's detail.

## A. Viewport (highest impact)

- Pan (drag with space held, middle mouse, or the Pan tool), zoom (wheel +
  buttons + pinch) 10–200 px/m, "Fit plan" and "100%" controls, and a
  persisted per-floor view state. Grid adapts: 0.1 m minor lines fade out
  below ~25 px/m, 1 m major lines always; a scale bar sits bottom-left.
- The canvas becomes an SVG viewBox transform — geometry stays in meters,
  never in pixels.

## B. Drawing that behaves like a drafting tool

- **Snapping ladder**, in priority order, all within a 12 px screen radius:
  existing wall endpoint → wall midpoint → point on a wall (creates a split
  on commit) → intersection of alignment guides → grid. The active snap is
  shown as a distinct marker with a label ("endpoint", "on wall") so the
  owner knows what they will get.
- **Alignment guides**: dashed lines when the cursor aligns horizontally or
  vertically with any endpoint of the current floor.
- **Chained walls**: after committing a wall the tool starts the next from
  that endpoint; Escape or Enter ends the chain; closing back onto the
  first endpoint ends it and (see C) offers the room.
- **Constrain to 0/45/90°** while Shift is held.
- **Live readout** at the cursor while drawing: length in meters and angle
  in degrees, updating continuously; typing a number while drawing commits
  that exact length (numeric entry beats mouse precision).
- **Endpoint editing**: with the Select tool, wall endpoints become
  draggable handles (snapping applies); dragging a wall body moves it whole.
- **Rectangle room tool**: drag a rectangle → four walls plus the room in
  one gesture, the fastest path to a first floor plan.

## C. Rooms that come from the walls

- After a chain closes, or on demand via "Detect rooms", find the closed
  cycles in the wall graph of the current floor and offer them as rooms
  (name field prefilled "Room N"); the owner confirms. Manual polygon
  drawing stays for irregular cases.
- Each room shows its **area** (m², computed by the shoelace formula) under
  its name label, and the floor total appears in the floor bar.
- Room labels are placed at the polygon centroid and stay legible at all
  zooms (constant screen size).

## D. Walls with thickness

- `Wall.thickness_m` (optional, default 0.1) added to the plan JSON —
  serde-defaulted so existing plans load unchanged and the store/service
  need no migration beyond accepting the field.
- 2D draws walls as thickness-scaled bands, not hairlines; openings punch
  visible gaps with a door arc (swing) and a window sill line.
- 3D extrudes the true thickness, so corners meet as solids.

## E. The Twin, made convincing

- Room **floor slabs** from polygons and a subtle ceiling plane when a floor
  is not the top one (hidden by the existing hide-walls toggle).
- Lighting: a warm key light plus cool ambient matching the v3 fire palette,
  soft contact shadows under device pins; materials get slight roughness
  variation so walls read as surfaces, not flat fills.
- **Camera presets**: Top, Isometric (default), and Front, plus "Frame
  selection"; smooth animated transitions that respect reduced motion.
- Selecting a device pin opens a glass detail card (name, presence, room,
  evidence, last seen) with a "Show in Devices" action — the twin becomes a
  way into the data, not just a picture.
- Rooms are pickable: hovering highlights the floor slab and shows the room
  name + area.

## F. Quality of life

- Duplicate a floor ("Copy of Ground") — the common way to start an upper
  storey.
- Keyboard: V/W/R/O/P tool shortcuts, Ctrl+Z/Y, Delete, Escape, arrow-key
  nudge (already present), Ctrl+D duplicate selection.
- An always-visible hint line under the toolbar telling the owner what the
  current tool does next ("Click to start a wall, Shift for straight,
  Esc to finish") — teaching without a manual.

## Non-negotiables carried forward

Owner placement still beats automatic estimates; estimates below 0.6
confidence stay labelled uncertain and never render as confident pins; the
draft/version/conflict behavior and the M5 gate's browser proof must keep
passing; `twin/heat.ts` values and the H9 risk/heat independence stand;
reduced motion and the 2D fallback stay honest.
