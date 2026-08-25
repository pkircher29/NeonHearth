# Home Twin

The Home Twin is a drawing of your actual home — floors, walls, rooms — with
your real devices placed in it, viewable flat (2D editor) or as a rotatable
3D model. All measurements are metric meters.

## Drawing your home

- **Floors.** Add floors by level: 0 is the ground floor, negative levels
  are basements. Each floor has a name and a ceiling height between 1.8 m
  and 6.0 m. You cannot delete the last remaining floor, and a floor that
  still has placed devices refuses deletion until you move or remove them.
- **Walls.** Draw walls point to point; everything snaps to a 0.1 m grid.
  Walls can be moved, deleted, or split. Moving a wall shorter than one of
  its openings removes the openings that no longer fit (undo restores
  them); a split that would land inside a door or window is rejected rather
  than mangling it.
- **Openings.** Each wall can carry doors, windows, and stair openings at a
  measured offset and width; an opening must actually fit its wall.
- **Rooms.** Rooms are named polygons of three or more points.
- **Undo/redo.** Every edit is undoable, up to 200 steps.

## Placing devices

The tray beside the plan lists every discovered device that has no
owner-confirmed spot ("Every known device has an owner-confirmed spot" when
it is empty). Pick a device, click its location, and optionally record its
height and mounting (wall, ceiling, floor, or shelf — height is bounded by
the floor's ceiling). Removing a placement returns the device to the tray.

## Estimated locations are labeled, not trusted

Your placement is authoritative and is stored separately from automatic
estimates, which never overwrite it. An estimate carries a confidence value
and the evidence behind it. Any unplaced device whose estimate is below 0.6
confidence appears in a "Place these devices" banner with its percentage —
NeonHearth prompts you to place it and never renders it as confidently
located. Estimates deliberately never claim an exact room from a single
sensor.

## Drafts, autosave, and recovery

- While you edit, the plan autosaves as a **draft** about two seconds after
  each change (status shows "Unsaved changes", "Saving draft…", "Draft
  saved", or "Draft save failed"). Drafts are capped at 512 KiB.
- Reopening the editor with a draft present offers **resume or discard**. A
  draft that fails validation is reported — "A saved draft could not be
  read and was discarded" — and the last committed plan is shown; a corrupt
  draft is never silently merged.
- **Save** commits the whole plan and bumps its version number. Every
  committed version is kept in history so a damaged current plan is
  recoverable to the newest valid saved version.

## Version conflicts

Saves use optimistic concurrency: your save declares which version you
started from. If the plan changed elsewhere in the meantime, the save is
refused and the editor shows a plain conflict banner — "This plan changed
somewhere else since you loaded it. Reload the latest plan, then redo your
edit." Nothing is overwritten silently.

## The 3D view

- **Controls:** drag to orbit, shift-drag (or right-drag) to pan, scroll to
  zoom, arrow keys to rotate. A toolbar offers **Reset view**, **Hide
  walls / Show walls**, **All floors**, and one button per floor to isolate
  it. A keyboard-accessible device list mirrors the pins.
- **Reduced motion:** with your system's reduced-motion preference (or the
  app setting), the continuous render loop is replaced by
  render-on-change.
- **No WebGL?** The view falls back to the 2D plan with the same device
  list and selection.

## Heat colors vs risk badges

These are two independent channels, on purpose:

- **Heat is bandwidth only.** Device pins ramp blue → cyan → gold → pink:
  blue is quiet (under 1 Mbps), cyan active (1–10 Mbps), gold busy
  (10–30 Mbps), pink saturating (above 30 Mbps). A device with no reading
  gets a neutral gray — never a ramp color.
- **Risk is badges and outlines.** Security risk appears as a badge/outline
  marker (secure / watch / risk) and never feeds the heat ramp.

A pink device is a busy device, not a dangerous one; a risk badge on a blue
device is still a risk.

## Not yet available

- The Home destination in the app's navigation still shows "This room is
  still being wired": the editor and 3D view are built and tested as
  components, but they are not yet mounted in the main app, and the
  service-side `/api/v1/home` storage routes are still being connected. The
  behavior above describes the built components and their locked contract.
- Blueprint/image import (manual drawing is the first release).
- Packet-path animations, Wi-Fi field estimates, and event animations in
  the 3D view.
- Multi-sensor location estimation (estimates currently come from limited
  collector evidence; placement by you is the reliable path).
