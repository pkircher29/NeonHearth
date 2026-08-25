# M5 Home Twin contracts

Locked before parallel implementation on 2026-08-24. Later workstreams extend
these types; they do not rename or duplicate them. Checklist items H1–H11.

## Ownership

| Area | Owner lane | Files |
|---|---|---|
| Domain types + `HomeChanged` event | backend | `crates/lattice-domain/src/home.rs`, `event.rs`, `lib.rs` |
| Migration 021 + repository | backend | `crates/lattice-store/migrations/021_home_twin.sql`, `crates/lattice-store/src/home.rs` |
| Service API + event emission | service (after backend) | `crates/lattice-service` |
| 2D editor + home store | editor-2d | `apps/desktop/src/lib/components/HomeEditor*.svelte`, `apps/desktop/src/lib/stores/home.ts` |
| 3D twin | twin-3d | `apps/desktop/src/lib/components/HomeTwin3D.svelte`, `apps/desktop/src/lib/twin/*`, `apps/desktop/package.json` (adds `three` only) |

## Units and grid

All geometry is metric meters in floor-local coordinates. The 2D editor snaps
to a 0.1 m grid. `level` 0 is the ground floor; negative levels are basements.

## Plan model (JSON wire shape, serde snake_case)

```jsonc
{
  "home_id": "uuid",            // one home per install for M5
  "version": 3,                  // u32, increments on every committed save
  "name": "Home",
  "floors": [{
    "floor_id": "uuid",
    "level": 0,
    "name": "Ground",
    "ceiling_height_m": 2.4,     // 1.8..=6.0
    "walls": [{
      "wall_id": "uuid",
      "start": {"x": 0.0, "y": 0.0},
      "end":   {"x": 4.2, "y": 0.0},
      "openings": [{
        "opening_id": "uuid",
        "kind": "door" | "window" | "stair",
        "offset_m": 0.8,         // from wall start, along the wall
        "width_m": 0.9
      }]
    }],
    "rooms": [{
      "room_id": "uuid",
      "name": "Kitchen",
      "polygon": [{"x":0,"y":0},{"x":4,"y":0},{"x":4,"y":3},{"x":0,"y":3}] // >= 3 points
    }]
  }]
}
```

## Placement and location truth (H4, H5, H11)

Owner-confirmed placement is authoritative; automatic estimates never
overwrite it and are stored separately.

```jsonc
// owner placement (authoritative)
{ "placement_id": "uuid", "device_id": "uuid", "floor_id": "uuid",
  "x": 1.5, "y": 2.0, "height_m": 1.1, "mounting": "wall"|"ceiling"|"floor"|"shelf"|null }

// automatic estimate (advisory; never claims exact room from one sensor)
{ "device_id": "uuid", "floor_id": "uuid"|null, "room_id": "uuid"|null,
  "confidence": 0.0-1.0, "evidence": ["w6-rssi", "collector-arp"],
  "estimated_at": "RFC3339" }
```

Effective location = owner placement if present, else estimate labeled with
its confidence. An estimate with confidence < 0.6 and no owner placement is
"uncertain" — the UI must prompt the owner to place the device (H11) and must
never render it as confidently located.

## Versioning, drafts, recovery (H1, H3)

- Committed saves are whole-plan writes with optimistic concurrency: the
  writer sends `expected_version`; a mismatch is rejected (service maps it to
  HTTP 409) and the caller reloads.
- Every committed save appends to `home_plan_history` (version, saved_at,
  full plan JSON) so a corrupt current row is recoverable to the newest valid
  history row.
- The editor autosaves an uncommitted draft (opaque JSON, capped 512 KiB)
  server-side per home. A draft that fails validation on load is reported as
  corrupt and discarded in favor of the committed plan — never silently
  merged.

## Event (appended to `EventPayload`)

```rust
HomeChanged(HomeChanged { home_id: HomeId, version: u32, summary: String })
```

Events carry no geometry and no device coordinates — clients refetch.

## Service API (loopback, bearer-authenticated like every other route)

- `GET  /api/v1/home` → `{ plan, placements: [..], estimates: [..] }`
- `PUT  /api/v1/home/plan` body `{ expected_version, plan }` → 409 on version mismatch
- `PUT  /api/v1/home/placements/{device_id}` body placement (owner action)
- `DELETE /api/v1/home/placements/{device_id}` (returns device to unplaced tray)
- `GET/PUT/DELETE /api/v1/home/draft` (opaque draft blob)

## 3D twin ground rules (H7–H10)

- Pure geometry assembly lives in `apps/desktop/src/lib/twin/` as testable
  functions (plan JSON → wall/floor/opening meshes description) — the Svelte
  component only renders that output with Three.js.
- Bandwidth heat (blue→cyan→gold→pink) and security risk are separate visual
  channels: risk uses badge/outline, never the heat ramp (H9).
- `prefers-reduced-motion` (and the app's reduced-motion setting) replaces
  continuous animation with state transitions; WebGL unavailable falls back
  to the 2D plan view with the same device list and selection (H10).
