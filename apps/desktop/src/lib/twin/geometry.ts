// Pure geometry assembly for the 3D home twin (checklist H7).
//
// Plan JSON (m5-home-twin-contracts.md) goes in, a plain renderable scene
// description comes out: positions, sizes, angles, colors, ids. No three.js
// imports live here — HomeTwin3D.svelte is the only place that touches the
// renderer, so every rule in this file is unit-testable in plain node.
//
// Coordinates: plan space is metric meters, floor-local, x/y in the floor
// plane. Vertical measures (`base_m`, `height_m`, `elevation_m`) are meters
// above the floor slab / ground. The renderer maps plan (x, y, vertical h)
// to three.js (x, h, y) with y-up; that mapping is the component's business.

export interface Vec2 {
  x: number;
  y: number;
}

export type OpeningKind = 'door' | 'window' | 'stair';
export interface PlanOpening {
  opening_id: string;
  kind: OpeningKind;
  offset_m: number; // from wall start, along the wall
  width_m: number;
}
export interface PlanWall {
  wall_id: string;
  start: Vec2;
  end: Vec2;
  openings?: PlanOpening[];
}
export interface PlanRoom {
  room_id: string;
  name: string;
  polygon: Vec2[]; // >= 3 points
}
export interface PlanFloor {
  floor_id: string;
  level: number; // 0 = ground, negative = basement
  name: string;
  ceiling_height_m?: number | null; // contract range 1.8..=6.0
  walls: PlanWall[];
  rooms: PlanRoom[];
}
export interface HomePlan {
  home_id: string;
  version: number;
  name: string;
  floors: PlanFloor[];
}

export type Mounting = 'wall' | 'ceiling' | 'floor' | 'shelf' | null;
export interface Placement {
  placement_id: string;
  device_id: string;
  floor_id: string;
  x: number;
  y: number;
  height_m: number;
  mounting: Mounting;
}

/** Presentation metadata the twin needs about a device (labels, camera flag). */
export interface TwinDevice {
  device_id: string;
  label?: string | null;
  is_camera?: boolean;
  /** Optional owner-set view direction, degrees CCW from +x in plan space. */
  facing_deg?: number | null;
}

// --- Tunable constants (documented so tests and the 2D editor agree) -------

export const DEFAULT_CEILING_M = 2.4;
export const MIN_CEILING_M = 1.8;
export const MAX_CEILING_M = 6.0;
export const WALL_THICKNESS_M = 0.12;
export const SLAB_THICKNESS_M = 0.12;
/** Visual breathing room between a floor's ceiling and the slab above it. */
export const FLOOR_GAP_M = 0.4;
export const DOOR_HEAD_M = 2.0;
export const WINDOW_SILL_M = 0.9;
export const WINDOW_HEAD_M = 2.1;
export const EXTENT_PADDING_M = 0.3;
export const CAMERA_CONE_LENGTH_M = 2.5;
export const CAMERA_CONE_HALF_ANGLE_RAD = Math.PI / 6; // 30 degrees
/** Cameras mounted above standing height get a gentle downward tilt. */
export const CAMERA_TILT_HEIGHT_M = 1.4;
export const CAMERA_TILT_DOWN = 0.25;

export const TWIN_COLORS = {
  slabExtent: '#0e2430',
  slabRoom: '#12303c',
  wall: '#28505a',
  stair: '#ffcd66'
} as const;

// --- Output shapes ---------------------------------------------------------

export interface WallBox {
  id: string;
  wall_id: string;
  segment: 'solid' | 'above_opening' | 'below_opening';
  center: Vec2; // plan meters, midpoint of the box footprint
  length_m: number;
  thickness_m: number;
  base_m: number; // above the floor slab
  height_m: number;
  angle_rad: number; // rotation about the vertical axis, from +x
  color: string;
}
export interface StairMarker {
  id: string;
  wall_id: string;
  center: Vec2;
  length_m: number;
  angle_rad: number;
  color: string;
}
export interface SlabDesc {
  id: string;
  kind: 'extent' | 'room';
  name?: string;
  polygon: Vec2[];
  color: string;
}
export interface DevicePin {
  device_id: string;
  label: string;
  floor_id: string;
  position: Vec2;
  height_m: number; // above the floor slab, clamped to the ceiling
  is_camera: boolean;
}
export interface CameraCone {
  device_id: string;
  apex: { x: number; y: number; h: number };
  /** Unit vector; x/y in the floor plane, z vertical (negative = downward). */
  direction: { x: number; y: number; z: number };
  length_m: number;
  half_angle_rad: number;
}
export interface FloorGroup {
  floor_id: string;
  level: number;
  name: string;
  elevation_m: number; // world height of this floor's walking surface
  ceiling_m: number;
  slabs: SlabDesc[];
  walls: WallBox[];
  stairs: StairMarker[];
  pins: DevicePin[];
  cones: CameraCone[];
}
export interface SceneBounds {
  min: Vec2;
  max: Vec2;
  center: Vec2;
  /** Fits horizontal extent and stacked height; feeds the reset-view camera. */
  radius_m: number;
}
export interface SceneDescription {
  floors: FloorGroup[]; // sorted ascending by level
  bounds: SceneBounds | null;
}

// --- Small pure helpers ----------------------------------------------------

export function clampCeiling(value: number | null | undefined): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return DEFAULT_CEILING_M;
  return Math.min(MAX_CEILING_M, Math.max(MIN_CEILING_M, value));
}

export function polygonCentroid(polygon: Vec2[]): Vec2 | null {
  if (polygon.length < 3) return null;
  let area = 0;
  let cx = 0;
  let cy = 0;
  for (let i = 0; i < polygon.length; i += 1) {
    const a = polygon[i]!;
    const b = polygon[(i + 1) % polygon.length]!;
    const cross = a.x * b.y - b.x * a.y;
    area += cross;
    cx += (a.x + b.x) * cross;
    cy += (a.y + b.y) * cross;
  }
  if (Math.abs(area) < 1e-9) return null; // degenerate polygon
  area *= 0.5;
  return { x: cx / (6 * area), y: cy / (6 * area) };
}

export function pointInPolygon(point: Vec2, polygon: Vec2[]): boolean {
  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i, i += 1) {
    const a = polygon[i]!;
    const b = polygon[j]!;
    const crosses = a.y > point.y !== b.y > point.y
      && point.x < ((b.x - a.x) * (point.y - a.y)) / (b.y - a.y) + a.x;
    if (crosses) inside = !inside;
  }
  return inside;
}

// --- Wall extrusion (openings become rectangular holes) --------------------

export interface WallExtrusion {
  boxes: WallBox[];
  stairs: StairMarker[];
}

/**
 * Decomposes one wall into axis-aligned-along-the-wall boxes so that door and
 * window openings become real rectangular holes:
 * - door: full-height gap with a header box from DOOR_HEAD_M to the ceiling
 * - window: gap between WINDOW_SILL_M and WINDOW_HEAD_M (sill box below,
 *   header box above)
 * - stair: full-height gap plus a flat marker strip on the floor
 * Openings are clamped to the wall, sorted, and overlaps collapse forward.
 */
export function extrudeWall(wall: PlanWall, ceiling_m: number): WallExtrusion {
  const boxes: WallBox[] = [];
  const stairs: StairMarker[] = [];
  const dx = wall.end.x - wall.start.x;
  const dy = wall.end.y - wall.start.y;
  const length = Math.hypot(dx, dy);
  if (length < 1e-9) return { boxes, stairs };
  const angle = Math.atan2(dy, dx);
  const ux = dx / length;
  const uy = dy / length;
  const at = (t: number): Vec2 => ({ x: wall.start.x + ux * t, y: wall.start.y + uy * t });

  const pushBox = (
    from: number,
    to: number,
    base: number,
    top: number,
    segment: WallBox['segment'],
    suffix: string
  ) => {
    const span = to - from;
    const height = top - base;
    if (span <= 1e-9 || height <= 1e-9) return;
    boxes.push({
      id: `${wall.wall_id}:${suffix}`,
      wall_id: wall.wall_id,
      segment,
      center: at(from + span / 2),
      length_m: span,
      thickness_m: WALL_THICKNESS_M,
      base_m: base,
      height_m: height,
      angle_rad: angle,
      color: TWIN_COLORS.wall
    });
  };

  const openings = [...(wall.openings ?? [])]
    .map((opening) => {
      const from = Math.min(Math.max(opening.offset_m, 0), length);
      const to = Math.min(Math.max(opening.offset_m + opening.width_m, from), length);
      return { ...opening, from, to };
    })
    .filter((opening) => opening.to - opening.from > 1e-9)
    .sort((a, b) => a.from - b.from);

  let cursor = 0;
  let index = 0;
  for (const opening of openings) {
    const from = Math.max(opening.from, cursor);
    const to = Math.max(opening.to, from);
    if (to - from <= 1e-9) continue;
    pushBox(cursor, from, 0, ceiling_m, 'solid', `solid-${index}`);
    if (opening.kind === 'door') {
      pushBox(from, to, Math.min(DOOR_HEAD_M, ceiling_m), ceiling_m, 'above_opening', `door-head-${opening.opening_id}`);
    } else if (opening.kind === 'window') {
      pushBox(from, to, 0, Math.min(WINDOW_SILL_M, ceiling_m), 'below_opening', `window-sill-${opening.opening_id}`);
      pushBox(from, to, Math.min(WINDOW_HEAD_M, ceiling_m), ceiling_m, 'above_opening', `window-head-${opening.opening_id}`);
    } else {
      stairs.push({
        id: `${wall.wall_id}:stair-${opening.opening_id}`,
        wall_id: wall.wall_id,
        center: at(from + (to - from) / 2),
        length_m: to - from,
        angle_rad: angle,
        color: TWIN_COLORS.stair
      });
    }
    cursor = to;
    index += 1;
  }
  pushBox(cursor, length, 0, ceiling_m, 'solid', `solid-${index}`);
  return { boxes, stairs };
}

// --- Floor stacking --------------------------------------------------------

export interface FloorElevation {
  floor_id: string;
  level: number;
  ceiling_m: number;
  elevation_m: number;
}

/**
 * Stacks the floors that exist, in level order. The lowest floor with
 * level >= 0 anchors at elevation 0; floors below it stack downward by their
 * own ceiling + slab + gap. If every floor is a basement (no level >= 0),
 * the topmost basement's ceiling sits just below elevation 0.
 */
export function floorElevations(floors: PlanFloor[]): FloorElevation[] {
  const sorted = [...floors].sort((a, b) => a.level - b.level);
  const result: FloorElevation[] = sorted.map((floor) => ({
    floor_id: floor.floor_id,
    level: floor.level,
    ceiling_m: clampCeiling(floor.ceiling_height_m),
    elevation_m: 0
  }));
  if (result.length === 0) return result;
  const step = (entry: FloorElevation) => entry.ceiling_m + SLAB_THICKNESS_M + FLOOR_GAP_M;
  let anchor = result.findIndex((entry) => entry.level >= 0);
  if (anchor === -1) {
    anchor = result.length - 1;
    result[anchor]!.elevation_m = -step(result[anchor]!);
  }
  for (let i = anchor + 1; i < result.length; i += 1) {
    result[i]!.elevation_m = result[i - 1]!.elevation_m + step(result[i - 1]!);
  }
  for (let i = anchor - 1; i >= 0; i -= 1) {
    result[i]!.elevation_m = result[i + 1]!.elevation_m - step(result[i]!);
  }
  return result;
}

// --- Slabs, pins, cones ----------------------------------------------------

function floorPoints(floor: PlanFloor): Vec2[] {
  const points: Vec2[] = [];
  for (const wall of floor.walls) points.push(wall.start, wall.end);
  for (const room of floor.rooms) points.push(...room.polygon);
  return points;
}

export function floorExtent(floor: PlanFloor): { min: Vec2; max: Vec2 } | null {
  const points = floorPoints(floor);
  if (points.length === 0) return null;
  const xs = points.map((point) => point.x);
  const ys = points.map((point) => point.y);
  return {
    min: { x: Math.min(...xs) - EXTENT_PADDING_M, y: Math.min(...ys) - EXTENT_PADDING_M },
    max: { x: Math.max(...xs) + EXTENT_PADDING_M, y: Math.max(...ys) + EXTENT_PADDING_M }
  };
}

export function floorSlabs(floor: PlanFloor): SlabDesc[] {
  const slabs: SlabDesc[] = [];
  const extent = floorExtent(floor);
  if (extent) {
    slabs.push({
      id: `${floor.floor_id}:extent`,
      kind: 'extent',
      polygon: [
        { x: extent.min.x, y: extent.min.y },
        { x: extent.max.x, y: extent.min.y },
        { x: extent.max.x, y: extent.max.y },
        { x: extent.min.x, y: extent.max.y }
      ],
      color: TWIN_COLORS.slabExtent
    });
  }
  for (const room of floor.rooms) {
    if (room.polygon.length < 3) continue; // contract requires >= 3 points
    slabs.push({
      id: `${floor.floor_id}:room:${room.room_id}`,
      kind: 'room',
      name: room.name,
      polygon: [...room.polygon],
      color: TWIN_COLORS.slabRoom
    });
  }
  return slabs;
}

export function deviceLabel(device: TwinDevice | undefined, device_id: string): string {
  const label = device?.label?.trim();
  return label && label.length > 0 ? label : `Device ${device_id.slice(0, 6)}`;
}

export function devicePinFor(
  placement: Placement,
  floor: PlanFloor,
  device: TwinDevice | undefined
): DevicePin {
  const ceiling = clampCeiling(floor.ceiling_height_m);
  return {
    device_id: placement.device_id,
    label: deviceLabel(device, placement.device_id),
    floor_id: placement.floor_id,
    position: { x: placement.x, y: placement.y },
    height_m: Math.min(Math.max(placement.height_m, 0), ceiling),
    is_camera: Boolean(device?.is_camera)
  };
}

/**
 * View cone for a camera pin. Direction priority:
 * 1. the device's owner-set facing_deg (degrees CCW from +x),
 * 2. toward the centroid of the room containing the pin,
 * 3. toward the centroid of the floor extent,
 * 4. +x as a last resort.
 * Cameras mounted above CAMERA_TILT_HEIGHT_M look slightly downward.
 */
export function cameraConeFor(
  pin: DevicePin,
  floor: PlanFloor,
  device: TwinDevice | undefined
): CameraCone {
  let dirX = 1;
  let dirY = 0;
  const facing = device?.facing_deg;
  if (typeof facing === 'number' && Number.isFinite(facing)) {
    const rad = (facing * Math.PI) / 180;
    dirX = Math.cos(rad);
    dirY = Math.sin(rad);
  } else {
    let target: Vec2 | null = null;
    const room = floor.rooms.find(
      (candidate) => candidate.polygon.length >= 3 && pointInPolygon(pin.position, candidate.polygon)
    );
    if (room) target = polygonCentroid(room.polygon);
    if (!target) {
      const extent = floorExtent(floor);
      if (extent) target = { x: (extent.min.x + extent.max.x) / 2, y: (extent.min.y + extent.max.y) / 2 };
    }
    if (target) {
      const tx = target.x - pin.position.x;
      const ty = target.y - pin.position.y;
      const span = Math.hypot(tx, ty);
      if (span > 1e-6) {
        dirX = tx / span;
        dirY = ty / span;
      }
    }
  }
  const tilt = pin.height_m > CAMERA_TILT_HEIGHT_M ? -CAMERA_TILT_DOWN : 0;
  const norm = Math.hypot(dirX, dirY, tilt);
  return {
    device_id: pin.device_id,
    apex: { x: pin.position.x, y: pin.position.y, h: pin.height_m },
    direction: { x: dirX / norm, y: dirY / norm, z: tilt / norm },
    length_m: CAMERA_CONE_LENGTH_M,
    half_angle_rad: CAMERA_CONE_HALF_ANGLE_RAD
  };
}

// --- Whole-scene assembly --------------------------------------------------

export function buildSceneDescription(
  plan: HomePlan,
  placements: Placement[] = [],
  devices: TwinDevice[] = []
): SceneDescription {
  const deviceById = new Map(devices.map((device) => [device.device_id, device]));
  const elevations = new Map(floorElevations(plan.floors).map((entry) => [entry.floor_id, entry]));
  const sortedFloors = [...plan.floors].sort((a, b) => a.level - b.level);

  const floors: FloorGroup[] = sortedFloors.map((floor) => {
    const elevation = elevations.get(floor.floor_id)!;
    const walls: WallBox[] = [];
    const stairs: StairMarker[] = [];
    for (const wall of floor.walls) {
      const extrusion = extrudeWall(wall, elevation.ceiling_m);
      walls.push(...extrusion.boxes);
      stairs.push(...extrusion.stairs);
    }
    const pins = placements
      .filter((placement) => placement.floor_id === floor.floor_id)
      .map((placement) => devicePinFor(placement, floor, deviceById.get(placement.device_id)));
    const cones = pins
      .filter((pin) => pin.is_camera)
      .map((pin) => cameraConeFor(pin, floor, deviceById.get(pin.device_id)));
    return {
      floor_id: floor.floor_id,
      level: floor.level,
      name: floor.name,
      elevation_m: elevation.elevation_m,
      ceiling_m: elevation.ceiling_m,
      slabs: floorSlabs(floor),
      walls,
      stairs,
      pins,
      cones
    };
  });

  let bounds: SceneBounds | null = null;
  const xs: number[] = [];
  const ys: number[] = [];
  const heights: number[] = [];
  for (const group of floors) {
    const floor = sortedFloors.find((candidate) => candidate.floor_id === group.floor_id)!;
    const extent = floorExtent(floor);
    if (extent) {
      xs.push(extent.min.x, extent.max.x);
      ys.push(extent.min.y, extent.max.y);
      heights.push(group.elevation_m, group.elevation_m + group.ceiling_m);
    }
    for (const pin of group.pins) {
      xs.push(pin.position.x);
      ys.push(pin.position.y);
      heights.push(group.elevation_m + pin.height_m);
    }
  }
  if (xs.length > 0) {
    const min = { x: Math.min(...xs), y: Math.min(...ys) };
    const max = { x: Math.max(...xs), y: Math.max(...ys) };
    const horizontal = Math.hypot(max.x - min.x, max.y - min.y) / 2;
    const vertical = heights.length > 0 ? Math.max(...heights) - Math.min(...heights) : 0;
    bounds = {
      min,
      max,
      center: { x: (min.x + max.x) / 2, y: (min.y + max.y) / 2 },
      radius_m: Math.max(horizontal, vertical, 1)
    };
  }
  return { floors, bounds };
}
