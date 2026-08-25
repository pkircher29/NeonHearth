import { describe, expect, it } from 'vitest';

import {
  buildSceneDescription,
  cameraConeFor,
  clampCeiling,
  DEFAULT_CEILING_M,
  devicePinFor,
  DOOR_HEAD_M,
  extrudeWall,
  EXTENT_PADDING_M,
  FLOOR_GAP_M,
  floorElevations,
  floorSlabs,
  pointInPolygon,
  polygonCentroid,
  SLAB_THICKNESS_M,
  TWIN_COLORS,
  WINDOW_HEAD_M,
  WINDOW_SILL_M,
  type HomePlan,
  type Placement,
  type PlanFloor,
  type PlanWall
} from './geometry';

const wall = (overrides: Partial<PlanWall> = {}): PlanWall => ({
  wall_id: 'wall-1',
  start: { x: 0, y: 0 },
  end: { x: 4, y: 0 },
  openings: [],
  ...overrides
});

const floor = (overrides: Partial<PlanFloor> = {}): PlanFloor => ({
  floor_id: 'floor-0',
  level: 0,
  name: 'Ground',
  ceiling_height_m: 2.4,
  walls: [],
  rooms: [],
  ...overrides
});

const plan = (floors: PlanFloor[]): HomePlan => ({
  home_id: 'home-1',
  version: 1,
  name: 'Home',
  floors
});

const placement = (overrides: Partial<Placement> = {}): Placement => ({
  placement_id: 'placement-1',
  device_id: 'device-1',
  floor_id: 'floor-0',
  x: 1,
  y: 1,
  height_m: 1.1,
  mounting: 'shelf',
  ...overrides
});

describe('clampCeiling', () => {
  it('defaults and clamps to the contract range 1.8..=6.0', () => {
    expect(clampCeiling(null)).toBe(DEFAULT_CEILING_M);
    expect(clampCeiling(undefined)).toBe(DEFAULT_CEILING_M);
    expect(clampCeiling(Number.NaN)).toBe(DEFAULT_CEILING_M);
    expect(clampCeiling(1.0)).toBe(1.8);
    expect(clampCeiling(9)).toBe(6.0);
    expect(clampCeiling(3.1)).toBe(3.1);
  });
});

describe('extrudeWall', () => {
  it('turns a plain wall into one full-height solid box', () => {
    const { boxes, stairs } = extrudeWall(wall(), 2.4);
    expect(stairs).toEqual([]);
    expect(boxes).toHaveLength(1);
    expect(boxes[0]).toMatchObject({
      segment: 'solid',
      length_m: 4,
      base_m: 0,
      height_m: 2.4,
      angle_rad: 0,
      center: { x: 2, y: 0 },
      color: TWIN_COLORS.wall
    });
  });

  it('computes the angle and center for a diagonal wall', () => {
    const { boxes } = extrudeWall(wall({ start: { x: 0, y: 0 }, end: { x: 3, y: 3 } }), 2.4);
    expect(boxes[0]!.angle_rad).toBeCloseTo(Math.PI / 4, 10);
    expect(boxes[0]!.length_m).toBeCloseTo(Math.hypot(3, 3), 10);
    expect(boxes[0]!.center.x).toBeCloseTo(1.5, 10);
    expect(boxes[0]!.center.y).toBeCloseTo(1.5, 10);
  });

  it('cuts a door as a full-height gap with a header above it', () => {
    const opening = { opening_id: 'op-1', kind: 'door' as const, offset_m: 1, width_m: 0.9 };
    const { boxes } = extrudeWall(wall({ openings: [opening] }), 2.4);
    const solids = boxes.filter((box) => box.segment === 'solid');
    const headers = boxes.filter((box) => box.segment === 'above_opening');
    expect(solids.map((box) => box.length_m)).toEqual([1, 4 - 1.9]);
    expect(headers).toHaveLength(1);
    expect(headers[0]!.base_m).toBe(DOOR_HEAD_M);
    expect(headers[0]!.length_m).toBeCloseTo(0.9, 10);
    expect(headers[0]!.height_m).toBeCloseTo(2.4 - DOOR_HEAD_M, 10);
    expect(headers[0]!.center.x).toBeCloseTo(1.45, 10);
    // nothing occupies the walk-through region of the doorway
    expect(boxes.some((box) => box.segment !== 'solid' && box.base_m < DOOR_HEAD_M)).toBe(false);
  });

  it('cuts a window as a gap between sill and head boxes', () => {
    const opening = { opening_id: 'op-2', kind: 'window' as const, offset_m: 1.5, width_m: 1 };
    const { boxes } = extrudeWall(wall({ openings: [opening] }), 2.4);
    const below = boxes.find((box) => box.segment === 'below_opening')!;
    const above = boxes.find((box) => box.segment === 'above_opening')!;
    expect(below).toMatchObject({ base_m: 0, height_m: WINDOW_SILL_M, length_m: 1 });
    expect(above.base_m).toBeCloseTo(WINDOW_HEAD_M, 10);
    expect(above.height_m).toBeCloseTo(2.4 - WINDOW_HEAD_M, 10);
    // the glass region (sill..head) stays open
    expect(
      boxes.some((box) => box.base_m < WINDOW_HEAD_M && box.base_m + box.height_m > WINDOW_SILL_M
        && box.segment !== 'solid')
    ).toBe(false);
  });

  it('drops the window head when the ceiling is at or below the head height', () => {
    const opening = { opening_id: 'op-2b', kind: 'window' as const, offset_m: 0.2, width_m: 0.5 };
    const { boxes } = extrudeWall(wall({ openings: [opening] }), 1.8);
    // 1.8 m ceiling < 2.1 m head: only the sill box remains for the opening
    expect(boxes.filter((box) => box.segment === 'above_opening')).toHaveLength(0);
    expect(boxes.filter((box) => box.segment === 'below_opening')).toHaveLength(1);
  });

  it('marks a stair opening as a full gap plus a floor marker', () => {
    const opening = { opening_id: 'op-3', kind: 'stair' as const, offset_m: 1, width_m: 1.2 };
    const { boxes, stairs } = extrudeWall(wall({ openings: [opening] }), 2.4);
    expect(boxes.every((box) => box.segment === 'solid')).toBe(true);
    expect(boxes.map((box) => box.length_m)).toEqual([1, 4 - 2.2]);
    expect(stairs).toHaveLength(1);
    expect(stairs[0]).toMatchObject({ color: TWIN_COLORS.stair, angle_rad: 0 });
    expect(stairs[0]!.length_m).toBeCloseTo(1.2, 10);
    expect(stairs[0]!.center.x).toBeCloseTo(1.6, 10);
  });

  it('clamps openings that run past the end of the wall', () => {
    const opening = { opening_id: 'op-4', kind: 'door' as const, offset_m: 3.5, width_m: 2 };
    const { boxes } = extrudeWall(wall({ openings: [opening] }), 2.4);
    const solids = boxes.filter((box) => box.segment === 'solid');
    expect(solids.map((box) => box.length_m)).toEqual([3.5]);
    const header = boxes.find((box) => box.segment === 'above_opening')!;
    expect(header.length_m).toBeCloseTo(0.5, 10);
  });

  it('ignores zero-width openings and produces nothing for a zero-length wall', () => {
    const opening = { opening_id: 'op-5', kind: 'door' as const, offset_m: 2, width_m: 0 };
    expect(extrudeWall(wall({ openings: [opening] }), 2.4).boxes).toHaveLength(1);
    expect(extrudeWall(wall({ end: { x: 0, y: 0 } }), 2.4)).toEqual({ boxes: [], stairs: [] });
  });

  it('keeps multiple sorted openings separated by solid segments', () => {
    const openings = [
      { opening_id: 'b', kind: 'window' as const, offset_m: 2.5, width_m: 0.8 },
      { opening_id: 'a', kind: 'door' as const, offset_m: 0.5, width_m: 0.9 }
    ];
    const { boxes } = extrudeWall(wall({ openings }), 2.4);
    const solids = boxes.filter((box) => box.segment === 'solid');
    expect(solids.map((box) => Number(box.length_m.toFixed(6)))).toEqual([0.5, 1.1, 0.7]);
  });
});

describe('floorElevations', () => {
  it('anchors the ground floor at zero and stacks upward and downward', () => {
    const floors = [
      floor({ floor_id: 'f1', level: 1, name: 'Upstairs', ceiling_height_m: 2.6 }),
      floor({ floor_id: 'f0', level: 0, ceiling_height_m: 2.4 }),
      floor({ floor_id: 'fb', level: -1, name: 'Basement', ceiling_height_m: 2.0 })
    ];
    const result = floorElevations(floors);
    expect(result.map((entry) => entry.level)).toEqual([-1, 0, 1]);
    const step0 = 2.4 + SLAB_THICKNESS_M + FLOOR_GAP_M;
    const stepB = 2.0 + SLAB_THICKNESS_M + FLOOR_GAP_M;
    expect(result[1]).toMatchObject({ floor_id: 'f0', elevation_m: 0 });
    expect(result[2]!.elevation_m).toBeCloseTo(step0, 10);
    expect(result[0]!.elevation_m).toBeCloseTo(-stepB, 10);
  });

  it('keeps an all-basement home below ground', () => {
    const result = floorElevations([floor({ floor_id: 'fb', level: -1, ceiling_height_m: 2.0 })]);
    expect(result[0]!.elevation_m).toBeCloseTo(-(2.0 + SLAB_THICKNESS_M + FLOOR_GAP_M), 10);
  });

  it('applies the default ceiling when a floor omits it', () => {
    const result = floorElevations([floor({ ceiling_height_m: null })]);
    expect(result[0]!.ceiling_m).toBe(DEFAULT_CEILING_M);
  });
});

describe('floorSlabs', () => {
  const room = { room_id: 'room-1', name: 'Kitchen', polygon: [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 3 }, { x: 0, y: 3 }] };

  it('emits a padded extent slab plus one slab per valid room', () => {
    const slabs = floorSlabs(floor({ walls: [wall()], rooms: [room] }));
    expect(slabs.map((slab) => slab.kind)).toEqual(['extent', 'room']);
    const extent = slabs[0]!;
    expect(extent.polygon[0]).toEqual({ x: -EXTENT_PADDING_M, y: -EXTENT_PADDING_M });
    expect(extent.polygon[2]).toEqual({ x: 4 + EXTENT_PADDING_M, y: 3 + EXTENT_PADDING_M });
    expect(slabs[1]).toMatchObject({ name: 'Kitchen', polygon: room.polygon, color: TWIN_COLORS.slabRoom });
  });

  it('skips degenerate rooms and empty floors', () => {
    const degenerate = { room_id: 'room-2', name: 'Sliver', polygon: [{ x: 0, y: 0 }, { x: 1, y: 1 }] };
    expect(floorSlabs(floor({ rooms: [degenerate] }))).toHaveLength(1); // extent only
    expect(floorSlabs(floor())).toEqual([]);
  });
});

describe('device pins', () => {
  it('positions a pin at the placement with its height clamped to the ceiling', () => {
    const pin = devicePinFor(placement({ height_m: 9 }), floor(), { device_id: 'device-1', label: 'Hall cam', is_camera: true });
    expect(pin).toMatchObject({
      device_id: 'device-1',
      label: 'Hall cam',
      position: { x: 1, y: 1 },
      height_m: 2.4,
      is_camera: true
    });
    expect(devicePinFor(placement({ height_m: -1 }), floor(), undefined).height_m).toBe(0);
  });

  it('falls back to a short id label for unnamed devices', () => {
    const pin = devicePinFor(placement({ device_id: 'abcdef123456' }), floor(), undefined);
    expect(pin.label).toBe('Device abcdef');
    expect(pin.is_camera).toBe(false);
  });
});

describe('camera cones', () => {
  const squareRoom = { room_id: 'room-1', name: 'Den', polygon: [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 4 }, { x: 0, y: 4 }] };

  it('honors an explicit facing_deg', () => {
    const pin = devicePinFor(placement({ height_m: 1.0 }), floor(), { device_id: 'device-1', is_camera: true });
    const cone = cameraConeFor(pin, floor(), { device_id: 'device-1', is_camera: true, facing_deg: 90 });
    expect(cone.direction.x).toBeCloseTo(0, 10);
    expect(cone.direction.y).toBeCloseTo(1, 10);
    expect(cone.direction.z).toBe(0); // low mount: no downward tilt
    expect(cone.apex).toEqual({ x: 1, y: 1, h: 1.0 });
  });

  it('aims at the containing room centroid by default and tilts high mounts down', () => {
    const theFloor = floor({ rooms: [squareRoom] });
    const pin = devicePinFor(placement({ x: 0.5, y: 0.5, height_m: 2.2 }), theFloor, { device_id: 'device-1', is_camera: true });
    const cone = cameraConeFor(pin, theFloor, { device_id: 'device-1', is_camera: true });
    // centroid (2,2) from (0.5,0.5): planar direction is +x=+y diagonal
    expect(cone.direction.x).toBeCloseTo(cone.direction.y, 10);
    expect(cone.direction.x).toBeGreaterThan(0);
    expect(cone.direction.z).toBeLessThan(0);
    const norm = Math.hypot(cone.direction.x, cone.direction.y, cone.direction.z);
    expect(norm).toBeCloseTo(1, 10);
  });

  it('falls back to the floor extent center outside every room', () => {
    const theFloor = floor({ walls: [wall({ start: { x: 0, y: 0 }, end: { x: 6, y: 6 } })] });
    const pin = devicePinFor(placement({ x: 0, y: 0, height_m: 1.0 }), theFloor, undefined);
    const cone = cameraConeFor(pin, theFloor, undefined);
    expect(cone.direction.x).toBeCloseTo(Math.SQRT1_2, 6);
    expect(cone.direction.y).toBeCloseTo(Math.SQRT1_2, 6);
  });
});

describe('buildSceneDescription', () => {
  const twoFloorPlan = plan([
    floor({
      floor_id: 'floor-0',
      level: 0,
      walls: [wall({ openings: [{ opening_id: 'op-1', kind: 'door', offset_m: 1, width_m: 0.9 }] })],
      rooms: [{ room_id: 'room-1', name: 'Kitchen', polygon: [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 3 }, { x: 0, y: 3 }] }]
    }),
    floor({ floor_id: 'floor-1', level: 1, name: 'Upstairs', walls: [wall({ wall_id: 'wall-2' })], rooms: [] })
  ]);

  it('groups walls, slabs, pins, and cones per floor with vertical offsets', () => {
    const placements: Placement[] = [
      placement({ device_id: 'device-1', floor_id: 'floor-0' }),
      placement({ placement_id: 'placement-2', device_id: 'device-2', floor_id: 'floor-1', x: 2, y: 0.5, height_m: 2.2 }),
      placement({ placement_id: 'placement-3', device_id: 'device-3', floor_id: 'missing-floor' })
    ];
    const devices = [
      { device_id: 'device-1', label: 'TV' },
      { device_id: 'device-2', label: 'Landing cam', is_camera: true, facing_deg: 180 }
    ];
    const scene = buildSceneDescription(twoFloorPlan, placements, devices);
    expect(scene.floors.map((group) => group.floor_id)).toEqual(['floor-0', 'floor-1']);
    expect(scene.floors[0]!.elevation_m).toBe(0);
    expect(scene.floors[1]!.elevation_m).toBeCloseTo(2.4 + SLAB_THICKNESS_M + FLOOR_GAP_M, 10);
    expect(scene.floors[0]!.pins.map((pin) => pin.device_id)).toEqual(['device-1']);
    expect(scene.floors[1]!.pins.map((pin) => pin.device_id)).toEqual(['device-2']);
    // pin on an unknown floor is dropped, never guessed onto a floor
    expect(scene.floors.flatMap((group) => group.pins.map((pin) => pin.device_id))).not.toContain('device-3');
    expect(scene.floors[0]!.cones).toEqual([]);
    expect(scene.floors[1]!.cones).toHaveLength(1);
    // facing 180 deg, high mount: planar part points -x, tilted slightly down
    expect(scene.floors[1]!.cones[0]!.direction.x).toBeLessThan(-0.9);
    expect(scene.floors[1]!.cones[0]!.direction.y).toBeCloseTo(0, 6);
    expect(scene.floors[1]!.cones[0]!.direction.z).toBeLessThan(0);
    expect(scene.floors[0]!.walls.some((box) => box.segment === 'above_opening')).toBe(true);
    expect(scene.floors[0]!.slabs.map((slab) => slab.kind)).toEqual(['extent', 'room']);
  });

  it('produces reset-view bounds covering extents and stacked height', () => {
    const scene = buildSceneDescription(twoFloorPlan, [], []);
    expect(scene.bounds).not.toBeNull();
    expect(scene.bounds!.center.x).toBeCloseTo(2, 10);
    expect(scene.bounds!.radius_m).toBeGreaterThan(0);
    // vertical span (two stacked floors) must be inside the fit radius
    const top = scene.floors[1]!.elevation_m + scene.floors[1]!.ceiling_m;
    expect(scene.bounds!.radius_m).toBeGreaterThanOrEqual(top);
  });

  it('handles an empty plan without bounds', () => {
    const scene = buildSceneDescription(plan([]), [], []);
    expect(scene).toEqual({ floors: [], bounds: null });
  });
});

describe('polygon helpers', () => {
  const square = [{ x: 0, y: 0 }, { x: 2, y: 0 }, { x: 2, y: 2 }, { x: 0, y: 2 }];

  it('computes centroids and containment', () => {
    expect(polygonCentroid(square)).toEqual({ x: 1, y: 1 });
    expect(polygonCentroid([{ x: 0, y: 0 }, { x: 1, y: 1 }])).toBeNull();
    expect(pointInPolygon({ x: 1, y: 1 }, square)).toBe(true);
    expect(pointInPolygon({ x: 3, y: 1 }, square)).toBe(false);
  });
});
