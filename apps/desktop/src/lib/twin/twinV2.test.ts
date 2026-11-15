import { describe, expect, it } from 'vitest';

import {
  buildSceneDescription,
  clampWallThickness,
  DEFAULT_WALL_THICKNESS_M,
  extrudeWall,
  floorSlabs,
  roomAtPoint,
  triangulatePolygon,
  trianglesArea,
  wallJoinExtensions,
  type HomePlan,
  type PlanFloor,
  type PlanWall,
  type Vec2
} from './geometry';
import {
  angleDelta,
  boxAround,
  contactShadow,
  easeOut,
  fitDistance,
  framePose,
  lerpPose,
  PHI_MAX,
  PHI_MIN,
  presetPose,
  sceneBox,
  tweenProgress,
  unitHash,
  wallIsCut,
  stubbedBox,
  WALL_STUB_M,
  EXPLODE_GAP_M,
  wallRoughness
} from './twinCamera';
import { buildPinCard, formatArea, formatLastSeen, MISSING, presenceLabel } from './twinCard';

const wall = (id: string, x1: number, y1: number, x2: number, y2: number, extra: Partial<PlanWall> = {}): PlanWall => ({
  wall_id: id, start: { x: x1, y: y1 }, end: { x: x2, y: y2 }, openings: [], ...extra
});
const floorOf = (overrides: Partial<PlanFloor> = {}): PlanFloor => ({
  floor_id: 'f0', level: 0, name: 'Ground', ceiling_height_m: 2.4, walls: [], rooms: [], ...overrides
});

describe('wall thickness', () => {
  it('defaults to 0.1 m and clamps to 0.02..1.0', () => {
    expect(clampWallThickness(undefined)).toBe(DEFAULT_WALL_THICKNESS_M);
    expect(clampWallThickness(null)).toBe(0.1);
    expect(clampWallThickness(Number.NaN)).toBe(0.1);
    expect(clampWallThickness(0.001)).toBe(0.02);
    expect(clampWallThickness(5)).toBe(1);
    expect(clampWallThickness(0.3)).toBe(0.3);
  });

  it('extrudes the wall at its true thickness', () => {
    const thick = extrudeWall(wall('w', 0, 0, 4, 0, { thickness_m: 0.3 }), 2.4).boxes[0]!;
    expect(thick.thickness_m).toBe(0.3);
    expect(extrudeWall(wall('w', 0, 0, 4, 0), 2.4).boxes[0]!.thickness_m).toBe(0.1);
    expect(extrudeWall(wall('w', 0, 0, 4, 0, { thickness_m: 9 }), 2.4).boxes[0]!.thickness_m).toBe(1);
  });
});

describe('corner joins', () => {
  const square = [
    wall('a', 0, 0, 4, 0, { thickness_m: 0.2 }),
    wall('b', 4, 0, 4, 3, { thickness_m: 0.2 }),
    wall('c', 4, 3, 0, 3, { thickness_m: 0.2 }),
    wall('d', 0, 3, 0, 0, { thickness_m: 0.2 })
  ];

  it('extends every joined end by half a thickness so corners are solid', () => {
    const ext = wallJoinExtensions(square);
    for (const id of ['a', 'b', 'c', 'd']) expect(ext.get(id)).toEqual({ start: 0.1, end: 0.1 });
  });

  it('covers the outer corner square (no notch)', () => {
    const ext = wallJoinExtensions(square);
    const a = extrudeWall(square[0]!, 2.4, ext.get('a')).boxes[0]!;
    // Wall a runs along x at y=0; with 0.1 reach it spans x in [-0.1, 4.1].
    expect(a.length_m).toBeCloseTo(4.2);
    expect(a.center.x).toBeCloseTo(2);
    const d = extrudeWall(square[3]!, 2.4, ext.get('d')).boxes[0]!;
    expect(d.length_m).toBeCloseTo(3.2);
  });

  it('leaves free ends, T-junction ends, and straight continuations alone', () => {
    const free = wallJoinExtensions([wall('a', 0, 0, 4, 0)]);
    expect(free.get('a')).toEqual({ start: 0, end: 0 });
    const line = wallJoinExtensions([wall('a', 0, 0, 2, 0), wall('b', 2, 0, 5, 0)]);
    expect(line.get('a')).toEqual({ start: 0, end: 0 });
    expect(line.get('b')).toEqual({ start: 0, end: 0 });
    const tee = wallJoinExtensions([wall('a', 0, 0, 6, 0), wall('b', 3, 0, 3, 4)]);
    expect(tee.get('a')).toEqual({ start: 0, end: 0 });
    expect(tee.get('b')).toEqual({ start: 0, end: 0 });
  });

  it('uses the thickest joined wall and keeps openings anchored to the original wall', () => {
    const thick = wall('t', 0, 0, 0, 5, { thickness_m: 0.4 });
    const thin = wall('n', 0, 0, 4, 0, {
      openings: [{ opening_id: 'd', kind: 'door', offset_m: 1, width_m: 1 }]
    });
    const ext = wallJoinExtensions([thick, thin]);
    expect(ext.get('n')!.start).toBeCloseTo(0.2);
    const boxes = extrudeWall(thin, 2.4, ext.get('n')).boxes;
    const first = boxes.find((box) => box.id === 'n:solid-0')!;
    expect(first.length_m).toBeCloseTo(1.2); // from -0.2 to the door at 1.0
    const head = boxes.find((box) => box.segment === 'above_opening')!;
    expect(head.center.x).toBeCloseTo(1.5); // the door still sits at 1.0-2.0 m
    expect(boxes.find((box) => box.id === 'n:solid-1')!.length_m).toBeCloseTo(2);
  });
});

describe('triangulatePolygon', () => {
  const l: Vec2[] = [
    { x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 2 }, { x: 2, y: 2 }, { x: 2, y: 4 }, { x: 0, y: 4 }
  ];

  it('triangulates a convex polygon into n-2 triangles covering its area', () => {
    const square: Vec2[] = [{ x: 0, y: 0 }, { x: 3, y: 0 }, { x: 3, y: 2 }, { x: 0, y: 2 }];
    const triangles = triangulatePolygon(square);
    expect(triangles).toHaveLength(2);
    expect(trianglesArea(square, triangles)).toBeCloseTo(6);
  });

  it('triangulates a concave L-shape without covering the notch', () => {
    const triangles = triangulatePolygon(l);
    expect(triangles).toHaveLength(4);
    expect(trianglesArea(l, triangles)).toBeCloseTo(12);
    for (const [a, b, c] of triangles) {
      const cx = (l[a]!.x + l[b]!.x + l[c]!.x) / 3;
      const cy = (l[a]!.y + l[b]!.y + l[c]!.y) / 3;
      expect(cx > 2 && cy > 2).toBe(false);
    }
  });

  it('is winding-independent and every triangle faces up under the renderer mapping', () => {
    for (const poly of [l, [...l].reverse()]) {
      const triangles = triangulatePolygon(poly);
      expect(trianglesArea(poly, triangles)).toBeCloseTo(12);
      for (const [a, b, c] of triangles) {
        const p = [poly[a]!, poly[b]!, poly[c]!];
        // three.js maps plan (x, y) -> (x, 0, z=y); the up-facing normal needs this sign.
        const ny = (p[1]!.y - p[0]!.y) * (p[2]!.x - p[0]!.x) - (p[1]!.x - p[0]!.x) * (p[2]!.y - p[0]!.y);
        expect(ny).toBeGreaterThan(0);
      }
    }
  });

  it('handles a comb with several reflex vertices and a repeated closing point', () => {
    const comb: Vec2[] = [
      { x: 0, y: 0 }, { x: 6, y: 0 }, { x: 6, y: 3 }, { x: 5, y: 3 }, { x: 5, y: 1 }, { x: 4, y: 1 },
      { x: 4, y: 3 }, { x: 2, y: 3 }, { x: 2, y: 1 }, { x: 1, y: 1 }, { x: 1, y: 3 }, { x: 0, y: 3 }, { x: 0, y: 0 }
    ];
    const triangles = triangulatePolygon(comb);
    let shoelace = 0;
    for (let i = 0; i < comb.length - 1; i += 1) shoelace += comb[i]!.x * comb[i + 1]!.y - comb[i + 1]!.x * comb[i]!.y;
    expect(trianglesArea(comb, triangles)).toBeCloseTo(Math.abs(shoelace) / 2);
  });

  it('returns nothing for degenerate input', () => {
    expect(triangulatePolygon([])).toEqual([]);
    expect(triangulatePolygon([{ x: 0, y: 0 }, { x: 1, y: 1 }])).toEqual([]);
    expect(triangulatePolygon([{ x: 0, y: 0 }, { x: 1, y: 1 }, { x: 2, y: 2 }])).toEqual([]);
  });
});

describe('slabs, ceilings, rooms', () => {
  const room = { room_id: 'r1', name: 'Den', polygon: [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 2.5 }, { x: 0, y: 2.5 }] };
  it('room slabs carry id and shoelace area', () => {
    const slabs = floorSlabs(floorOf({ rooms: [room] }));
    const roomSlab = slabs.find((slab) => slab.kind === 'room')!;
    expect(roomSlab.room_id).toBe('r1');
    expect(roomSlab.area_m2).toBeCloseTo(10);
  });

  it('only non-top floors get a ceiling plane', () => {
    const plan: HomePlan = {
      home_id: 'h', version: 1, name: 'Home',
      floors: [
        floorOf({ floor_id: 'g', walls: [wall('a', 0, 0, 4, 0)] }),
        floorOf({ floor_id: 'u', level: 1, name: 'Up', walls: [wall('b', 0, 0, 4, 0)] })
      ]
    };
    const scene = buildSceneDescription(plan);
    expect(scene.floors[0]!.ceiling).not.toBeNull();
    expect(scene.floors[1]!.ceiling).toBeNull();
  });

  it('a single floor has no ceiling plane', () => {
    const scene = buildSceneDescription({ home_id: 'h', version: 1, name: 'H', floors: [floorOf({ walls: [wall('a', 0, 0, 4, 0)] })] });
    expect(scene.floors[0]!.ceiling).toBeNull();
  });

  it('finds the room containing a point', () => {
    const f = floorOf({ rooms: [room] });
    expect(roomAtPoint(f, { x: 1, y: 1 })?.name).toBe('Den');
    expect(roomAtPoint(f, { x: 9, y: 9 })).toBeNull();
  });
});

describe('camera presets', () => {
  const plan: HomePlan = {
    home_id: 'h', version: 1, name: 'H',
    floors: [
      floorOf({ floor_id: 'g', walls: [wall('a', 0, 0, 8, 0), wall('b', 8, 0, 8, 6)] }),
      floorOf({ floor_id: 'u', level: 1, name: 'Up', walls: [wall('c', 0, 0, 8, 0)] })
    ]
  };
  const scene = buildSceneDescription(plan);

  it('iso keeps the long-standing default framing', () => {
    const pose = presetPose('iso', scene);
    expect(pose.theta).toBeCloseTo(-Math.PI / 4);
    expect(pose.phi).toBeCloseTo(1.05);
    expect(pose.radius).toBeCloseTo(scene.bounds!.radius_m * 2.4);
    expect(pose.target.x).toBeCloseTo(scene.bounds!.center.x);
  });

  it('top looks straight down, centred, inside the orbit limits', () => {
    const pose = presetPose('top', scene);
    expect(pose.phi).toBeCloseTo(PHI_MIN);
    expect(pose.target.x).toBeCloseTo(scene.bounds!.center.x);
    expect(pose.target.z).toBeCloseTo(scene.bounds!.center.y);
    expect(pose.radius).toBeGreaterThan(8);
  });

  it('front looks horizontally and stays within the orbit limits', () => {
    const pose = presetPose('front', scene);
    expect(pose.phi).toBeGreaterThan(1.4);
    expect(pose.phi).toBeLessThanOrEqual(PHI_MAX);
  });

  it('all presets are distinct and finite; an empty scene yields the default pose', () => {
    const poses = (['top', 'iso', 'front'] as const).map((name) => presetPose(name, scene));
    for (const pose of poses) {
      expect(Number.isFinite(pose.radius)).toBe(true);
      expect(Number.isFinite(pose.target.y)).toBe(true);
    }
    expect(new Set(poses.map((pose) => `${pose.theta}|${pose.phi}`)).size).toBe(3);
    expect(presetPose('top', { floors: [], bounds: null }).radius).toBe(14);
  });

  it('a wider viewport needs less distance than a narrow one', () => {
    expect(fitDistance(10, 4, 50, 2)).toBeLessThan(fitDistance(10, 4, 50, 0.7));
  });

  it('scene box spans every stacked floor', () => {
    const box = sceneBox(scene)!;
    expect(box.min.y).toBe(0);
    expect(box.max.y).toBeGreaterThan(2.4);
    expect(box.max.x - box.min.x).toBeGreaterThanOrEqual(8);
  });

  it('frames a selection around its centre and clamps the distance', () => {
    const box = boxAround([{ x: 2, y: 1, z: 3 }], 0.5);
    const pose = framePose(box, { theta: 0.3, phi: 1 }, 4 / 3);
    expect(pose.target).toEqual({ x: 2, y: 1, z: 3 });
    expect(pose.theta).toBe(0.3);
    expect(pose.radius).toBeGreaterThanOrEqual(3);
    expect(pose.radius).toBeLessThan(10);
  });
});

describe('camera tween helpers', () => {
  it('takes the short way around the circle', () => {
    expect(angleDelta(3, -3)).toBeCloseTo(2 * Math.PI - 6);
    expect(angleDelta(0, Math.PI / 2)).toBeCloseTo(Math.PI / 2);
    expect(angleDelta(-Math.PI / 4, Math.PI / 2)).toBeCloseTo((3 * Math.PI) / 4);
  });
  it('eases 0..1 and clamps', () => {
    expect(easeOut(0)).toBe(0);
    expect(easeOut(1)).toBe(1);
    expect(easeOut(0.5)).toBeGreaterThan(0.5);
    expect(easeOut(2)).toBe(1);
    expect(easeOut(-1)).toBe(0);
  });
  it('lerps endpoints exactly', () => {
    const a = { theta: 0, phi: 1, radius: 10, target: { x: 0, y: 0, z: 0 } };
    const b = { theta: 1, phi: 0.5, radius: 4, target: { x: 2, y: 4, z: 6 } };
    expect(lerpPose(a, b, 0)).toEqual(a);
    expect(lerpPose(a, b, 1)).toEqual(b);
    expect(lerpPose(a, b, 0.5).radius).toBe(7);
  });
  it('reports done at the end and instantly for a zero duration', () => {
    expect(tweenProgress(0, 100).done).toBe(false);
    expect(tweenProgress(0, 450).done).toBe(true);
    expect(tweenProgress(0, 0, 0)).toEqual({ k: 1, done: true });
  });
});

describe('wall cut-away (dollhouse)', () => {
  const origin = { x: 0, y: 0 };
  it('cuts walls on the camera side and keeps far walls tall', () => {
    expect(wallIsCut({ x: 5, y: 0 }, origin, { x: 1, y: 0 }, 1.05)).toBe(true);
    expect(wallIsCut({ x: -5, y: 0 }, origin, { x: 1, y: 0 }, 1.05)).toBe(false);
    expect(wallIsCut({ x: 0.1, y: 4 }, origin, { x: 1, y: 0 }, 1.05)).toBe(false);
  });
  it('never cuts from straight overhead or without a horizontal camera direction', () => {
    expect(wallIsCut({ x: 5, y: 0 }, origin, { x: 1, y: 0 }, 0.02)).toBe(false);
    expect(wallIsCut({ x: 5, y: 0 }, origin, { x: 0, y: 0 }, 1)).toBe(false);
  });
  it('stubs low boxes and hides boxes that start above the stub', () => {
    expect(stubbedBox(0, 2.4)).toEqual({ base: 0, height: WALL_STUB_M });
    expect(stubbedBox(0, 0.1)).toEqual({ base: 0, height: 0.1 });
    expect(stubbedBox(2, 0.4)).toBeNull();
  });
  it('exploded stacks add the gap to the scene box and framing', () => {
    const plan: HomePlan = { home_id: 'h', version: 1, name: 'H', floors: [floorOf({ floor_id: 'g', walls: [wall('a', 0, 0, 8, 0)] }), floorOf({ floor_id: 'u', level: 1, walls: [wall('b', 0, 0, 8, 0)] })] };
    const scene = buildSceneDescription(plan);
    expect(sceneBox(scene, EXPLODE_GAP_M)!.max.y - sceneBox(scene)!.max.y).toBeCloseTo(EXPLODE_GAP_M);
    expect(presetPose('iso', scene, 4 / 3, 50, EXPLODE_GAP_M).target.y).toBeGreaterThan(presetPose('iso', scene).target.y);
  });
});

describe('shadows and material variation', () => {
  it('higher pins cast wider, fainter shadows', () => {
    const low = contactShadow(0.2);
    const high = contactShadow(2.4);
    expect(high.radius).toBeGreaterThan(low.radius);
    expect(high.opacity).toBeLessThan(low.opacity);
    expect(contactShadow(-5).radius).toBeCloseTo(0.28);
    expect(contactShadow(99).opacity).toBeGreaterThan(0);
  });
  it('wall roughness varies deterministically within a band', () => {
    expect(wallRoughness('a')).toBe(wallRoughness('a'));
    const values = ['a', 'b', 'c', 'd', 'e', 'f'].map(wallRoughness);
    expect(new Set(values).size).toBeGreaterThan(3);
    for (const value of values) {
      expect(value).toBeGreaterThanOrEqual(0.62);
      expect(value).toBeLessThanOrEqual(0.88);
    }
    expect(unitHash('x')).toBeLessThan(1);
  });
});

describe('detail card model', () => {
  const plan: HomePlan = {
    home_id: 'h', version: 1, name: 'H',
    floors: [floorOf({ rooms: [{ room_id: 'r', name: 'Kitchen', polygon: [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 4 }, { x: 0, y: 4 }] }] })]
  };
  const pin = { device_id: 'd1', label: 'Fridge cam', floor_id: 'f0', position: { x: 1, y: 1 }, height_m: 1, is_camera: true };

  it('fills every field when the data exists', () => {
    const now = new Date('2026-11-15T12:00:00Z');
    const card = buildPinCard(pin, plan, undefined, { evidence: ['mdns', 'arp'], last_seen_at: '2026-11-15T11:58:00Z' }, 'online', now);
    expect(card).toEqual({
      device_id: 'd1', name: 'Fridge cam', presence: 'Online', room: 'Kitchen', evidence: 'mdns, arp', lastSeen: '2 min ago'
    });
  });

  it('shows an em-dash for every missing value, never a guess', () => {
    const outside = { ...pin, position: { x: 50, y: 50 } };
    const card = buildPinCard(outside, plan, undefined, undefined, undefined);
    expect(card.room).toBe(MISSING);
    expect(card.evidence).toBe(MISSING);
    expect(card.lastSeen).toBe(MISSING);
    expect(card.presence).toBe('Unknown');
  });

  it('formats helpers honestly', () => {
    expect(formatArea(12.345)).toBe('12.3 m²');
    expect(formatArea(undefined)).toBe(MISSING);
    expect(formatLastSeen('not a date')).toBe(MISSING);
    expect(formatLastSeen('2026-11-15T11:59:50Z', new Date('2026-11-15T12:00:00Z'))).toBe('Just now');
    expect(formatLastSeen('2026-11-15T07:00:00Z', new Date('2026-11-15T12:00:00Z'))).toBe('5 h ago');
    expect(presenceLabel('offline')).toBe('Offline');
    expect(presenceLabel(null)).toBe(MISSING);
  });
});
