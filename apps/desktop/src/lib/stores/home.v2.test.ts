import { describe, expect, it } from 'vitest';

import {
  DEFAULT_THICKNESS_M, MAX_THICKNESS_M, MIN_THICKNESS_M, copyFloorFootprint, createEditorState, isHomePlan, reduceEditor,
  type EditAction, type EditorState, type HomePlan
} from './home';

const homeId = '018f47a0-9b5c-7a22-8a33-aabbccdd0001';
const groundId = '018f47a0-9b5c-7a22-8a33-aabbccdd0010';
const wallId = '018f47a0-9b5c-7a22-8a33-aabbccdd0020';
const doorId = '018f47a0-9b5c-7a22-8a33-aabbccdd0030';
const id = (suffix: string) => `018f47a0-9b5c-7a22-8a33-aabbccdd${suffix}`;

function plan(): HomePlan {
  return {
    home_id: homeId, version: 1, name: 'Home',
    floors: [{
      floor_id: groundId, level: 0, name: 'Ground', ceiling_height_m: 2.4,
      walls: [{ wall_id: wallId, start: { x: 0, y: 0 }, end: { x: 4, y: 0 }, thickness_m: 0.2, openings: [{ opening_id: doorId, kind: 'door', offset_m: 0.5, width_m: 0.9 }] }],
      rooms: []
    }]
  };
}
const fresh = (): EditorState => createEditorState(plan(), []);
const walls = (state: EditorState) => state.doc.plan.floors[0].walls;
const addWall = (wall_id: string, sx: number, sy: number, ex: number, ey: number, extra: Partial<Extract<EditAction, { type: 'add_wall' }>> = {}): EditAction =>
  ({ type: 'add_wall', floor_id: groundId, wall_id, start: { x: sx, y: sy }, end: { x: ex, y: ey }, ...extra });

describe('batch', () => {
  it('applies every edit in order as ONE history entry and undoes them together', () => {
    const state = reduceEditor(fresh(), {
      type: 'batch',
      actions: [
        addWall(id('0100'), 0, 0, 0, 3),
        addWall(id('0101'), 0, 3, 4, 3),
        { type: 'add_room', floor_id: groundId, room_id: id('0102'), name: 'Hall', polygon: [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 3 }, { x: 0, y: 3 }] }
      ]
    });
    expect(walls(state)).toHaveLength(3);
    expect(state.doc.plan.floors[0].rooms).toHaveLength(1);
    expect(state.past).toHaveLength(1);
    const undone = reduceEditor(state, { type: 'undo' });
    expect(walls(undone)).toHaveLength(1);
    expect(undone.doc.plan.floors[0].rooms).toHaveLength(0);
    expect(reduceEditor(undone, { type: 'redo' }).doc.plan.floors[0].walls).toHaveLength(3);
  });

  it('rejects the whole batch when any edit fails and leaves history untouched', () => {
    const state = fresh();
    const next = reduceEditor(state, { type: 'batch', actions: [addWall(id('0100'), 0, 0, 0, 3), addWall(id('0101'), 5, 5, 5, 5)] });
    expect(next).toBe(state);
    expect(next.past).toHaveLength(0);
  });

  it('rejects empty and oversized batches', () => {
    const state = fresh();
    expect(reduceEditor(state, { type: 'batch', actions: [] })).toBe(state);
    const many = Array.from({ length: 65 }, (_, index) => addWall(id(`02${String(index).padStart(2, '0')}`), index, 10, index + 1, 10));
    expect(reduceEditor(state, { type: 'batch', actions: many })).toBe(state);
  });

  it('later edits see earlier ones: split then add a wall that ends on the split point', () => {
    const state = reduceEditor(fresh(), {
      type: 'batch',
      actions: [
        { type: 'split_wall', floor_id: groundId, wall_id: wallId, at: { x: 2, y: 0 }, new_wall_id: id('0110'), exact: true },
        addWall(id('0111'), 2, 3, 2, 0, { exact: true })
      ]
    });
    expect(walls(state).map((wall) => wall.wall_id)).toEqual([wallId, id('0110'), id('0111')]);
    expect(walls(state)[1].start).toEqual({ x: 2, y: 0 });
    expect(walls(state)[2].end).toEqual({ x: 2, y: 0 });
    expect(state.past).toHaveLength(1);
  });

  it('applies the grid to every action in the batch', () => {
    const state = reduceEditor(fresh(), { type: 'batch', actions: [addWall(id('0120'), 0, 1, 3.048, 1)], grid_m: 0.0254 });
    expect(walls(state).at(-1)!.end.x).toBe(3.048);
  });
});

describe('exact points', () => {
  it('add_wall exact keeps an off-grid endpoint instead of re-snapping it', () => {
    const exact = reduceEditor(fresh(), addWall(id('0200'), 0.0507, 1, 3.0333333, 1, { exact: true }));
    expect(walls(exact).at(-1)).toMatchObject({ start: { x: 0.0507, y: 1 }, end: { x: 3.033333, y: 1 } });
    const snapped = reduceEditor(fresh(), addWall(id('0201'), 0.0507, 1, 3.0333333, 1));
    expect(walls(snapped).at(-1)).toMatchObject({ start: { x: 0.1, y: 1 }, end: { x: 3.0, y: 1 } });
  });

  it('an exact endpoint lands exactly on an existing imperial endpoint (the endpoint-snap bug)', () => {
    const imperial = reduceEditor(fresh(), { type: 'batch', grid_m: 0.0254, actions: [addWall(id('0210'), 0, 2, 3.048, 2, { exact: true })] });
    const joined = reduceEditor(imperial, { type: 'batch', grid_m: 0.0254, actions: [addWall(id('0211'), 3.048, 2, 3.048, 5, { exact: true })] });
    expect(walls(joined).at(-1)!.start).toEqual(walls(joined).at(-2)!.end);
  });

  it('move_wall exact does not move a pre-snapped point', () => {
    const moved = reduceEditor(fresh(), { type: 'move_wall', floor_id: groundId, wall_id: wallId, start: { x: 0, y: 0 }, end: { x: 4.0123, y: 0 }, exact: true });
    expect(walls(moved)[0].end.x).toBe(4.0123);
  });

  it('split_wall exact splits where the point is, and refuses a point that is not on the wall', () => {
    const state = fresh();
    const split = reduceEditor(state, { type: 'split_wall', floor_id: groundId, wall_id: wallId, at: { x: 3.0123, y: 0 }, new_wall_id: id('0220'), exact: true });
    expect(walls(split)[0].end.x).toBe(3.0123);
    expect(walls(split)[1].start.x).toBe(3.0123);
    expect(reduceEditor(state, { type: 'split_wall', floor_id: groundId, wall_id: wallId, at: { x: 3, y: 1 }, new_wall_id: id('0221'), exact: true })).toBe(state);
  });

  it('add_room exact keeps polygon corners that already sit on real endpoints', () => {
    const state = reduceEditor(fresh(), { type: 'add_room', floor_id: groundId, room_id: id('0230'), name: 'Odd', polygon: [{ x: 0.0507, y: 0 }, { x: 3.0333333, y: 0 }, { x: 3, y: 2 }], exact: true });
    expect(state.doc.plan.floors[0].rooms[0].polygon[0]).toEqual({ x: 0.0507, y: 0 });
  });
});

describe('duplicate walls', () => {
  it('rejects a wall with the same two endpoints, in either order', () => {
    const state = fresh();
    expect(reduceEditor(state, addWall(id('0300'), 0, 0, 4, 0))).toBe(state);
    expect(reduceEditor(state, addWall(id('0301'), 4, 0, 0, 0))).toBe(state);
    expect(reduceEditor(state, addWall(id('0302'), 0, 0, 4, 0.1))).not.toBe(state);
  });
  it('rejects a reused wall id', () => {
    const state = fresh();
    expect(reduceEditor(state, addWall(wallId, 0, 1, 4, 1))).toBe(state);
  });
  it('rejects moving a wall on top of another wall but allows moving it onto itself', () => {
    const two = reduceEditor(fresh(), addWall(id('0310'), 0, 3, 4, 3));
    expect(reduceEditor(two, { type: 'move_wall', floor_id: groundId, wall_id: id('0310'), start: { x: 0, y: 0 }, end: { x: 4, y: 0 } })).toBe(two);
    expect(reduceEditor(two, { type: 'move_wall', floor_id: groundId, wall_id: id('0310'), start: { x: 0, y: 3 }, end: { x: 5, y: 3 } })).not.toBe(two);
  });
});

describe('wall thickness', () => {
  it('writes the default thickness on new walls and an explicit one when given', () => {
    const state = reduceEditor(reduceEditor(fresh(), addWall(id('0400'), 0, 1, 4, 1)), addWall(id('0401'), 0, 2, 4, 2, { thickness_m: 0.25 }));
    expect(walls(state)[1].thickness_m).toBe(DEFAULT_THICKNESS_M);
    expect(walls(state)[2].thickness_m).toBe(0.25);
  });
  it('rejects an out-of-range thickness on add_wall', () => {
    const state = fresh();
    expect(reduceEditor(state, addWall(id('0402'), 0, 1, 4, 1, { thickness_m: 5 }))).toBe(state);
    expect(reduceEditor(state, addWall(id('0403'), 0, 1, 4, 1, { thickness_m: 0 }))).toBe(state);
  });
  it('set_wall_thickness changes thickness, is one undo step, and survives a split', () => {
    const state = reduceEditor(fresh(), { type: 'set_wall_thickness', floor_id: groundId, wall_id: wallId, thickness_m: 0.3 });
    expect(walls(state)[0].thickness_m).toBe(0.3);
    expect(state.past).toHaveLength(1);
    expect(reduceEditor(state, { type: 'undo' }).doc.plan.floors[0].walls[0].thickness_m).toBe(0.2);
    const split = reduceEditor(state, { type: 'split_wall', floor_id: groundId, wall_id: wallId, at: { x: 3, y: 0 }, new_wall_id: id('0410') });
    expect(walls(split).map((wall) => wall.thickness_m)).toEqual([0.3, 0.3]);
  });
  it('accepts the bounds and rejects values outside them, non-numbers, no-ops and unknown walls', () => {
    const state = fresh();
    const set = (thickness_m: number, wall_id = wallId) => reduceEditor(state, { type: 'set_wall_thickness', floor_id: groundId, wall_id, thickness_m });
    expect(walls(set(MIN_THICKNESS_M))[0].thickness_m).toBe(MIN_THICKNESS_M);
    expect(walls(set(MAX_THICKNESS_M))[0].thickness_m).toBe(MAX_THICKNESS_M);
    expect(set(MIN_THICKNESS_M / 2)).toBe(state);
    expect(set(MAX_THICKNESS_M + 0.01)).toBe(state);
    expect(set(Number.NaN)).toBe(state);
    expect(set(Number.POSITIVE_INFINITY)).toBe(state);
    expect(set(0.2)).toBe(state);
    expect(set(0.3, id('dead'))).toBe(state);
  });
  it('rounds float noise from unit conversion before validating', () => {
    const state = reduceEditor(fresh(), { type: 'set_wall_thickness', floor_id: groundId, wall_id: wallId, thickness_m: 0.5 * 0.3048 / 0.3048 + 1e-12 });
    expect(walls(state)[0].thickness_m).toBe(0.5);
  });
  it('copy footprint carries thickness to the new floor', () => {
    let n = 0;
    const copy = copyFloorFootprint(plan().floors[0], { floor_id: id('0420'), level: 1, name: 'Up', ceiling_height_m: 2.4, walls: [], rooms: [] }, () => id(`05${String(n++).padStart(2, '0')}`));
    expect(copy.walls[0].thickness_m).toBe(0.2);
    const state = reduceEditor(fresh(), { type: 'copy_footprint', floor: copy });
    expect(state.doc.plan.floors[1].walls[0].thickness_m).toBe(0.2);
  });
});

describe('isHomePlan thickness validation', () => {
  const withThickness = (value: unknown) => {
    const candidate = plan();
    (candidate.floors[0].walls[0] as unknown as Record<string, unknown>).thickness_m = value;
    return candidate;
  };
  it('accepts a missing thickness (older plans) and an in-range one', () => {
    const older = plan();
    delete (older.floors[0].walls[0] as { thickness_m?: number }).thickness_m;
    expect(isHomePlan(older)).toBe(true);
    expect(isHomePlan(withThickness(0.1))).toBe(true);
    expect(isHomePlan(withThickness(MIN_THICKNESS_M))).toBe(true);
    expect(isHomePlan(withThickness(MAX_THICKNESS_M))).toBe(true);
  });
  it('rejects out-of-range, non-finite and non-numeric thickness', () => {
    for (const bad of [0, 0.01, 1.01, -0.1, Number.NaN, Number.POSITIVE_INFINITY, '0.1', null]) expect(isHomePlan(withThickness(bad))).toBe(false);
  });
});
