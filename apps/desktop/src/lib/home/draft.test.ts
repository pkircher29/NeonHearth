import { describe, expect, it } from 'vitest';

import { createEditorState, reduceEditor, type EditorState, type Floor } from '../stores/home';
import { parseLengthEntry, planRectangleBatch, planWallBatch, rectangleCorners, wallsContaining } from './draft';

const groundId = 'f1';
function floor(walls: Floor['walls'] = []): Floor {
  return { floor_id: groundId, level: 0, name: 'Ground', ceiling_height_m: 2.4, walls, rooms: [] };
}
const stateOf = (f: Floor): EditorState => createEditorState({ home_id: 'h', version: 0, name: 'Home', floors: [f] }, []);
const sequence = () => { let n = 0; return () => `id-${n++}`; };
const wall = (wall_id: string, sx: number, sy: number, ex: number, ey: number) => ({ wall_id, start: { x: sx, y: sy }, end: { x: ex, y: ey }, openings: [] });

describe('wallsContaining', () => {
  const walls = [wall('a', 0, 0, 4, 0)];
  it('finds a wall whose body holds the point, but not at its endpoints or off the line', () => {
    expect(wallsContaining(walls, { x: 2, y: 0 })).toEqual(['a']);
    expect(wallsContaining(walls, { x: 0, y: 0 })).toEqual([]);
    expect(wallsContaining(walls, { x: 4, y: 0 })).toEqual([]);
    expect(wallsContaining(walls, { x: 2, y: 0.01 })).toEqual([]);
    expect(wallsContaining(walls, { x: 5, y: 0 })).toEqual([]);
  });
});

describe('planWallBatch', () => {
  it('adds a plain wall with thickness and exact points when nothing is touched', () => {
    const actions = planWallBatch({ floor: floor(), walls: [{ start: { x: 0, y: 0 }, end: { x: 3, y: 0 } }], newId: sequence() })!;
    expect(actions).toHaveLength(1);
    expect(actions[0]).toMatchObject({ type: 'add_wall', thickness_m: 0.1, exact: true });
  });

  it('splits the wall a new endpoint lands on, so the new wall truly joins it', () => {
    const base = floor([wall('a', 0, 0, 4, 0)]);
    const actions = planWallBatch({ floor: base, walls: [{ start: { x: 2, y: 3 }, end: { x: 2, y: 0 } }], newId: sequence() })!;
    expect(actions.map((action) => action.type)).toEqual(['split_wall', 'add_wall']);
    const next = reduceEditor(stateOf(base), { type: 'batch', actions });
    const walls = next.doc.plan.floors[0].walls;
    expect(walls).toHaveLength(3);
    const joint = walls.filter((w) => (w.start.x === 2 && w.start.y === 0) || (w.end.x === 2 && w.end.y === 0));
    expect(joint).toHaveLength(3); // the two halves and the new wall all meet at (2, 0)
    expect(next.past).toHaveLength(1);
  });

  it('splits at both ends of the same wall; a wall that would then duplicate the middle piece is rejected whole', () => {
    const base = floor([wall('a', 0, 0, 10, 0)]);
    const actions = planWallBatch({ floor: base, walls: [{ start: { x: 2, y: 0 }, end: { x: 8, y: 0 } }], newId: sequence() })!;
    expect(actions.filter((action) => action.type === 'split_wall')).toHaveLength(2);
    const state = stateOf(base);
    expect(reduceEditor(state, { type: 'batch', actions })).toBe(state);
  });

  it('resolves a second split to the half created by the first', () => {
    const base = floor([wall('a', 0, 0, 10, 0)]);
    const actions = planWallBatch({ floor: base, walls: [{ start: { x: 2, y: 0 }, end: { x: 8, y: 3 } }, { start: { x: 8, y: 3 }, end: { x: 8, y: 0 } }], newId: sequence() })!;
    const next = reduceEditor(stateOf(base), { type: 'batch', actions });
    expect(next.doc.plan.floors[0].walls).toHaveLength(3 + 2); // 'a' split twice => three walls, plus two new
  });

  it('does not split the wall it is editing (ignoreWallIds) and emits move_wall', () => {
    const base = floor([wall('a', 0, 0, 4, 0), wall('b', 0, 2, 4, 2)]);
    const actions = planWallBatch({ floor: base, walls: [{ start: { x: 0, y: 2 }, end: { x: 2, y: 0 } }], newId: sequence(), moveWallId: 'b', ignoreWallIds: ['b'] })!;
    expect(actions.map((action) => action.type)).toEqual(['split_wall', 'move_wall']);
    const next = reduceEditor(stateOf(base), { type: 'batch', actions });
    expect(next.doc.plan.floors[0].walls.find((w) => w.wall_id === 'b')!.end).toEqual({ x: 2, y: 0 });
  });

  it('rejects a duplicate wall through the reducer, but skipExisting drops it from the batch', () => {
    const base = floor([wall('a', 0, 0, 4, 0)]);
    const duplicate = planWallBatch({ floor: base, walls: [{ start: { x: 4, y: 0 }, end: { x: 0, y: 0 } }], newId: sequence() })!;
    expect(reduceEditor(stateOf(base), { type: 'batch', actions: duplicate }).doc.plan.floors[0].walls).toHaveLength(1);
    expect(planWallBatch({ floor: base, walls: [{ start: { x: 4, y: 0 }, end: { x: 0, y: 0 } }], newId: sequence(), skipExisting: true })).toBeNull();
  });

  it('returns null for a zero-length wall', () => {
    expect(planWallBatch({ floor: floor(), walls: [{ start: { x: 1, y: 1 }, end: { x: 1, y: 1 } }], newId: sequence() })).toBeNull();
  });
});

describe('rectangles', () => {
  it('orders corners clockwise from the top-left regardless of click order', () => {
    expect(rectangleCorners({ x: 4, y: 3 }, { x: 0, y: 0 })).toEqual([{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 3 }, { x: 0, y: 3 }]);
  });

  it('makes four walls plus the room in ONE undo step', () => {
    const base = floor();
    const batch = planRectangleBatch(base, { x: 0, y: 0 }, { x: 4, y: 3 }, 'Room 1', sequence())!;
    expect(batch.map((action) => action.type)).toEqual(['add_wall', 'add_wall', 'add_wall', 'add_wall', 'add_room']);
    const next = reduceEditor(stateOf(base), { type: 'batch', actions: batch });
    expect(next.doc.plan.floors[0].walls).toHaveLength(4);
    expect(next.doc.plan.floors[0].rooms).toHaveLength(1);
    expect(next.doc.plan.floors[0].walls.every((w) => w.thickness_m === 0.1)).toBe(true);
    expect(next.past).toHaveLength(1);
    const undone = reduceEditor(next, { type: 'undo' });
    expect(undone.doc.plan.floors[0].walls).toHaveLength(0);
    expect(undone.doc.plan.floors[0].rooms).toHaveLength(0);
  });

  it('shares an existing wall instead of duplicating it, and splits a wall a corner lands on', () => {
    const base = floor([wall('a', 0, 0, 4, 0), wall('b', 8, -2, 8, 6)]);
    const shared = planRectangleBatch(base, { x: 0, y: 0 }, { x: 4, y: 3 }, 'Room 2', sequence())!;
    expect(shared.filter((action) => action.type === 'add_wall')).toHaveLength(3);
    const touching = planRectangleBatch(base, { x: 6, y: 0 }, { x: 8, y: 3 }, 'Room 3', sequence())!;
    expect(touching.filter((action) => action.type === 'split_wall')).toHaveLength(2); // corners (8,0) and (8,3) are on wall b
    const next = reduceEditor(stateOf(base), { type: 'batch', actions: touching });
    expect(next.doc.plan.floors[0].walls).toHaveLength(1 + 3 + 3); // a, b split twice, and three new walls (the fourth is the middle piece of b)
  });

  it('rejects slivers', () => {
    expect(planRectangleBatch(floor(), { x: 0, y: 0 }, { x: 0.01, y: 3 }, 'x', sequence())).toBeNull();
    expect(planRectangleBatch(floor(), { x: 0, y: 0 }, { x: 3, y: 0 }, 'x', sequence())).toBeNull();
  });
});

describe('parseLengthEntry', () => {
  it('accepts digits with one dot and rejects everything else', () => {
    expect(parseLengthEntry('3.5')).toBe(3.5);
    expect(parseLengthEntry('.75')).toBe(0.75);
    expect(parseLengthEntry('12')).toBe(12);
    expect(parseLengthEntry('3.')).toBe(3);
    for (const bad of ['', '.', '0', '0.0', '1.2.3', '-4', '1e3', 'abc']) expect(parseLengthEntry(bad)).toBeNull();
  });
});
