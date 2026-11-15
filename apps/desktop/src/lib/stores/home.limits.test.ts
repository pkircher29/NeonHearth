import { describe, expect, it, vi } from 'vitest';

import {
  PLAN_LIMITS, PlanLimitError, createEditorState, createHomeApi, isHomePlan, polygonProblem, rejectionReason, reduceEditor,
  type EditAction, type EditorState, type HomePlan, type Wall
} from './home';

const uuid = (n: number) => `018f47a0-9b5c-7a22-8a33-${n.toString(16).padStart(12, '0')}`;
const homeId = uuid(1);
const groundId = uuid(2);
let counter = 1000;
const next = () => uuid(counter++);

function emptyPlan(): HomePlan {
  return { home_id: homeId, version: 1, name: 'Home', floors: [{ floor_id: groundId, level: 0, name: 'Ground', ceiling_height_m: 2.4, walls: [], rooms: [] }] };
}
const fresh = (plan: HomePlan = emptyPlan()): EditorState => createEditorState(plan, []);
const wall = (i: number): Wall => ({ wall_id: next(), start: { x: i * 0.1, y: 0 }, end: { x: i * 0.1, y: 1 }, openings: [] });
const rect = () => [{ x: 0, y: 0 }, { x: 2, y: 0 }, { x: 2, y: 2 }, { x: 0, y: 2 }];

describe('reducer enforces the validator caps and unique ids', () => {
  it('refuses the 2049th wall on a floor, with a specific reason', () => {
    const plan = emptyPlan();
    plan.floors[0]!.walls = Array.from({ length: PLAN_LIMITS.walls }, (_, i) => wall(i));
    const state = fresh(plan);
    const action: EditAction = { type: 'add_wall', floor_id: groundId, wall_id: next(), start: { x: 500, y: 0 }, end: { x: 500, y: 1 } };
    expect(reduceEditor(state, action)).toBe(state);
    expect(rejectionReason(state, action)).toMatch(/at most 2048 walls/);
  });

  it('refuses a duplicate id for a wall, opening, room and floor', () => {
    let state = fresh();
    const wallId = next();
    state = reduceEditor(state, { type: 'add_wall', floor_id: groundId, wall_id: wallId, start: { x: 0, y: 0 }, end: { x: 3, y: 0 } });
    const dupWall: EditAction = { type: 'add_wall', floor_id: groundId, wall_id: wallId, start: { x: 0, y: 1 }, end: { x: 3, y: 1 } };
    expect(reduceEditor(state, dupWall)).toBe(state);
    expect(rejectionReason(state, dupWall)).toMatch(/wall id is already used/);

    const openingId = next();
    state = reduceEditor(state, { type: 'add_opening', floor_id: groundId, wall_id: wallId, opening: { opening_id: openingId, kind: 'door', offset_m: 0.5, width_m: 0.9 } });
    const dupOpening: EditAction = { type: 'add_opening', floor_id: groundId, wall_id: wallId, opening: { opening_id: openingId, kind: 'window', offset_m: 1.5, width_m: 0.8 } };
    expect(reduceEditor(state, dupOpening)).toBe(state);
    expect(rejectionReason(state, dupOpening)).toMatch(/opening id/);

    const roomId = next();
    state = reduceEditor(state, { type: 'add_room', floor_id: groundId, room_id: roomId, name: 'Hall', polygon: rect() });
    const dupRoom: EditAction = { type: 'add_room', floor_id: groundId, room_id: roomId, name: 'Hall 2', polygon: rect() };
    expect(reduceEditor(state, dupRoom)).toBe(state);
    expect(rejectionReason(state, dupRoom)).toMatch(/room id/);

    const dupFloor: EditAction = { type: 'add_floor', floor_id: groundId, level: 1, name: 'Up', ceiling_height_m: 2.4 };
    expect(reduceEditor(state, dupFloor)).toBe(state);
    expect(rejectionReason(state, dupFloor)).toMatch(/floor id/);
  });

  it('refuses a room outline with more than 256 corners and the 65th floor', () => {
    const state = fresh();
    const many = Array.from({ length: PLAN_LIMITS.roomPoints + 1 }, (_, i) => ({ x: Math.cos((i / 257) * 2 * Math.PI) * 5, y: Math.sin((i / 257) * 2 * Math.PI) * 5 }));
    const room: EditAction = { type: 'add_room', floor_id: groundId, room_id: next(), name: 'Round', polygon: many };
    expect(reduceEditor(state, room)).toBe(state);
    expect(rejectionReason(state, room)).toMatch(/at most 256 corners/);

    let floors = state;
    for (let level = 1; level < PLAN_LIMITS.floors; level += 1) floors = reduceEditor(floors, { type: 'add_floor', floor_id: next(), level, name: `F${level}`, ceiling_height_m: 2.4 });
    expect(floors.doc.plan.floors).toHaveLength(PLAN_LIMITS.floors);
    const extra: EditAction = { type: 'add_floor', floor_id: next(), level: 70, name: 'Too many', ceiling_height_m: 2.4 };
    expect(reduceEditor(floors, extra)).toBe(floors);
    expect(rejectionReason(floors, extra)).toMatch(/at most 64 floors/);
  });

  it('every state the reducer accepts is storable (validator agrees)', () => {
    let state = fresh();
    for (let i = 0; i < 40; i += 1) state = reduceEditor(state, { type: 'add_wall', floor_id: groundId, wall_id: next(), start: { x: i, y: 0 }, end: { x: i, y: 2 } });
    expect(isHomePlan(state.doc.plan)).toBe(true);
  });
});

describe('room outlines', () => {
  it('rejects self-intersecting, zero-area and repeated-corner polygons', () => {
    const state = fresh();
    const bow: EditAction = { type: 'add_room', floor_id: groundId, room_id: next(), name: 'Bow', polygon: [{ x: 0, y: 0 }, { x: 2, y: 2 }, { x: 2, y: 0 }, { x: 0, y: 2 }] };
    expect(reduceEditor(state, bow)).toBe(state);
    expect(rejectionReason(state, bow)).toBe('The outline crosses itself.');
    const flat: EditAction = { type: 'add_room', floor_id: groundId, room_id: next(), name: 'Flat', polygon: [{ x: 0, y: 0 }, { x: 1, y: 0 }, { x: 2, y: 0 }] };
    expect(reduceEditor(state, flat)).toBe(state);
    expect(rejectionReason(state, flat)).toBe('The corners enclose no area.');
    expect(polygonProblem([{ x: 0, y: 0 }, { x: 0, y: 0 }, { x: 1, y: 1 }, { x: 2, y: 0 }])).toMatch(/same place/);
    expect(polygonProblem([{ x: 0, y: 0 }, { x: 2, y: 0 }, { x: 2, y: 2 }])).toBeNull();
  });
});

describe('split_wall clamping', () => {
  it('never creates a wall outside the original: a point beyond an end is refused', () => {
    let state = fresh();
    const wallId = next();
    state = reduceEditor(state, { type: 'add_wall', floor_id: groundId, wall_id: wallId, start: { x: 0, y: 0 }, end: { x: 4, y: 0 } });
    const beyond: EditAction = { type: 'split_wall', floor_id: groundId, wall_id: wallId, at: { x: 9, y: 0 }, new_wall_id: next() };
    expect(reduceEditor(state, beyond)).toBe(state);
    const before: EditAction = { type: 'split_wall', floor_id: groundId, wall_id: wallId, at: { x: -3, y: 0 }, new_wall_id: next() };
    expect(reduceEditor(state, before)).toBe(state);
    const ok = reduceEditor(state, { type: 'split_wall', floor_id: groundId, wall_id: wallId, at: { x: 2, y: 0 }, new_wall_id: next() });
    expect(ok.doc.plan.floors[0]!.walls.map((w) => [w.start.x, w.end.x])).toEqual([[0, 2], [2, 4]]);
  });
});

describe('draft persistence of over-limit plans', () => {
  const overCap = (): HomePlan => {
    const plan = emptyPlan();
    plan.floors[0]!.walls = Array.from({ length: PLAN_LIMITS.walls + 5 }, (_, i) => wall(i));
    return plan;
  };

  it('offers an intact over-limit draft instead of deleting it, and a structurally broken one is still discarded', async () => {
    const calls: string[] = [];
    const draft = { plan: overCap(), saved_at: '2026-08-23T00:00:00Z' };
    const fetchImpl = vi.fn(async (_url: string, init: RequestInit) => { calls.push(String(init.method)); return new Response(JSON.stringify(draft), { status: 200 }); });
    const api = createHomeApi({ baseUrl: 'http://127.0.0.1:1', fetchImpl: fetchImpl as never });
    const result = await api.loadDraft();
    expect(result.status).toBe('draft');
    expect(result.status === 'draft' && result.overLimits).toBe(true);
    expect(calls).toEqual(['GET']); // no DELETE

    const broken = { plan: { ...emptyPlan(), floors: [{ nope: true }] }, saved_at: '2026-08-23T00:00:00Z' };
    const calls2: string[] = [];
    const fetch2 = vi.fn(async (_url: string, init: RequestInit) => { calls2.push(String(init.method)); return new Response(init.method === 'GET' ? JSON.stringify(broken) : null, { status: init.method === 'GET' ? 200 : 204 }); });
    const result2 = await createHomeApi({ baseUrl: 'http://127.0.0.1:1', fetchImpl: fetch2 as never }).loadDraft();
    expect(result2.status).toBe('corrupt');
    expect(calls2).toEqual(['GET', 'DELETE']);
  });

  it('refuses to save an over-limit plan with a message that names the limit', async () => {
    const api = createHomeApi({ baseUrl: 'http://127.0.0.1:1', fetchImpl: vi.fn() as never });
    await expect(api.savePlan(overCap(), 1)).rejects.toBeInstanceOf(PlanLimitError);
    await expect(api.savePlan(overCap(), 1)).rejects.toThrow(/2053 walls, max 2048/);
  });
});
