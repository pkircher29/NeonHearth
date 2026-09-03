import { describe, expect, it, vi } from 'vitest';

import {
  HISTORY_LIMIT, createEditorState, createHomeApi, isHomePlan, reduceEditor, selectUncertain, selectUnplaced, snap, wallLength,
  type EditorState, type Estimate, type HomeDeviceRef, type HomePlan, type Placement
} from './home';

const homeId = '018f47a0-9b5c-7a22-8a33-aabbccdd0001';
const groundId = '018f47a0-9b5c-7a22-8a33-aabbccdd0010';
const upperId = '018f47a0-9b5c-7a22-8a33-aabbccdd0011';
const wallId = '018f47a0-9b5c-7a22-8a33-aabbccdd0020';
const doorId = '018f47a0-9b5c-7a22-8a33-aabbccdd0030';
const roomId = '018f47a0-9b5c-7a22-8a33-aabbccdd0040';
const deviceA = '018f47a0-9b5c-7a22-8a33-aabbccdd0050';
const deviceB = '018f47a0-9b5c-7a22-8a33-aabbccdd0051';
const placementId = '018f47a0-9b5c-7a22-8a33-aabbccdd0060';
const freshId = (suffix: string) => `018f47a0-9b5c-7a22-8a33-aabbccdd${suffix}`;

function fixturePlan(): HomePlan {
  return {
    home_id: homeId, version: 3, name: 'Home',
    floors: [
      {
        floor_id: groundId, level: 0, name: 'Ground', ceiling_height_m: 2.4,
        walls: [{ wall_id: wallId, start: { x: 0, y: 0 }, end: { x: 4.2, y: 0 }, openings: [{ opening_id: doorId, kind: 'door', offset_m: 0.8, width_m: 0.9 }] }],
        rooms: [{ room_id: roomId, name: 'Kitchen', polygon: [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 3 }, { x: 0, y: 3 }] }]
      },
      { floor_id: upperId, level: 1, name: 'Upstairs', ceiling_height_m: 2.4, walls: [], rooms: [] }
    ]
  };
}
const fixturePlacement = (): Placement => ({ placement_id: placementId, device_id: deviceA, floor_id: groundId, x: 1.5, y: 2.0, height_m: 1.1, mounting: 'wall' });
const fresh = (placements: Placement[] = []): EditorState => createEditorState(fixturePlan(), placements);
const ground = (state: EditorState) => state.doc.plan.floors[0];

describe('editor reducer', () => {
  it('adds walls snapped to the 0.1 m grid and rejects zero-length walls', () => {
    const state = fresh();
    const added = reduceEditor(state, { type: 'add_wall', floor_id: groundId, wall_id: freshId('0100'), start: { x: 1.234, y: 0.96 }, end: { x: 3.049, y: 0.96 } });
    const wall = ground(added).walls.at(-1)!;
    expect(wall.start).toEqual({ x: 1.2, y: 1.0 });
    expect(wall.end).toEqual({ x: 3.0, y: 1.0 });
    expect(reduceEditor(state, { type: 'add_wall', floor_id: groundId, wall_id: freshId('0101'), start: { x: 1.01, y: 1.01 }, end: { x: 0.99, y: 0.99 } })).toBe(state);
    expect(reduceEditor(state, { type: 'add_wall', floor_id: freshId('dead'), wall_id: freshId('0102'), start: { x: 0, y: 0 }, end: { x: 1, y: 1 } })).toBe(state);
  });

  it('moves walls with snapping and drops only openings that no longer fit', () => {
    const moved = reduceEditor(fresh(), { type: 'move_wall', floor_id: groundId, wall_id: wallId, start: { x: 0, y: 0 }, end: { x: 1.44, y: 0 } });
    const wall = ground(moved).walls[0];
    expect(wall.end).toEqual({ x: 1.4, y: 0 });
    expect(wall.openings).toEqual([]); // door needed 0.8 + 0.9 m
    const stretched = reduceEditor(fresh(), { type: 'move_wall', floor_id: groundId, wall_id: wallId, start: { x: 0, y: 0 }, end: { x: 6, y: 0 } });
    expect(ground(stretched).walls[0].openings).toHaveLength(1);
  });

  it('splits a wall at a snapped interior point and distributes openings', () => {
    const newWall = freshId('0110');
    const split = reduceEditor(fresh(), { type: 'split_wall', floor_id: groundId, wall_id: wallId, at: { x: 2.04, y: 0.03 }, new_wall_id: newWall });
    const walls = ground(split).walls;
    expect(walls).toHaveLength(2);
    expect(walls[0].end).toEqual({ x: 2.0, y: 0 });
    expect(walls[1]).toMatchObject({ wall_id: newWall, start: { x: 2.0, y: 0 }, end: { x: 4.2, y: 0 } });
    expect(walls[0].openings).toEqual([{ opening_id: doorId, kind: 'door', offset_m: 0.8, width_m: 0.9 }]);
    expect(walls[1].openings).toEqual([]);
    // Splitting inside the door (0.8..1.7) or at an endpoint is rejected.
    const state = fresh();
    expect(reduceEditor(state, { type: 'split_wall', floor_id: groundId, wall_id: wallId, at: { x: 1.0, y: 0 }, new_wall_id: newWall })).toBe(state);
    expect(reduceEditor(state, { type: 'split_wall', floor_id: groundId, wall_id: wallId, at: { x: 0.02, y: 0 }, new_wall_id: newWall })).toBe(state);
  });

  it('validates opening offset and width against the wall length', () => {
    const state = fresh();
    const fits = reduceEditor(state, { type: 'add_opening', floor_id: groundId, wall_id: wallId, opening: { opening_id: freshId('0120'), kind: 'window', offset_m: 3.0, width_m: 1.2 } });
    expect(ground(fits).walls[0].openings).toHaveLength(2);
    for (const opening of [
      { opening_id: freshId('0121'), kind: 'window' as const, offset_m: 3.6, width_m: 0.7 }, // 4.3 > 4.2
      { opening_id: freshId('0122'), kind: 'door' as const, offset_m: -0.2, width_m: 0.9 },
      { opening_id: freshId('0123'), kind: 'stair' as const, offset_m: 1.0, width_m: 0 }
    ]) {
      expect(reduceEditor(state, { type: 'add_opening', floor_id: groundId, wall_id: wallId, opening })).toBe(state);
    }
  });

  it('manages rooms with a >= 3 point polygon rule and honest renames', () => {
    const state = fresh();
    const added = reduceEditor(state, { type: 'add_room', floor_id: groundId, room_id: freshId('0130'), name: 'Den', polygon: [{ x: 0.04, y: 0 }, { x: 2, y: 0 }, { x: 2, y: 2 }] });
    expect(ground(added).rooms.at(-1)).toMatchObject({ name: 'Den', polygon: [{ x: 0, y: 0 }, { x: 2, y: 0 }, { x: 2, y: 2 }] });
    expect(reduceEditor(state, { type: 'add_room', floor_id: groundId, room_id: freshId('0131'), name: 'Bad', polygon: [{ x: 0, y: 0 }, { x: 2, y: 0 }] })).toBe(state);
    expect(reduceEditor(state, { type: 'rename_room', floor_id: groundId, room_id: roomId, name: '   ' })).toBe(state);
    const renamed = reduceEditor(state, { type: 'rename_room', floor_id: groundId, room_id: roomId, name: 'Galley' });
    expect(ground(renamed).rooms[0].name).toBe('Galley');
    const deleted = reduceEditor(state, { type: 'delete_room', floor_id: groundId, room_id: roomId });
    expect(ground(deleted).rooms).toHaveLength(0);
  });

  it('manages floors with level uniqueness and the 1.8..6.0 m ceiling rule', () => {
    const state = fresh([fixturePlacement()]);
    const added = reduceEditor(state, { type: 'add_floor', floor_id: freshId('0140'), level: -1, name: 'Basement', ceiling_height_m: 2.1 });
    expect(added.doc.plan.floors.map((floor) => floor.level)).toEqual([-1, 0, 1]);
    expect(reduceEditor(state, { type: 'add_floor', floor_id: freshId('0141'), level: 0, name: 'Duplicate', ceiling_height_m: 2.4 })).toBe(state);
    expect(reduceEditor(state, { type: 'add_floor', floor_id: freshId('0142'), level: 2, name: 'Attic', ceiling_height_m: 1.7 })).toBe(state);
    expect(reduceEditor(state, { type: 'set_ceiling_height', floor_id: groundId, ceiling_height_m: 6.5 })).toBe(state);
    expect(ground(reduceEditor(state, { type: 'set_ceiling_height', floor_id: groundId, ceiling_height_m: 3.2 })).ceiling_height_m).toBe(3.2);
    // A floor with owner placements cannot be deleted; an empty one can.
    expect(reduceEditor(state, { type: 'delete_floor', floor_id: groundId })).toBe(state);
    expect(reduceEditor(state, { type: 'delete_floor', floor_id: upperId }).doc.plan.floors).toHaveLength(1);
  });

  it('places, moves, configures and removes device placements with snapping and ceiling bounds', () => {
    const state = fresh();
    const placed = reduceEditor(state, { type: 'place_device', placement: { ...fixturePlacement(), x: 1.52, y: 2.04 } });
    expect(placed.doc.placements[0]).toMatchObject({ device_id: deviceA, x: 1.5, y: 2.0 });
    // Re-placing the same device is an upsert that keeps the original placement_id.
    const replaced = reduceEditor(placed, { type: 'place_device', placement: { ...fixturePlacement(), placement_id: freshId('0150'), x: 3, y: 3 } });
    expect(replaced.doc.placements).toHaveLength(1);
    expect(replaced.doc.placements[0]).toMatchObject({ placement_id: placementId, x: 3, y: 3 });
    expect(reduceEditor(state, { type: 'place_device', placement: { ...fixturePlacement(), height_m: 2.5 } })).toBe(state);
    const moved = reduceEditor(placed, { type: 'move_placement', device_id: deviceA, x: 2.28, y: 0.11 });
    expect(moved.doc.placements[0]).toMatchObject({ x: 2.3, y: 0.1 });
    expect(reduceEditor(placed, { type: 'configure_placement', device_id: deviceA, height_m: 9 })).toBe(placed);
    const configured = reduceEditor(placed, { type: 'configure_placement', device_id: deviceA, height_m: 2.2, mounting: 'ceiling' });
    expect(configured.doc.placements[0]).toMatchObject({ height_m: 2.2, mounting: 'ceiling' });
    expect(reduceEditor(placed, { type: 'remove_placement', device_id: deviceA }).doc.placements).toEqual([]);
    expect(reduceEditor(state, { type: 'remove_placement', device_id: deviceA })).toBe(state);
  });

  it('round-trips undo and redo and clears redo on a new edit', () => {
    const start = fresh();
    const one = reduceEditor(start, { type: 'rename_floor', floor_id: groundId, name: 'Main' });
    const two = reduceEditor(one, { type: 'delete_room', floor_id: groundId, room_id: roomId });
    const undoOnce = reduceEditor(two, { type: 'undo' });
    expect(undoOnce.doc).toBe(one.doc);
    const undoTwice = reduceEditor(undoOnce, { type: 'undo' });
    expect(undoTwice.doc).toBe(start.doc);
    expect(reduceEditor(undoTwice, { type: 'undo' })).toBe(undoTwice);
    const redoOnce = reduceEditor(undoTwice, { type: 'redo' });
    expect(redoOnce.doc).toBe(one.doc);
    expect(reduceEditor(reduceEditor(redoOnce, { type: 'redo' }), { type: 'redo' }).doc).toBe(two.doc);
    const branched = reduceEditor(redoOnce, { type: 'rename_floor', floor_id: groundId, name: 'Lounge' });
    expect(branched.future).toEqual([]);
    expect(reduceEditor(branched, { type: 'redo' })).toBe(branched);
  });

  it('bounds history to the newest entries', () => {
    let state = fresh();
    for (let step = 0; step < HISTORY_LIMIT + 5; step += 1) {
      state = reduceEditor(state, { type: 'rename_floor', floor_id: groundId, name: `Ground ${step}` });
    }
    expect(state.past).toHaveLength(HISTORY_LIMIT);
    while (state.past.length > 0) state = reduceEditor(state, { type: 'undo' });
    expect(state.doc.plan.floors[0].name).toBe('Ground 4'); // the 5 oldest entries were evicted
  });
});

describe('selectors', () => {
  const devices: HomeDeviceRef[] = [{ device_id: deviceA, name: 'Hall sensor' }, { device_id: deviceB, name: 'Attic node' }];
  const estimate = (device_id: string, confidence: number): Estimate => ({ device_id, floor_id: groundId, room_id: roomId, confidence, evidence: ['w6-rssi'], estimated_at: '2026-08-20T00:00:00Z' });

  it('lists only devices without an owner placement in the tray', () => {
    expect(selectUnplaced(devices, [fixturePlacement()]).map((device) => device.device_id)).toEqual([deviceB]);
    expect(selectUnplaced(devices, []).map((device) => device.device_id)).toEqual([deviceA, deviceB]);
  });

  it('marks a device uncertain only when an estimate is below 0.6 and no owner placement exists', () => {
    const uncertain = selectUncertain(devices, [], [estimate(deviceA, 0.4), estimate(deviceB, 0.85)]);
    expect(uncertain.map((entry) => entry.device.device_id)).toEqual([deviceA]);
    expect(selectUncertain(devices, [fixturePlacement()], [estimate(deviceA, 0.4)])).toEqual([]);
    expect(selectUncertain(devices, [], [estimate(deviceA, 0.6)])).toEqual([]);
  });
});

describe('createHomeApi', () => {
  const options = { baseUrl: 'https://collector.example', serviceToken: 'secret' };
  const snapshot = { plan: fixturePlan(), placements: [fixturePlacement()], estimates: [] };

  it('fetches and strictly validates the home snapshot', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(snapshot), { status: 200 }));
    const api = createHomeApi({ ...options, fetchImpl });
    await expect(api.fetchHome()).resolves.toEqual(snapshot);
    expect(fetchImpl).toHaveBeenCalledWith('https://collector.example/api/v1/home', { method: 'GET', headers: { Authorization: 'Bearer secret' }, signal: expect.any(AbortSignal) });
    const malformed = vi.fn(async () => new Response(JSON.stringify({ plan: { ...fixturePlan(), version: -1 }, placements: [], estimates: [] }), { status: 200 }));
    await expect(createHomeApi({ ...options, fetchImpl: malformed }).fetchHome()).rejects.toThrow('Invalid home response');
  });

  it('saves a plan with expected_version and surfaces a 409 as a distinct conflict result', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ version: 4 }), { status: 200 }));
    const api = createHomeApi({ ...options, fetchImpl });
    await expect(api.savePlan(fixturePlan(), 3)).resolves.toEqual({ status: 'saved', version: 4 });
    const [, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.method).toBe('PUT');
    expect(JSON.parse(String(init.body))).toMatchObject({ expected_version: 3, plan: { home_id: homeId } });
    const conflicted = createHomeApi({ ...options, fetchImpl: vi.fn(async () => new Response(null, { status: 409 })) });
    await expect(conflicted.savePlan(fixturePlan(), 3)).resolves.toEqual({ status: 'conflict' });
    const failing = createHomeApi({ ...options, fetchImpl: vi.fn(async () => new Response(null, { status: 503 })) });
    await expect(failing.savePlan(fixturePlan(), 3)).rejects.toThrow('status 503');
  });

  it('caps drafts at 512 KiB before they leave the app', async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
    const api = createHomeApi({ ...options, fetchImpl });
    const oversized = { plan: { ...fixturePlan(), name: 'Home' }, saved_at: '2026-08-24T00:00:00Z', padding: 'x'.repeat(512 * 1024) } as unknown as { plan: HomePlan; saved_at: string };
    await expect(api.saveDraft(oversized)).rejects.toThrow('Draft exceeds safety bound');
    expect(fetchImpl).not.toHaveBeenCalled();
    await expect(api.saveDraft({ plan: fixturePlan(), saved_at: '2026-08-24T00:00:00Z' })).resolves.toBeUndefined();
  });

  it('reports a missing draft, a valid draft, and discards a corrupt draft', async () => {
    const none = createHomeApi({ ...options, fetchImpl: vi.fn(async () => new Response(null, { status: 404 })) });
    await expect(none.loadDraft()).resolves.toEqual({ status: 'none' });

    const draft = { plan: fixturePlan(), saved_at: '2026-08-24T00:00:00Z' };
    const valid = createHomeApi({ ...options, fetchImpl: vi.fn(async () => new Response(JSON.stringify(draft), { status: 200 })) });
    await expect(valid.loadDraft()).resolves.toEqual({ status: 'draft', draft });

    const calls: Array<{ url: string; method?: string }> = [];
    const corruptFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), method: init?.method });
      return init?.method === 'DELETE' ? new Response(null, { status: 204 }) : new Response('{"plan":{"broken', { status: 200 });
    });
    await expect(createHomeApi({ ...options, fetchImpl: corruptFetch }).loadDraft()).resolves.toEqual({ status: 'corrupt' });
    expect(calls).toEqual([
      { url: 'https://collector.example/api/v1/home/draft', method: 'GET' },
      { url: 'https://collector.example/api/v1/home/draft', method: 'DELETE' }
    ]);
  });

  it('writes and deletes owner placements through the per-device routes', async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
    const api = createHomeApi({ ...options, fetchImpl });
    await api.putPlacement(fixturePlacement());
    await api.deletePlacement(deviceA);
    const calls = fetchImpl.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls[0][0]).toBe(`https://collector.example/api/v1/home/placements/${deviceA}`);
    expect(calls[1][1].method).toBe('DELETE');
    await expect(api.putPlacement({ ...fixturePlacement(), device_id: 'not-a-uuid' })).rejects.toThrow('Invalid placement');
  });
});

describe('plan helpers', () => {
  it('snaps to the 0.1 m grid without float drift and measures walls', () => {
    expect(snap(0.30000000000000004)).toBe(0.3);
    expect(snap(1.25)).toBe(1.3);
    expect(wallLength({ start: { x: 0, y: 0 }, end: { x: 3, y: 4 } })).toBe(5);
    expect(isHomePlan(fixturePlan())).toBe(true);
    expect(isHomePlan({ ...fixturePlan(), floors: [{ ...fixturePlan().floors[0], ceiling_height_m: 1.0 }] })).toBe(false);
  });
});
