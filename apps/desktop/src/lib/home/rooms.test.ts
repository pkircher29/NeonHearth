import { describe, expect, it } from 'vitest';

import { MIN_ROOM_AREA_M2, detectRoomCycles, floorArea, newRoomCandidates, polygonArea, polygonCentroid, samePolygon, signedArea, dividedRooms, pointInPolygon } from './rooms';

let counter = 0;
const wall = (sx: number, sy: number, ex: number, ey: number) => ({ wall_id: `w${counter++}`, start: { x: sx, y: sy }, end: { x: ex, y: ey } });
const rectangle = (x: number, y: number, w: number, h: number) => [wall(x, y, x + w, y), wall(x + w, y, x + w, y + h), wall(x + w, y + h, x, y + h), wall(x, y + h, x, y)];

describe('polygon maths', () => {
  const square = [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 3 }, { x: 0, y: 3 }];
  it('computes shoelace area, signed and absolute', () => {
    expect(polygonArea(square)).toBe(12);
    expect(signedArea(square)).toBe(12); // clockwise on a y-down plan is positive
    expect(signedArea([...square].reverse())).toBe(-12);
    expect(polygonArea([{ x: 0, y: 0 }, { x: 1, y: 1 }])).toBe(0);
  });
  it('is area-weighted: a skinny L has its centroid in the heavy part, not at the vertex mean', () => {
    const l = [{ x: 0, y: 0 }, { x: 10, y: 0 }, { x: 10, y: 1 }, { x: 1, y: 1 }, { x: 1, y: 10 }, { x: 0, y: 10 }];
    const centre = polygonCentroid(l);
    const mean = { x: l.reduce((sum, p) => sum + p.x, 0) / l.length, y: l.reduce((sum, p) => sum + p.y, 0) / l.length };
    expect(centre.x).toBeCloseTo(54.5 / 19, 6);
    expect(centre.y).toBeCloseTo(54.5 / 19, 6);
    expect(Math.hypot(centre.x - mean.x, centre.y - mean.y)).toBeGreaterThan(0.1);
  });
  it('centroid of a rectangle is its centre and degenerate input falls back to the mean', () => {
    expect(polygonCentroid(square)).toEqual({ x: 2, y: 1.5 });
    expect(polygonCentroid([{ x: 0, y: 0 }, { x: 2, y: 0 }, { x: 4, y: 0 }])).toEqual({ x: 2, y: 0 });
    expect(polygonCentroid([])).toEqual({ x: 0, y: 0 });
  });
  it('sums room areas for a floor', () => {
    expect(floorArea([{ polygon: square }, { polygon: [{ x: 0, y: 0 }, { x: 2, y: 0 }, { x: 2, y: 2 }, { x: 0, y: 2 }] }])).toBe(16);
    expect(floorArea([])).toBe(0);
  });
  it('compares polygons ignoring order and start point', () => {
    expect(samePolygon(square, [square[2], square[3], square[0], square[1]])).toBe(true);
    expect(samePolygon(square, [...square].reverse())).toBe(true);
    expect(samePolygon(square, [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 4 }, { x: 0, y: 4 }])).toBe(false);
    expect(samePolygon(square, square.slice(0, 3))).toBe(false);
  });
});

describe('detectRoomCycles', () => {
  it('finds a single closed room with the right area and centroid', () => {
    const rooms = detectRoomCycles(rectangle(0, 0, 4, 3));
    expect(rooms).toHaveLength(1);
    expect(rooms[0].area).toBe(12);
    expect(rooms[0].centroid).toEqual({ x: 2, y: 1.5 });
    expect(rooms[0].polygon).toHaveLength(4);
    expect(rooms[0].wall_ids).toHaveLength(4);
  });

  it('finds nothing in an open chain', () => {
    expect(detectRoomCycles([wall(0, 0, 4, 0), wall(4, 0, 4, 3), wall(4, 3, 0, 3)])).toEqual([]);
    expect(detectRoomCycles([])).toEqual([]);
  });

  it('finds two rooms that share a wall, largest first, and not the outer outline', () => {
    const walls = [...rectangle(0, 0, 4, 3), wall(2, 0, 2, 3)].filter((w, index) => !(index === 0));
    // Rebuild cleanly: outer rectangle split at x=2 along the top and bottom, plus the divider.
    const clean = [wall(0, 0, 2, 0), wall(2, 0, 4, 0), wall(4, 0, 4, 3), wall(4, 3, 2, 3), wall(2, 3, 0, 3), wall(0, 3, 0, 0), wall(2, 0, 2, 3)];
    const rooms = detectRoomCycles(clean);
    expect(walls.length).toBeGreaterThan(0);
    expect(rooms).toHaveLength(2);
    expect(rooms.map((room) => room.area)).toEqual([6, 6]);
    expect(rooms.every((room) => room.polygon.length === 4)).toBe(true);
  });

  it('sorts rooms largest first', () => {
    const rooms = detectRoomCycles([...rectangle(0, 0, 2, 2), ...rectangle(10, 0, 5, 4)]);
    expect(rooms.map((room) => room.area)).toEqual([20, 4]);
  });

  it('ignores a dangling wall hanging into a room', () => {
    const rooms = detectRoomCycles([...rectangle(0, 0, 4, 3), wall(2, 0, 2, 1.5)]);
    // The spur walks the same vertex twice, so the face containing it is discarded rather than mis-reported.
    for (const room of rooms) expect(new Set(room.polygon.map((p) => `${p.x}:${p.y}`)).size).toBe(room.polygon.length);
  });

  it('drops degenerate slivers below the minimum area', () => {
    expect(MIN_ROOM_AREA_M2).toBeGreaterThan(0);
    expect(detectRoomCycles(rectangle(0, 0, 0.3, 0.3))).toEqual([]);
    expect(detectRoomCycles(rectangle(0, 0, 0.6, 0.6))).toHaveLength(1);
  });

  it('skips zero-length walls and keeps working', () => {
    expect(detectRoomCycles([...rectangle(0, 0, 4, 3), wall(1, 1, 1, 1)])).toHaveLength(1);
  });

  it('handles a triangle and an L-shaped room', () => {
    expect(detectRoomCycles([wall(0, 0, 4, 0), wall(4, 0, 0, 3), wall(0, 3, 0, 0)])[0].area).toBe(6);
    const l = [wall(0, 0, 4, 0), wall(4, 0, 4, 2), wall(4, 2, 2, 2), wall(2, 2, 2, 4), wall(2, 4, 0, 4), wall(0, 4, 0, 0)];
    const [room] = detectRoomCycles(l);
    expect(room.area).toBe(12);
    expect(room.polygon).toHaveLength(6);
  });

  it('treats endpoints within a decimeter bucket as the same node (joined by snapping)', () => {
    const rooms = detectRoomCycles([wall(0, 0, 4, 0), wall(4.001, 0, 4, 3), wall(4, 3.0002, 0, 3), wall(0.0003, 3, 0, 0)]);
    expect(rooms).toHaveLength(1);
  });
});

describe('newRoomCandidates', () => {
  it('drops cycles that are already rooms', () => {
    const walls = rectangle(0, 0, 4, 3);
    const existing = [{ polygon: [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 3 }, { x: 0, y: 3 }] }];
    expect(newRoomCandidates(walls, existing)).toEqual([]);
    expect(newRoomCandidates(walls, [])).toHaveLength(1);
  });
  it('keeps the cycles that are not rooms yet', () => {
    const walls = [...rectangle(0, 0, 4, 3), ...rectangle(10, 0, 3, 3)];
    const candidates = newRoomCandidates(walls, [{ polygon: [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 3 }, { x: 0, y: 3 }] }]);
    expect(candidates).toHaveLength(1);
    expect(candidates[0].area).toBe(9);
  });
});

describe('dividedRooms', () => {
  const wall = (id: string, x1: number, y1: number, x2: number, y2: number) => ({ wall_id: id, start: { x: x1, y: y1 }, end: { x: x2, y: y2 } });
  const whole = { polygon: [{ x: 0, y: 0 }, { x: 10, y: 0 }, { x: 10, y: 6 }, { x: 0, y: 6 }] };
  const left = { polygon: [{ x: 0, y: 0 }, { x: 5, y: 0 }, { x: 5, y: 6 }, { x: 0, y: 6 }] };
  const right = { polygon: [{ x: 5, y: 0 }, { x: 10, y: 0 }, { x: 10, y: 6 }, { x: 5, y: 6 }] };
  const split = [wall('a', 0, 0, 5, 0), wall('b', 5, 0, 10, 0), wall('c', 10, 0, 10, 6), wall('d', 10, 6, 5, 6), wall('e', 5, 6, 0, 6), wall('f', 0, 6, 0, 0), wall('p', 5, 0, 5, 6)];

  it('reports a room once a partition has divided it and both halves are rooms', () => {
    expect(dividedRooms(split, [whole, left, right])).toEqual([whole]);
  });
  it('keeps the room while a half is still missing', () => {
    expect(dividedRooms(split, [whole, left])).toEqual([]);
  });
  it('keeps an undivided room and a room with no walls around it', () => {
    const outline = split.filter((entry) => entry.wall_id !== 'p');
    expect(dividedRooms(outline, [whole])).toEqual([]);
    expect(dividedRooms([], [whole])).toEqual([]);
  });
  it('pointInPolygon separates inside from outside', () => {
    expect(pointInPolygon({ x: 2, y: 2 }, whole.polygon)).toBe(true);
    expect(pointInPolygon({ x: 12, y: 2 }, whole.polygon)).toBe(false);
  });
});
