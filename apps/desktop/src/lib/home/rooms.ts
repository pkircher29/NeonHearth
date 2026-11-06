// Rooms derived from the wall graph (home tools v2 · spec C).
//
// Walls form a planar graph. Every bounded face of that graph is a room the
// owner might want. We enumerate faces by half-edge traversal: leaving a node
// we always take the next edge clockwise from the one we arrived on, which
// walks each face exactly once. The unbounded face of each connected component
// comes out with the opposite winding, so it drops out on the area sign test.

import type { PlanPoint, Room, Wall } from '../stores/home';

export interface RoomCandidate {
  polygon: PlanPoint[];
  /** Area in m², always positive. */
  area: number;
  centroid: PlanPoint;
  /** Walls that bound this cycle. */
  wall_ids: string[];
}

/** Smallest cycle worth offering as a room — below this it is a drafting artefact. */
export const MIN_ROOM_AREA_M2 = 0.25;
const MAX_FACE_VERTICES = 256;

/** Signed shoelace area. Positive means clockwise on a screen-y-down plan. */
export function signedArea(points: readonly PlanPoint[]): number {
  if (points.length < 3) return 0;
  let total = 0;
  for (let index = 0; index < points.length; index += 1) {
    const a = points[index];
    const b = points[(index + 1) % points.length];
    total += a.x * b.y - b.x * a.y;
  }
  return total / 2;
}

/** Polygon area in m² (shoelace, absolute). */
export const polygonArea = (points: readonly PlanPoint[]): number => Math.abs(signedArea(points));

/** Area-weighted centroid; degenerate polygons fall back to the vertex mean. */
export function polygonCentroid(points: readonly PlanPoint[]): PlanPoint {
  const mean = points.reduce((acc, point) => ({ x: acc.x + point.x, y: acc.y + point.y }), { x: 0, y: 0 });
  if (points.length === 0) return { x: 0, y: 0 };
  const fallback = { x: mean.x / points.length, y: mean.y / points.length };
  const area = signedArea(points);
  if (Math.abs(area) < 1e-9) return fallback;
  let cx = 0;
  let cy = 0;
  for (let index = 0; index < points.length; index += 1) {
    const a = points[index];
    const b = points[(index + 1) % points.length];
    const cross = a.x * b.y - b.x * a.y;
    cx += (a.x + b.x) * cross;
    cy += (a.y + b.y) * cross;
  }
  return { x: cx / (6 * area), y: cy / (6 * area) };
}

/** Total area of a floor's rooms in m². */
export const floorArea = (rooms: readonly Pick<Room, 'polygon'>[]): number =>
  rooms.reduce((total, room) => total + polygonArea(room.polygon), 0);

const nodeKey = (point: PlanPoint) => `${Math.round(point.x * 10)}:${Math.round(point.y * 10)}`;

interface HalfEdge { id: string; from: string; to: string; angle: number; wall_id: string }

/**
 * Closed cycles in the wall graph, as candidate room polygons ordered
 * largest-first. Dangling walls and repeated-vertex walks are discarded.
 */
export function detectRoomCycles(walls: readonly Pick<Wall, 'wall_id' | 'start' | 'end'>[]): RoomCandidate[] {
  const points = new Map<string, PlanPoint>();
  const outgoing = new Map<string, HalfEdge[]>();
  const edges = new Map<string, HalfEdge>();

  for (const wall of walls) {
    const fromKey = nodeKey(wall.start);
    const toKey = nodeKey(wall.end);
    if (fromKey === toKey) continue;
    points.set(fromKey, wall.start);
    points.set(toKey, wall.end);
    const pair: HalfEdge[] = [
      { id: `${wall.wall_id}:+`, from: fromKey, to: toKey, wall_id: wall.wall_id, angle: Math.atan2(wall.end.y - wall.start.y, wall.end.x - wall.start.x) },
      { id: `${wall.wall_id}:-`, from: toKey, to: fromKey, wall_id: wall.wall_id, angle: Math.atan2(wall.start.y - wall.end.y, wall.start.x - wall.end.x) }
    ];
    for (const edge of pair) {
      edges.set(edge.id, edge);
      const list = outgoing.get(edge.from);
      if (list) list.push(edge);
      else outgoing.set(edge.from, [edge]);
    }
  }
  for (const list of outgoing.values()) list.sort((a, b) => a.angle - b.angle);

  // Arriving on `edge`, leave on the neighbour immediately clockwise from the
  // way back — the classic next-face rule.
  function nextEdge(edge: HalfEdge): HalfEdge | null {
    const list = outgoing.get(edge.to);
    if (!list || list.length === 0) return null;
    const back = list.findIndex((candidate) => candidate.id === `${edge.wall_id}:${edge.id.endsWith('+') ? '-' : '+'}`);
    if (back < 0) return null;
    return list[(back - 1 + list.length) % list.length];
  }

  const visited = new Set<string>();
  const candidates: RoomCandidate[] = [];
  for (const start of edges.values()) {
    if (visited.has(start.id)) continue;
    const face: HalfEdge[] = [];
    let current: HalfEdge | null = start;
    while (current && !visited.has(current.id) && face.length <= MAX_FACE_VERTICES) {
      visited.add(current.id);
      face.push(current);
      current = nextEdge(current);
      if (current && current.id === start.id) break;
    }
    if (face.length < 3 || face.length > MAX_FACE_VERTICES) continue;
    const nodes = face.map((edge) => edge.from);
    if (new Set(nodes).size !== nodes.length) continue; // a spur was walked twice
    const polygon = nodes.map((key) => points.get(key)!);
    const area = signedArea(polygon);
    // Interior faces wind one way, the unbounded face of each component the other.
    if (area <= 0) continue;
    if (area < MIN_ROOM_AREA_M2) continue;
    candidates.push({ polygon, area, centroid: polygonCentroid(polygon), wall_ids: face.map((edge) => edge.wall_id) });
  }
  return candidates.sort((a, b) => b.area - a.area);
}

/** True when two polygons enclose the same set of corners (order and start-point independent). */
export function samePolygon(a: readonly PlanPoint[], b: readonly PlanPoint[]): boolean {
  if (a.length !== b.length) return false;
  const keys = (points: readonly PlanPoint[]) => points.map(nodeKey).sort().join('|');
  return keys(a) === keys(b);
}

/** Detected cycles that are not already an existing room on the floor. */
export function newRoomCandidates(
  walls: readonly Pick<Wall, 'wall_id' | 'start' | 'end'>[],
  rooms: readonly Pick<Room, 'polygon'>[]
): RoomCandidate[] {
  return detectRoomCycles(walls).filter((candidate) => !rooms.some((room) => samePolygon(room.polygon, candidate.polygon)));
}
