// Drafting actions for the plan editor (home tools v2 · spec B/C): everything that turns
// snapped clicks into reducer actions, kept pure so it is unit-testable without a canvas.

import type { EditAction, Floor, PlanPoint, Wall } from '../stores/home';
import { DEFAULT_THICKNESS_M } from '../stores/home';
import { projectOnSegment } from './snap';

export interface WallSpec { start: PlanPoint; end: PlanPoint }
export interface RoomSpec { name: string; polygon: PlanPoint[] }
export interface BatchOptions {
  floor: Floor;
  walls: readonly WallSpec[];
  newId: () => string;
  thickness_m?: number;
  /** Silently skip a new wall that already exists (rectangles sharing an edge); otherwise the batch will be rejected. */
  skipExisting?: boolean;
  room?: RoomSpec;
  /** Walls that must not be split (the wall being edited). */
  ignoreWallIds?: readonly string[];
  /** When set, the single spec moves this existing wall instead of adding one. */
  moveWallId?: string;
}

const TOUCH_M = 1e-4;
const samePoint = (a: PlanPoint, b: PlanPoint) => Math.abs(a.x - b.x) < 1e-6 && Math.abs(a.y - b.y) < 1e-6;
const sameSegment = (a: WallSpec, b: WallSpec) =>
  (samePoint(a.start, b.start) && samePoint(a.end, b.end)) || (samePoint(a.start, b.end) && samePoint(a.end, b.start));

/** Walls whose body (not an endpoint) contains `point`. */
export function wallsContaining(walls: readonly Pick<Wall, 'wall_id' | 'start' | 'end'>[], point: PlanPoint): string[] {
  const hits: string[] = [];
  for (const wall of walls) {
    const projected = projectOnSegment(point, wall.start, wall.end);
    if (projected.t <= 0 || projected.t >= 1) continue;
    if (Math.hypot(point.x - projected.point.x, point.y - projected.point.y) > TOUCH_M) continue;
    if (samePoint(point, wall.start) || samePoint(point, wall.end)) continue;
    hits.push(wall.wall_id);
  }
  return hits;
}

/**
 * One batch that adds (or moves) walls so each new endpoint truly joins whatever it touches:
 * a new endpoint that lands on the body of an existing wall first splits that wall there.
 * Returns null when there is nothing to do.
 */
export function planWallBatch(options: BatchOptions): EditAction[] | null {
  const { floor } = options;
  const actions: EditAction[] = [];
  const ignored = options.ignoreWallIds ?? [];
  let segments: Array<Pick<Wall, 'wall_id' | 'start' | 'end'>> = floor.walls
    .filter((wall) => !ignored.includes(wall.wall_id))
    .map((wall) => ({ wall_id: wall.wall_id, start: wall.start, end: wall.end }));

  const splitAt = (point: PlanPoint) => {
    for (const wall_id of wallsContaining(segments, point)) {
      const segment = segments.find((candidate) => candidate.wall_id === wall_id)!;
      const new_wall_id = options.newId();
      actions.push({ type: 'split_wall', floor_id: floor.floor_id, wall_id, at: point, new_wall_id, exact: true });
      segments = segments.flatMap((candidate) => candidate.wall_id === wall_id
        ? [{ ...candidate, end: point }, { wall_id: new_wall_id, start: point, end: segment.end }]
        : [candidate]);
    }
  };

  for (const wall of options.walls) {
    if (samePoint(wall.start, wall.end)) return null;
    splitAt(wall.start);
    splitAt(wall.end);
  }
  const added: WallSpec[] = [];
  for (const wall of options.walls) {
    const exists = floor.walls.some((candidate) => sameSegment(candidate, wall)) || added.some((candidate) => sameSegment(candidate, wall));
    if (exists && options.skipExisting) continue;
    added.push(wall);
    if (options.moveWallId) {
      actions.push({ type: 'move_wall', floor_id: floor.floor_id, wall_id: options.moveWallId, start: wall.start, end: wall.end, exact: true });
    } else {
      actions.push({ type: 'add_wall', floor_id: floor.floor_id, wall_id: options.newId(), start: wall.start, end: wall.end, thickness_m: options.thickness_m ?? DEFAULT_THICKNESS_M, exact: true });
    }
  }
  if (options.room) actions.push({ type: 'add_room', floor_id: floor.floor_id, room_id: options.newId(), name: options.room.name, polygon: options.room.polygon, exact: true });
  return actions.length > 0 ? actions : null;
}

/** The four corners of an axis-aligned rectangle spanned by two opposite corners, clockwise on screen. */
export function rectangleCorners(a: PlanPoint, b: PlanPoint): PlanPoint[] {
  const minX = Math.min(a.x, b.x), maxX = Math.max(a.x, b.x), minY = Math.min(a.y, b.y), maxY = Math.max(a.y, b.y);
  return [{ x: minX, y: minY }, { x: maxX, y: minY }, { x: maxX, y: maxY }, { x: minX, y: maxY }];
}

/** Four walls plus the room for a rectangle, as one batch. Null for a degenerate rectangle. */
export function planRectangleBatch(floor: Floor, a: PlanPoint, b: PlanPoint, name: string, newId: () => string, thickness_m = DEFAULT_THICKNESS_M): EditAction[] | null {
  if (Math.abs(a.x - b.x) < 0.05 || Math.abs(a.y - b.y) < 0.05) return null;
  const corners = rectangleCorners(a, b);
  const walls = corners.map((start, index) => ({ start, end: corners[(index + 1) % 4] }));
  return planWallBatch({ floor, walls, newId, thickness_m, skipExisting: true, room: { name, polygon: corners } });
}

/** Parse a typed length ("3.5", ".75") in display units; null when it is not a usable positive number. */
export function parseLengthEntry(entry: string): number | null {
  if (!/^\d*\.?\d*$/.test(entry) || entry === '' || entry === '.') return null;
  const value = Number(entry);
  return Number.isFinite(value) && value > 0 ? value : null;
}
