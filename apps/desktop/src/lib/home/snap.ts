// The drafting snap ladder (home tools v2 · spec B).
//
// Priority, all inside a 12 px screen radius:
//   wall endpoint → wall midpoint → point on a wall → alignment-guide
//   intersection → grid.
// The winner carries a human label so the canvas can tell the owner exactly
// what the next click will produce ("endpoint", "on wall").

import { snapPoint, type PlanPoint } from '../stores/home';

export const SNAP_RADIUS_PX = 12;
/** Alignment guides latch a little wider than the snap radius so they are easy to catch. */
export const GUIDE_RADIUS_PX = 8;

export type SnapKind = 'endpoint' | 'midpoint' | 'on-wall' | 'guide' | 'grid';

export interface SnapSegment { wall_id: string; start: PlanPoint; end: PlanPoint }

export interface SnapOptions {
  walls: readonly SnapSegment[];
  /** Pixels per meter — the screen radius is converted to meters with it. */
  scale: number;
  radiusPx?: number;
  /** Walls excluded from snapping (the one being dragged). */
  excludeWallIds?: readonly string[];
  /** Extra endpoint-tier targets, e.g. the first point of the chain being drawn. */
  extraPoints?: readonly PlanPoint[];
}

export interface SnapResult {
  point: PlanPoint;
  kind: SnapKind;
  label: string;
  /** Set when the point lies on a wall's body and committing should split it. */
  wall_id: string | null;
  /** Alignment guides under the cursor, in plan coordinates (for the dashed overlay). */
  guides: { x: number | null; y: number | null };
}

export const SNAP_LABELS: Record<SnapKind, string> = {
  endpoint: 'endpoint',
  midpoint: 'midpoint',
  'on-wall': 'on wall',
  guide: 'align',
  grid: 'grid'
};

const distance = (a: PlanPoint, b: PlanPoint) => Math.hypot(a.x - b.x, a.y - b.y);

/** Every endpoint on the floor — the anchors alignment guides are drawn from. */
export function guideAnchors(walls: readonly SnapSegment[]): PlanPoint[] {
  const seen = new Set<string>();
  const anchors: PlanPoint[] = [];
  for (const wall of walls) {
    for (const point of [wall.start, wall.end]) {
      const key = `${point.x}:${point.y}`;
      if (seen.has(key)) continue;
      seen.add(key);
      anchors.push(point);
    }
  }
  return anchors;
}

/** Perpendicular projection of `point` onto the segment, with its clamped parameter. */
export function projectOnSegment(point: PlanPoint, start: PlanPoint, end: PlanPoint): { point: PlanPoint; t: number } {
  const dx = end.x - start.x;
  const dy = end.y - start.y;
  const lengthSquared = dx * dx + dy * dy;
  if (lengthSquared < 1e-12) return { point: { ...start }, t: 0 };
  const t = Math.min(1, Math.max(0, ((point.x - start.x) * dx + (point.y - start.y) * dy) / lengthSquared));
  return { point: { x: start.x + t * dx, y: start.y + t * dy }, t };
}

export function computeSnap(cursor: PlanPoint, options: SnapOptions): SnapResult {
  const scale = options.scale > 0 ? options.scale : 1;
  const radius = (options.radiusPx ?? SNAP_RADIUS_PX) / scale;
  const guideRadius = GUIDE_RADIUS_PX / scale;
  const excluded = new Set(options.excludeWallIds ?? []);
  const walls = options.walls.filter((wall) => !excluded.has(wall.wall_id));

  // Guides are computed for every cursor position: they are an overlay, not only a snap tier.
  const anchors = guideAnchors(walls);
  let guideX: number | null = null;
  let guideY: number | null = null;
  let bestGuideX = guideRadius;
  let bestGuideY = guideRadius;
  for (const anchor of anchors) {
    const dx = Math.abs(anchor.x - cursor.x);
    if (dx < bestGuideX) { bestGuideX = dx; guideX = anchor.x; }
    const dy = Math.abs(anchor.y - cursor.y);
    if (dy < bestGuideY) { bestGuideY = dy; guideY = anchor.y; }
  }
  const guides = { x: guideX, y: guideY };
  const result = (point: PlanPoint, kind: SnapKind, wall_id: string | null = null): SnapResult =>
    ({ point: snapPoint(point), kind, label: SNAP_LABELS[kind], wall_id, guides });

  // 1 — wall endpoints (and the chain's own origin).
  let best: { point: PlanPoint; d: number } | null = null;
  for (const point of [...options.extraPoints ?? [], ...walls.flatMap((wall) => [wall.start, wall.end])]) {
    const d = distance(cursor, point);
    if (d <= radius && (!best || d < best.d)) best = { point, d };
  }
  if (best) return result(best.point, 'endpoint');

  // 2 — wall midpoints.
  best = null;
  for (const wall of walls) {
    const mid = { x: (wall.start.x + wall.end.x) / 2, y: (wall.start.y + wall.end.y) / 2 };
    const d = distance(cursor, mid);
    if (d <= radius && (!best || d < best.d)) best = { point: mid, d };
  }
  if (best) return result(best.point, 'midpoint');

  // 3 — a point on a wall's body; committing here splits that wall.
  let onWall: { point: PlanPoint; d: number; wall_id: string } | null = null;
  for (const wall of walls) {
    const projected = projectOnSegment(cursor, wall.start, wall.end);
    if (projected.t <= 0.001 || projected.t >= 0.999) continue;
    const d = distance(cursor, projected.point);
    if (d <= radius && (!onWall || d < onWall.d)) onWall = { point: projected.point, d, wall_id: wall.wall_id };
  }
  if (onWall) return result(onWall.point, 'on-wall', onWall.wall_id);

  // 4 — the intersection of a horizontal and a vertical alignment guide.
  if (guideX !== null && guideY !== null) return result({ x: guideX, y: guideY }, 'guide');

  // 5 — the 0.1 m grid.
  return result(cursor, 'grid');
}

/** Shift constraint: keep the direction on the nearest 45° ray from `from`. */
export function constrainAngle(from: PlanPoint, to: PlanPoint): PlanPoint {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const length = Math.hypot(dx, dy);
  if (length < 1e-9) return { ...to };
  const step = Math.PI / 4;
  const angle = Math.round(Math.atan2(dy, dx) / step) * step;
  return snapPoint({ x: from.x + Math.cos(angle) * length, y: from.y + Math.sin(angle) * length });
}

/** The point `length` meters from `from` along the `from → towards` direction. */
export function pointAtLength(from: PlanPoint, towards: PlanPoint, length: number): PlanPoint {
  const dx = towards.x - from.x;
  const dy = towards.y - from.y;
  const current = Math.hypot(dx, dy);
  if (current < 1e-9) return snapPoint({ x: from.x + length, y: from.y });
  return snapPoint({ x: from.x + (dx / current) * length, y: from.y + (dy / current) * length });
}

/** Compass-style bearing in degrees, 0 = east, measured counter-clockwise on a screen-y-down plan. */
export function angleDegrees(from: PlanPoint, to: PlanPoint): number {
  const degrees = (Math.atan2(-(to.y - from.y), to.x - from.x) * 180) / Math.PI;
  return Math.round(((degrees % 360) + 360) % 360);
}
