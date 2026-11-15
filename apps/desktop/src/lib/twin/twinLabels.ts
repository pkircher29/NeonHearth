// Pure maths for the twin's floating room labels and constant-size pins.
// No three.js here: the component projects points, these functions decide
// where a label sits, which labels survive, and how big a pin must be.

import { pointInPolygon, polygonCentroid, type Vec2 } from './geometry';

export interface Rect {
  x: number; // left
  y: number; // top
  w: number;
  h: number;
}

export interface LabelCandidate {
  id: string;
  /** Screen-space centre in canvas pixels. */
  x: number;
  y: number;
  w: number;
  h: number;
  /** Larger wins an overlap (room area in m^2). */
  priority: number;
}

/**
 * Where a room's label goes: the area-weighted centroid, or, for a concave
 * room whose centroid falls outside it, the middle of the widest horizontal
 * span through the centroid's row.
 */
export function labelAnchor(polygon: Vec2[]): Vec2 {
  if (polygon.length === 0) return { x: 0, y: 0 };
  const centroid = polygonCentroid(polygon);
  if (centroid && pointInPolygon(centroid, polygon)) return centroid;
  const y = centroid?.y ?? polygon[0]!.y;
  const xs: number[] = [];
  for (let i = 0; i < polygon.length; i += 1) {
    const a = polygon[i]!;
    const b = polygon[(i + 1) % polygon.length]!;
    if (a.y > y === b.y > y) continue;
    xs.push(a.x + ((y - a.y) / (b.y - a.y)) * (b.x - a.x));
  }
  xs.sort((p, q) => p - q);
  let best: Vec2 | null = null;
  let widest = -1;
  for (let i = 0; i + 1 < xs.length; i += 2) {
    const span = xs[i + 1]! - xs[i]!;
    if (span > widest) {
      widest = span;
      best = { x: (xs[i]! + xs[i + 1]!) / 2, y };
    }
  }
  if (best) return best;
  const mean = polygon.reduce((acc, p) => ({ x: acc.x + p.x, y: acc.y + p.y }), { x: 0, y: 0 });
  return { x: mean.x / polygon.length, y: mean.y / polygon.length };
}

/** Rough pill size in px for overlap culling (real text is measured by the browser). */
export function estimateLabelSize(name: string, hasArea = true): { w: number; h: number } {
  const w = Math.max(64, Math.min(220, name.length * 7.2 + 22));
  return { w, h: hasArea ? 38 : 24 };
}

const overlaps = (a: Rect, b: Rect, pad: number) =>
  a.x < b.x + b.w + pad && a.x + a.w + pad > b.x && a.y < b.y + b.h + pad && a.y + a.h + pad > b.y;

const rectOf = (c: LabelCandidate): Rect => ({ x: c.x - c.w / 2, y: c.y - c.h / 2, w: c.w, h: c.h });

/**
 * Keeps the labels that fit: centre inside the canvas, clear of every blocker
 * (the open detail card), and not overlapping a larger room's label.
 */
export function cullLabels(
  candidates: LabelCandidate[],
  viewport: { w: number; h: number },
  blockers: Rect[] = [],
  pad = 4
): Set<string> {
  const kept: Rect[] = [];
  const result = new Set<string>();
  const ordered = [...candidates].sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id));
  for (const candidate of ordered) {
    if (candidate.x < 0 || candidate.y < 0 || candidate.x > viewport.w || candidate.y > viewport.h) continue;
    const rect = rectOf(candidate);
    if (blockers.some((blocker) => overlaps(rect, blocker, 0))) continue;
    if (kept.some((other) => overlaps(rect, other, pad))) continue;
    kept.push(rect);
    result.add(candidate.id);
  }
  return result;
}

/** Labels read poorly when floors are seen edge-on (Front), so they hide there. */
export function labelsVisibleForPhi(phi: number): boolean {
  return phi < 1.3;
}

/**
 * Scale factor that keeps a pin at least `minPx` px in radius on screen,
 * growing with camera distance and capped so it never balloons up close.
 * Never below 1 (the pin's natural size).
 */
export function pinScreenScale(
  distance: number,
  fovDeg: number,
  viewportHeightPx: number,
  baseRadius = 0.13,
  minPx = 10,
  maxScale = 3
): number {
  if (!(distance > 0) || !(viewportHeightPx > 0)) return 1;
  const worldPerPx = (2 * distance * Math.tan((fovDeg * Math.PI) / 360)) / viewportHeightPx;
  const wanted = (minPx * worldPerPx) / baseRadius;
  return Math.min(maxScale, Math.max(1, wanted));
}
