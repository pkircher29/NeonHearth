// Per-floor view persistence and the first-open auto-fit rule (home tools v2 · spec A).

import type { Floor, PlanPoint } from '../stores/home';
import { boundsOf, clampScale, defaultView, fitView, type Bounds, type Size, type ViewState } from './view';

export const DEFAULT_CANVAS_SIZE: Size = { width: 720, height: 480 };
const KEY_PREFIX = 'neonhearth.home.view.';

const finite = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value) && Math.abs(value) < 1e6;

export function readFloorView(floorId: string): ViewState | null {
  try {
    const raw = localStorage.getItem(KEY_PREFIX + floorId);
    if (!raw) return null;
    const value: unknown = JSON.parse(raw);
    if (typeof value !== 'object' || value === null) return null;
    const { scale, x, y } = value as Record<string, unknown>;
    if (!finite(scale) || !finite(x) || !finite(y)) return null;
    return { scale: clampScale(scale), origin: { x, y } };
  } catch { return null; }
}

export function saveFloorView(floorId: string, view: ViewState): void {
  try { localStorage.setItem(KEY_PREFIX + floorId, JSON.stringify({ scale: view.scale, x: view.origin.x, y: view.origin.y })); }
  catch { /* View persistence is a convenience; private windows and blocked storage are fine. */ }
}

/** Every drawn point of a floor: walls and room corners. */
export function floorPoints(floor: Pick<Floor, 'walls' | 'rooms'>): PlanPoint[] {
  return [...floor.walls.flatMap((wall) => [wall.start, wall.end]), ...floor.rooms.flatMap((room) => room.polygon)];
}

/** True when every point is visible inside the default view (origin 0,0 at 40 px/m) with a small margin. */
export function fitsDefaultView(bounds: Bounds | null, size: Size, marginPx = 0): boolean {
  if (!bounds) return true;
  const view = defaultView();
  return bounds.min.x * view.scale >= marginPx && bounds.min.y * view.scale >= marginPx
    && bounds.max.x * view.scale <= size.width - marginPx && bounds.max.y * view.scale <= size.height - marginPx;
}

/**
 * The view a floor opens with the first time: the default view when the drawing fits it,
 * otherwise a view framing the whole drawing.
 */
export function initialFloorView(floor: Pick<Floor, 'walls' | 'rooms'>, size: Size): ViewState {
  const bounds = boundsOf(floorPoints(floor));
  return fitsDefaultView(bounds, size) ? defaultView() : fitView(bounds, size);
}
