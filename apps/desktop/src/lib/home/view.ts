// Viewport maths for the 2D plan editor (home tools v2 · spec A).
//
// Geometry is always stored in meters. The SVG user-unit is one CSS pixel at the
// current zoom, so the viewBox is `origin_m * scale` offset by the element size:
// text, hairlines and handles stay a constant screen size for free, while wall
// bands and the grid scale with the zoom because their geometry is in meters.

import type { PlanPoint } from '../stores/home';

export interface ViewState {
  /** Pixels per meter. */
  scale: number;
  /** Plan coordinates (meters) shown at the viewport's top-left corner. */
  origin: PlanPoint;
}

export interface Bounds { min: PlanPoint; max: PlanPoint }
export interface Size { width: number; height: number }

export const MIN_SCALE = 10;
export const MAX_SCALE = 200;
export const DEFAULT_SCALE = 40;
/** Below this zoom the 0.1 m minor grid is denser than it is useful. */
export const MINOR_GRID_MIN_SCALE = 25;

export const clampScale = (scale: number): number =>
  Math.min(MAX_SCALE, Math.max(MIN_SCALE, Number.isFinite(scale) ? scale : DEFAULT_SCALE));

export const defaultView = (): ViewState => ({ scale: DEFAULT_SCALE, origin: { x: 0, y: 0 } });

/** The SVG viewBox for a view state over an element of `size` CSS pixels. */
export function viewBox(view: ViewState, size: Size): string {
  return `${view.origin.x * view.scale} ${view.origin.y * view.scale} ${Math.max(1, size.width)} ${Math.max(1, size.height)}`;
}

/** Plan meters → SVG user units (pixels at the current zoom). */
export const units = (view: ViewState, meters: number): number => meters * view.scale;

/** Pointer offset inside the element (CSS px) → plan coordinates in meters. */
export function toPlan(view: ViewState, offsetX: number, offsetY: number): PlanPoint {
  return { x: view.origin.x + offsetX / view.scale, y: view.origin.y + offsetY / view.scale };
}

/** Plan coordinates → pointer offset inside the element (CSS px). */
export function toScreen(view: ViewState, point: PlanPoint): { x: number; y: number } {
  return { x: (point.x - view.origin.x) * view.scale, y: (point.y - view.origin.y) * view.scale };
}

/** Zoom by `factor` keeping the plan point under the cursor pinned to the cursor. */
export function zoomAt(view: ViewState, factor: number, offsetX: number, offsetY: number): ViewState {
  const scale = clampScale(view.scale * factor);
  if (scale === view.scale) return view;
  const anchor = toPlan(view, offsetX, offsetY);
  return { scale, origin: { x: anchor.x - offsetX / scale, y: anchor.y - offsetY / scale } };
}

/** Zoom to an exact px/m, keeping the centre of the viewport pinned. */
export function zoomTo(view: ViewState, scale: number, size: Size): ViewState {
  return zoomAt(view, clampScale(scale) / view.scale, size.width / 2, size.height / 2);
}

/** Drag-pan by a screen delta in CSS pixels. */
export function panBy(view: ViewState, dxPx: number, dyPx: number): ViewState {
  return { scale: view.scale, origin: { x: view.origin.x - dxPx / view.scale, y: view.origin.y - dyPx / view.scale } };
}

export function boundsOf(points: readonly PlanPoint[]): Bounds | null {
  if (points.length === 0) return null;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const point of points) {
    if (point.x < minX) minX = point.x;
    if (point.y < minY) minY = point.y;
    if (point.x > maxX) maxX = point.x;
    if (point.y > maxY) maxY = point.y;
  }
  return { min: { x: minX, y: minY }, max: { x: maxX, y: maxY } };
}

/** The view that frames `bounds` inside `size` with a pixel margin, clamped to the zoom range. */
export function fitView(bounds: Bounds | null, size: Size, marginPx = 48): ViewState {
  const width = Math.max(1, size.width);
  const height = Math.max(1, size.height);
  if (!bounds) return defaultView();
  const spanX = Math.max(bounds.max.x - bounds.min.x, 0.5);
  const spanY = Math.max(bounds.max.y - bounds.min.y, 0.5);
  const usableX = Math.max(1, width - marginPx * 2);
  const usableY = Math.max(1, height - marginPx * 2);
  const scale = clampScale(Math.min(usableX / spanX, usableY / spanY));
  const centre = { x: (bounds.min.x + bounds.max.x) / 2, y: (bounds.min.y + bounds.max.y) / 2 };
  return { scale, origin: { x: centre.x - width / (2 * scale), y: centre.y - height / (2 * scale) } };
}

/** Minor (0.1 m) grid opacity: it fades out below ~25 px/m and is gone by 15 px/m. */
export function minorGridOpacity(scale: number): number {
  if (scale <= MINOR_GRID_MIN_SCALE) return 0;
  return Math.min(1, (scale - MINOR_GRID_MIN_SCALE) / 25);
}

const SCALE_BAR_STEPS = [0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100];

/** A round-number scale bar between ~60 and ~160 px long at the current zoom. */
export function scaleBar(scale: number): { meters: number; px: number; label: string } {
  const meters = SCALE_BAR_STEPS.find((step) => step * scale >= 60) ?? SCALE_BAR_STEPS.at(-1)!;
  const label = meters < 1 ? `${(meters * 100).toFixed(0)} cm` : `${meters} m`;
  return { meters, px: meters * scale, label };
}
