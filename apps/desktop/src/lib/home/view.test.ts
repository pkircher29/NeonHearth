import { describe, expect, it } from 'vitest';

import {
  DEFAULT_SCALE, MAX_SCALE, MIN_SCALE, boundsOf, clampScale, defaultView, fitView, minorGridOpacity, panBy, pinchView, scaleBar, toPlan, toScreen, units, viewBox, zoomAt, zoomTo
} from './view';

const size = { width: 800, height: 600 };

describe('view maths', () => {
  it('defaults to 40 px/m at the origin so legacy pixel positions hold', () => {
    expect(defaultView()).toEqual({ scale: 40, origin: { x: 0, y: 0 } });
    expect(viewBox(defaultView(), { width: 720, height: 480 })).toBe('0 0 720 480');
  });

  it('builds the viewBox from the origin in scaled units and never collapses the size', () => {
    expect(viewBox({ scale: 20, origin: { x: 5, y: -2 } }, size)).toBe('100 -40 800 600');
    expect(viewBox(defaultView(), { width: 0, height: 0 })).toBe('0 0 1 1');
  });

  it('converts meters to units and round-trips plan <-> screen', () => {
    const view = { scale: 25, origin: { x: 3, y: 1 } };
    expect(units(view, 2)).toBe(50);
    const screen = toScreen(view, { x: 5, y: 4 });
    expect(screen).toEqual({ x: 50, y: 75 });
    expect(toPlan(view, screen.x, screen.y)).toEqual({ x: 5, y: 4 });
  });

  it('clamps the zoom to 10..200 px/m and survives garbage', () => {
    expect(clampScale(1)).toBe(MIN_SCALE);
    expect(clampScale(1e6)).toBe(MAX_SCALE);
    expect(clampScale(Number.NaN)).toBe(DEFAULT_SCALE);
    expect(clampScale(75)).toBe(75);
  });

  it('zooms about the cursor: the plan point under the cursor does not move', () => {
    const view = { scale: 40, origin: { x: 2, y: 1 } };
    const before = toPlan(view, 300, 200);
    const zoomed = zoomAt(view, 2, 300, 200);
    expect(zoomed.scale).toBe(80);
    const after = toPlan(zoomed, 300, 200);
    expect(after.x).toBeCloseTo(before.x, 10);
    expect(after.y).toBeCloseTo(before.y, 10);
  });

  it('returns the same view object when the zoom is already at the limit', () => {
    const maxed = { scale: MAX_SCALE, origin: { x: 0, y: 0 } };
    expect(zoomAt(maxed, 2, 10, 10)).toBe(maxed);
    const mined = { scale: MIN_SCALE, origin: { x: 0, y: 0 } };
    expect(zoomAt(mined, 0.5, 10, 10)).toBe(mined);
  });

  it('zoomTo pins the centre of the viewport', () => {
    const view = defaultView();
    const centre = toPlan(view, size.width / 2, size.height / 2);
    const zoomed = zoomTo(view, 100, size);
    expect(zoomed.scale).toBe(100);
    const after = toPlan(zoomed, size.width / 2, size.height / 2);
    expect(after.x).toBeCloseTo(centre.x, 10);
    expect(after.y).toBeCloseTo(centre.y, 10);
  });

  it('pans opposite to the drag, in meters', () => {
    const panned = panBy({ scale: 50, origin: { x: 1, y: 1 } }, 100, -50);
    expect(panned).toEqual({ scale: 50, origin: { x: -1, y: 2 } });
  });

  it('computes bounds and none for no points', () => {
    expect(boundsOf([])).toBeNull();
    expect(boundsOf([{ x: 1, y: 5 }, { x: -2, y: 3 }, { x: 4, y: 0 }])).toEqual({ min: { x: -2, y: 0 }, max: { x: 4, y: 5 } });
  });

  it('fits bounds inside the viewport with a margin and centres them', () => {
    const bounds = { min: { x: 0, y: 0 }, max: { x: 20, y: 10 } };
    const view = fitView(bounds, size, 50);
    expect(view.scale).toBeCloseTo(35, 10); // limited by width: (800 - 100) / 20
    const topLeft = toScreen(view, bounds.min);
    const bottomRight = toScreen(view, bounds.max);
    expect(topLeft.x).toBeGreaterThanOrEqual(50 - 1e-9);
    expect(bottomRight.x).toBeLessThanOrEqual(750 + 1e-9);
    expect(bottomRight.y).toBeLessThanOrEqual(550 + 1e-9);
    expect((topLeft.x + bottomRight.x) / 2).toBeCloseTo(400, 8);
    expect((topLeft.y + bottomRight.y) / 2).toBeCloseTo(300, 8);
  });

  it('fit clamps to the zoom range and falls back to the default for an empty plan', () => {
    expect(fitView({ min: { x: 0, y: 0 }, max: { x: 0.1, y: 0.1 } }, size).scale).toBe(MAX_SCALE);
    expect(fitView({ min: { x: 0, y: 0 }, max: { x: 1000, y: 1000 } }, size).scale).toBe(MIN_SCALE);
    expect(fitView(null, size)).toEqual(defaultView());
  });

  it('fades the 0.1 m grid out at or below 25 px/m and shows it fully by 50 px/m', () => {
    expect(minorGridOpacity(10)).toBe(0);
    expect(minorGridOpacity(25)).toBe(0);
    expect(minorGridOpacity(37.5)).toBeCloseTo(0.5, 10);
    expect(minorGridOpacity(50)).toBe(1);
    expect(minorGridOpacity(200)).toBe(1);
  });

  it('picks a round scale bar between 60 and 160 px', () => {
    for (const scale of [10, 17, 40, 73, 120, 200]) {
      const bar = scaleBar(scale);
      expect(bar.px).toBeGreaterThanOrEqual(60);
      expect(bar.px).toBeLessThanOrEqual(160 + 1e-9);
      expect(bar.px).toBeCloseTo(bar.meters * scale, 10);
    }
    expect(scaleBar(40)).toMatchObject({ meters: 2, label: '2 m' });
    expect(scaleBar(200).label).toBe('50 cm');
  });
});

describe('pinchView', () => {
  const pair = (ax: number, ay: number, bx: number, by: number) => ({ a: { x: ax, y: ay }, b: { x: bx, y: by } });
  it('zooms by the ratio of finger spacing about the midpoint', () => {
    const view = { scale: 40, origin: { x: 2, y: 1 } };
    const before = toPlan(view, 150, 100);
    const next = pinchView(view, pair(100, 100, 200, 100), pair(50, 100, 250, 100));
    expect(next.scale).toBe(80);
    const after = toPlan(next, 150, 100); // same midpoint, so the same plan point stays under it
    expect(after.x).toBeCloseTo(before.x, 10);
    expect(after.y).toBeCloseTo(before.y, 10);
  });
  it('pans when the fingers translate without changing spacing', () => {
    const view = { scale: 50, origin: { x: 0, y: 0 } };
    const next = pinchView(view, pair(100, 100, 200, 100), pair(150, 120, 250, 120));
    expect(next.scale).toBe(50);
    expect(next.origin.x).toBeCloseTo(-1, 10);
    expect(next.origin.y).toBeCloseTo(-0.4, 10);
  });
  it('moves the plan point under the old midpoint to the new midpoint while zooming', () => {
    const view = { scale: 40, origin: { x: 0, y: 0 } };
    const prev = pair(100, 100, 200, 100);
    const next = pair(100, 200, 300, 200);
    const anchor = toPlan(view, 150, 100);
    const out = pinchView(view, prev, next);
    const landed = toScreen(out, anchor);
    expect(landed.x).toBeCloseTo(200, 8);
    expect(landed.y).toBeCloseTo(200, 8);
  });
  it('clamps to the zoom range and ignores coincident fingers', () => {
    const view = { scale: 150, origin: { x: 1, y: 1 } };
    expect(pinchView(view, pair(0, 0, 10, 0), pair(0, 0, 1000, 0)).scale).toBe(MAX_SCALE);
    expect(pinchView(view, pair(0, 0, 1000, 0), pair(0, 0, 1, 0)).scale).toBe(MIN_SCALE);
    expect(pinchView(view, pair(5, 5, 5, 5), pair(0, 0, 100, 0)).scale).toBe(150);
  });
});
