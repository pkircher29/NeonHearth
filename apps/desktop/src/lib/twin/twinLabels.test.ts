import { describe, expect, it } from 'vitest';

import { pointInPolygon } from './geometry';
import { cullLabels, estimateLabelSize, labelAnchor, labelsVisibleForPhi, pinScreenScale } from './twinLabels';

describe('labelAnchor', () => {
  it('is the centroid for a convex room', () => {
    const anchor = labelAnchor([{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 2 }, { x: 0, y: 2 }]);
    expect(anchor.x).toBeCloseTo(2);
    expect(anchor.y).toBeCloseTo(1);
  });

  it('stays inside a concave C-shaped room whose centroid is outside', () => {
    const c = [
      { x: 0, y: 0 }, { x: 6, y: 0 }, { x: 6, y: 1 }, { x: 1, y: 1 }, { x: 1, y: 5 },
      { x: 6, y: 5 }, { x: 6, y: 6 }, { x: 0, y: 6 }
    ];
    const anchor = labelAnchor(c);
    expect(pointInPolygon(anchor, c)).toBe(true);
  });

  it('handles empty and degenerate polygons without throwing', () => {
    expect(labelAnchor([])).toEqual({ x: 0, y: 0 });
    const flat = labelAnchor([{ x: 0, y: 0 }, { x: 2, y: 0 }, { x: 4, y: 0 }]);
    expect(Number.isFinite(flat.x)).toBe(true);
  });
});

describe('cullLabels', () => {
  const vp = { w: 800, h: 500 };
  const label = (id: string, x: number, y: number, priority: number) => ({ id, x, y, w: 100, h: 40, priority });

  it('keeps separated labels', () => {
    expect([...cullLabels([label('a', 100, 100, 1), label('b', 400, 300, 1)], vp)].sort()).toEqual(['a', 'b']);
  });

  it('keeps the larger room when two overlap', () => {
    const kept = cullLabels([label('small', 200, 200, 3), label('big', 230, 210, 20)], vp);
    expect([...kept]).toEqual(['big']);
  });

  it('drops labels whose centre is off-canvas', () => {
    expect(cullLabels([label('out', -5, 100, 1), label('below', 100, 600, 1)], vp).size).toBe(0);
  });

  it('drops labels under a blocker such as the detail card', () => {
    const kept = cullLabels([label('a', 700, 60, 5), label('b', 200, 300, 1)], vp, [{ x: 600, y: 0, w: 200, h: 200 }]);
    expect([...kept]).toEqual(['b']);
  });

  it('is deterministic on ties', () => {
    const a = [...cullLabels([label('x', 100, 100, 1), label('y', 110, 100, 1)], vp)];
    const b = [...cullLabels([label('y', 110, 100, 1), label('x', 100, 100, 1)], vp)];
    expect(a).toEqual(b);
  });
});

describe('label helpers', () => {
  it('sizes pills by text length within bounds', () => {
    expect(estimateLabelSize('A').w).toBe(64);
    expect(estimateLabelSize('A very long room name indeed, longer than any sane one'.repeat(3)).w).toBe(220);
    expect(estimateLabelSize('Den', false).h).toBeLessThan(estimateLabelSize('Den', true).h);
  });
  it('hides labels when floors are seen edge-on', () => {
    expect(labelsVisibleForPhi(1.05)).toBe(true);
    expect(labelsVisibleForPhi(0.02)).toBe(true);
    expect(labelsVisibleForPhi(1.5)).toBe(false);
  });
});

describe('pinScreenScale', () => {
  it('never shrinks below natural size and grows with distance', () => {
    expect(pinScreenScale(0.5, 50, 600)).toBe(1);
    const near = pinScreenScale(8, 50, 600);
    const far = pinScreenScale(20, 50, 600);
    expect(far).toBeGreaterThan(near);
    expect(near).toBeGreaterThanOrEqual(1);
  });
  it('meets the minimum on-screen radius when uncapped', () => {
    const distance = 12;
    const scale = pinScreenScale(distance, 50, 600);
    const worldPerPx = (2 * distance * Math.tan((50 * Math.PI) / 360)) / 600;
    expect(0.13 * scale / worldPerPx).toBeGreaterThanOrEqual(9.99);
  });
  it('is capped so it cannot balloon and tolerates bad input', () => {
    expect(pinScreenScale(500, 50, 600)).toBe(3);
    expect(pinScreenScale(0, 50, 600)).toBe(1);
    expect(pinScreenScale(10, 50, 0)).toBe(1);
  });
});
