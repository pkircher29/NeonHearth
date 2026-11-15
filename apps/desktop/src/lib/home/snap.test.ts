import { describe, expect, it } from 'vitest';

import { GUIDE_RADIUS_PX, SNAP_RADIUS_PX, angleDegrees, computeSnap, constrainAngle, guideAnchors, pointAtLength, projectOnSegment, type SnapSegment } from './snap';

const wall = (wall_id: string, sx: number, sy: number, ex: number, ey: number): SnapSegment => ({ wall_id, start: { x: sx, y: sy }, end: { x: ex, y: ey } });
const walls = [wall('a', 0, 0, 4, 0), wall('b', 4, 0, 4, 3)];

describe('computeSnap', () => {
  it('snaps to a wall endpoint and returns the exact endpoint, not a grid point', () => {
    const odd = [wall('a', 0.0507, 1.0333, 4, 1.0333)];
    const result = computeSnap({ x: 0.1, y: 1.0 }, { walls: odd, scale: 40 });
    expect(result.kind).toBe('endpoint');
    expect(result.label).toBe('endpoint');
    expect(result.point).toEqual({ x: 0.0507, y: 1.0333 });
    expect(result.wall_id).toBeNull();
  });

  it('prefers an endpoint over a midpoint and a midpoint over a point on the wall', () => {
    const short = [wall('a', 0, 0, 0.4, 0)]; // at 100 px/m the 12 px radius is 0.12 m
    expect(computeSnap({ x: 0.05, y: 0 }, { walls: short, scale: 100 }).kind).toBe('endpoint');
    expect(computeSnap({ x: 0.21, y: 0 }, { walls: short, scale: 100 }).kind).toBe('midpoint');
    const long = computeSnap({ x: 1.0, y: 0.1 }, { walls: [wall('a', 0, 0, 4, 0)], scale: 40 });
    expect(long.kind).toBe('on-wall');
  });

  it('midpoint snaps exactly to the middle and carries the wall to split', () => {
    const result = computeSnap({ x: 2.1, y: 0.1 }, { walls, scale: 40 });
    expect(result).toMatchObject({ kind: 'midpoint', label: 'midpoint', wall_id: 'a', point: { x: 2, y: 0 } });
  });

  it('on-wall snaps along the body, names the wall, and sits on the 0.1 grid for an axis-aligned wall', () => {
    const result = computeSnap({ x: 1.04, y: 0.12 }, { walls, scale: 40 });
    expect(result).toMatchObject({ kind: 'on-wall', label: 'on wall', wall_id: 'a', point: { x: 1, y: 0 } });
  });

  it('on-wall stays exactly on a diagonal wall', () => {
    const diagonal = [wall('d', 0, 0, 3, 4)];
    const result = computeSnap({ x: 0.9, y: 1.4 }, { walls: diagonal, scale: 40 });
    expect(result.kind).toBe('on-wall');
    const projected = projectOnSegment(result.point, diagonal[0].start, diagonal[0].end);
    expect(Math.hypot(result.point.x - projected.point.x, result.point.y - projected.point.y)).toBeLessThan(1e-5);
  });

  it('a wall end never counts as "on wall"', () => {
    // 0.2 m away from the endpoint is outside the endpoint radius at 100 px/m (0.12 m) but the projection t is tiny.
    const result = computeSnap({ x: 0.0005, y: 0.05 }, { walls: [wall('a', 0, 0, 4, 0)], scale: 100 });
    expect(result.kind).toBe('endpoint');
  });

  it('the screen radius shrinks in meters as you zoom in', () => {
    const near = { x: 0.2, y: 0.2 };
    expect(computeSnap(near, { walls: [wall('a', 0, 0, 4, 0)], scale: 40 }).kind).toBe('endpoint');
    expect(computeSnap(near, { walls: [wall('a', 0, 0, 4, 0)], scale: 200 }).kind).not.toBe('endpoint');
    expect(SNAP_RADIUS_PX).toBe(12);
    expect(GUIDE_RADIUS_PX).toBeLessThanOrEqual(SNAP_RADIUS_PX);
  });

  it('falls back to the grid, and to the imperial grid when asked', () => {
    expect(computeSnap({ x: 7.04, y: 5.96 }, { walls: [], scale: 40 })).toMatchObject({ kind: 'grid', label: 'grid', point: { x: 7, y: 6 } });
    const imperial = computeSnap({ x: 7.04, y: 5.96 }, { walls: [], scale: 40, grid: 0.0254 });
    expect(imperial.point.x).toBeCloseTo(Math.round(7.04 / 0.0254) * 0.0254, 6);
    expect(imperial.point.y).toBeCloseTo(Math.round(5.96 / 0.0254) * 0.0254, 6);
  });

  it('shows alignment guides and pins the aligned axis to the anchor', () => {
    const result = computeSnap({ x: 4.04, y: 7 }, { walls, scale: 40 });
    expect(result.guides.x).toBe(4);
    expect(result.guides.y).toBeNull();
    expect(result).toMatchObject({ kind: 'guide', label: 'align', point: { x: 4, y: 7 } });
  });

  it('snaps to the intersection of two guides', () => {
    const result = computeSnap({ x: 4.05, y: 0.05 + 6 }, { walls: [wall('a', 4, 0, 5, 0), wall('b', 0, 6, 1, 6)], scale: 40 });
    expect(result.guides).toEqual({ x: 4, y: 6 });
    expect(result.point).toEqual({ x: 4, y: 6 });
    expect(result.kind).toBe('guide');
  });

  it('guidePoints add guides without becoming snap targets', () => {
    const result = computeSnap({ x: 5.02, y: 2 }, { walls: [], scale: 40, guidePoints: [{ x: 5, y: 9 }] });
    expect(result.guides.x).toBe(5);
    expect(result.kind).toBe('guide');
    const near = computeSnap({ x: 5.05, y: 9.05 }, { walls: [], scale: 40, guidePoints: [{ x: 5, y: 9 }] });
    expect(near.kind).not.toBe('endpoint');
  });

  it('extraPoints are endpoint-tier targets (the first point of the chain)', () => {
    const result = computeSnap({ x: 10.1, y: 10.1 }, { walls: [], scale: 40, extraPoints: [{ x: 10.0333, y: 10 }] });
    expect(result).toMatchObject({ kind: 'endpoint', point: { x: 10.0333, y: 10 } });
  });

  it('excluded walls are invisible to every tier (the wall being dragged)', () => {
    const result = computeSnap({ x: 0.05, y: 0.05 }, { walls: [wall('a', 0, 0, 4, 0)], scale: 40, excludeWallIds: ['a'] });
    expect(result.kind).toBe('grid');
    expect(result.guides).toEqual({ x: null, y: null });
  });

  it('survives a degenerate scale', () => {
    expect(() => computeSnap({ x: 1, y: 1 }, { walls, scale: 0 })).not.toThrow();
  });
});

describe('guideAnchors and projection', () => {
  it('lists each distinct endpoint once', () => {
    expect(guideAnchors(walls)).toEqual([{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 3 }]);
    expect(guideAnchors(walls, [{ x: 4, y: 0 }, { x: 9, y: 9 }]).at(-1)).toEqual({ x: 9, y: 9 });
  });
  it('projects onto a segment with a clamped parameter and survives a zero-length segment', () => {
    expect(projectOnSegment({ x: 2, y: 3 }, { x: 0, y: 0 }, { x: 4, y: 0 })).toEqual({ point: { x: 2, y: 0 }, t: 0.5 });
    expect(projectOnSegment({ x: 9, y: 3 }, { x: 0, y: 0 }, { x: 4, y: 0 }).t).toBe(1);
    expect(projectOnSegment({ x: 9, y: 3 }, { x: 1, y: 1 }, { x: 1, y: 1 })).toEqual({ point: { x: 1, y: 1 }, t: 0 });
  });
});

describe('constrainAngle, pointAtLength, angleDegrees', () => {
  it('constrains to the nearest 45 degree ray, keeping the length', () => {
    expect(constrainAngle({ x: 0, y: 0 }, { x: 5, y: 0.7 })).toEqual({ x: 5, y: 0 });
    expect(constrainAngle({ x: 0, y: 0 }, { x: 0.4, y: 5 })).toEqual({ x: 0, y: 5 });
    const diagonal = constrainAngle({ x: 1, y: 1 }, { x: 4, y: 3.6 });
    expect(diagonal.x - 1).toBeCloseTo(diagonal.y - 1, 6);
    expect(constrainAngle({ x: 2, y: 2 }, { x: 2, y: 2 })).toEqual({ x: 2, y: 2 });
  });
  it('honours an imperial grid', () => {
    const point = constrainAngle({ x: 0, y: 0 }, { x: 3.0, y: 0.1 }, 0.0254);
    expect(point.y).toBe(0);
    expect(point.x / 0.0254).toBeCloseTo(Math.round(point.x / 0.0254), 6);
  });
  it('places a typed length exactly along the direction (no grid snap by default)', () => {
    expect(pointAtLength({ x: 0, y: 0 }, { x: 10, y: 0 }, 3.45)).toEqual({ x: 3.45, y: 0 });
    const diagonal = pointAtLength({ x: 1, y: 1 }, { x: 4, y: 5 }, 5);
    expect(Math.hypot(diagonal.x - 1, diagonal.y - 1)).toBeCloseTo(5, 6);
    expect(diagonal).toEqual({ x: 4, y: 5 });
  });
  it('defaults east when there is no direction, and snaps only when given a grid', () => {
    expect(pointAtLength({ x: 2, y: 2 }, { x: 2, y: 2 }, 1.25)).toEqual({ x: 3.25, y: 2 });
    expect(pointAtLength({ x: 0, y: 0 }, { x: 10, y: 0 }, 3.45, 0.1)).toEqual({ x: 3.5, y: 0 });
  });
  it('measures angles with 0 = east, counter-clockwise on a y-down plan', () => {
    const origin = { x: 0, y: 0 };
    expect(angleDegrees(origin, { x: 1, y: 0 })).toBe(0);
    expect(angleDegrees(origin, { x: 0, y: -1 })).toBe(90);
    expect(angleDegrees(origin, { x: -1, y: 0 })).toBe(180);
    expect(angleDegrees(origin, { x: 0, y: 1 })).toBe(270);
    expect(angleDegrees(origin, { x: 1, y: -1 })).toBe(45);
  });
});
