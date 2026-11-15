// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { DEFAULT_CANVAS_SIZE, fitsDefaultView, floorPoints, initialFloorView, readFloorView, saveFloorView } from './viewStore';
import { boundsOf, defaultView } from './view';

const wall = (sx: number, sy: number, ex: number, ey: number) => ({ wall_id: 'w', start: { x: sx, y: sy }, end: { x: ex, y: ey }, openings: [] });

describe('per-floor view persistence', () => {
  beforeEach(() => {
    const values = new Map<string, string>();
    vi.stubGlobal('localStorage', { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value) });
  });

  it('round-trips a view per floor id', () => {
    saveFloorView('floor-a', { scale: 80, origin: { x: -3, y: 2.5 } });
    expect(readFloorView('floor-a')).toEqual({ scale: 80, origin: { x: -3, y: 2.5 } });
    expect(readFloorView('floor-b')).toBeNull();
  });

  it('clamps a stored zoom and rejects garbage', () => {
    localStorage.setItem('neonhearth.home.view.f', JSON.stringify({ scale: 9999, x: 0, y: 0 }));
    expect(readFloorView('f')?.scale).toBe(200);
    for (const bad of ['not json', '{"scale":"a","x":0,"y":0}', '{"scale":40,"x":null,"y":0}', 'null', '[]', '{"scale":40,"x":1e9,"y":0}']) {
      localStorage.setItem('neonhearth.home.view.g', bad);
      expect(readFloorView('g')).toBeNull();
    }
  });

  it('never throws when storage is unavailable', () => {
    vi.stubGlobal('localStorage', { getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); } });
    expect(() => saveFloorView('x', defaultView())).not.toThrow();
    expect(readFloorView('x')).toBeNull();
  });
});

describe('first-open auto-fit', () => {
  it('collects wall endpoints and room corners', () => {
    const points = floorPoints({ walls: [wall(0, 0, 1, 1)], rooms: [{ room_id: 'r', name: 'R', polygon: [{ x: 5, y: 5 }, { x: 6, y: 5 }, { x: 6, y: 6 }] }] });
    expect(points).toHaveLength(5);
  });

  it('a drawing inside the default view keeps the default view, even touching the origin', () => {
    expect(fitsDefaultView(boundsOf([{ x: 0, y: 0 }, { x: 4.2, y: 0 }]), DEFAULT_CANVAS_SIZE)).toBe(true);
    expect(fitsDefaultView(null, DEFAULT_CANVAS_SIZE)).toBe(true);
    expect(initialFloorView({ walls: [wall(0, 0, 4.2, 0)], rooms: [] }, DEFAULT_CANVAS_SIZE)).toEqual(defaultView());
    expect(initialFloorView({ walls: [], rooms: [] }, DEFAULT_CANVAS_SIZE)).toEqual(defaultView());
  });

  it('a drawing past the default view is framed instead', () => {
    const view = initialFloorView({ walls: [wall(0, 0, 30, 0), wall(30, 0, 30, 20)], rooms: [] }, DEFAULT_CANVAS_SIZE);
    expect(view.scale).toBeLessThan(40);
    expect(view.scale).toBeGreaterThanOrEqual(10);
    expect(fitsDefaultView(boundsOf([{ x: 0, y: 0 }, { x: 30, y: 20 }]), DEFAULT_CANVAS_SIZE)).toBe(false);
  });

  it('a drawing left of the origin does not fit the default view either', () => {
    expect(fitsDefaultView(boundsOf([{ x: -2, y: 1 }, { x: 3, y: 2 }]), DEFAULT_CANVAS_SIZE)).toBe(false);
  });

  it('a bigger measured canvas lets a wider drawing keep the default view', () => {
    const bounds = boundsOf([{ x: 1, y: 1 }, { x: 30, y: 10 }]);
    expect(fitsDefaultView(bounds, DEFAULT_CANVAS_SIZE)).toBe(false);
    expect(fitsDefaultView(bounds, { width: 1400, height: 680 })).toBe(true);
  });
});
