// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import * as THREE from 'three';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { HomePlan, Placement, TwinDevice } from '../twin/geometry';
import HomeTwin3D from './HomeTwin3D.svelte';

const mocks = vi.hoisted(() => ({
  detectWebGL: vi.fn<() => boolean>(() => true),
  renderer: { setSize: vi.fn(), setPixelRatio: vi.fn(), render: vi.fn(), dispose: vi.fn(), forceContextLoss: vi.fn() },
  createTwinRenderer: vi.fn()
}));
vi.mock('../twin/webgl', () => ({ detectWebGL: mocks.detectWebGL, createTwinRenderer: mocks.createTwinRenderer }));

const plan: HomePlan = {
  home_id: 'home-1', version: 1, name: 'Home',
  floors: [{ floor_id: 'floor-0', level: 0, name: 'Ground', ceiling_height_m: 2.4, walls: [{ wall_id: 'wall-1', start: { x: 0, y: 0 }, end: { x: 4, y: 0 }, openings: [] }], rooms: [{ room_id: 'room-1', name: 'Kitchen', polygon: [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 3 }, { x: 0, y: 3 }] }] }]
};
const placements: Placement[] = [{ placement_id: 'p-1', device_id: 'device-1', floor_id: 'floor-0', x: 1, y: 1, height_m: 1.1, mounting: 'shelf' }];
const devices: TwinDevice[] = [{ device_id: 'device-1', label: 'Living room TV' }];

beforeEach(() => {
  mocks.detectWebGL.mockReturnValue(true);
  for (const fn of Object.values(mocks.renderer)) fn.mockClear();
  mocks.createTwinRenderer.mockReset().mockReturnValue(mocks.renderer);
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

const stage = (container: HTMLElement) => container.querySelector('.twin-stage') as HTMLElement;
const canvas = (container: HTMLElement) => container.querySelector('canvas') as HTMLCanvasElement;
const twin = (container: HTMLElement) => container.querySelector('.twin') as HTMLElement;

describe('HomeTwin3D teardown', () => {
  it('releases the renderer, the GL context, the listeners and the animation frame on unmount', () => {
    const cancel = vi.spyOn(window, 'cancelAnimationFrame');
    const removeWindow = vi.spyOn(window, 'removeEventListener');
    const view = render(HomeTwin3D, { plan, placements, devices });
    expect(twin(view.container).getAttribute('data-loop')).toBe('running');
    const removeCanvas = vi.spyOn(canvas(view.container), 'removeEventListener');
    view.unmount();
    expect(mocks.renderer.dispose).toHaveBeenCalledTimes(1);
    expect(mocks.renderer.forceContextLoss).toHaveBeenCalledTimes(1);
    expect(cancel).toHaveBeenCalled();
    expect(removeWindow).toHaveBeenCalledWith('resize', expect.any(Function));
    expect(removeCanvas).toHaveBeenCalledWith('webglcontextlost', expect.any(Function));
    expect(removeCanvas).toHaveBeenCalledWith('webglcontextrestored', expect.any(Function));
  });

  it('disposes the previous scene geometries and materials when it is rebuilt, and everything again on unmount', async () => {
    const geometry = vi.spyOn(THREE.BufferGeometry.prototype, 'dispose');
    const material = vi.spyOn(THREE.Material.prototype, 'dispose');
    const view = render(HomeTwin3D, { plan, placements, devices, reducedMotion: true });
    expect(geometry).not.toHaveBeenCalled();
    await view.rerender({ placements: [{ ...placements[0]!, x: 2 }] });
    const afterRebuild = geometry.mock.calls.length;
    expect(afterRebuild).toBeGreaterThan(0);
    expect(material.mock.calls.length).toBeGreaterThan(0);
    view.unmount();
    expect(geometry.mock.calls.length).toBeGreaterThan(afterRebuild);
  });
});

describe('HomeTwin3D context loss', () => {
  it('prevents the default, freezes honestly, and resumes drawing when the context comes back', async () => {
    const view = render(HomeTwin3D, { plan, placements, devices, reducedMotion: true });
    const lost = new Event('webglcontextlost', { cancelable: true });
    canvas(view.container).dispatchEvent(lost);
    expect(lost.defaultPrevented).toBe(true);
    expect(await screen.findByText(/3D view paused: the graphics context was lost/)).toBeTruthy();
    mocks.renderer.render.mockClear();
    await fireEvent.click(screen.getByRole('button', { name: 'Top' })); // a camera move while lost must not draw
    expect(mocks.renderer.render).not.toHaveBeenCalled();
    canvas(view.container).dispatchEvent(new Event('webglcontextrestored'));
    await Promise.resolve();
    expect(screen.queryByText(/3D view paused/)).toBeNull();
    expect(mocks.renderer.render).toHaveBeenCalled();
  });

  it('falls back to the 2D fallback when the context is not restored in time', async () => {
    vi.useFakeTimers();
    const onfallback = vi.fn();
    const view = render(HomeTwin3D, { plan, placements, devices, reducedMotion: true, onfallback });
    canvas(view.container).dispatchEvent(new Event('webglcontextlost', { cancelable: true }));
    await vi.advanceTimersByTimeAsync(5100);
    expect(twin(view.container).getAttribute('data-mode')).toBe('fallback');
    expect(onfallback).toHaveBeenCalledTimes(1);
  });
});

describe('HomeTwin3D pointer robustness', () => {
  const orbit = async (view: { container: HTMLElement }, move: () => Promise<unknown>) => {
    await fireEvent.pointerDown(stage(view.container), { clientX: 100, clientY: 100, button: 0, buttons: 1, pointerId: 1 });
    await move();
  };

  it('a drag with a button held changes the camera preset (control)', async () => {
    const view = render(HomeTwin3D, { plan, placements, devices, reducedMotion: true });
    expect(twin(view.container).getAttribute('data-camera-preset')).toBe('iso');
    await orbit(view, () => fireEvent.pointerMove(stage(view.container), { clientX: 160, clientY: 130, buttons: 1, pointerId: 1 }));
    expect(twin(view.container).getAttribute('data-camera-preset')).toBe('');
  });

  it('a cancelled pointer ends the drag: later moves do not steer the camera', async () => {
    const view = render(HomeTwin3D, { plan, placements, devices, reducedMotion: true });
    await orbit(view, () => fireEvent.pointerCancel(stage(view.container), { pointerId: 1 }));
    await fireEvent.pointerMove(stage(view.container), { clientX: 200, clientY: 200, buttons: 1, pointerId: 1 });
    expect(twin(view.container).getAttribute('data-camera-preset')).toBe('iso');
  });

  it('a lost pointer capture ends the drag the same way', async () => {
    const view = render(HomeTwin3D, { plan, placements, devices, reducedMotion: true });
    await orbit(view, () => fireEvent(stage(view.container), new Event('lostpointercapture')));
    await fireEvent.pointerMove(stage(view.container), { clientX: 200, clientY: 200, buttons: 1, pointerId: 1 });
    expect(twin(view.container).getAttribute('data-camera-preset')).toBe('iso');
  });

  it('a move with no button down heals a stuck drag (release outside the window)', async () => {
    const view = render(HomeTwin3D, { plan, placements, devices, reducedMotion: true });
    await orbit(view, async () => undefined);
    await fireEvent.pointerMove(stage(view.container), { clientX: 220, clientY: 210, buttons: 0, pointerId: 1 });
    expect(twin(view.container).getAttribute('data-camera-preset')).toBe('iso');
  });
});
