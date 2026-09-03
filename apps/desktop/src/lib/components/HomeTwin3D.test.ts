// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { HomePlan, Placement, TwinDevice } from '../twin/geometry';
import HomeTwin3D from './HomeTwin3D.svelte';

// Component tests run in jsdom with NO real WebGL: the twin/webgl boundary is
// mocked so the fallback path is deterministic and the 3D path can use a stub
// renderer. We test wiring (props -> geometry, select, device-list parity,
// reduced motion), never pixels.
const mocks = vi.hoisted(() => ({
  detectWebGL: vi.fn<() => boolean>(() => false),
  createTwinRenderer: vi.fn(() => ({
    setSize: vi.fn(),
    setPixelRatio: vi.fn(),
    render: vi.fn(),
    dispose: vi.fn()
  }))
}));
vi.mock('../twin/webgl', () => ({
  detectWebGL: mocks.detectWebGL,
  createTwinRenderer: mocks.createTwinRenderer
}));

const plan: HomePlan = {
  home_id: 'home-1',
  version: 1,
  name: 'Home',
  floors: [
    {
      floor_id: 'floor-0',
      level: 0,
      name: 'Ground',
      ceiling_height_m: 2.4,
      walls: [{
        wall_id: 'wall-1',
        start: { x: 0, y: 0 },
        end: { x: 4, y: 0 },
        openings: [{ opening_id: 'op-1', kind: 'door', offset_m: 1, width_m: 0.9 }]
      }],
      rooms: [{ room_id: 'room-1', name: 'Kitchen', polygon: [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 3 }, { x: 0, y: 3 }] }]
    },
    { floor_id: 'floor-1', level: 1, name: 'Upstairs', ceiling_height_m: 2.4, walls: [], rooms: [] }
  ]
};
const placements: Placement[] = [
  { placement_id: 'p-1', device_id: 'device-1', floor_id: 'floor-0', x: 1, y: 1, height_m: 1.1, mounting: 'shelf' },
  { placement_id: 'p-2', device_id: 'device-2', floor_id: 'floor-1', x: 2, y: 1.5, height_m: 2.2, mounting: 'wall' }
];
const devices: TwinDevice[] = [
  { device_id: 'device-1', label: 'Living room TV' },
  { device_id: 'device-2', label: 'Landing cam', is_camera: true }
];

beforeEach(() => {
  mocks.detectWebGL.mockReset().mockReturnValue(false);
  mocks.createTwinRenderer.mockClear();
});

describe('HomeTwin3D fallback path (no WebGL)', () => {
  it('renders the fallback message and emits the fallback event once', async () => {
    const onfallback = vi.fn();
    const view = render(HomeTwin3D, { plan, placements, devices, onfallback, reducedMotion: true });
    expect(await screen.findByRole('status')).toBeTruthy();
    expect(screen.getByText(/3D view is unavailable/i)).toBeTruthy();
    expect(onfallback).toHaveBeenCalledTimes(1);
    expect(view.container.querySelector('.twin')?.getAttribute('data-mode')).toBe('fallback');
    expect(mocks.createTwinRenderer).not.toHaveBeenCalled();
  });

  it('keeps the accessible device list present with the same ids and labels as the pins', () => {
    const view = render(HomeTwin3D, { plan, placements, devices, reducedMotion: true });
    const buttons = [...view.container.querySelectorAll('button[data-device-id]')];
    expect(buttons.map((button) => button.getAttribute('data-device-id'))).toEqual(['device-1', 'device-2']);
    expect(buttons[0]!.textContent).toContain('Living room TV');
    expect(buttons[1]!.textContent).toContain('Landing cam');
    expect(view.container.querySelector('.twin')?.getAttribute('data-pin-count')).toBe('2');
  });

  it('selecting from the device list emits select with the device_id', async () => {
    const onselect = vi.fn();
    const view = render(HomeTwin3D, { plan, placements, devices, onselect, reducedMotion: true });
    const button = view.container.querySelector('button[data-device-id="device-2"]')!;
    await fireEvent.click(button);
    expect(onselect).toHaveBeenCalledWith('device-2');
    expect(view.container.querySelector('.twin')?.getAttribute('data-selected')).toBe('device-2');
    expect(button.getAttribute('aria-pressed')).toBe('true');
  });

  it('surfaces device presence in the accessible list', () => {
    const view = render(HomeTwin3D, {
      plan,
      placements,
      devices,
      presence: { 'device-1': 'online', 'device-2': 'blocked' },
      reducedMotion: true
    });
    const buttons = [...view.container.querySelectorAll('button[data-device-id]')];
    expect(buttons[0]!.textContent).toContain('online');
    expect(buttons[1]!.textContent).toContain('blocked');
  });
});

describe('HomeTwin3D reduced motion', () => {
  it('reflects the explicit reducedMotion prop', () => {
    const view = render(HomeTwin3D, { plan, placements, devices, reducedMotion: true });
    expect(view.container.querySelector('.twin')?.getAttribute('data-reduced-motion')).toBe('true');
  });

  it('stays animated by default when neither the prop nor the media query asks for less', () => {
    const view = render(HomeTwin3D, { plan, placements, devices });
    expect(view.container.querySelector('.twin')?.getAttribute('data-reduced-motion')).toBe('false');
  });

  it('honors prefers-reduced-motion from the platform', () => {
    const original = window.matchMedia;
    window.matchMedia = ((query: string) => ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      addEventListener: () => {},
      removeEventListener: () => {}
    })) as unknown as typeof window.matchMedia;
    try {
      const view = render(HomeTwin3D, { plan, placements, devices });
      expect(view.container.querySelector('.twin')?.getAttribute('data-reduced-motion')).toBe('true');
    } finally {
      window.matchMedia = original;
    }
  });
});

describe('HomeTwin3D 3D path (stub renderer)', () => {
  beforeEach(() => {
    mocks.detectWebGL.mockReturnValue(true);
  });

  it('builds the scene from the plan props and reports floor and pin counts', () => {
    const view = render(HomeTwin3D, { plan, placements, devices, reducedMotion: true });
    const root = view.container.querySelector('.twin')!;
    expect(root.getAttribute('data-mode')).toBe('3d');
    expect(root.getAttribute('data-floor-count')).toBe('2');
    expect(root.getAttribute('data-pin-count')).toBe('2');
    expect(mocks.createTwinRenderer).toHaveBeenCalledTimes(1);
    const stub = mocks.createTwinRenderer.mock.results[0]!.value as { render: ReturnType<typeof vi.fn> };
    expect(stub.render).toHaveBeenCalled();
  });

  it('offers reset view, wall hiding, and per-floor isolation controls', async () => {
    render(HomeTwin3D, { plan, placements, devices, reducedMotion: true });
    expect(screen.getByRole('button', { name: 'Reset view' })).toBeTruthy();
    const hideWalls = screen.getByRole('button', { name: 'Hide walls' });
    expect(hideWalls.getAttribute('aria-pressed')).toBe('false');
    await fireEvent.click(hideWalls);
    expect(screen.getByRole('button', { name: 'Show walls' }).getAttribute('aria-pressed')).toBe('true');

    const allFloors = screen.getByRole('button', { name: 'All floors' });
    const upstairs = screen.getByRole('button', { name: 'Upstairs' });
    expect(allFloors.getAttribute('aria-pressed')).toBe('true');
    await fireEvent.click(upstairs);
    expect(upstairs.getAttribute('aria-pressed')).toBe('true');
    expect(allFloors.getAttribute('aria-pressed')).toBe('false');
    await fireEvent.click(upstairs); // toggling again returns to all floors
    expect(allFloors.getAttribute('aria-pressed')).toBe('true');
  });

  it('keeps device-list parity and select wiring in 3D mode', async () => {
    const onselect = vi.fn();
    const view = render(HomeTwin3D, { plan, placements, devices, onselect, reducedMotion: true });
    const buttons = [...view.container.querySelectorAll('button[data-device-id]')];
    expect(buttons.map((button) => button.getAttribute('data-device-id'))).toEqual(['device-1', 'device-2']);
    await fireEvent.click(buttons[0]!);
    expect(onselect).toHaveBeenCalledWith('device-1');
    expect(view.container.querySelector('.twin')?.getAttribute('data-selected')).toBe('device-1');
  });

  it('updates live pin state without rebuilding when presence and bandwidth change', async () => {
    const view = render(HomeTwin3D, {
      plan,
      placements,
      devices,
      presence: { 'device-1': 'online' },
      bandwidth: { 'device-1': 1000 },
      reducedMotion: true
    });
    await view.rerender({ presence: { 'device-1': 'blocked' }, bandwidth: { 'device-1': 50_000_000 } });
    const buttons = [...view.container.querySelectorAll('button[data-device-id]')];
    expect(buttons[0]!.textContent).toContain('blocked');
    expect(view.container.querySelector('.twin')?.getAttribute('data-mode')).toBe('3d');
  });

  it('rebuilds the scene for new placements but resets the camera only for a new plan (H-5)', async () => {
    const view = render(HomeTwin3D, { plan, placements, devices, reducedMotion: true });
    const root = view.container.querySelector('.twin')!;
    expect(root.getAttribute('data-rebuild-count')).toBe('1');
    expect(root.getAttribute('data-reset-count')).toBe('1');

    // Same plan and placements, a fresh-but-equal devices array: nothing rebuilds.
    await view.rerender({ devices: devices.map((device) => ({ ...device })), presence: { 'device-1': 'online' } });
    expect(root.getAttribute('data-rebuild-count')).toBe('2'); // a new array IS a change at this level; HomeView memoizes it
    expect(root.getAttribute('data-reset-count')).toBe('1');

    // A moved placement rebuilds the geometry without touching the camera.
    await view.rerender({ placements: [{ ...placements[0]!, x: 2.5 }, placements[1]!] });
    expect(root.getAttribute('data-rebuild-count')).toBe('3');
    expect(root.getAttribute('data-reset-count')).toBe('1');

    // A different plan object is a new home: the camera reframes it.
    await view.rerender({ plan: { ...plan, version: 2 } });
    expect(root.getAttribute('data-rebuild-count')).toBe('4');
    expect(root.getAttribute('data-reset-count')).toBe('2');
  });

  it('stops the render loop while hidden and resumes when visible again (M-26)', async () => {
    const view = render(HomeTwin3D, { plan, placements, devices, visible: false });
    const root = view.container.querySelector('.twin')!;
    expect(root.getAttribute('data-reduced-motion')).toBe('false');
    expect(root.getAttribute('data-loop')).toBe('stopped');
    await view.rerender({ visible: true });
    expect(root.getAttribute('data-loop')).toBe('running');
    await view.rerender({ visible: false });
    expect(root.getAttribute('data-loop')).toBe('stopped');
  });

  it('falls back gracefully when the renderer cannot be created', async () => {
    mocks.createTwinRenderer.mockReturnValueOnce(null as never);
    const onfallback = vi.fn();
    const view = render(HomeTwin3D, { plan, placements, devices, onfallback, reducedMotion: true });
    expect(await screen.findByRole('status')).toBeTruthy();
    expect(onfallback).toHaveBeenCalledTimes(1);
    expect(view.container.querySelector('.twin')?.getAttribute('data-mode')).toBe('fallback');
  });
});

describe('HomeTwin3D without a plan', () => {
  it('renders empty counts and no device buttons', () => {
    const view = render(HomeTwin3D, { plan: null, reducedMotion: true });
    const root = view.container.querySelector('.twin')!;
    expect(root.getAttribute('data-floor-count')).toBe('0');
    expect(root.getAttribute('data-pin-count')).toBe('0');
    expect(view.container.querySelectorAll('button[data-device-id]')).toHaveLength(0);
  });
});
