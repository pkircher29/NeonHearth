// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { Estimate, HomeApi, HomeDeviceRef, HomePlan, Placement } from '../stores/home';
import HomeEditorView from './HomeEditorView.svelte';

const homeId = '018f47a0-9b5c-7a22-8a33-aabbccdd0001';
const groundId = '018f47a0-9b5c-7a22-8a33-aabbccdd0010';
const upperId = '018f47a0-9b5c-7a22-8a33-aabbccdd0011';
const wallId = '018f47a0-9b5c-7a22-8a33-aabbccdd0020';
const roomId = '018f47a0-9b5c-7a22-8a33-aabbccdd0040';
const deviceA = '018f47a0-9b5c-7a22-8a33-aabbccdd0050';
const deviceB = '018f47a0-9b5c-7a22-8a33-aabbccdd0051';
const placementId = '018f47a0-9b5c-7a22-8a33-aabbccdd0060';

const devices: HomeDeviceRef[] = [{ device_id: deviceA, name: 'Hall sensor' }, { device_id: deviceB, name: 'Porch node' }];

function fixturePlan(): HomePlan {
  return {
    home_id: homeId, version: 3, name: 'Home',
    floors: [
      {
        floor_id: groundId, level: 0, name: 'Ground', ceiling_height_m: 2.4,
        walls: [{ wall_id: wallId, start: { x: 0, y: 0 }, end: { x: 4.2, y: 0 }, openings: [] }],
        rooms: [{ room_id: roomId, name: 'Kitchen', polygon: [{ x: 0, y: 0 }, { x: 4, y: 0 }, { x: 4, y: 3 }, { x: 0, y: 3 }] }]
      },
      { floor_id: upperId, level: 1, name: 'Upstairs', ceiling_height_m: 2.4, walls: [], rooms: [] }
    ]
  };
}

function apiStub(overrides: Partial<HomeApi> = {}, options: { placements?: Placement[]; estimates?: Estimate[] } = {}): HomeApi {
  return {
    fetchHome: vi.fn(async () => ({ plan: fixturePlan(), placements: options.placements ?? [], estimates: options.estimates ?? [] })),
    savePlan: vi.fn(async () => ({ status: 'saved' as const, version: 4 })),
    saveDraft: vi.fn(async () => undefined),
    loadDraft: vi.fn(async () => ({ status: 'none' as const })),
    deleteDraft: vi.fn(async () => undefined),
    putPlacement: vi.fn(async () => undefined),
    deletePlacement: vi.fn(async () => undefined),
    ...overrides
  };
}

describe('HomeEditorView', () => {
  beforeEach(() => {
    const values = new Map<string, string>();
    vi.stubGlobal('localStorage', { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value) });
  });
  it('switches units without changing geometry and saves an eight-foot ceiling in meters', async () => {
    const api = apiStub();
    const view = render(HomeEditorView, { api, devices });
    await screen.findByRole('button', { name: /Ground/ });
    const before = view.container.querySelector('.wall')!.outerHTML;
    await fireEvent.change(screen.getByRole('combobox', { name: 'Measurement units' }), { target: { value: 'imperial' } });
    expect(screen.getByRole('button', { name: 'Wall, 13.78 ft' })).toBeTruthy();
    expect(localStorage.getItem('neonhearth.home.units')).toBe('imperial');
    await fireEvent.click(screen.getByRole('button', { name: /Ground/ }));
    await fireEvent.change(screen.getByLabelText('Ceiling height (ft)'), { target: { value: '8' } });
    await fireEvent.change(screen.getByRole('combobox', { name: 'Measurement units' }), { target: { value: 'metric' } });
    expect((screen.getByLabelText('Ceiling height (m)') as HTMLInputElement).valueAsNumber).toBe(2.4384);
    expect(view.container.querySelector('.wall')!.outerHTML).toBe(before);
    await fireEvent.click(screen.getByRole('button', { name: 'Save plan' }));
    expect(api.savePlan).toHaveBeenCalledWith(expect.objectContaining({ floors: expect.arrayContaining([expect.objectContaining({ ceiling_height_m: 2.4384 })]) }), 3);
  });

  it('copies to an existing empty floor, undo restores it, and a new-floor copy saves', async () => {
    const api = apiStub();
    const view = render(HomeEditorView, { api, devices });
    await screen.findByRole('button', { name: /Ground/ });
    await fireEvent.change(screen.getByRole('combobox', { name: 'Footprint destination' }), { target: { value: upperId } });
    await fireEvent.click(screen.getByRole('button', { name: 'Copy footprint' }));
    expect(screen.getByRole('application').getAttribute('aria-label')).toContain('Upstairs');
    expect(view.container.querySelectorAll('.wall')).toHaveLength(1);
    expect(view.container.querySelector('.wall')!.getAttribute('data-wall-id')).not.toBe(wallId);
    await fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
    expect(view.container.querySelectorAll('.wall')).toHaveLength(0);
    await fireEvent.click(screen.getByRole('button', { name: /Ground/ }));
    await fireEvent.click(screen.getByRole('button', { name: 'Copy footprint' }));
    expect(screen.getByRole('application').getAttribute('aria-label')).toContain('Floor 2');
    await fireEvent.click(screen.getByRole('button', { name: 'Save plan' }));
    expect(vi.mocked(api.savePlan).mock.calls[0][0].floors).toHaveLength(3);
    expect(api.putPlacement).not.toHaveBeenCalled();
  });
  it('renders floors, walls and rooms from the committed plan', async () => {
    const view = render(HomeEditorView, { api: apiStub(), devices });
    expect(await screen.findByRole('button', { name: /Ground/ })).toBeTruthy();
    expect(screen.getByRole('button', { name: /Upstairs/ })).toBeTruthy();
    expect(view.container.querySelectorAll('.wall')).toHaveLength(1);
    expect(screen.getByText('Kitchen', { selector: '.room-label' })).toBeTruthy();
    expect(screen.getByText('All changes committed')).toBeTruthy();
  });

  it('adds a grid-snapped wall with the wall tool and undo reverts it', async () => {
    const view = render(HomeEditorView, { api: apiStub(), devices });
    await screen.findByRole('button', { name: /Ground/ });
    await fireEvent.click(screen.getByRole('button', { name: 'Wall' }));
    const canvas = view.container.querySelector('.plan-canvas')!;
    await fireEvent.click(canvas, { clientX: 81, clientY: 41 }); // 2.025, 1.025 → snaps to 2.0, 1.0
    await fireEvent.click(canvas, { clientX: 201, clientY: 41 }); // 5.025, 1.025 → snaps to 5.0, 1.0
    const walls = view.container.querySelectorAll('.wall');
    expect(walls).toHaveLength(2);
    const added = walls[1];
    expect([added.getAttribute('x1'), added.getAttribute('y1'), added.getAttribute('x2'), added.getAttribute('y2')]).toEqual(['80', '40', '200', '40']);
    expect(screen.getByText('3.00 m', { selector: '.dimension' })).toBeTruthy(); // calibration label on the selected wall
    await fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
    expect(view.container.querySelectorAll('.wall')).toHaveLength(1);
  });

  it('places a dragged tray device as an owner placement via putPlacement', async () => {
    const api = apiStub();
    const view = render(HomeEditorView, { api, devices });
    await screen.findByRole('button', { name: /Ground/ });
    expect(screen.getByRole('button', { name: /Hall sensor/ })).toBeTruthy(); // tray lists unplaced devices
    const canvas = view.container.querySelector('.plan-canvas')!;
    // jsdom has no DragEvent; a MouseEvent carries the drop coordinates the same way.
    const drop = new MouseEvent('drop', { bubbles: true, clientX: 61, clientY: 84 });
    Object.defineProperty(drop, 'dataTransfer', { value: { getData: (format: string) => (format === 'text/plain' ? deviceA : '') } });
    await fireEvent(canvas, drop);
    expect(api.putPlacement).toHaveBeenCalledTimes(1);
    expect(api.putPlacement).toHaveBeenCalledWith(expect.objectContaining({ device_id: deviceA, floor_id: groundId, x: 1.5, y: 2.1, height_m: 1.0, mounting: null }));
    expect(view.container.querySelector(`.placement[data-device-id="${deviceA}"]`)).toBeTruthy();
    expect(view.container.querySelectorAll('.tray-device')).toHaveLength(1); // only Porch node remains unplaced
  });

  it('shows a reload prompt when a committed save hits a version conflict', async () => {
    const api = apiStub({ savePlan: vi.fn(async () => ({ status: 'conflict' as const })) });
    render(HomeEditorView, { api, devices });
    await screen.findByRole('button', { name: /Ground/ });
    await fireEvent.click(screen.getByRole('button', { name: 'Save plan' }));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toMatch(/Save conflict/i);
    expect(api.savePlan).toHaveBeenCalledWith(expect.objectContaining({ home_id: homeId, version: 3 }), 3);
    await fireEvent.click(screen.getByRole('button', { name: 'Reload latest plan' }));
    expect(api.fetchHome).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('offers to resume or discard a server draft on mount', async () => {
    const draftPlan = { ...fixturePlan(), floors: [{ ...fixturePlan().floors[0], name: 'Drafted ground' }, fixturePlan().floors[1]] };
    const api = apiStub({ loadDraft: vi.fn(async () => ({ status: 'draft' as const, draft: { plan: draftPlan, saved_at: '2026-08-24T00:00:00Z' } })) });
    render(HomeEditorView, { api, devices });
    const region = await screen.findByRole('region', { name: 'Draft found' });
    expect(region.textContent).toMatch(/Unsaved draft found/i);
    await fireEvent.click(screen.getByRole('button', { name: 'Resume draft' }));
    expect(screen.queryByRole('region', { name: 'Draft found' })).toBeNull();
    expect(screen.getByRole('button', { name: /Drafted ground/ })).toBeTruthy();
  });

  it('surfaces a corrupt draft as a non-blocking notice over the committed plan', async () => {
    const api = apiStub({ loadDraft: vi.fn(async () => ({ status: 'corrupt' as const })) });
    render(HomeEditorView, { api, devices });
    await screen.findByRole('button', { name: /Ground/ });
    expect((await screen.findByText(/draft could not be read and was discarded/i))).toBeTruthy();
    expect(screen.getByText('Kitchen', { selector: '.room-label' })).toBeTruthy();
  });

  it('prompts the owner to place exactly the uncertain devices', async () => {
    const estimates: Estimate[] = [
      { device_id: deviceA, floor_id: groundId, room_id: roomId, confidence: 0.4, evidence: ['w6-rssi'], estimated_at: '2026-08-20T00:00:00Z' },
      { device_id: deviceB, floor_id: groundId, room_id: null, confidence: 0.9, evidence: ['collector-arp'], estimated_at: '2026-08-20T00:00:00Z' }
    ];
    render(HomeEditorView, { api: apiStub({}, { estimates }), devices });
    const banner = await screen.findByRole('region', { name: 'Place these devices' });
    expect(banner.textContent).toMatch(/Hall sensor · 40%/);
    expect(banner.textContent).not.toMatch(/Porch node/);
    // Estimates never render as confirmed: they are labeled advisory in the tray.
    expect(screen.getByText(/estimated · 40% confidence/i)).toBeTruthy();
  });

  it('keeps placed devices honest and nudges a selected placement by one grid step', async () => {
    const placements: Placement[] = [{ placement_id: placementId, device_id: deviceA, floor_id: groundId, x: 1.5, y: 2.0, height_m: 1.1, mounting: 'wall' }];
    const api = apiStub({}, { placements });
    const view = render(HomeEditorView, { api, devices });
    await screen.findByRole('button', { name: /Ground/ });
    const marker = view.container.querySelector(`.placement[data-device-id="${deviceA}"]`)!;
    expect(marker.getAttribute('aria-label')).toMatch(/owner-placed/);
    await fireEvent.click(marker);
    const canvas = view.container.querySelector('.plan-canvas')!;
    await fireEvent.keyDown(canvas, { key: 'ArrowRight' });
    expect(api.putPlacement).toHaveBeenCalledWith(expect.objectContaining({ device_id: deviceA, x: 1.6, y: 2.0 }));
  });

  it('coalesces a burst of nudges into one in-flight write plus the newest position (M-29)', async () => {
    const placements: Placement[] = [{ placement_id: placementId, device_id: deviceA, floor_id: groundId, x: 1.5, y: 2.0, height_m: 1.1, mounting: 'wall' }];
    const resolvers: Array<() => void> = [];
    const putPlacement = vi.fn(() => new Promise<void>((resolve) => { resolvers.push(resolve); }));
    const api = apiStub({ putPlacement }, { placements });
    const view = render(HomeEditorView, { api, devices });
    await screen.findByRole('button', { name: /Ground/ });
    await fireEvent.click(view.container.querySelector(`.placement[data-device-id="${deviceA}"]`)!);
    const canvas = view.container.querySelector('.plan-canvas')!;
    for (let step = 0; step < 6; step += 1) await fireEvent.keyDown(canvas, { key: 'ArrowRight' });

    // Six nudges, one request on the wire while it is pending.
    expect(putPlacement).toHaveBeenCalledTimes(1);
    expect(putPlacement).toHaveBeenLastCalledWith(expect.objectContaining({ x: 1.6 }));
    resolvers[0]!();
    await Promise.resolve();
    await Promise.resolve();
    // The queued write carries the final position, not the five intermediate ones.
    expect(putPlacement).toHaveBeenCalledTimes(2);
    expect(putPlacement).toHaveBeenLastCalledWith(expect.objectContaining({ x: 2.1 }));
    resolvers[1]!();
    await Promise.resolve();
    await Promise.resolve();
    expect(putPlacement).toHaveBeenCalledTimes(2);
  });

  it('rolls a placement back to the last server-acknowledged position when the write fails', async () => {
    const placements: Placement[] = [{ placement_id: placementId, device_id: deviceA, floor_id: groundId, x: 1.5, y: 2.0, height_m: 1.1, mounting: 'wall' }];
    const api = apiStub({ putPlacement: vi.fn(async () => { throw new Error('Request failed with status 503'); }) }, { placements });
    const onsnapshot = vi.fn();
    const view = render(HomeEditorView, { api, devices, onsnapshot });
    await screen.findByRole('button', { name: /Ground/ });
    const marker = view.container.querySelector(`.placement[data-device-id="${deviceA}"]`)!;
    await fireEvent.click(marker);
    await fireEvent.keyDown(view.container.querySelector('.plan-canvas')!, { key: 'ArrowRight' });
    expect(api.putPlacement).toHaveBeenCalledWith(expect.objectContaining({ x: 1.6 })); // the optimistic move went out
    await screen.findByText(/could not be saved to the service/);
    expect(view.container.querySelector(`.placement[data-device-id="${deviceA}"] circle`)!.getAttribute('cx')).toBe('60'); // back to 1.5 m
    // The parent hears the optimistic move and the rollback.
    expect(onsnapshot).toHaveBeenCalled();
    expect(onsnapshot.mock.lastCall![0].placements[0]).toMatchObject({ device_id: deviceA, x: 1.5 });
  });

  it('adopts a parent-provided snapshot without fetching and reports committed saves (M-27)', async () => {
    const api = apiStub({}, { placements: [] });
    const onsnapshot = vi.fn();
    render(HomeEditorView, { api, devices, snapshot: { plan: fixturePlan(), placements: [], estimates: [] }, onsnapshot });
    await screen.findByRole('button', { name: /Ground/ });
    expect(api.fetchHome).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole('button', { name: 'Save plan' }));
    await screen.findByText(/Plan saved as version 4/);
    expect(onsnapshot).toHaveBeenCalledWith(expect.objectContaining({ plan: expect.objectContaining({ version: 4 }) }));
  });

  describe('v2 editor', () => {
    const canvasOf = (container: HTMLElement) => container.querySelector('.plan-canvas')!;
    const wallAttrs = (element: Element) => ['x1', 'y1', 'x2', 'y2'].map((name) => element.getAttribute(name));
    const click = (canvas: Element, x: number, y: number, extra: MouseEventInit = {}) => fireEvent.click(canvas, { clientX: x, clientY: y, ...extra });
    const key = (canvas: Element, name: string, extra: KeyboardEventInit = {}) => fireEvent.keyDown(canvas, { key: name, ...extra });
    async function openEditor(api = apiStub()) {
      const view = render(HomeEditorView, { api, devices });
      await screen.findByRole('button', { name: /Ground/ });
      return { view, api, canvas: canvasOf(view.container) };
    }
    const squareWalls = (): HomePlan => {
      const plan = fixturePlan();
      const ids = ['21', '22', '23', '24'].map((suffix) => `018f47a0-9b5c-7a22-8a33-aabbccdd00${suffix}`);
      plan.floors[0].walls = [
        { wall_id: ids[0], start: { x: 2, y: 2 }, end: { x: 5, y: 2 }, openings: [] }, { wall_id: ids[1], start: { x: 5, y: 2 }, end: { x: 5, y: 5 }, openings: [] },
        { wall_id: ids[2], start: { x: 5, y: 5 }, end: { x: 2, y: 5 }, openings: [] }, { wall_id: ids[3], start: { x: 2, y: 5 }, end: { x: 2, y: 2 }, openings: [] }
      ];
      plan.floors[0].rooms = [];
      return plan;
    };

    it('chains walls: each wall starts where the last ended, and Escape or Enter ends the chain', async () => {
      const { view, canvas } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Wall' }));
      await click(canvas, 80, 80);
      await click(canvas, 200, 80);
      await click(canvas, 200, 200);
      let walls = view.container.querySelectorAll('.wall');
      expect(walls).toHaveLength(3);
      expect(wallAttrs(walls[1])).toEqual(['80', '80', '200', '80']);
      expect(wallAttrs(walls[2])).toEqual(['200', '80', '200', '200']); // started from the previous end, not a fresh click
      await key(canvas, 'Escape');
      await click(canvas, 400, 400);
      await click(canvas, 440, 400);
      walls = view.container.querySelectorAll('.wall');
      expect(walls).toHaveLength(4);
      expect(wallAttrs(walls[3])).toEqual(['400', '400', '440', '400']); // a fresh chain after Escape
      await key(canvas, 'Enter'); // Enter also ends a chain
      await click(canvas, 500, 400);
      await click(canvas, 540, 400);
      expect(wallAttrs(view.container.querySelectorAll('.wall')[4])).toEqual(['500', '400', '540', '400']);
    });

    it('closing a chain on its first point ends it and offers the room, with its area', async () => {
      const { view, canvas } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Wall' }));
      for (const [x, y] of [[80, 80], [200, 80], [200, 200], [80, 200], [80, 80]]) await click(canvas, x, y);
      expect(view.container.querySelectorAll('.wall')).toHaveLength(5);
      const offer = screen.getByRole('region', { name: 'Detected rooms' });
      expect(offer.textContent).toMatch(/9\.0 m²/);
      expect((screen.getByLabelText('Name for detected room 1') as HTMLInputElement).value).toBe('Room 2'); // the Kitchen holds the first slot
      expect(view.container.querySelectorAll('.candidate')).toHaveLength(1);
      await fireEvent.input(screen.getByLabelText('Name for detected room 1'), { target: { value: 'Studio' } });
      await fireEvent.click(screen.getByRole('button', { name: 'Add' }));
      expect(screen.queryByRole('region', { name: 'Detected rooms' })).toBeNull();
      expect(screen.getByText('Studio', { selector: '.room-label' })).toBeTruthy();
      const labels = [...view.container.querySelectorAll('.room-area')].map((element) => element.textContent);
      expect(labels).toEqual(['12.0 m²', '9.0 m²']); // Kitchen 4 x 3, Studio 3 x 3
      await fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
      expect(view.container.querySelectorAll('.room')).toHaveLength(1);
    });

    it('Detect rooms finds closed walls, adds all in one undo step, and reports when there is nothing', async () => {
      const second = squareWalls();
      second.floors[0].walls.push(
        { wall_id: '018f47a0-9b5c-7a22-8a33-aabbccdd0031', start: { x: 8, y: 2 }, end: { x: 10, y: 2 }, openings: [] },
        { wall_id: '018f47a0-9b5c-7a22-8a33-aabbccdd0032', start: { x: 10, y: 2 }, end: { x: 10, y: 4 }, openings: [] },
        { wall_id: '018f47a0-9b5c-7a22-8a33-aabbccdd0033', start: { x: 10, y: 4 }, end: { x: 8, y: 4 }, openings: [] },
        { wall_id: '018f47a0-9b5c-7a22-8a33-aabbccdd0034', start: { x: 8, y: 4 }, end: { x: 8, y: 2 }, openings: [] }
      );
      const api = apiStub({ fetchHome: vi.fn(async () => ({ plan: second, placements: [], estimates: [] })) });
      const { view } = await openEditor(api);
      await fireEvent.click(screen.getByRole('button', { name: 'Detect rooms' }));
      expect(screen.getByRole('region', { name: 'Detected rooms' }).textContent).toMatch(/2 closed rooms were found/);
      await fireEvent.click(screen.getByRole('button', { name: 'Add all' }));
      expect(view.container.querySelectorAll('.room')).toHaveLength(2);
      await fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
      expect(view.container.querySelectorAll('.room')).toHaveLength(0); // both rooms came out together
      await fireEvent.click(screen.getByRole('button', { name: 'Redo' }));
      await fireEvent.click(screen.getByRole('button', { name: 'Detect rooms' }));
      expect(screen.getByText(/No new closed rooms found/)).toBeTruthy();
    });

    it('splits the wall it lands on so the new wall truly joins it, in one undo step', async () => {
      const { view, canvas } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Wall' }));
      await click(canvas, 41, 121); // (1, 3)
      await click(canvas, 41, 1); // 0.025 m off the Kitchen wall: "on wall"
      const walls = [...view.container.querySelectorAll('.wall')];
      expect(walls).toHaveLength(3);
      expect(wallAttrs(walls[0])).toEqual(['0', '0', '40', '0']);
      expect(wallAttrs(walls[1])).toEqual(['40', '0', '168', '0']);
      expect(wallAttrs(walls[2])).toEqual(['40', '120', '40', '0']);
      await fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
      expect(view.container.querySelectorAll('.wall')).toHaveLength(1);
      expect(wallAttrs(view.container.querySelector('.wall')!)).toEqual(['0', '0', '168', '0']);
    });

    it('shows the snap marker with its label and a live length and angle readout while drawing', async () => {
      const { view, canvas } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Wall' }));
      await fireEvent.pointerMove(canvas, { clientX: 3, clientY: 2 }); // right on the Kitchen wall's start
      expect(view.container.querySelector('.snap-marker')!.getAttribute('data-snap-kind')).toBe('endpoint');
      expect(view.container.querySelector('.snap-label')!.textContent).toBe('endpoint');
      await click(canvas, 3, 2);
      await fireEvent.pointerMove(canvas, { clientX: 0, clientY: 200 }); // straight down from the start, 5 m
      expect(view.container.querySelector('.readout-length')!.textContent).toBe('5.00 m');
      expect(view.container.querySelector('.readout-angle')!.textContent).toBe('270°');
    });

    it('typing digits while a wall is in progress builds an exact length that Enter commits', async () => {
      const { view, canvas } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Wall' }));
      await click(canvas, 80, 200);
      await fireEvent.pointerMove(canvas, { clientX: 200, clientY: 200 });
      for (const digit of ['3', '.', '4', '5']) await key(canvas, digit);
      expect(view.container.querySelector('.readout-length')!.textContent).toContain('3.45 m');
      await key(canvas, 'Backspace');
      expect(view.container.querySelector('.readout-length')!.textContent).toContain('3.4 m');
      await key(canvas, '5');
      await key(canvas, 'Enter');
      const added = [...view.container.querySelectorAll('.wall')].at(-1)!;
      expect(wallAttrs(added)).toEqual(['80', '200', '218', '200']); // 2 + 3.45 m = 5.45 m exactly, not snapped to the grid
      expect(view.container.querySelectorAll('.wall')).toHaveLength(2); // Backspace did not delete a selected wall
    });

    it('the Rectangle tool makes four walls and a room in ONE undo step', async () => {
      const { view, canvas } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Rectangle' }));
      await click(canvas, 80, 120);
      await fireEvent.pointerMove(canvas, { clientX: 240, clientY: 240 });
      expect(view.container.querySelector('.preview-rect')).toBeTruthy();
      expect(view.container.querySelector('.readout-length')!.textContent).toBe('4.00 m × 3.00 m');
      await click(canvas, 240, 240);
      expect(view.container.querySelectorAll('.wall')).toHaveLength(5);
      expect(screen.getByText('Room 2', { selector: '.room-label' })).toBeTruthy();
      await fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
      expect(view.container.querySelectorAll('.wall')).toHaveLength(1);
      expect(view.container.querySelectorAll('.room')).toHaveLength(1);
    });

    it('walls render as bands of true thickness and the inspector edits it, saved on new and edited walls', async () => {
      const { view, canvas, api } = await openEditor();
      expect(view.container.querySelector('.wall')!.getAttribute('stroke-width')).toBe('4'); // default 0.1 m at 40 px/m
      await fireEvent.click(screen.getByRole('button', { name: 'Wall, 4.20 m' }));
      const input = screen.getByLabelText('Thickness (m)') as HTMLInputElement;
      expect(input.valueAsNumber).toBe(0.1);
      await fireEvent.change(input, { target: { value: '0.25' } });
      expect(view.container.querySelector('.wall')!.getAttribute('stroke-width')).toBe('10');
      await fireEvent.change(screen.getByLabelText('Thickness (m)'), { target: { value: '5' } }); // out of range: refused
      expect(view.container.querySelector('.wall')!.getAttribute('stroke-width')).toBe('10');
      await fireEvent.click(screen.getByRole('button', { name: 'Wall' }));
      await click(canvas, 80, 80);
      await click(canvas, 200, 80);
      await fireEvent.click(screen.getByRole('button', { name: 'Save plan' }));
      const saved = vi.mocked(api.savePlan).mock.calls[0][0].floors[0].walls;
      expect(saved.map((wall) => wall.thickness_m)).toEqual([0.25, 0.1]);
    });

    it('thin walls never render thinner than 2 px when zoomed out', async () => {
      const { view } = await openEditor();
      for (let step = 0; step < 6; step += 1) await fireEvent.click(screen.getByRole('button', { name: 'Zoom out' }));
      expect(Number(view.container.querySelector('.wall')!.getAttribute('stroke-width'))).toBeGreaterThanOrEqual(2);
    });

    it('zoom buttons change the viewBox about the centre, 100% restores it, and the view persists per floor', async () => {
      const { view } = await openEditor();
      const svg = () => view.container.querySelector('.plan-canvas')!.getAttribute('viewBox');
      expect(svg()).toBe('0 0 720 480');
      await fireEvent.click(screen.getByRole('button', { name: 'Zoom in' }));
      expect(svg()).toBe('90 60 720 480'); // 50 px/m with the centre (9 m, 6 m) pinned
      expect(screen.getByLabelText('Current zoom').textContent).toBe('50 px/m');
      expect(JSON.parse(localStorage.getItem('neonhearth.home.view.' + groundId)!)).toMatchObject({ scale: 50 });
      await fireEvent.click(screen.getByRole('button', { name: 'Zoom out' }));
      expect(svg()).toBe('0 0 720 480');
      await fireEvent.click(screen.getByRole('button', { name: 'Zoom in' }));
      await fireEvent.click(screen.getByRole('button', { name: '100%' }));
      expect(svg()).toBe('0 0 720 480');
      await fireEvent.click(screen.getByRole('button', { name: 'Fit plan' }));
      expect(svg()).not.toBe('0 0 720 480');
      expect(Number(screen.getByLabelText('Current zoom').textContent!.replace(' px/m', ''))).toBeGreaterThan(100);
      // Another floor keeps its own view; coming back restores this one.
      await fireEvent.click(screen.getByRole('button', { name: /Upstairs/ }));
      expect(svg()).toBe('0 0 720 480');
      await fireEvent.click(screen.getByRole('button', { name: /Ground/ }));
      expect(Number(screen.getByLabelText('Current zoom').textContent!.replace(' px/m', ''))).toBeGreaterThan(100);
    });

    it('the grid rects always cover the viewBox, and the minor grid fades out when zoomed out', async () => {
      const { view } = await openEditor();
      const grid = () => view.container.querySelector('rect.grid-major-fill')!;
      await fireEvent.click(screen.getByRole('button', { name: 'Zoom in' }));
      expect([grid().getAttribute('x'), grid().getAttribute('y'), grid().getAttribute('width'), grid().getAttribute('height')]).toEqual(['90', '60', '720', '480']);
      expect(view.container.querySelector('rect.grid-minor-fill')).toBeTruthy();
      for (let step = 0; step < 5; step += 1) await fireEvent.click(screen.getByRole('button', { name: 'Zoom out' }));
      expect(view.container.querySelector('rect.grid-minor-fill')).toBeNull();
    });

    it('wheel zooms about the cursor', async () => {
      const { canvas } = await openEditor();
      await fireEvent.wheel(canvas, { deltaY: -200, clientX: 0, clientY: 0 });
      expect(Number(screen.getByLabelText('Current zoom').textContent!.replace(' px/m', ''))).toBeGreaterThan(40);
      expect(canvas.getAttribute('viewBox')!.startsWith('0 0 ')).toBe(true); // the cursor sat on the origin, so it stays put
      await fireEvent.wheel(canvas, { deltaY: 400, clientX: 360, clientY: 240 });
      expect(Number(screen.getByLabelText('Current zoom').textContent!.replace(' px/m', ''))).toBeLessThan(40);
    });

    it('the Pan tool drags the view without drawing', async () => {
      const { view, canvas } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Pan' }));
      await fireEvent.pointerDown(canvas, { button: 0, clientX: 100, clientY: 100, pointerId: 1 });
      await fireEvent.pointerMove(canvas, { clientX: 150, clientY: 120, pointerId: 1 });
      await fireEvent.pointerUp(canvas, { clientX: 150, clientY: 120, pointerId: 1 });
      expect(canvas.getAttribute('viewBox')).toBe('-50 -20 720 480');
      await click(canvas, 150, 120); // the click that ends a drag does nothing
      expect(view.container.querySelectorAll('.wall')).toHaveLength(1);
    });

    it('middle-mouse drags pan in any tool', async () => {
      const { canvas } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Wall' }));
      await fireEvent.pointerDown(canvas, { button: 1, clientX: 200, clientY: 200, pointerId: 2 });
      await fireEvent.pointerMove(canvas, { clientX: 160, clientY: 200, pointerId: 2 });
      await fireEvent.pointerUp(canvas, { clientX: 160, clientY: 200, pointerId: 2 });
      expect(canvas.getAttribute('viewBox')).toBe('40 0 720 480');
    });

    it('Space held pans and its release stops it', async () => {
      const { canvas } = await openEditor();
      await key(canvas, ' ');
      expect(canvas.classList.contains('pan-ready')).toBe(true);
      await fireEvent.pointerDown(canvas, { button: 0, clientX: 100, clientY: 100, pointerId: 3 });
      await fireEvent.pointerMove(canvas, { clientX: 140, clientY: 100, pointerId: 3 });
      await fireEvent.pointerUp(canvas, { clientX: 140, clientY: 100, pointerId: 3 });
      expect(canvas.getAttribute('viewBox')).toBe('-40 0 720 480');
      await fireEvent.keyUp(canvas, { key: ' ' });
      expect(canvas.classList.contains('pan-ready')).toBe(false);
    });

    it('single-letter shortcuts switch tools but never fire while typing in a field', async () => {
      const { canvas } = await openEditor();
      const pressed = (name: string) => screen.getByRole('button', { name }).getAttribute('aria-pressed');
      await key(canvas, 'w');
      expect(pressed('Wall')).toBe('true');
      await key(canvas, 'r');
      expect(pressed('Room')).toBe('true');
      await key(canvas, 'o');
      expect(pressed('Opening')).toBe('true');
      await key(canvas, 'p');
      expect(pressed('Place device')).toBe('true');
      await key(canvas, 'h');
      expect(pressed('Pan')).toBe('true');
      await key(canvas, 'b');
      expect(pressed('Rectangle')).toBe('true');
      await key(canvas, 'v');
      expect(pressed('Select')).toBe('true');
      // In a text field or a select the same keys do nothing.
      await fireEvent.click(screen.getByRole('button', { name: /Ground/ }));
      await fireEvent.keyDown(screen.getByLabelText('Floor name'), { key: 'w' });
      await fireEvent.keyDown(screen.getByRole('combobox', { name: 'Measurement units' }), { key: 'r' });
      expect(pressed('Select')).toBe('true');
    });

    it('typing in a field does not feed the length entry while a wall is in progress', async () => {
      const { view, canvas } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Wall' }));
      await click(canvas, 80, 200);
      await fireEvent.click(screen.getByRole('button', { name: /Ground/ }));
      await fireEvent.keyDown(screen.getByLabelText('Floor name'), { key: '7' });
      expect(view.container.querySelector('.readout')).toBeNull();
    });

    it('shows a hint line that follows the tool and the drawing state', async () => {
      const { view, canvas } = await openEditor();
      const hint = () => view.container.querySelector('.tool-hint')!.textContent!;
      expect(hint()).toMatch(/select/i);
      await fireEvent.click(screen.getByRole('button', { name: 'Wall' }));
      expect(hint()).toMatch(/Click to start a wall/);
      await click(canvas, 80, 80);
      expect(hint()).toMatch(/type a length/i);
      await fireEvent.click(screen.getByRole('button', { name: 'Rectangle' }));
      expect(hint()).toMatch(/one corner/);
    });

    it('drags a selected wall endpoint with snapping, and drags a wall body to move it whole', async () => {
      const { view, canvas } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Wall, 4.20 m' }));
      const handle = view.container.querySelector('[data-handle="end"]')!;
      await fireEvent.pointerDown(handle, { button: 0, clientX: 168, clientY: 0, pointerId: 4 });
      await fireEvent.pointerMove(canvas, { clientX: 241, clientY: 1, pointerId: 4 });
      expect(wallAttrs(view.container.querySelector('.wall')!)).toEqual(['0', '0', '240', '0']); // live preview
      await fireEvent.pointerUp(canvas, { clientX: 241, clientY: 1, pointerId: 4 });
      expect(wallAttrs(view.container.querySelector('.wall')!)).toEqual(['0', '0', '240', '0']);
      await fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
      expect(wallAttrs(view.container.querySelector('.wall')!)).toEqual(['0', '0', '168', '0']);

      const body = screen.getByRole('button', { name: 'Wall, 4.20 m' });
      await fireEvent.pointerDown(body, { button: 0, clientX: 40, clientY: 0, pointerId: 5 });
      await fireEvent.pointerMove(canvas, { clientX: 120, clientY: 40, pointerId: 5 });
      await fireEvent.pointerUp(canvas, { clientX: 120, clientY: 40, pointerId: 5 });
      expect(wallAttrs(view.container.querySelector('.wall')!)).toEqual(['80', '40', '248', '40']);
    });

    it('an endpoint dragged onto another wall endpoint lands exactly on it', async () => {
      const plan = fixturePlan();
      plan.floors[0].walls.push({ wall_id: '018f47a0-9b5c-7a22-8a33-aabbccdd0021', start: { x: 0.0507, y: 3 }, end: { x: 3, y: 3 }, openings: [] });
      const api = apiStub({ fetchHome: vi.fn(async () => ({ plan, placements: [], estimates: [] })) });
      const { view, canvas } = await openEditor(api);
      await fireEvent.click(screen.getByRole('button', { name: 'Wall, 4.20 m' }));
      const handle = view.container.querySelector('[data-handle="start"]')!;
      await fireEvent.pointerDown(handle, { button: 0, clientX: 0, clientY: 0, pointerId: 6 });
      await fireEvent.pointerMove(canvas, { clientX: 3, clientY: 118, pointerId: 6 }); // near (0.0507, 3)
      await fireEvent.pointerUp(canvas, { clientX: 3, clientY: 118, pointerId: 6 });
      await fireEvent.click(screen.getByRole('button', { name: 'Save plan' }));
      const walls = vi.mocked(api.savePlan).mock.calls[0][0].floors[0].walls;
      expect(walls[0].start).toEqual({ x: 0.0507, y: 3 });
    });

    it('draws room labels as SVG text positioned from the plan, so they keep a constant screen size', async () => {
      const { view } = await openEditor();
      const before = view.container.querySelector('.room-label')!.getAttribute('y');
      await fireEvent.click(screen.getByRole('button', { name: 'Zoom in' }));
      expect(view.container.querySelector('.room-label')!.getAttribute('y')).not.toBe(before);
      expect(view.container.querySelector('.scale-bar text')!.textContent).toMatch(/\d/);
    });

    it('shows each floor total area in the floor bar', async () => {
      await openEditor();
      expect(screen.getByRole('button', { name: /Ground.*12\.0 m²/ })).toBeTruthy();
    });
  });

  describe('v2 editor follow-up', () => {
    const canvasOf = (container: HTMLElement) => container.querySelector('.plan-canvas')!;
    const wallAttrs = (element: Element) => ['x1', 'y1', 'x2', 'y2'].map((name) => element.getAttribute(name));
    async function openEditor(api = apiStub()) {
      const view = render(HomeEditorView, { api, devices });
      await screen.findByRole('button', { name: /Ground/ });
      return { view, api, canvas: canvasOf(view.container) };
    }
    const touch = (pointerId: number, x: number, y: number) => ({ pointerType: 'touch', pointerId, clientX: x, clientY: y, isPrimary: pointerId === 11 });

    it('lays out as a drafting table: tool rail, canvas with its view controls, status bar, floors beside it', async () => {
      const { view } = await openEditor();
      const frame = view.container.querySelector('.canvas-frame')!;
      expect(frame.querySelector('[role="toolbar"][aria-label="Plan view"]')).toBeTruthy();
      // The tools are a vertical toolbar of named buttons; the shortcut letter is not part of the name.
      const tools = screen.getByRole('toolbar', { name: 'Editor tools' });
      expect(tools.getAttribute('aria-orientation')).toBe('vertical');
      expect([...tools.querySelectorAll('button.tool')].map((button) => button.querySelector('.tool-name')!.textContent))
        .toEqual(['Select', 'Pan', 'Wall', 'Rectangle', 'Room', 'Opening', 'Place device']);
      expect(screen.getByRole('button', { name: 'Wall' }).getAttribute('aria-keyshortcuts')).toBe('W');
      // Detect rooms stays outside the tools toolbar (its name would collide with the Room tool).
      expect(tools.querySelector('button.detect')).toBeNull();
      const status = view.container.querySelector('.status-bar')!;
      expect(status.contains(screen.getByRole('button', { name: 'Detect rooms' }))).toBe(true);
      expect(status.contains(screen.getByRole('combobox', { name: 'Measurement units' }))).toBe(true);
      expect(status.querySelector('.tool-hint')).toBeTruthy();
      // Floors, with Copy footprint, sit in the side column above the tray.
      const floors = view.container.querySelector('.floors-panel')!;
      expect(floors.contains(screen.getByRole('navigation', { name: 'Floors' }))).toBe(true);
      expect(floors.contains(screen.getByRole('combobox', { name: 'Footprint destination' }))).toBe(true);
      expect(floors.contains(screen.getByRole('button', { name: 'Copy footprint' }))).toBe(true);
      // Undo / Redo / Save live in the title bar.
      const top = view.container.querySelector('.editor-top')!;
      expect(top.contains(screen.getByRole('button', { name: 'Undo' }))).toBe(true);
      expect(top.contains(screen.getByRole('button', { name: 'Save plan' }))).toBe(true);
    });

    it('two-finger pinch zooms about the finger midpoint and two-finger drag pans, without drawing', async () => {
      const { view, canvas } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Wall' }));
      await fireEvent.pointerDown(canvas, touch(11, 100, 100));
      await fireEvent.pointerDown(canvas, touch(12, 200, 100));
      await fireEvent.pointerMove(canvas, touch(12, 300, 100)); // spacing 100 -> 200: 40 -> 80 px/m
      expect(screen.getByLabelText('Current zoom').textContent).toBe('80 px/m');
      expect(canvas.getAttribute('viewBox')).toBe('100 100 720 480'); // the plan point under the old midpoint is under the new one
      await fireEvent.pointerMove(canvas, touch(11, 140, 100)); // both fingers move right 40: pure pan
      await fireEvent.pointerMove(canvas, touch(12, 340, 100));
      expect(screen.getByLabelText('Current zoom').textContent).toBe('80 px/m');
      expect(canvas.getAttribute('viewBox')).toBe('60 100 720 480'); // midpoint moved 40 px right at 80 px/m
      await fireEvent.pointerUp(canvas, touch(12, 340, 100));
      await fireEvent.pointerUp(canvas, touch(11, 140, 100));
      await fireEvent.click(canvas, { clientX: 140, clientY: 100 }); // the click ending the gesture is swallowed
      expect(view.container.querySelector('.pending-start')).toBeNull();
      expect(view.container.querySelectorAll('.wall')).toHaveLength(1);
    });

    it('Ctrl+D duplicates the selected wall one grid step over, in one undo step, and selects the copy', async () => {
      const { view, canvas } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Wall, 4.20 m' }));
      await fireEvent.keyDown(canvas, { key: 'd', ctrlKey: true });
      const walls = [...view.container.querySelectorAll('.wall')];
      expect(walls).toHaveLength(2);
      expect(wallAttrs(walls[1])).toEqual(['40', '40', '208', '40']);
      expect(walls[1].classList.contains('selected')).toBe(true);
      await fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
      expect(view.container.querySelectorAll('.wall')).toHaveLength(1);
    });

    it('Ctrl+D duplicates a selected room with a new name, and does nothing in a text field or with no selection', async () => {
      const { view, canvas } = await openEditor();
      await fireEvent.keyDown(canvas, { key: 'd', ctrlKey: true });
      expect(view.container.querySelectorAll('.room')).toHaveLength(1);
      await fireEvent.click(screen.getByRole('button', { name: 'Room Kitchen' }));
      await fireEvent.keyDown(screen.getByLabelText('Room name'), { key: 'd', ctrlKey: true });
      expect(view.container.querySelectorAll('.room')).toHaveLength(1);
      await fireEvent.keyDown(canvas, { key: 'd', ctrlKey: true });
      expect(view.container.querySelectorAll('.room')).toHaveLength(2);
      expect(screen.getByText('Kitchen copy', { selector: '.room-label' })).toBeTruthy();
      await fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
      expect(view.container.querySelectorAll('.room')).toHaveLength(1);
    });

    it('endpoint handles are focusable, labelled, and arrow keys nudge just that endpoint (Shift = 10 steps)', async () => {
      const { view } = await openEditor();
      await fireEvent.click(screen.getByRole('button', { name: 'Wall, 4.20 m' }));
      const start = screen.getByRole('button', { name: 'Wall start handle' });
      const end = screen.getByRole('button', { name: 'Wall end handle' });
      expect(start.getAttribute('tabindex')).toBe('0');
      expect(end.getAttribute('tabindex')).toBe('0');
      await fireEvent.keyDown(start, { key: 'ArrowRight' });
      expect(wallAttrs(view.container.querySelector('.wall')!)).toEqual(['4', '0', '168', '0']); // only the start moved, by 0.1 m
      await fireEvent.keyDown(end, { key: 'ArrowDown', shiftKey: true });
      expect(wallAttrs(view.container.querySelector('.wall')!)).toEqual(['4', '0', '168', '40']); // ten steps = 1 m
      await fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
      expect(wallAttrs(view.container.querySelector('.wall')!)).toEqual(['4', '0', '168', '0']);
    });

    it('says exactly why a wall could not be joined when its end lands inside a door opening', async () => {
      const plan = fixturePlan();
      plan.floors[0].walls[0].openings = [{ opening_id: '018f47a0-9b5c-7a22-8a33-aabbccdd0030', kind: 'door', offset_m: 0.8, width_m: 0.9 }];
      const api = apiStub({ fetchHome: vi.fn(async () => ({ plan, placements: [], estimates: [] })) });
      const { view, canvas } = await openEditor(api);
      await fireEvent.click(screen.getByRole('button', { name: 'Wall' }));
      await fireEvent.click(canvas, { clientX: 41, clientY: 121 });
      await fireEvent.click(canvas, { clientX: 41, clientY: 1 }); // (1, 0) is inside the door's 0.8-1.7 m span
      expect(screen.getByText('That point is inside a door opening — the wall was drawn but not joined.')).toBeTruthy();
      expect(view.container.querySelectorAll('.wall')).toHaveLength(2); // drawn, not split
    });
  });

  describe('Duplicate floor', () => {
    it('copies the active floor to a new floor above in one undo step and saves it', async () => {
      const api = apiStub();
      const view = render(HomeEditorView, { api, devices });
      await screen.findByRole('button', { name: /Ground/ });
      await fireEvent.click(screen.getByRole('button', { name: 'Duplicate floor' }));

      expect(screen.getByRole('application').getAttribute('aria-label')).toContain('Copy of Ground');
      expect(screen.getByRole('button', { name: /Copy of Ground/ }).getAttribute('aria-pressed')).toBe('true');
      const walls = view.container.querySelectorAll('.wall');
      expect(walls).toHaveLength(1);
      expect(walls[0].getAttribute('data-wall-id')).not.toBe(wallId); // a copy with its own ids
      expect(screen.getByText('Kitchen', { selector: '.room-label' })).toBeTruthy();
      expect(screen.getByText(/Duplicated Ground as Copy of Ground \(level 2\)/)).toBeTruthy();

      await fireEvent.click(screen.getByRole('button', { name: 'Save plan' }));
      const saved = vi.mocked(api.savePlan).mock.calls[0][0];
      expect(saved.floors.map((floor) => [floor.name, floor.level])).toEqual([['Ground', 0], ['Upstairs', 1], ['Copy of Ground', 2]]);
      expect(saved.floors[2].ceiling_height_m).toBe(2.4);
      expect(saved.floors[2].rooms[0].room_id).not.toBe(roomId);
      expect(saved.floors[0].walls[0].wall_id).toBe(wallId); // the original is untouched
      expect(api.putPlacement).not.toHaveBeenCalled(); // devices stay where they are

      await fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
      expect(screen.queryByRole('button', { name: /Copy of Ground/ })).toBeNull();
    });

    it('numbers a second copy and duplicates an empty floor as an empty floor', async () => {
      const view = render(HomeEditorView, { api: apiStub(), devices });
      await screen.findByRole('button', { name: /^Ground/ });
      await fireEvent.click(screen.getByRole('button', { name: 'Duplicate floor' }));
      await fireEvent.click(screen.getByRole('button', { name: /^Ground/ }));
      await fireEvent.click(screen.getByRole('button', { name: 'Duplicate floor' }));
      expect(screen.getByRole('button', { name: /^Copy of Ground 2/ }).getAttribute('aria-pressed')).toBe('true');

      await fireEvent.click(screen.getByRole('button', { name: /^Upstairs/ }));
      await fireEvent.click(screen.getByRole('button', { name: 'Duplicate floor' }));
      expect(screen.getByRole('button', { name: /^Copy of Upstairs/ }).getAttribute('aria-pressed')).toBe('true');
      expect(view.container.querySelectorAll('.wall')).toHaveLength(0);
    });
  });
});
