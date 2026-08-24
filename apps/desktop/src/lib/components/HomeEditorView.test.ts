// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';

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
});
