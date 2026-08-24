// @vitest-environment jsdom
import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { DeviceSnapshot } from '../api/types';
import type { HomeApi, HomeSnapshot } from '../stores/home';
import { initialLiveState, type LiveState } from '../stores/live';
import HomeView from './HomeView.svelte';
import { isNotFound, toBandwidthMap, toHomeDeviceRefs, toPresenceMap, toTwinDevices, withEmptyPlanOn404 } from './homeViewData';

// The twin's WebGL seam is the documented mock point (src/lib/twin/webgl.ts):
// enabled=true keeps the 3D mode alive in jsdom, enabled=false exercises the fallback.
const webgl = vi.hoisted(() => ({ enabled: false }));
vi.mock('../twin/webgl', () => ({
  detectWebGL: () => webgl.enabled,
  createTwinRenderer: () => (webgl.enabled ? { setSize() {}, setPixelRatio() {}, render() {}, dispose() {} } : null)
}));

const cameraId = '018f47a0-9b5c-7a22-8a33-112233445501';
const laptopId = '018f47a0-9b5c-7a22-8a33-112233445502';
const floorId = '018f47a0-9b5c-7a22-8a33-112233445610';

interface DeviceOverrides {
  owner_name?: string | null;
  classification?: string | null;
  state?: DeviceSnapshot['presence']['state'];
  available?: boolean;
  upload?: number | null;
  download?: number | null;
}

function makeDevice(device_id: string, overrides: DeviceOverrides = {}): DeviceSnapshot {
  return {
    device_id,
    first_seen_at: '2026-01-01T00:00:00Z',
    last_seen_at: '2026-01-01T00:05:00Z',
    owner_name: overrides.owner_name ?? null,
    owner_type: null,
    owner_confirmed: false,
    presence: { state: overrides.state ?? 'unknown', observed_at: null, source: null, kind: null },
    evidence: null,
    identity: { available: overrides.classification != null, classification: overrides.classification ?? null, confidence: null },
    bandwidth: {
      available: overrides.available ?? false,
      upload: overrides.upload ?? null,
      download: overrides.download ?? null,
      coverage: null,
      observed_at: null
    },
    policy: null
  };
}

function liveFixture(): LiveState {
  const devices = {
    [cameraId]: makeDevice(cameraId, { owner_name: 'Front Door Cam', classification: 'camera', state: 'online', available: true, upload: 1000, download: 2000 }),
    [laptopId]: makeDevice(laptopId, { classification: 'laptop', state: 'offline' })
  };
  return { ...initialLiveState, connected: true, devices, deviceOrder: [cameraId, laptopId] };
}

function snapshotFixture(): HomeSnapshot {
  return {
    plan: {
      home_id: '018f47a0-9b5c-7a22-8a33-112233445600',
      version: 1,
      name: 'Home',
      floors: [{ floor_id: floorId, level: 0, name: 'Ground', ceiling_height_m: 2.4, walls: [], rooms: [] }]
    },
    placements: [{ placement_id: '018f47a0-9b5c-7a22-8a33-112233445620', device_id: cameraId, floor_id: floorId, x: 1, y: 1, height_m: 1, mounting: null }],
    estimates: []
  };
}

function apiStub(overrides: Partial<HomeApi> = {}): HomeApi {
  return {
    fetchHome: vi.fn(async () => snapshotFixture()),
    savePlan: vi.fn(async () => ({ status: 'saved' as const, version: 2 })),
    saveDraft: vi.fn(async () => undefined),
    loadDraft: vi.fn(async () => ({ status: 'none' as const })),
    deleteDraft: vi.fn(async () => undefined),
    putPlacement: vi.fn(async () => undefined),
    deletePlacement: vi.fn(async () => undefined),
    ...overrides
  };
}

beforeEach(() => {
  webgl.enabled = false;
});

describe('HomeView', () => {
  it('renders both tabs, switches, and keeps the twin selection when returning to the editor', async () => {
    webgl.enabled = true;
    render(HomeView, { liveState: liveFixture(), api: apiStub() });

    expect(await screen.findByRole('heading', { name: 'Draw the home you protect.' })).toBeTruthy();
    const editorTab = screen.getByRole('tab', { name: 'Plan editor' });
    const twinTab = screen.getByRole('tab', { name: '3D view' });
    expect(editorTab.getAttribute('aria-selected')).toBe('true');

    await fireEvent.click(twinTab);
    expect(twinTab.getAttribute('aria-selected')).toBe('true');

    // Selecting a pin in the 3D view (its accessible device list) records the shared selection…
    const pin = await screen.findByRole('button', { name: 'Front Door Cam — online' });
    await fireEvent.click(pin);
    expect(await screen.findByText('Front Door Cam', { selector: '.home-selection strong' })).toBeTruthy();

    // …and the selection persists when switching back to the plan editor.
    await fireEvent.click(editorTab);
    expect(editorTab.getAttribute('aria-selected')).toBe('true');
    expect(screen.getByText('Front Door Cam', { selector: '.home-selection strong' })).toBeTruthy();
  });

  it('shows live devices in the unplaced tray through HomeEditorView', async () => {
    render(HomeView, { liveState: liveFixture(), api: apiStub() });
    const tray = await screen.findByRole('complementary', { name: 'Unplaced devices' });
    // The laptop has no owner name and no placement; the camera is placed, so it is not in the tray.
    expect(within(tray).getByRole('button', { name: 'Unnamed device' })).toBeTruthy();
    expect(within(tray).queryByText(/Front Door Cam/)).toBeNull();
  });

  it('degrades a missing home route (404) to the empty-plan editor state', async () => {
    const api = apiStub({ fetchHome: vi.fn(async () => { throw new Error('Request failed with status 404'); }) });
    render(HomeView, { liveState: liveFixture(), api });
    expect(await screen.findByText(/This home has no floors yet/)).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('offers a retry when the home fetch fails, then recovers', async () => {
    const fetchHome = vi.fn<() => Promise<HomeSnapshot>>()
      .mockRejectedValueOnce(new Error('Request failed with status 500'))
      .mockRejectedValueOnce(new Error('Request failed with status 500'))
      .mockResolvedValue(snapshotFixture());
    render(HomeView, { liveState: liveFixture(), api: apiStub({ fetchHome }) });

    expect(await screen.findByText(/The home plan is unavailable right now/)).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByLabelText(/Floor plan for Ground/)).toBeTruthy();
    expect(screen.queryByText(/The home plan is unavailable right now/)).toBeNull();
  });

  it('switches to the plan editor with a notice when the twin falls back', async () => {
    render(HomeView, { liveState: liveFixture(), api: apiStub() });
    await screen.findByRole('heading', { name: 'Draw the home you protect.' });

    await fireEvent.click(screen.getByRole('tab', { name: '3D view' }));

    expect(await screen.findByText(/3D unavailable on this device/)).toBeTruthy();
    expect(screen.getByRole('tab', { name: 'Plan editor' }).getAttribute('aria-selected')).toBe('true');
  });
});

describe('homeViewData', () => {
  it('derives device refs, twin devices, presence and bandwidth maps from live devices', () => {
    const devices = liveFixture().devices;

    expect(toHomeDeviceRefs(devices)).toEqual([
      { device_id: cameraId, name: 'Front Door Cam' },
      { device_id: laptopId, name: null }
    ]);

    expect(toTwinDevices(devices)).toEqual([
      { device_id: cameraId, label: 'Front Door Cam', is_camera: true },
      { device_id: laptopId, label: `Device ${laptopId.slice(0, 8)}`, is_camera: false }
    ]);

    expect(toPresenceMap(devices)).toEqual({ [cameraId]: 'online', [laptopId]: 'offline' });

    // Upload + download summed; devices without bandwidth data are omitted.
    expect(toBandwidthMap(devices)).toEqual({ [cameraId]: 3000 });
  });

  it('sums partial bandwidth values when only one direction is known', () => {
    const id = '018f47a0-9b5c-7a22-8a33-112233445503';
    const devices = { [id]: makeDevice(id, { available: true, upload: null, download: 500 }) };
    expect(toBandwidthMap(devices)).toEqual({ [id]: 500 });
  });

  it('withEmptyPlanOn404 returns an empty snapshot only for 404 and rethrows other failures', async () => {
    const wrapped = withEmptyPlanOn404(apiStub({ fetchHome: vi.fn(async () => { throw new Error('Request failed with status 404'); }) }));
    const snapshot = await wrapped.fetchHome();
    expect(snapshot.plan.floors).toEqual([]);
    expect(snapshot.placements).toEqual([]);

    const broken = withEmptyPlanOn404(apiStub({ fetchHome: vi.fn(async () => { throw new Error('Request failed with status 503'); }) }));
    await expect(broken.fetchHome()).rejects.toThrow('503');

    expect(isNotFound(new Error('Request failed with status 404'))).toBe(true);
    expect(isNotFound(new Error('Request failed with status 4041'))).toBe(false);
    expect(isNotFound('404')).toBe(false);
  });
});
