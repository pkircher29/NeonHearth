// Route-mock installer for the Home tab e2e proof (M5 gate).
// Playwright route handlers stand in for the lattice-service Home API described in
// docs/architecture/m5-home-twin-contracts.md. State lives in an in-memory object in
// the test process so committed saves and placements persist across page.reload().
import type { Page } from '@playwright/test';
import type { Estimate, HomeDraft, HomePlan, Placement } from '../../src/lib/stores/home';

export const HOME_ID = '99999999-9999-4999-8999-999999999999';
export const GROUND_ID = 'f1000000-0000-4000-8000-000000000001';
export const UPPER_ID = 'f2000000-0000-4000-8000-000000000002';
export const ATTIC_ID = 'f3000000-0000-4000-8000-000000000003';
export const CAMERA_DEVICE_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
export const SPEAKER_DEVICE_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
export const CAMERA_DEVICE_NAME = 'Den camera';
export const SPEAKER_DEVICE_NAME = 'Wandering speaker';

const AT = '2026-01-01T00:00:00Z';

// Same DeviceSnapshot wire shape guard.spec.ts uses; it must pass the client's validators.
function liveDevice(device_id: string, owner_name: string) {
  return {
    device_id, first_seen_at: AT, last_seen_at: AT, owner_name, owner_type: null, owner_confirmed: false,
    presence: { state: 'online', observed_at: AT, source: 'fixture', kind: 'test' }, evidence: null,
    identity: { available: true, classification: 'guest', confidence: 0.8 },
    bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null },
    policy: {
      owner_decision: 'pending', protection: 'none',
      evaluation: { policy_version: 1, reason: 'pending_confirmation', requested_action: 'none', warning: null, deadline: null },
      enforcement_result: 'not_requested', undo_available: false, delivery_pending: true
    }
  };
}

const wall = (wall_id: string, x1: number, y1: number, x2: number, y2: number) =>
  ({ wall_id, start: { x: x1, y: y1 }, end: { x: x2, y: y2 }, openings: [] });

/** One ground floor, nothing drawn yet — the canvas the owner draws on. */
export function basePlan(): HomePlan {
  return {
    home_id: HOME_ID, version: 0, name: 'Home',
    floors: [{ floor_id: GROUND_ID, level: 0, name: 'Ground', ceiling_height_m: 2.4, walls: [], rooms: [] }]
  };
}

/** A committed two-floor home with geometry, used to exercise the 3D twin directly. */
export function seededTwinPlan(): HomePlan {
  return {
    home_id: HOME_ID, version: 3, name: 'Home',
    floors: [
      {
        floor_id: GROUND_ID, level: 0, name: 'Ground', ceiling_height_m: 2.4,
        walls: [
          wall('dddddddd-dddd-4ddd-8ddd-000000000001', 0, 0, 6, 0),
          wall('dddddddd-dddd-4ddd-8ddd-000000000002', 6, 0, 6, 4),
          wall('dddddddd-dddd-4ddd-8ddd-000000000003', 6, 4, 0, 4),
          wall('dddddddd-dddd-4ddd-8ddd-000000000004', 0, 4, 0, 0)
        ],
        rooms: [{
          room_id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', name: 'Den',
          polygon: [{ x: 0.5, y: 0.5 }, { x: 3, y: 0.5 }, { x: 3, y: 3 }, { x: 0.5, y: 3 }]
        }]
      },
      {
        floor_id: UPPER_ID, level: 1, name: 'Upstairs', ceiling_height_m: 2.4,
        walls: [
          wall('dddddddd-dddd-4ddd-8ddd-000000000005', 0, 0, 6, 0),
          wall('dddddddd-dddd-4ddd-8ddd-000000000006', 0, 0, 0, 4)
        ],
        rooms: []
      }
    ]
  };
}

/** An owner-confirmed camera placement on the ground floor of the seeded plan. */
export function seededCameraPlacement(): Placement {
  return {
    placement_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', device_id: CAMERA_DEVICE_ID,
    floor_id: GROUND_ID, x: 2, y: 2, height_m: 1.0, mounting: null
  };
}

/** A low-confidence (< 0.6) advisory estimate for the speaker — never authoritative. */
export function speakerEstimate(): Estimate {
  return {
    device_id: SPEAKER_DEVICE_ID, floor_id: GROUND_ID, room_id: null,
    confidence: 0.45, evidence: ['w6-rssi'], estimated_at: AT
  };
}

/** A stored server-side draft: the base plan plus an Attic floor with one wall. */
export function atticDraft(): HomeDraft {
  const plan = basePlan();
  plan.floors.push({
    floor_id: ATTIC_ID, level: 1, name: 'Attic', ceiling_height_m: 2.0,
    walls: [wall('dddddddd-dddd-4ddd-8ddd-000000000007', 1, 1, 4, 1)], rooms: []
  });
  return { plan, saved_at: '2026-02-02T10:00:00Z' };
}

export interface HomeServerOptions {
  plan?: HomePlan;
  placements?: Placement[];
  estimates?: Estimate[];
  draft?: HomeDraft | null;
  conflictOnPlanSave?: boolean;
}

export interface HomeServer {
  plan: HomePlan;
  placements: Map<string, Placement>;
  estimates: Estimate[];
  draft: HomeDraft | null;
  conflictOnPlanSave: boolean;
  /** Every PUT /api/v1/home/plan body, in order. */
  planPuts: Array<{ expected_version: number; plan: HomePlan }>;
  /** Every PUT /api/v1/home/placements/{device_id} body, in order. */
  placementPuts: Placement[];
  placementDeletes: string[];
}

/**
 * Installs the app-level fixtures (health/state/ticket + WebSocket stub, mirroring
 * guard.spec.ts) plus a stateful fake of the Home API. Returns the server object so
 * tests can assert on captured requests and mutate behavior (e.g. clear a conflict).
 */
export async function installHomeFixture(page: Page, options: HomeServerOptions = {}): Promise<HomeServer> {
  const server: HomeServer = {
    plan: options.plan ?? basePlan(),
    placements: new Map((options.placements ?? []).map((placement) => [placement.device_id, placement])),
    estimates: options.estimates ?? [],
    draft: options.draft ?? null,
    conflictOnPlanSave: options.conflictOnPlanSave ?? false,
    planPuts: [],
    placementPuts: [],
    placementDeletes: []
  };

  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', api_version: 'fixture' } }));
  await page.route('**/api/v1/state**', (route) => route.fulfill({
    json: {
      sequence: 1,
      devices: [liveDevice(CAMERA_DEVICE_ID, CAMERA_DEVICE_NAME), liveDevice(SPEAKER_DEVICE_ID, SPEAKER_DEVICE_NAME)],
      next_after: null, service_status: 'ready'
    }
  }));
  await page.route('**/api/v1/events/ticket', (route) => route.fulfill({ json: { ticket: 'fixture-ticket', expires_in_seconds: 30 } }));

  await page.route('**/api/v1/home', (route) => route.fulfill({
    json: { plan: server.plan, placements: [...server.placements.values()], estimates: server.estimates }
  }));

  await page.route('**/api/v1/home/plan', (route) => {
    const body = route.request().postDataJSON() as { expected_version: number; plan: HomePlan };
    server.planPuts.push(body);
    if (server.conflictOnPlanSave) return route.fulfill({ status: 409, json: { error: 'version_conflict' } });
    const version = body.expected_version + 1;
    server.plan = { ...body.plan, version };
    return route.fulfill({ json: { version } });
  });

  await page.route('**/api/v1/home/draft', (route) => {
    const method = route.request().method();
    if (method === 'GET') {
      return server.draft
        ? route.fulfill({ json: server.draft })
        : route.fulfill({ status: 404, json: { error: 'not_found' } });
    }
    if (method === 'PUT') {
      server.draft = route.request().postDataJSON() as HomeDraft;
      return route.fulfill({ status: 204 });
    }
    server.draft = null;
    return route.fulfill({ status: 204 });
  });

  await page.route('**/api/v1/home/placements/*', (route) => {
    const method = route.request().method();
    const deviceId = new URL(route.request().url()).pathname.split('/').at(-1) ?? '';
    if (method === 'PUT') {
      const placement = route.request().postDataJSON() as Placement;
      server.placements.set(placement.device_id, placement);
      server.placementPuts.push(placement);
      return route.fulfill({ json: {} });
    }
    server.placements.delete(deviceId);
    server.placementDeletes.push(deviceId);
    return route.fulfill({ status: 204 });
  });

  // The app opens a live WebSocket after fetching state; a stub that just opens is enough here.
  await page.addInitScript(() => {
    class FixtureSocket {
      onopen?: () => void; onclose?: () => void; onerror?: () => void; onmessage?: (e: { data: string }) => void;
      constructor() { setTimeout(() => this.onopen?.(), 0); }
      close() { this.onclose?.(); }
      send() {}
    }
    (window as unknown as { WebSocket: unknown }).WebSocket = FixtureSocket;
  });

  return server;
}
