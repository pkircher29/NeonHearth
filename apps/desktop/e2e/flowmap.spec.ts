// Assertions for the Pulse Flow Map: rendered beside the traffic scope, the Flow / Hearth choice, and the honest
// no-counters state. Adapted from the former screenshot harness; it writes no images.
import { test, expect, type Page } from '@playwright/test';
import { isolateApi, settled } from './fixtures/isolation';

const AT = '2026-01-01T00:00:00Z';
const MBPS = 125_000;
const TOKEN = '/#token=fixture-only-pulse-owner-0000000000000000000';

interface Spec { name: string; type?: string; cls?: string; state?: string; down?: number; up?: number; counters?: boolean }
const SPECS: Spec[] = [
  { name: 'Studio PC', type: 'desktop', down: 62, up: 6 },
  { name: 'Work laptop', type: 'laptop', down: 7, up: 2 },
  { name: 'NAS', type: 'nas', down: 3, up: 14 },
  { name: 'Mac mini', type: 'computer', down: 0, up: 0 },
  { name: 'Paul iPhone', type: 'phone', down: 9, up: 0.8 },
  { name: 'Old Galaxy', type: 'phone', state: 'offline', counters: true, down: 0, up: 0 },
  { name: 'Living room TV', type: 'tv', down: 26, up: 0.4 },
  { name: 'Kitchen speaker', type: 'speaker', down: 1.1, up: 0.05 },
  { name: 'Porch camera', cls: 'camera', down: 0.05, up: 2.2 },
  { name: 'Driveway camera', cls: 'camera', state: 'blocked', down: 0.1, up: 1.0 },
  { name: 'Nursery camera', cls: 'camera', counters: false },
  { name: 'Smart plug', type: 'plug', counters: false },
  { name: 'Unlabelled device', state: 'unknown', counters: false }
];

const idOf = (index: number) => `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`;

function snapshotDevice(spec: Spec, index: number) {
  return {
    device_id: idOf(index), first_seen_at: AT, last_seen_at: AT, owner_name: spec.name, owner_type: spec.type ?? null, owner_confirmed: true,
    presence: { state: spec.state ?? 'online', observed_at: AT, source: 'fixture', kind: 'test' }, evidence: null,
    identity: { available: Boolean(spec.cls), classification: spec.cls ?? null, confidence: spec.cls ? 0.8 : null },
    bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null }, policy: null
  };
}

async function install(page: Page, opts: { socket?: 'live' | 'never' | 'noframes'; devices?: boolean } = {}) {
  await isolateApi(page);
  const devices = opts.devices === false ? [] : SPECS.map(snapshotDevice);
  const frames = SPECS.map((spec, index) => ({ spec, index })).filter(({ spec }) => spec.counters !== false).map(({ spec, index }) => ({ id: idOf(index), down: spec.down ?? 0, up: spec.up ?? 0 }));
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', api_version: 'fixture' } }));
  await page.route('**/api/v1/state**', (route) => route.fulfill({ json: { sequence: 1, devices, next_after: null, service_status: 'ready' } }));
  await page.route('**/api/v1/events/ticket', (route) => route.fulfill({ json: { ticket: 'fixture-ticket', expires_in_seconds: 30 } }));
  await page.addInitScript(({ mode, frames, mbps }) => {
    class FixtureSocket {
      onopen?: () => void; onclose?: () => void; onerror?: () => void; onmessage?: (e: { data: string }) => void;
      timer: ReturnType<typeof setInterval> | null = null;
      constructor() {
        if (mode === 'never') return;
        setTimeout(() => this.onopen?.(), 0);
        if (mode === 'noframes') return;
        let seq = 2; let tick = 0;
        const emit = () => {
          const now = new Date().toISOString();
          const samples = frames.map((f: { id: string; down: number; up: number }, i: number) => {
            const wobble = 1 + 0.2 * Math.sin(tick * 0.7 + i * 1.3);
            const d = Math.max(0, f.down * mbps * wobble); const u = Math.max(0, f.up * mbps * wobble);
            return { device_id: f.id, delta: { upload: Math.round(u), download: Math.round(d) }, upload_bytes_per_second: Math.round(u), download_bytes_per_second: Math.round(d), coverage: 'complete' };
          });
          tick += 1;
          this.onmessage?.({ data: JSON.stringify({ type: 'event', data: { sequence: seq++, occurred_at: now, payload: { type: 'bandwidth_frame', data: { interval_ms: 1000, observed_at: now, emitted_at: now, samples } } } }) });
        };
        setTimeout(() => { emit(); this.timer = setInterval(emit, 1000); }, 50);
      }
      close() { if (this.timer) clearInterval(this.timer); this.onclose?.(); }
      send() {}
    }
    (window as unknown as { WebSocket: unknown }).WebSocket = FixtureSocket;
  }, { mode: opts.socket ?? 'live', frames, mbps: MBPS });
}

const noHorizontalScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);

test('with per-device counters the Flow Map sits beside the traffic scope and names its top talkers', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await install(page);
  await page.goto(TOKEN);
  const flow = page.getByRole('img', { name: /Network flow map:/ });
  await expect(flow).toHaveAttribute('aria-label', /Top talkers/, { timeout: 15000 });
  await expect(page.getByRole('heading', { name: 'Traffic scope' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Flow map' })).toBeVisible();
  await expect(page.getByRole('note')).toContainText('uses per-device counters');
  await expect(page.getByRole('complementary', { name: 'How to read the flow map' })).toBeVisible();
  await settled(page);
  expect(errors).toEqual([]);
});

test('the Flow / Hearth choice switches the visual, keeps the scope, and survives a reload', async ({ page }) => {
  await install(page);
  await page.goto(TOKEN);
  await expect(page.getByRole('img', { name: /Network flow map:/ })).toBeVisible({ timeout: 15000 });
  await expect(page.getByRole('button', { name: 'Flow' })).toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', { name: 'Hearth' }).click();
  await expect(page.getByRole('img', { name: /Network hearth:/ })).toBeVisible();
  await expect(page.getByRole('img', { name: /Network flow map:/ })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Traffic scope' })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('img', { name: /Network hearth:/ })).toBeVisible({ timeout: 15000 });
  await expect(page.getByRole('button', { name: 'Hearth' })).toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', { name: 'Flow' }).click();
  await expect(page.getByRole('img', { name: /Network flow map:/ })).toBeVisible();
});

test('without per-device counters the map says so and draws no flows', async ({ page }) => {
  await install(page, { socket: 'noframes' });
  await page.goto(TOKEN);
  await expect(page.getByText('No per-device counters', { exact: true })).toBeVisible({ timeout: 15000 });
  await expect(page.getByRole('note')).toContainText('Per-device traffic is unavailable');
  await expect(page.getByRole('note')).toContainText('Nothing is estimated or invented');
  await expect(page.getByRole('img', { name: /Network flow map:/ })).not.toHaveAttribute('aria-label', /Top talkers/);
  await expect(page.getByText('No per-device counter source', { exact: true })).toBeVisible();
  await expect(page.locator('body')).not.toContainText('Predator');
});

test('with no devices the map shows the empty state', async ({ page }) => {
  await install(page, { devices: false, socket: 'noframes' });
  await page.goto(TOKEN);
  await expect(page.getByText('No devices yet', { exact: true })).toBeVisible({ timeout: 15000 });
});

test('with the collector offline the map and note say it is unavailable', async ({ page }) => {
  await install(page, { socket: 'never' });
  await page.goto(TOKEN);
  await expect(page.getByRole('note')).toContainText('Per-device traffic is unavailable', { timeout: 15000 });
  await expect(page.getByRole('img', { name: /Network flow map:/ })).not.toHaveAttribute('aria-label', /Top talkers/);
});

test('the Pulse page does not scroll sideways at phone, tablet or desktop width', async ({ page }) => {
  await install(page);
  await page.goto(TOKEN);
  await expect(page.getByRole('img', { name: /Network flow map:/ })).toHaveAttribute('aria-label', /Top talkers/, { timeout: 15000 });
  for (const width of [320, 390, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await settled(page);
    expect(await noHorizontalScroll(page), `scrolls sideways at ${width}px`).toBe(true);
    await expect(page.getByRole('img', { name: /Network flow map:/ })).toBeVisible();
  }
});
