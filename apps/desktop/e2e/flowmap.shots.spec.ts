// Visual review harness for the Pulse Flow Map. Skipped unless FLOW_SHOTS=1.
// Renders Pulse against a rich fake home (28 devices in 7 groups, a few heavy talkers, one blocked,
// some offline, some without counters) and saves PNGs to <repo>/output/flow-map/.
//   FLOW_SHOTS=1 E2E_PORT=4183 npx playwright test --config=e2e/playwright.config.ts e2e/flowmap.shots.spec.ts
import { test, expect, type Page } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

const OUT = resolve(process.cwd(), '../../output/flow-map');
const AT = '2026-01-01T00:00:00Z';
const MBPS = 125_000;

interface Spec { name: string; type?: string; cls?: string; state?: string; down?: number; up?: number; counters?: boolean }
const SPECS: Spec[] = [
  { name: 'Studio PC', type: 'desktop', down: 62, up: 6 },
  { name: 'Work laptop', type: 'laptop', down: 7, up: 2 },
  { name: 'Kids laptop', type: 'laptop', down: 1.4, up: 0.2 },
  { name: 'NAS', type: 'nas', down: 3, up: 14 },
  { name: 'Mac mini', type: 'computer', down: 0, up: 0 },
  { name: 'Paul iPhone', type: 'phone', down: 9, up: 0.8 },
  { name: 'Sam Pixel', type: 'phone', down: 0.3, up: 0.05 },
  { name: 'Family iPad', type: 'tablet', down: 0.02, up: 0 },
  { name: 'Old Galaxy', type: 'phone', state: 'offline', counters: true, down: 0, up: 0 },
  { name: 'Visitor phone', type: 'phone', state: 'offline', counters: true, down: 0, up: 0 },
  { name: 'Living room TV', type: 'tv', down: 26, up: 0.4 },
  { name: 'Bedroom TV', type: 'tv', down: 4.5, up: 0.1 },
  { name: 'Kitchen speaker', type: 'speaker', down: 1.1, up: 0.05 },
  { name: 'PS5', type: 'console', state: 'quiet', down: 0.01, up: 0 },
  { name: 'Chromecast', type: 'media', down: 0, up: 0 },
  { name: 'Porch camera', cls: 'camera', down: 0.05, up: 2.2 },
  { name: 'Garage camera', cls: 'camera', down: 0.05, up: 2.0 },
  { name: 'Driveway camera', cls: 'camera', state: 'blocked', down: 0.1, up: 1.0 },
  { name: 'Nursery camera', cls: 'camera', counters: false },
  { name: 'Thermostat', type: 'thermostat', down: 0.01, up: 0.01 },
  { name: 'Hue bridge', type: 'hub', down: 0.02, up: 0.01 },
  { name: 'Smart plug', type: 'plug', counters: false },
  { name: 'Printer', type: 'printer', down: 0, up: 0 },
  { name: 'Mesh node hall', cls: 'access point', down: 0.4, up: 0.4 },
  { name: 'Mesh node loft', cls: 'access point', down: 0.2, up: 0.2 },
  { name: 'Guest laptop', cls: 'guest', down: 5, up: 0.6 },
  { name: 'Guest tablet', cls: 'guest', down: 0.8, up: 0.1 },
  { name: 'Unlabelled device', state: 'unknown', counters: false },
  { name: 'Mystery gadget', down: 0.03, up: 0.01 }
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

/** 150 devices: the 28 above plus generated phones, IoT, media and a few busy ones. */
function bigSpecs(): Spec[] {
  const out: Spec[] = [...SPECS];
  const kinds: Array<Pick<Spec, 'type' | 'cls'>> = [{ type: 'phone' }, { type: 'bulb' }, { type: 'tv' }, { cls: 'camera' }, { type: 'laptop' }, { type: 'sensor' }, { cls: 'guest' }, {}];
  for (let i = out.length; i < 150; i += 1) {
    const kind = kinds[i % kinds.length]!;
    const busy = i % 17 === 0;
    out.push({ name: `Device ${i}`, ...kind, state: i % 9 === 0 ? 'offline' : i % 13 === 0 ? 'quiet' : 'online', counters: i % 10 !== 0, down: busy ? 3 + (i % 5) * 3 : (i % 4) * 0.05, up: busy ? 0.5 : (i % 3) * 0.01 });
  }
  return out;
}

/**
 * A "real-shaped" home as a stock install sees it without the router feed: 89 devices, no owner names, no types,
 * no counters, presence quiet, MAC makers as in the live inventory; plus a host snapshot whose connection bytes grow.
 */
const MAKERS: Array<[string | null, string, number]> = [
  ['Espressif Inc.', 'assigned', 25], ['WiZ', 'assigned', 6], ['Proxmox Server Solutions GmbH', 'assigned', 6], ['Amazon Technologies Inc.', 'assigned', 5],
  ['Tuya Smart Inc.', 'assigned', 4], ['FLIR Systems', 'assigned', 3], ['Shenzhen Jixian Technology Co., Ltd.', 'assigned', 3], [null, 'unknown', 3],
  ['Wyze Labs Inc', 'assigned', 2], ['Raspberry Pi (Trading) Ltd', 'assigned', 2], ['Google, Inc.', 'assigned', 2], ['Sichuan AI-Link Technology Co., Ltd.', 'assigned', 2],
  ['Lumi United Technology Co., Ltd', 'assigned', 2], [null, 'locally_administered', 2], ['NVIDIA', 'assigned', 1], ['GIGA-BYTE TECHNOLOGY CO.,LTD.', 'assigned', 1],
  ['GD Midea Air-Conditioning Equipment Co.,Ltd.', 'assigned', 1], ['Blink by Amazon', 'assigned', 1], ['TP-Link Systems Inc.', 'assigned', 2], ['Hewlett Packard', 'assigned', 1],
  ['Sony Home Entertainment&Sound Products Inc', 'assigned', 1], ['Hangzhou Hikvision Digital Technology Co.,Ltd.', 'assigned', 1], ['Acer Inc.', 'assigned', 1],
  ['Microsoft Corporation', 'assigned', 1], ['Dell Inc.', 'assigned', 1], ['Ubiquiti Inc', 'assigned', 1], ['Liteon Technology Corporation', 'assigned', 1], ['Camille Bauer', 'assigned', 1]
];
function realShape() {
  const rows: Array<{ id: string; org: string | null; status: string; ip: string }> = [];
  for (const [org, status, count] of MAKERS) for (let i = 0; i < count; i += 1) {
    const n = rows.length;
    rows.push({ id: `01a1dfa1-02d7-7a11-9f34-${String(n + 1).padStart(12, '0')}`, org, status, ip: `192.168.1.${100 + n}` });
  }
  return rows;
}
async function installRealShaped(page: Page) {
  const rows = realShape();
  const devices = rows.map((r, i) => ({
    device_id: r.id, first_seen_at: AT, last_seen_at: AT, owner_name: null, owner_type: null, owner_confirmed: false,
    presence: { state: i === 40 ? 'offline' : 'quiet', observed_at: AT, source: 'neighbor-interface-21', kind: 'neighbor_cache' }, evidence: null,
    identity: { available: false, classification: null, confidence: null }, bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null }, policy: null
  }));
  await page.route('**/api/v1/**', (route) => route.fulfill({ status: 503, json: { error: 'fixture unavailable' } }));
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', api_version: 'fixture' } }));
  await page.route('**/api/v1/state**', (route) => route.fulfill({ json: { sequence: 1, devices, next_after: null, service_status: 'ready' } }));
  await page.route('**/api/v1/events/ticket', (route) => route.fulfill({ json: { ticket: 'fixture-ticket', expires_in_seconds: 30 } }));
  await page.route('**/api/v1/network/monitor?*', (route) => route.fulfill({ status: 503, json: { error: 'fixture' } }));
  await page.route('**/api/v1/automation/network', (route) => route.fulfill({ json: {
    status: 'ready', observed_at: AT,
    devices: rows.map((r) => ({ device_id: r.id, mac_addresses: ['00:00:00:00:00:01'], ip_addresses: [r.ip], home_assistant: null, mac_assignments: [{ mac_address: '00:00:00:00:00:01', organization: r.org, registry: r.org ? 'MA-L' : null, status: r.status }] }))
  } }));
  let calls = 0;
  const apps = [['chrome.exe', 420_000, 60_000], ['node.exe', 90_000, 1_800_000], ['Teams.exe', 260_000, 190_000], ['svchost.exe', 5_000, 25_000], ['OneDrive.exe', 700_000, 12_000], ['code.exe', 22_000, 8_000], ['steam.exe', 3_000, 520_000]] as const;
  await page.route('**/api/v1/host/snapshot', (route) => {
    calls += 1;
    const now = Date.now();
    const wob = 1 + 0.3 * Math.sin(calls * 0.9);
    route.fulfill({ json: {
      observed_at: new Date(now).toISOString(), status: 'ready', detail: 'This computer only. Physical-interface bytes include all protocols.', interfaces: [],
      applications: apps.map((a, i) => ({ app_id: `app-${i}`, name: a[0], executable: null, pid: 100 + i, started: AT, cpu_time_ms: null, memory_bytes: null })),
      connections: apps.flatMap((a, i) => [0, 1].map((k) => ({ connection_id: `c-${i}-${k}`, app_id: `app-${i}`, pid: 100 + i, protocol: 'tcp', local_address: '192.168.1.2', local_port: 50000 + i * 2 + k, remote_address: '203.0.113.9', remote_port: 443, state: 'established', sent_bytes: k === 1 && i === 3 ? null : Math.round(a[1] * wob * calls * 2.5 / 2), received_bytes: k === 1 && i === 3 ? null : Math.round(a[2] * wob * calls * 2.5 / 2) }))),
      upload_bytes_per_second: 1_641_975 * wob, download_bytes_per_second: 2_100_000 * wob + 45_994, last_interval_ms: 2000, app_counters: 'sampled_tcp', firewall_available: false, memory_total_bytes: null, memory_available_bytes: null
    } });
  });
  await page.addInitScript(() => {
    class FixtureSocket {
      onopen?: () => void; onclose?: () => void; onerror?: () => void; onmessage?: (e: { data: string }) => void;
      constructor() { setTimeout(() => this.onopen?.(), 0); }
      close() { this.onclose?.(); }
      send() {}
    }
    (window as unknown as { WebSocket: unknown }).WebSocket = FixtureSocket;
  });
}

async function install(page: Page, opts: { devices?: boolean; socket?: 'live' | 'never' | 'noframes'; specs?: Spec[] } = {}) {
  const SPECS_ = opts.specs ?? SPECS;
  const devices = opts.devices === false ? [] : SPECS_.map(snapshotDevice);
  const frameSpecs = SPECS_.map((spec, index) => ({ spec, index })).filter(({ spec }) => spec.counters !== false);
  await page.route('**/api/v1/**', (route) => route.fulfill({ status: 503, json: { error: 'fixture unavailable' } }));
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', api_version: 'fixture' } }));
  await page.route('**/api/v1/state**', (route) => route.fulfill({ json: { sequence: 1, devices, next_after: null, service_status: 'ready' } }));
  await page.route('**/api/v1/events/ticket', (route) => route.fulfill({ json: { ticket: 'fixture-ticket', expires_in_seconds: 30 } }));
  await page.route('**/api/v1/network/monitor?*', (route) => route.fulfill({ status: 503, json: { error: 'fixture' } }));
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
            const wobble = 1 + 0.22 * Math.sin(tick * 0.7 + i * 1.3) + 0.08 * Math.sin(tick * 2.1 + i);
            const spike = f.id.endsWith('01') && tick % 11 > 7 ? 1.5 : 1;
            const d = Math.max(0, f.down * mbps * wobble * spike); const u = Math.max(0, f.up * mbps * wobble);
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
  }, { mode: opts.socket ?? 'live', frames: frameSpecs.map(({ spec, index }) => ({ id: idOf(index), down: spec.down ?? 0, up: spec.up ?? 0 })), mbps: MBPS });
}

async function shoot(page: Page, name: string, full = false) {
  mkdirSync(OUT, { recursive: true });
  const panel = page.locator('.hearth-panel');
  await panel.screenshot({ path: resolve(OUT, `${name}.png`) });
  if (full) await page.screenshot({ path: resolve(OUT, `${name}-page.png`), fullPage: true });
}

test.describe('flow map visual review', () => {
  test.skip(!process.env.FLOW_SHOTS, 'set FLOW_SHOTS=1 to render review screenshots');

  test('live with motion', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'no-preference', deviceScaleFactor: 1 });
    const page = await context.newPage();
    const errors: string[] = []; page.on('pageerror', (e) => errors.push(e.message));
    await install(page);
    await page.goto('/#token=fixture-only-pulse-owner-0000000000000000000');
    await expect(page.getByRole('img', { name: /Network flow map:/ })).toHaveAttribute('aria-label', /Top talkers/, { timeout: 15000 });
    await page.waitForTimeout(9000);
    await shoot(page, '01-live', true);
    await page.waitForTimeout(700);
    await shoot(page, '01-live-b');
    await page.getByRole('button', { name: 'Hearth' }).click();
    await page.waitForTimeout(1200);
    await shoot(page, '07-hearth-comparison');
    expect(errors).toEqual([]);
    await context.close();
  });

  test('paused / reduced motion', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
    const page = await context.newPage();
    await install(page);
    await page.goto('/#token=fixture-only-pulse-owner-0000000000000000000');
    await expect(page.getByRole('img', { name: /Network flow map:/ })).toHaveAttribute('aria-label', /Top talkers/, { timeout: 15000 });
    await page.waitForTimeout(6000);
    await shoot(page, '02-paused-reduced');
    await context.close();
  });

  test('disconnected collector', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'no-preference' });
    const page = await context.newPage();
    await install(page, { socket: 'never' });
    await page.goto('/#token=fixture-only-pulse-owner-0000000000000000000');
    await expect(page.getByText('Collector offline', { exact: true })).toBeVisible({ timeout: 15000 });
    await page.waitForTimeout(1500);
    await shoot(page, '03-disconnected');
    await context.close();
  });

  test('empty network', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'no-preference' });
    const page = await context.newPage();
    await install(page, { devices: false, socket: 'noframes' });
    await page.goto('/#token=fixture-only-pulse-owner-0000000000000000000');
    await expect(page.getByText('No devices yet', { exact: true })).toBeVisible({ timeout: 15000 });
    await page.waitForTimeout(1200);
    await shoot(page, '04-empty');
    await context.close();
  });

  test('missing counters', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'no-preference' });
    const page = await context.newPage();
    await install(page, { socket: 'noframes' });
    await page.goto('/#token=fixture-only-pulse-owner-0000000000000000000');
    await expect(page.getByText('No per-device counters', { exact: true })).toBeVisible({ timeout: 15000 });
    await page.waitForTimeout(1200);
    await shoot(page, '05-no-counters');
    await context.close();
  });

  test('150 devices: frame time and readability', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'no-preference', deviceScaleFactor: 1 });
    const page = await context.newPage();
    await install(page, { specs: bigSpecs() });
    // Time every rAF callback (the component's whole paint) so CPU cost is visible even when vsync caps frame deltas.
    await page.addInitScript(() => {
      const w = window as unknown as { __cb: number[]; __on: boolean };
      w.__cb = []; w.__on = false;
      const raf = window.requestAnimationFrame.bind(window);
      window.requestAnimationFrame = (cb) => raf((t) => { const s = performance.now(); cb(t); if (w.__on) w.__cb.push(performance.now() - s); });
    });
    await page.goto('/#token=fixture-only-pulse-owner-0000000000000000000');
    await expect(page.getByRole('img', { name: /Network flow map:/ })).toHaveAttribute('aria-label', /Top talkers/, { timeout: 15000 });
    await page.waitForTimeout(4000);
    await page.evaluate(() => { (window as unknown as { __on: boolean }).__on = true; });
    const stats = await page.evaluate(() => new Promise<{ frames: number; avg: number; worst: number; p95: number; paintAvg: number; paintMax: number }>((resolveStats) => {
      const deltas: number[] = []; let last = 0; const start = performance.now();
      const tick = (now: number) => {
        if (last) deltas.push(now - last);
        last = now;
        if (now - start < 10000) requestAnimationFrame(tick);
        else { const sorted = [...deltas].sort((a, b) => a - b); const cb = (window as unknown as { __cb: number[] }).__cb; resolveStats({ paintAvg: cb.reduce((a, b) => a + b, 0) / Math.max(1, cb.length), paintMax: Math.max(...cb), frames: deltas.length, avg: deltas.reduce((a, b) => a + b, 0) / deltas.length, worst: sorted[sorted.length - 1]!, p95: sorted[Math.floor(sorted.length * 0.95)]! }); }
      };
      requestAnimationFrame(tick);
    }));
    console.log('FRAME_STATS_150', JSON.stringify(stats));
    await shoot(page, '08-150-devices');
    expect(stats.frames).toBeGreaterThan(100);
    await context.close();
  });

  test('real-shaped: 89 unnamed devices, no counters, host traffic fallback', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'no-preference', deviceScaleFactor: 1 });
    const page = await context.newPage();
    const errors: string[] = []; page.on('pageerror', (e) => errors.push(e.message));
    await installRealShaped(page);
    await page.goto('/#token=fixture-only-pulse-owner-0000000000000000000');
    await expect(page.getByRole('img', { name: /showing this computer only/ })).toHaveAttribute('aria-label', /Top applications/, { timeout: 30000 });
    await page.waitForTimeout(12000);
    await shoot(page, '09-real-shaped-live');
    expect(errors).toEqual([]);
    await context.close();
  });

  test('narrow mobile width', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 390, height: 844 }, reducedMotion: 'no-preference', deviceScaleFactor: 2, isMobile: true, hasTouch: true });
    const page = await context.newPage();
    await install(page);
    await page.goto('/#token=fixture-only-pulse-owner-0000000000000000000');
    await expect(page.getByRole('img', { name: /Network flow map:/ })).toHaveAttribute('aria-label', /Top talkers/, { timeout: 15000 });
    await page.waitForTimeout(7000);
    await shoot(page, '06-mobile', true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await context.close();
  });
});
