// Visual check of the Flow Map against a REAL running service. Skipped unless FLOW_REAL=1.
//
// Read-only by construction: the page's own API calls are intercepted, and only an allow-list of GET paths is
// forwarded to the live service (with the bearer token added here, in the test process, never in the browser and
// never logged). Every other request is answered locally. The event socket is a stub that just opens, so the page
// shows real devices, real MAC makers and this computer's real traffic, but no bandwidth frames.
//
//   FLOW_REAL=1 E2E_PORT=4183 npx playwright test --config=e2e/playwright.config.ts e2e/flowmap.live.spec.ts
//   NH_LIVE_CONNECTION=<path to connection.json {url, token}> is required: the file scripts/run-local.py writes.
import { test, expect, type Page } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { settled } from './fixtures/isolation';

const OUT = resolve(process.cwd(), '../../output/flow-map');
const CONNECTION = process.env.NH_LIVE_CONNECTION ?? '';
const ALLOW = [/^\/api\/v1\/health$/, /^\/api\/v1\/state$/, /^\/api\/v1\/automation\/network$/, /^\/api\/v1\/host\/snapshot$/];

async function installLive(page: Page) {
  const { url, token } = JSON.parse(readFileSync(CONNECTION, 'utf8')) as { url: string; token: string };
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request();
    const target = new URL(request.url());
    if (request.url().endsWith('/api/v1/events/ticket')) return route.fulfill({ json: { ticket: 'local-stub-ticket', expires_in_seconds: 30 } });
    if (request.method() !== 'GET' || !ALLOW.some((rule) => rule.test(target.pathname))) return route.fulfill({ status: 503, json: { error: 'not forwarded by the read-only harness' } });
    const response = await fetch(`${url}${target.pathname}${target.search}`, { method: 'GET', headers: { Authorization: `Bearer ${token}` } });
    return route.fulfill({ status: response.status, contentType: 'application/json', body: await response.text() });
  });
  // The page treats a silent socket as stale after 20 s, so the stub sends a harmless service_status heartbeat
  // every 4 s, numbered after the live snapshot's sequence. It carries no device or bandwidth data.
  const snapshot = await fetch(`${url}/api/v1/state`, { method: 'GET', headers: { Authorization: `Bearer ${token}` } });
  const sequence = ((await snapshot.json()) as { sequence: number }).sequence;
  await page.addInitScript((startSequence: number) => {
    class StubSocket {
      onopen?: () => void; onclose?: () => void; onerror?: () => void; onmessage?: (e: { data: string }) => void;
      timer: ReturnType<typeof setInterval> | null = null;
      constructor() {
        setTimeout(() => this.onopen?.(), 0);
        let seq = startSequence + 1;
        this.timer = setInterval(() => {
          const now = new Date().toISOString();
          this.onmessage?.({ data: JSON.stringify({ type: 'event', data: { sequence: seq++, occurred_at: now, payload: { type: 'service_status', data: { state: 'ready', detail: 'harness heartbeat' } } } }) });
        }, 4000);
        setTimeout(() => this.onmessage?.({ data: JSON.stringify({ type: 'event', data: { sequence: seq++, occurred_at: new Date().toISOString(), payload: { type: 'service_status', data: { state: 'ready', detail: 'harness heartbeat' } } } }) }), 100);
      }
      close() { if (this.timer) clearInterval(this.timer); this.onclose?.(); }
      send() {}
    }
    (window as unknown as { WebSocket: unknown }).WebSocket = StubSocket;
  }, sequence);
}

async function shoot(page: Page, name: string) {
  mkdirSync(OUT, { recursive: true });
  await page.locator('.hearth-panel').screenshot({ path: resolve(OUT, `${name}.png`) });
}

test.describe('flow map against the live service', () => {
  test.skip(!process.env.FLOW_REAL || !CONNECTION, 'set FLOW_REAL=1 and NH_LIVE_CONNECTION to run against the live service');

  test('live motion, frame time, paused, mobile', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'no-preference', deviceScaleFactor: 1 });
    const page = await context.newPage();
    const errors: string[] = []; page.on('pageerror', (e) => errors.push(e.message));
    await page.addInitScript(() => {
      const w = window as unknown as { __cb: number[]; __on: boolean };
      w.__cb = []; w.__on = false;
      const raf = window.requestAnimationFrame.bind(window);
      window.requestAnimationFrame = (cb) => raf((t) => { const s = performance.now(); cb(t); if (w.__on) w.__cb.push(performance.now() - s); });
    });
    await installLive(page);
    await page.goto('/#token=fixture-only-pulse-owner-0000000000000000000');
    const flow = page.getByRole('img', { name: /Network flow map/ });
    await expect(flow).toHaveAttribute('aria-label', /showing this computer only/, { timeout: 45000 });
    await settled(page);
    const label = (await flow.getAttribute('aria-label')) ?? '';
    console.log('REAL_ARIA', label.slice(0, 400));
    console.log('REAL_GROUPS', await page.evaluate(() => document.querySelector('canvas') ? 'canvas-ok' : 'no-canvas'));
    await shoot(page, '09-real-live');
    await page.evaluate(() => { (window as unknown as { __on: boolean }).__on = true; });
    const stats = await page.evaluate(() => new Promise<{ frames: number; avg: number; worst: number; p95: number; paintAvg: number; paintMax: number }>((resolveStats) => {
      const deltas: number[] = []; let last = 0; const start = performance.now();
      const tick = (now: number) => {
        if (last) deltas.push(now - last);
        last = now;
        if (now - start < 10000) requestAnimationFrame(tick);
        else {
          const sorted = [...deltas].sort((a, b) => a - b);
          const cb = (window as unknown as { __cb: number[] }).__cb;
          resolveStats({ paintAvg: cb.reduce((a, b) => a + b, 0) / Math.max(1, cb.length), paintMax: Math.max(...cb), frames: deltas.length, avg: deltas.reduce((a, b) => a + b, 0) / deltas.length, worst: sorted[sorted.length - 1]!, p95: sorted[Math.floor(sorted.length * 0.95)]! });
        }
      };
      requestAnimationFrame(tick);
    }));
    console.log('REAL_FRAME_STATS', JSON.stringify(stats));
    await page.getByRole('button', { name: /Pause decorative animation/ }).click();
    await settled(page);
    await shoot(page, '10-real-paused');
    expect(errors).toEqual([]);
    await context.close();

    const phone = await browser.newContext({ viewport: { width: 390, height: 844 }, reducedMotion: 'no-preference', deviceScaleFactor: 2, isMobile: true, hasTouch: true });
    const mobile = await phone.newPage();
    await installLive(mobile);
    await mobile.goto('/#token=fixture-only-pulse-owner-0000000000000000000');
    await expect(mobile.getByRole('img', { name: /Network flow map/ })).toHaveAttribute('aria-label', /showing this computer only/, { timeout: 45000 });
    await settled(mobile);
    await shoot(mobile, '11-real-mobile');
    expect(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await phone.close();
  });
});
