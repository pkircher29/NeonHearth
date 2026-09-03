// Throwaway: renders the Pulse view with a mocked live network and screenshots it.
// Not a test; deleted before merge.
import { chromium } from '@playwright/test';

const at = '2026-01-01T00:00:00Z';
function device(id: string, owner_name: string, presence: string, upload: number | null, download: number | null) {
  const available = upload !== null;
  return { device_id: id, first_seen_at: at, last_seen_at: at, owner_name, owner_type: null, owner_confirmed: true,
    presence: { state: presence, observed_at: at, source: 'fixture', kind: 'test' }, evidence: null,
    identity: { available: true, classification: 'guest', confidence: 0.8 },
    bandwidth: { available, upload, download, coverage: available ? 'complete' : null, observed_at: available ? at : null },
    policy: null };
}
const devices = [
  device('11111111-1111-4111-8111-111111111111', 'Living room TV', 'online', 120_000, 3_100_000),
  device('22222222-2222-4222-8222-222222222222', 'Paul laptop', 'online', 900_000, 1_400_000),
  device('33333333-3333-4333-8333-333333333333', 'Kitchen speaker', 'online', 8_000, 60_000),
  device('44444444-4444-4444-8444-444444444444', 'Den camera', 'online', 420_000, 4_000),
  device('55555555-5555-4555-8555-555555555555', 'Thermostat', 'quiet', 200, 900),
  device('66666666-6666-4666-8666-666666666666', 'Guest phone', 'blocked', null, null),
  device('77777777-7777-4777-8777-777777777777', 'Printer', 'offline', null, null),
  device('88888888-8888-4888-8888-888888888888', 'Old tablet', 'unknown', null, null)
];
const samples = devices.filter((d) => d.bandwidth.available).map((d) => ({ device_id: d.device_id, delta: { upload: 1, download: 1 }, upload_bytes_per_second: d.bandwidth.upload, download_bytes_per_second: d.bandwidth.download, coverage: 'complete' }));

const browser = await chromium.launch();
for (const [name, viewport] of [['desktop', { width: 1440, height: 1000 }], ['mobile', { width: 390, height: 844 }]] as const) {
  const page = await browser.newPage({ viewport, reducedMotion: 'no-preference' });
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', api_version: 'fixture' } }));
  await page.route('**/api/v1/state**', (route) => route.fulfill({ json: { sequence: 1, devices, next_after: null, service_status: 'ready' } }));
  await page.route('**/api/v1/events/ticket', (route) => route.fulfill({ json: { ticket: 'fixture-ticket', expires_in_seconds: 30 } }));
  const frames = Array.from({ length: 30 }, (_, i) => ({ at: new Date(Date.parse(at) + i * 1000).toISOString(), frame: { interval_ms: 1000, observed_at: at, emitted_at: at, samples: samples.map((s) => ({ ...s, download_bytes_per_second: Math.round(s.download_bytes_per_second! * (0.6 + 0.4 * Math.abs(Math.sin(i / 3)))) })) } }));
  await page.addInitScript(`(() => {
    const frames = ${JSON.stringify(frames)};
    class FixtureSocket {
      constructor() { setTimeout(() => { this.onopen && this.onopen(); let seq = 2; for (const f of frames) { const s = seq++; const msg = { type: 'event', data: { sequence: s, occurred_at: f.at, payload: { type: 'bandwidth_frame', data: f.frame } } }; setTimeout(() => this.onmessage && this.onmessage({ data: JSON.stringify(msg) }), 40 * s); } }, 0); }
      close() { this.onclose && this.onclose(); }
      send() {}
    }
    window.WebSocket = FixtureSocket;
  })();`);
  await page.goto('http://127.0.0.1:4173/');
  await page.waitForTimeout(2500);
  await page.screenshot({ path: `/tmp/claude-1000/-home-paul/9bc552c2-bf67-4d47-8052-e1d1454ef2f2/scratchpad/pulse-${name}.png`, fullPage: false });
  await page.close();
}
await browser.close();
