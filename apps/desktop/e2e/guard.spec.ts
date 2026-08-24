import { test, expect, type Page } from '@playwright/test';

const id = '11111111-1111-4111-8111-111111111111';
const at = '2026-01-01T00:00:00Z';
const device = { device_id: id, first_seen_at: at, last_seen_at: at, owner_name: 'Test guest', owner_type: null, owner_confirmed: false,
  presence: { state: 'online', observed_at: at, source: 'fixture', kind: 'test' }, evidence: null,
  identity: { available: true, classification: 'guest', confidence: 0.8 }, bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null },
  policy: { owner_decision: 'pending', protection: 'none', evaluation: { policy_version: 1, reason: 'pending_confirmation', requested_action: 'none', warning: null, deadline: null }, enforcement_result: 'not_requested', undo_available: false, delivery_pending: true } };
const update = { device_id: id, policy_version: 2, evaluation: { policy_version: 2, reason: 'owner_rejected', requested_action: 'permanent_ban', warning: null, deadline: null }, requested_action: 'permanent_ban', evidence_summary: 'typed test policy update', enforcement_result: 'verified', undo_available: false };

async function installFixture(page: Page) {
  await page.route('**/api/v1/health', route => route.fulfill({ json: { status: 'ok', api_version: 'fixture' } }));
  await page.route('**/api/v1/state**', route => route.fulfill({ json: { sequence: 1, devices: [device], next_after: null, service_status: 'ready' } }));
  await page.route('**/api/v1/events/ticket', route => route.fulfill({ json: { ticket: 'fixture-ticket', expires_in_seconds: 30 } }));
  await page.addInitScript(({ event }) => {
    class FixtureSocket {
      onopen?: () => void; onclose?: () => void; onerror?: () => void; onmessage?: (e: { data: string }) => void;
      constructor() { setTimeout(() => this.onopen?.(), 0); setTimeout(() => this.onmessage?.({ data: JSON.stringify(event) }), 120); }
      close() { this.onclose?.(); }
      send() { setTimeout(() => this.onmessage?.({ data: JSON.stringify(event) }), 80); }
    }
    // The app's ticketed WebSocket sends the subscription cursor through send().
    (window as unknown as { WebSocket: unknown }).WebSocket = FixtureSocket;
  }, { event: { type: 'event', data: { sequence: 2, occurred_at: at, payload: { type: 'policy_changed', data: update } } } });
}

test('desktop Guard shows pending policy, live typed update, and remount lifecycle', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await installFixture(page);
  await page.goto('/');
  await page.getByRole('button', { name: 'Guard' }).first().click();
  await expect(page.getByText('Test guest')).toBeVisible();
  await expect(page.getByText('delivery pending')).toBeVisible();
  await expect(page.getByText('Permanent ban', { exact: true })).toBeVisible();
  await expect(page.locator('.enforcement')).toContainText('verified');
  await expect(page.getByText('Guard: owner rejected')).toBeVisible();
  await page.getByRole('button', { name: 'Pulse' }).first().click();
  await page.getByRole('button', { name: 'Guard' }).first().click();
  await expect(page.locator('.policy-card')).toHaveCount(1);
  await expect(page.locator('.policy-card')).toHaveAttribute('data-lifecycle-key', /\|2\|permanent_ban\|verified/);
  await expect(page.locator('.guard-orbit')).toHaveCSS('animation-name', 'none');
});

test('phone More menu opens Guard', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await installFixture(page);
  await page.goto('/');
  await page.getByRole('button', { name: 'More' }).click();
  await page.getByRole('button', { name: 'Guard' }).last().click();
  await expect(page.locator('#guard-heading')).toBeVisible();
});
