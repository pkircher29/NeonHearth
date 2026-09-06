// @vitest-environment jsdom
import { cleanup, fireEvent, render } from '@testing-library/svelte';
import { afterEach, expect, it, vi } from 'vitest';
import type { ScanApi, ScanStatus } from '../api/networkScan';
import type { DeviceSnapshot } from '../api/types';
import type { LiveState } from '../stores/live';
import DevicesView from './DevicesView.svelte';
import NetworkScanPanel from './NetworkScanPanel.svelte';

afterEach(cleanup);
const at = '2026-09-06T12:00:00Z';
const device: DeviceSnapshot = {
  device_id: 'device-one', owner_name: 'My confirmed name', owner_type: null, owner_confirmed: true,
  first_seen_at: at, last_seen_at: at, evidence: null,
  identity: { available: false, classification: null, confidence: null },
  presence: { state: 'online', observed_at: at, source: null, kind: null },
  bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null }, policy: null,
};
const scan: ScanStatus = {
  job_id: 'test', state: 'complete', started_at: at, finished_at: at, devices: 1, skipped_devices: 0,
  total: 2, completed: 2, open_ports: 1, refused: 0, no_response: 0, errors: 0, results_truncated: false, detail: 'Reported clues',
  findings: [{ device_id: device.device_id, address: '192.168.1.2', protocol: 'tcp', port: 443,
    status: 'open', service_hint: 'HTTPS', observed_at: at,
    facts: { web_scheme: 'https', web_status: '200', web_title: '<img src=x onerror=alert(1)> Home Assistant', web_identity_hint: 'Home Assistant', certificate_trust: 'unverified' },
  }],
};
function api(): ScanApi {
  return { status: vi.fn(async () => scan), start: vi.fn(async () => scan), cancel: vi.fn(async () => {}),
    capabilities: vi.fn(async () => ({})), capture: vi.fn(async () => ({ imported_at: at, findings: [], detail: '' })) };
}

it('shows searchable web clues as text while preserving the owner name and trust status', async () => {
  const liveState = { devices: { [device.device_id]: device }, deviceOrder: [device.device_id], connected: true } as LiveState;
  const { findByText, getByText, getByRole, container } = render(DevicesView, { liveState, scanApi: api() });
  expect(await findByText(/Web identification · HTTPS 443/)).toBeTruthy();
  expect(getByText('My confirmed name')).toBeTruthy();
  expect(container.querySelector('.web-identity')?.textContent).toContain('<img src=x onerror=alert(1)>');
  expect(container.querySelector('.web-identity img')).toBeNull();
  expect(getByText(/certificate unverified/)).toBeTruthy();
  await fireEvent.input(getByRole('textbox', { name: 'Search devices' }), { target: { value: 'home assistant' } });
  expect(getByText('My confirmed name')).toBeTruthy();
  await fireEvent.input(getByRole('textbox', { name: 'Search devices' }), { target: { value: 'no such product' } });
  expect(getByText('No devices match')).toBeTruthy();
});

it('enables web identification by default and includes an explicit opt-out in scan requests', async () => {
  const client = api();
  const { getByRole } = render(NetworkScanPanel, { api: client, onchange: vi.fn() });
  const checkbox = getByRole('checkbox', { name: 'Identify open web ports with HTTP / HTTPS' }) as HTMLInputElement;
  expect(checkbox.checked).toBe(true);
  await fireEvent.click(getByRole('button', { name: 'Scan all devices' }));
  expect(client.start).toHaveBeenLastCalledWith(expect.objectContaining({ web_identification: true }));
  await fireEvent.click(checkbox);
  await fireEvent.click(getByRole('button', { name: 'Scan all devices' }));
  expect(client.start).toHaveBeenLastCalledWith(expect.objectContaining({ web_identification: false }));
});
