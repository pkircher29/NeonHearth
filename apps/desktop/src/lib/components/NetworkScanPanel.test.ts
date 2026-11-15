// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ScanApi, ScanStatus } from '../api/networkScan';
import NetworkScanPanel from './NetworkScanPanel.svelte';

const idle: ScanStatus = { job_id: null, state: 'idle', started_at: null, finished_at: null, devices: 0, skipped_devices: 0, total: 0, completed: 0, open_ports: 0, refused: 0, no_response: 0, errors: 0, findings: [], results_truncated: false, detail: '' };
const api = (overrides: Partial<ScanApi> = {}): ScanApi => ({
  status: vi.fn(async () => idle), start: vi.fn(async () => ({ ...idle, job_id: 'j', state: 'running' })), cancel: vi.fn(async () => undefined),
  capabilities: vi.fn(async () => ({})), capture: vi.fn(async () => ({ imported_at: '', findings: [], detail: '' })), ...overrides
});
const devices = [{ id: 'dev-1', label: 'Printer' }, { id: 'dev-2', label: 'Switch' }];
afterEach(cleanup);


describe('NetworkScanPanel SNMP', () => {
  it('does not enable the scan until at least one device is chosen for SNMP, and says why', async () => {
    const client = api();
    const view = render(NetworkScanPanel, { api: client, onchange: vi.fn(), devices });
    await fireEvent.click(screen.getByLabelText('SNMP inventory'));
    const button = screen.getByRole('button', { name: /^Scan 0 chosen devices$/ }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(view.container.textContent).toContain('SNMP is only sent to devices you choose');
    await fireEvent.click(button);
    expect(client.start).not.toHaveBeenCalled();
  });

  it('sends the chosen devices with the SNMP request', async () => {
    const client = api();
    render(NetworkScanPanel, { api: client, onchange: vi.fn(), devices });
    await fireEvent.click(screen.getByLabelText('SNMP inventory'));
    await fireEvent.click(screen.getByLabelText('Printer'));
    const button = screen.getByRole('button', { name: /^Scan 1 chosen device$/ }) as HTMLButtonElement;
    expect(button.disabled).toBe(false);
    await fireEvent.click(button);
    expect(client.start).toHaveBeenCalledTimes(1);
    const input = (client.start as ReturnType<typeof vi.fn>).mock.calls[0]![0];
    expect(input.device_ids).toEqual(['dev-1']);
    expect(input.protocols).toContain('snmp');
  });

  it('shows the service refusal text when a 4xx comes back', async () => {
    const client = api({ start: vi.fn(async () => { throw new Error('SNMP needs an explicit device list'); }) });
    render(NetworkScanPanel, { api: client, onchange: vi.fn(), devices });
    await fireEvent.click(screen.getByLabelText('SNMP inventory'));
    await fireEvent.click(screen.getByLabelText('Switch'));
    await fireEvent.click(screen.getByRole('button', { name: /^Scan 1 chosen device$/ }));
    expect((await screen.findByRole('alert')).textContent).toContain('SNMP needs an explicit device list');
  });

  it('leaves the normal scan unchanged when SNMP is not selected', async () => {
    const client = api();
    render(NetworkScanPanel, { api: client, onchange: vi.fn(), devices });
    await fireEvent.click(screen.getByRole('button', { name: 'Scan all devices' }));
    const input = (client.start as ReturnType<typeof vi.fn>).mock.calls[0]![0];
    expect(input.device_ids).toBeUndefined();
  });
});

