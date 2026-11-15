// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DeviceSnapshot } from '../api/types';
import { initialLiveState, type GuardPolicy, type LiveState } from '../stores/live';
import GuardView from './GuardView.svelte';

const id = '018f47a0-9b5c-7a22-8a33-112233445599';
const device = { device_id: id, owner_name: 'Kitchen Tablet', owner_type: null, owner_confirmed: true, first_seen_at: '2026-08-23T00:00:00Z', last_seen_at: '2026-08-23T00:00:00Z', presence: { state: 'online', observed_at: null, source: null, kind: null }, evidence: null, identity: { available: false, classification: null, confidence: null }, bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null }, policy: null } as DeviceSnapshot;
const policy: GuardPolicy = { device_id: id, evaluation: { policy_version: 1, reason: 'pending_confirmation', requested_action: 'none', deadline: null, warning: null }, requested_action: 'none', enforcement_result: 'not_requested', undo_available: false, delivery_pending: false };
const state = (connected: boolean): LiveState => ({ ...initialLiveState, connected, devices: { [id]: device }, deviceOrder: [id], policies: { [id]: policy } });

afterEach(cleanup);

describe('GuardView while the collector is unreachable', () => {
  it('says the records are last-known and disables every owner decision', async () => {
    const policyAction = vi.fn(async () => ({}) as never);
    render(GuardView, { state: state(false), client: { policyAction } });
    expect(screen.getByRole('alert').textContent).toContain('Collector offline');
    expect(screen.getByText('policy records, last known')).toBeTruthy();
    for (const name of ['Approve Kitchen Tablet', 'Reject Kitchen Tablet', 'Quarantine Kitchen Tablet']) {
      const button = screen.getByRole('button', { name }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      await fireEvent.click(button);
    }
    expect(policyAction).not.toHaveBeenCalled();
  });

  it('shows no banner and live wording when connected, with decisions enabled', () => {
    render(GuardView, { state: state(true), client: { policyAction: vi.fn() } });
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByText('policy records live')).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Approve Kitchen Tablet' }) as HTMLButtonElement).disabled).toBe(false);
  });
});
