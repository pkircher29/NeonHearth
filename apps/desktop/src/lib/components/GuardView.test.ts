// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';

import type { PolicyActionResult } from '../api/client';
import type { DeviceSnapshot } from '../api/types';
import { initialLiveState, type GuardPolicy, type LiveState } from '../stores/live';
import GuardView from './GuardView.svelte';

describe('GuardView', () => {
  it('renders a verified quarantine lifecycle with independent risk cues', () => {
    const device_id = '018f47a0-9b5c-7a22-8a33-112233445599';
    const state: LiveState = {
      ...initialLiveState,
      connected: true,
      policies: {
        [device_id]: {
          device_id,
          evaluation: {
            policy_version: 1,
            reason: 'unknown_deadline_expired',
            requested_action: 'quarantine',
            deadline: null,
            warning: null
          },
          requested_action: 'quarantine',
          enforcement_result: 'verified',
          undo_available: true,
          delivery_pending: false
        }
      }
    };

    const view = render(GuardView, { state });

    expect(screen.getByRole('heading', { name: 'Every guest earns trust.' })).toBeTruthy();
    expect(screen.getByText('Verified', { selector: '.policy-path span' })).toBeTruthy();
    expect(screen.getByText('verified', { selector: '.enforcement' })).toBeTruthy();
    expect(view.container.querySelector('.action-quarantine.enforcement-verified')).toBeTruthy();
    expect(screen.getByText('Available')).toBeTruthy();
  });

  it('replaces the card when a policy lifecycle changes without changing its version', async () => {
    const device_id = '018f47a0-9b5c-7a22-8a33-112233445599';
    const policy = {
      device_id,
      evaluation: { policy_version: 1 as const, reason: 'unknown_deadline_expired' as const, requested_action: 'quarantine' as const, deadline: null, warning: null },
      requested_action: 'quarantine' as const,
      enforcement_result: 'verified' as const,
      undo_available: true,
      delivery_pending: false
    };
    const view = render(GuardView, { state: { ...initialLiveState, policies: { [device_id]: policy } } });
    const first = view.container.querySelector('.policy-card');
    const firstKey = first?.getAttribute('data-lifecycle-key');

    await view.rerender({ state: { ...initialLiveState, policies: { [device_id]: { ...policy, undo_available: false } } } });

    const second = view.container.querySelector('.policy-card');
    expect(second).not.toBe(first);
    expect(second?.getAttribute('data-lifecycle-key')).not.toBe(firstKey);
    expect(second?.getAttribute('aria-live')).toBeNull();
  });

  const deviceId = '018f47a0-9b5c-7a22-8a33-112233445599';
  const kitchenTablet: DeviceSnapshot = {
    device_id: deviceId, first_seen_at: '2026-08-23T00:00:00Z', last_seen_at: '2026-08-23T00:00:01Z',
    owner_name: 'Kitchen Tablet', owner_type: null, owner_confirmed: true,
    presence: { state: 'online', observed_at: '2026-08-23T00:00:00Z', source: 'sensor', kind: 'reply' },
    evidence: null, identity: { available: false, classification: null, confidence: null },
    bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null },
    policy: null
  };
  function guardPolicy(overrides: Partial<GuardPolicy> = {}): GuardPolicy {
    return {
      device_id: deviceId,
      evaluation: { policy_version: 1, reason: 'pending_confirmation', requested_action: 'none', deadline: { kind: 'unknown48_hours', due_at: '2026-08-25T00:00:00Z' }, warning: null },
      requested_action: 'none',
      enforcement_result: 'not_requested',
      undo_available: false,
      delivery_pending: false,
      ...overrides
    };
  }
  function stateWith(policy: GuardPolicy): LiveState {
    return { ...initialLiveState, connected: true, devices: { [deviceId]: kitchenTablet }, policies: { [policy.device_id]: policy } };
  }
  const approvedResult: PolicyActionResult = {
    evaluation: { policy_version: 1, reason: 'owner_approved', requested_action: 'none', deadline: null, warning: null },
    enforcement_result: 'not_requested'
  };

  it('offers every owner decision while confirmation is pending and posts approve without confirmation', async () => {
    const policyAction = vi.fn(async () => approvedResult);
    render(GuardView, { state: stateWith(guardPolicy()), client: { policyAction } });

    expect(screen.getByRole('button', { name: 'Reject Kitchen Tablet' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Quarantine Kitchen Tablet' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Extend once Kitchen Tablet' })).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Approve Kitchen Tablet' }));

    expect(policyAction).toHaveBeenCalledExactlyOnceWith(deviceId, 'approve');
    // The card is not optimistically rewritten; the live stream owns the outcome.
    await waitFor(() => expect((screen.getByRole('button', { name: 'Approve Kitchen Tablet' }) as HTMLButtonElement).disabled).toBe(false));
    expect(screen.getByText('pending confirmation')).toBeTruthy();
  });

  it('renders no owner controls without a client', () => {
    render(GuardView, { state: stateWith(guardPolicy()) });
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('requires a two-step inline confirmation for destructive decisions', async () => {
    const policyAction = vi.fn(async () => approvedResult);
    render(GuardView, { state: stateWith(guardPolicy()), client: { policyAction } });

    await fireEvent.click(screen.getByRole('button', { name: 'Reject Kitchen Tablet' }));
    expect(policyAction).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm reject Kitchen Tablet' }));
    expect(policyAction).toHaveBeenCalledExactlyOnceWith(deviceId, 'reject');

    await fireEvent.click(screen.getByRole('button', { name: 'Quarantine Kitchen Tablet' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel quarantine Kitchen Tablet' }));
    expect(screen.queryByRole('button', { name: 'Confirm quarantine Kitchen Tablet' })).toBeNull();
    expect(policyAction).toHaveBeenCalledTimes(1);
  });

  it('posts a one-use extension 24 hours past the active deadline and disables it after use', async () => {
    const policyAction = vi.fn(async () => approvedResult);
    const view = render(GuardView, { state: stateWith(guardPolicy()), client: { policyAction } });

    await fireEvent.click(screen.getByRole('button', { name: 'Extend once Kitchen Tablet' }));
    expect(policyAction).toHaveBeenCalledExactlyOnceWith(deviceId, { extend_once: { until: '2026-08-26T00:00:00.000Z' } });

    await view.rerender({
      state: stateWith(guardPolicy({ evaluation: { policy_version: 1, reason: 'owner_extension', requested_action: 'none', deadline: { kind: 'unknown48_hours', due_at: '2026-08-26T00:00:00Z' }, warning: null } })),
      client: { policyAction }
    });
    const used = screen.getByRole('button', { name: 'Extend once Kitchen Tablet' }) as HTMLButtonElement;
    expect(used.disabled).toBe(true);
    expect(used.textContent).toContain('Extension used');
  });

  it('withholds the extension once a deadline has expired while decisions stay available', () => {
    const expired = guardPolicy({
      evaluation: { policy_version: 1, reason: 'unknown_deadline_expired', requested_action: 'quarantine', deadline: null, warning: null },
      requested_action: 'quarantine'
    });
    render(GuardView, { state: stateWith(expired), client: { policyAction: vi.fn(async () => approvedResult) } });

    expect(screen.queryByRole('button', { name: 'Extend once Kitchen Tablet' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Approve Kitchen Tablet' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Reject Kitchen Tablet' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Quarantine Kitchen Tablet' })).toBeTruthy();
  });

  it('shows the protected explanation instead of destructive controls for protected devices', () => {
    const protectedPolicy = guardPolicy({
      evaluation: { policy_version: 1, reason: 'protected_device', requested_action: 'owner_attention', deadline: null, warning: null },
      requested_action: 'owner_attention'
    });
    render(GuardView, { state: stateWith(protectedPolicy), client: { policyAction: vi.fn(async () => approvedResult) } });

    expect(screen.getByText(/Protected device/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Approve Kitchen Tablet' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Reject Kitchen Tablet' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Quarantine Kitchen Tablet' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Extend once Kitchen Tablet' })).toBeNull();
  });

  it('offers no controls after a decision except a release while undo remains available', async () => {
    const decided = guardPolicy({
      evaluation: { policy_version: 1, reason: 'owner_quarantined', requested_action: 'quarantine', deadline: null, warning: null },
      requested_action: 'quarantine', enforcement_result: 'verified', undo_available: true
    });
    const view = render(GuardView, { state: stateWith(decided), client: { policyAction: vi.fn(async () => approvedResult) } });
    expect(screen.getByRole('button', { name: 'Approve Kitchen Tablet' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Reject Kitchen Tablet' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Quarantine Kitchen Tablet' })).toBeNull();

    await view.rerender({ state: stateWith({ ...decided, undo_available: false }), client: { policyAction: vi.fn(async () => approvedResult) } });
    expect(screen.queryByRole('button')).toBeNull();

    await view.rerender({
      state: stateWith(guardPolicy({ evaluation: { policy_version: 1, reason: 'owner_approved', requested_action: 'none', deadline: null, warning: null } })),
      client: { policyAction: vi.fn(async () => approvedResult) }
    });
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('disables the row while a decision is in flight', async () => {
    let resolveAction!: (value: PolicyActionResult) => void;
    const policyAction = vi.fn(() => new Promise<PolicyActionResult>((resolve) => { resolveAction = resolve; }));
    render(GuardView, { state: stateWith(guardPolicy()), client: { policyAction } });

    await fireEvent.click(screen.getByRole('button', { name: 'Approve Kitchen Tablet' }));

    expect((screen.getByRole('button', { name: 'Approve Kitchen Tablet' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Reject Kitchen Tablet' }) as HTMLButtonElement).disabled).toBe(true);
    resolveAction(approvedResult);
    await waitFor(() => expect((screen.getByRole('button', { name: 'Approve Kitchen Tablet' }) as HTMLButtonElement).disabled).toBe(false));
  });

  it('surfaces a server rejection inline without blocking further decisions', async () => {
    const policyAction = vi.fn(async () => { throw new Error('Request failed with status 400'); });
    render(GuardView, { state: stateWith(guardPolicy()), client: { policyAction } });

    await fireEvent.click(screen.getByRole('button', { name: 'Approve Kitchen Tablet' }));

    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('Request failed with status 400'));
    expect(screen.getByRole('alert').textContent).toContain('Kitchen Tablet');
    expect((screen.getByRole('button', { name: 'Approve Kitchen Tablet' }) as HTMLButtonElement).disabled).toBe(false);
  });
});
