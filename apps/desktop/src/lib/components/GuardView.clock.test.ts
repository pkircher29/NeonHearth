// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';

import type { PolicyActionResult } from '../api/client';
import { initialLiveState, type LiveState } from '../stores/live';
import GuardView from './GuardView.svelte';

const unused = vi.fn(async (): Promise<PolicyActionResult> => { throw new Error('not used'); });
const suspect: LiveState = { ...initialLiveState, connected: true, clock: { status: 'suspect', detail: 'system clock jumped far forward' } };

describe('GuardView clock notice', () => {
  it('is hidden while the clock is trusted or the service does not report it', () => {
    render(GuardView, { state: { ...initialLiveState, connected: true, clock: { status: 'trusted', detail: null } }, client: { policyAction: unused, acknowledgeClock: vi.fn() } });
    expect(screen.queryByText(/clock changed unexpectedly/)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Confirm the clock is correct' })).toBeNull();
  });

  it('explains a suspect clock and confirms it through the service', async () => {
    const acknowledgeClock = vi.fn(async () => ({ status: 'trusted' as const, detail: null }));
    render(GuardView, { state: suspect, client: { policyAction: unused, acknowledgeClock } });

    expect(screen.getByText(/clock changed unexpectedly, so automatic quarantine deadlines are paused/)).toBeTruthy();
    expect(screen.getByText(/system clock jumped far forward/)).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm the clock is correct' }));

    expect(acknowledgeClock).toHaveBeenCalledOnce();
    await waitFor(() => expect(screen.queryByText(/clock changed unexpectedly/)).toBeNull());
  });

  it('keeps the notice and reports the failure when the service refuses', async () => {
    const acknowledgeClock = vi.fn(async () => { throw new Error('Request failed with status 503'); });
    render(GuardView, { state: suspect, client: { policyAction: unused, acknowledgeClock } });

    await fireEvent.click(screen.getByRole('button', { name: 'Confirm the clock is correct' }));

    await waitFor(() => expect(screen.getByText(/Could not confirm the clock: Request failed with status 503/)).toBeTruthy());
    expect(screen.getByText(/clock changed unexpectedly/)).toBeTruthy();
  });

  it('tells a paired phone the owner confirms the clock, with no button', () => {
    const acknowledgeClock = vi.fn();
    render(GuardView, { state: suspect, client: { policyAction: unused, acknowledgeClock }, owner: false });

    expect(screen.getByText(/clock changed unexpectedly, so automatic quarantine deadlines are paused/)).toBeTruthy();
    expect(screen.getByText('The owner can confirm the clock is correct from the home computer.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Confirm the clock is correct' })).toBeNull();
    expect(acknowledgeClock).not.toHaveBeenCalled();
  });

  it('shows the notice without a button when no client can acknowledge', () => {
    render(GuardView, { state: suspect });
    expect(screen.getByText(/clock changed unexpectedly/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Confirm the clock is correct' })).toBeNull();
  });
});
