// @vitest-environment jsdom
import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';

import { initialLiveState, type LiveState } from '../stores/live';
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
});
