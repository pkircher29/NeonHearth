// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import App from './App.svelte';

// The app talks to the collector through window.fetch; a 401 from the first
// protected request must bring up the sign-in screen, and the credential the
// owner enters must reach the next request (M-25).
const snapshot = { sequence: 1, devices: [], next_after: null, service_status: 'ready' };
const ownerToken = 'o'.repeat(40);

class IdleWebSocket {
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  close() {}
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  window.sessionStorage.clear();
  vi.stubGlobal('WebSocket', IdleWebSocket);
  fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const url = String(input);
    if (url.includes('/api/v1/health')) return new Response(JSON.stringify({ status: 'ready' }), { status: 200 });
    if (headers.Authorization !== `Bearer ${ownerToken}`) return new Response(null, { status: 401 });
    if (url.includes('/api/v1/events/ticket')) return new Response(JSON.stringify({ ticket: 'ticket', expires_in_seconds: 30 }), { status: 200 });
    if (url.includes('/api/v1/state')) return new Response(JSON.stringify(snapshot), { status: 200 });
    return new Response(null, { status: 404 });
  });
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('App sign-in', () => {
  it('shows the sign-in screen after a 401 and retries with the entered owner token', async () => {
    render(App);
    expect(await screen.findByRole('heading', { name: 'Unlock your home.' })).toBeTruthy();
    // No credential was held, so nothing was ever sent as an empty bearer.
    for (const call of fetchMock.mock.calls) {
      const headers = ((call[1] as RequestInit | undefined)?.headers ?? {}) as Record<string, string>;
      expect(headers.Authorization).toBeUndefined();
    }

    await fireEvent.input(screen.getByLabelText('Service token'), { target: { value: ownerToken } });
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Unlock your home.' })).toBeNull());
    expect(await screen.findByRole('heading', { name: 'Your network, breathing.' })).toBeTruthy();
    const authorized = fetchMock.mock.calls.filter((call) => (((call[1] as RequestInit | undefined)?.headers ?? {}) as Record<string, string>).Authorization === `Bearer ${ownerToken}`);
    expect(authorized.length).toBeGreaterThan(0);
    expect(window.sessionStorage.getItem('neonhearth.session')).toBeNull();
  });

  it('explains a rejected credential and keeps the sign-in screen', async () => {
    render(App);
    await screen.findByRole('heading', { name: 'Unlock your home.' });
    await fireEvent.input(screen.getByLabelText('Service token'), { target: { value: 'w'.repeat(40) } });
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText(/That credential was not accepted/)).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Unlock your home.' })).toBeTruthy();
  });
});
