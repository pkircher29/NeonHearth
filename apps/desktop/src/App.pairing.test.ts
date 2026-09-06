// @vitest-environment jsdom
// The "not working" fix: a stale stored pairing token (401 from the service)
// must clear itself and render the actionable re-pair state instead of a
// silent, dead UI.
import { render, screen, waitFor } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';

const STORAGE_KEY = 'neonhearth.service-token';
const STALE = 'stale-token-0123456789012345678901234567890123';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

describe('App pairing recovery', () => {
  beforeEach(() => {
    sessionStorage.clear();
    // The connection layer never reaches the socket in these tests (the
    // snapshot call fails first), but App constructs a client eagerly.
    vi.stubGlobal('WebSocket', class {
      onopen: (() => void) | null = null;
      close(): void {}
      send(): void {}
    });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    sessionStorage.clear();
  });

  it('clears the stored token and shows the re-pair state when the service answers 401', async () => {
    sessionStorage.setItem(STORAGE_KEY, STALE);
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/api/v1/health')) return jsonResponse({ status: 'ok', api_version: 'test' });
      if (url.includes('/api/v1/state')) return jsonResponse({ error: 'unauthorized' }, 401);
      return jsonResponse({ error: 'unexpected' }, 500);
    }));

    render(App);

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Unlock your home.' })).toBeTruthy());
    expect(screen.getByText(/That credential was not accepted/)).toBeTruthy();
    // The dead token is gone: a reload will not retry a pairing that cannot heal.
    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    // The action state replaces the live chrome instead of sitting beside a dead QUIET rail.
    expect(sessionStorage.getItem('neonhearth.session')).toBeNull();
  });

  it('keeps the normal UI when the stored pairing is accepted', async () => {
    sessionStorage.setItem(STORAGE_KEY, STALE);
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/api/v1/health')) return jsonResponse({ status: 'ok', api_version: 'test' });
      if (url.includes('/api/v1/state')) return jsonResponse({ sequence: 1, devices: [], next_after: null, service_status: 'ready' });
      if (url.includes('/api/v1/events/ticket')) return jsonResponse({ ticket: 'fresh-ticket', expires_in_seconds: 30 });
      return jsonResponse({ error: 'unexpected' }, 500);
    }));

    render(App);

    await waitFor(() => expect(screen.getByText('Your network, breathing.')).toBeTruthy());
    expect(screen.queryByText("This window's pairing expired.")).toBeNull();
    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    expect(JSON.parse(sessionStorage.getItem('neonhearth.session')!)).toEqual({ kind: 'owner', token: STALE });
  });

  it('a fresh #token fragment still pairs after a cleared token (bootstrap on mount)', async () => {
    // Simulate the launcher opening the page with a fragment after the stale
    // token was cleared by a previous 401.
    window.location.hash = `#token=${STALE}`;
    const authHeaders: Array<string | null> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/api/v1/state')) {
        authHeaders.push((init?.headers as Record<string, string> | undefined)?.Authorization ?? null);
        return jsonResponse({ sequence: 1, devices: [], next_after: null, service_status: 'ready' });
      }
      if (url.includes('/api/v1/health')) return jsonResponse({ status: 'ok', api_version: 'test' });
      if (url.includes('/api/v1/events/ticket')) return jsonResponse({ ticket: 'fresh-ticket', expires_in_seconds: 30 });
      return jsonResponse({ error: 'unexpected' }, 500);
    }));

    render(App);

    await waitFor(() => expect(authHeaders.length).toBeGreaterThan(0));
    expect(authHeaders[0]).toBe(`Bearer ${STALE}`);
    // The fragment was persisted and stripped by the bootstrap.
    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    expect(JSON.parse(sessionStorage.getItem('neonhearth.session')!)).toEqual({ kind: 'owner', token: STALE });
    expect(window.location.hash).toBe('');
  });
});
