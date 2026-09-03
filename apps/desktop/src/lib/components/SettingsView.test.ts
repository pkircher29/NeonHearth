// @vitest-environment jsdom
import { cleanup, fireEvent, render, waitFor } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { DoctorSettings, IntegrationToken, PhoneSession, RemoteStatus } from '../api/client';
import type { AuthState } from '../auth/session';
import SettingsView from './SettingsView.svelte';

const owner: AuthState = { credential: { kind: 'owner', token: 'x'.repeat(40) }, challenged: false, stepupRequired: false, stepupUntil: null, remembered: false, failure: null };
const phone: AuthState = { credential: { kind: 'phone', sessionId: '11111111-1111-4111-8111-111111111111', secret: 'a'.repeat(64) }, challenged: false, stepupRequired: false, stepupUntil: null, remembered: false, failure: null };
const at = '2026-08-23T00:00:00Z';
const status: RemoteStatus = { daemon: { running: true, backend_state: 'Running', dns_name: 'hearth.tail.ts.net' }, daemon_error: null, serve_configured: false, funnel_conflict: false, loopback_port: 58120 };
const session: PhoneSession = { session_id: '22222222-2222-4222-8222-222222222222', device_label: "Paul's phone", created_at: at, expires_at: at, last_used_at: null, revoked: false };
const token: IntegrationToken = { id: '33333333-3333-4333-8333-333333333333', name: 'Home Assistant', scopes: ['devices:read'], created_at: at, revoked: false };
const doctor: DoctorSettings = { interface: 'eth0', gateway: '192.168.1.1', gateway_source: 'platform', configured_resolvers: ['192.168.1.1'], independent_resolver: '9.9.9.9', internet_probe_address: '1.1.1.1', internet_probe_port: 443, dns_probe_name: 'example.com', external_probes_confirmed: false };

function client() {
  return {
    pairPhone: vi.fn(async () => ({ session_id: session.session_id, secret: 'b'.repeat(64), expires_at: at })),
    remoteStatus: vi.fn(async () => status),
    remoteServe: vi.fn(async () => ({ configured: true, changed: true, https_port: 443, target: 'http://127.0.0.1:58120', dns_name: 'hearth.tail.ts.net' })),
    remoteSessions: vi.fn(async () => [session]),
    revokePhoneSession: vi.fn(async () => undefined),
    integrationTokens: vi.fn(async () => [token]),
    mintIntegrationToken: vi.fn(async (name: string, scopes: string[]) => ({ id: token.id, name, scopes, token: 'c'.repeat(64), created_at: at })),
    revokeIntegrationToken: vi.fn(async () => undefined),
    doctorSettings: vi.fn(async () => doctor),
    updateDoctorSettings: vi.fn(async () => ({ status: 'saved' as const, settings: { ...doctor, external_probes_confirmed: true } }))
  };
}

beforeEach(() => { try { window.localStorage.clear(); } catch { /* jsdom */ } delete document.documentElement.dataset.motion; });
afterEach(cleanup);

describe('SettingsView', () => {
  it('shows owner sections with live remote status, sessions, tokens, and doctor targets', async () => {
    const api = client();
    const { findByText, getByText } = render(SettingsView, { client: api, auth: owner, onsignout: vi.fn() });
    expect(await findByText(/Running · Running/)).toBeTruthy();
    expect(getByText("Paul's phone")).toBeTruthy();
    expect(getByText('Home Assistant')).toBeTruthy();
    expect((document.querySelector('input[placeholder="9.9.9.9"]') as HTMLInputElement).value).toBe('9.9.9.9');
    expect(getByText('Turn on private access')).toBeTruthy();
  });

  it('hides owner-only sections for a paired phone', async () => {
    const api = client();
    const { queryByText, getByText } = render(SettingsView, { client: api, auth: phone, onsignout: vi.fn() });
    expect(getByText('Paired phone')).toBeTruthy();
    expect(queryByText('Pair a phone')).toBeNull();
    expect(queryByText('Integrations')).toBeNull();
    expect(api.remoteStatus).not.toHaveBeenCalled();
  });

  it('revokes a session and refreshes the list', async () => {
    const api = client();
    api.remoteSessions.mockResolvedValueOnce([session]).mockResolvedValueOnce([{ ...session, revoked: true }]);
    const { findByText, getAllByText } = render(SettingsView, { client: api, auth: owner, onsignout: vi.fn() });
    await findByText("Paul's phone");
    await fireEvent.click(getAllByText('Revoke')[0]!);
    await waitFor(() => expect(api.revokePhoneSession).toHaveBeenCalledWith(session.session_id));
    expect(await findByText('Revoked')).toBeTruthy();
  });

  it('mints a token with the ticked scopes and shows it once', async () => {
    const api = client();
    const { findByText, getByPlaceholderText, getByText } = render(SettingsView, { client: api, auth: owner, onsignout: vi.fn() });
    await findByText('Home Assistant');
    await fireEvent.input(getByPlaceholderText('e.g. Home Assistant'), { target: { value: 'Grafana' } });
    await fireEvent.click(getByText('presence:read'));
    await fireEvent.click(getByText('Mint token'));
    await waitFor(() => expect(api.mintIntegrationToken).toHaveBeenCalledWith('Grafana', ['devices:read', 'presence:read']));
    expect(await findByText('c'.repeat(64))).toBeTruthy();
  });

  it('saves doctor targets and reports a rejection honestly', async () => {
    const api = client();
    api.updateDoctorSettings.mockResolvedValueOnce({ status: 'rejected', error: 'gateway must be an IP address' } as never);
    const { findByText, getByText, getAllByPlaceholderText } = render(SettingsView, { client: api, auth: owner, onsignout: vi.fn() });
    await findByText('Save targets');
    await fireEvent.input(getAllByPlaceholderText('192.168.1.1')[0]!, { target: { value: 'not-an-ip' } });
    await fireEvent.click(getByText('Save targets'));
    expect(await findByText('gateway must be an IP address')).toBeTruthy();
    await fireEvent.click(getByText('Save targets'));
    expect(await findByText(/Saved\. The next diagnostic/)).toBeTruthy();
  });

  it('applies the motion preference to the document root', async () => {
    const api = client();
    const { getByText } = render(SettingsView, { client: api, auth: phone, onsignout: vi.fn() });
    await fireEvent.click(getByText('Reduce motion'));
    expect(document.documentElement.dataset.motion).toBe('reduced');
    await fireEvent.click(getByText('Follow system'));
    expect(document.documentElement.dataset.motion).toBeUndefined();
  });
});
