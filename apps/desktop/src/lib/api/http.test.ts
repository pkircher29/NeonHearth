import { describe, expect, it, vi } from 'vitest';

import { createAuthSession } from '../auth/session';
import { createAutomationApi, sanitizeAutomationSnapshot } from './automation';
import { createDeviceLabelsApi } from './deviceLabels';
import { createHostApi, sanitizeHostSnapshot } from './hostMonitor';
import { createHttp, validRows } from './http';
import { createNetworkApi } from './networkMonitor';
import { SNMP_NEEDS_DEVICES, createScanApi } from './networkScan';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const OWNER = 'x'.repeat(40);
const header = () => `Bearer ${OWNER}`;

describe('shared send()', () => {
  it('never sends an empty Authorization header when there is no credential', async () => {
    const seen: Array<Record<string, string>> = [];
    const fetchImpl = vi.fn(async (_url: string, init: RequestInit) => { seen.push({ ...(init.headers as Record<string, string>) }); return json([]); });
    for (const call of [
      () => createDeviceLabelsApi({ header: () => null }, fetchImpl as never).list(),
      () => createAutomationApi({ header: () => null }, fetchImpl as never).network().catch(() => undefined),
      () => createNetworkApi({ header: () => null }, fetchImpl as never).snapshot().catch(() => undefined),
      () => createHostApi({ header: () => null }, fetchImpl as never).snapshot().catch(() => undefined),
      () => createScanApi({ header: () => null }, fetchImpl as never).status().catch(() => undefined)
    ]) await call();
    expect(seen.length).toBe(5);
    for (const headers of seen) expect(Object.keys(headers).map((key) => key.toLowerCase())).not.toContain('authorization');
  });

  it('sends the bearer when there is one, resolved against the base URL', async () => {
    const fetchImpl = vi.fn(async () => json({ ok: true }));
    const http = createHttp({ baseUrl: 'http://127.0.0.1:9999', auth: { header }, fetchImpl: fetchImpl as never });
    await http.send('/api/v1/x', { headers: http.authHeaders() });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://127.0.0.1:9999/api/v1/x');
    expect((init.headers as Record<string, string>).Authorization).toBe(header());
  });

  it('reports 401 with the header that was sent, and 403 as step-up only for phone sessions', async () => {
    const unauthorized = vi.fn();
    const stepupRequired = vi.fn();
    let status = 401;
    const fetchImpl = vi.fn(async () => json({}, status));
    const owner = createHttp({ baseUrl: 'http://x', auth: { header, unauthorized, stepupRequired }, fetchImpl: fetchImpl as never });
    await owner.send('/a');
    expect(unauthorized).toHaveBeenCalledWith(header());
    status = 403;
    await owner.send('/a');
    expect(stepupRequired).not.toHaveBeenCalled();
    const phone = createHttp({ baseUrl: 'http://x', auth: { header: () => 'PhoneSession id:secret', unauthorized, stepupRequired }, fetchImpl: fetchImpl as never });
    await phone.send('/a');
    expect(stepupRequired).toHaveBeenCalledTimes(1);
  });

  it('times out and honours the caller abort signal', async () => {
    vi.useFakeTimers();
    try {
      const fetchImpl = vi.fn((_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason))));
      const http = createHttp({ baseUrl: 'http://x', fetchImpl: fetchImpl as never, timeoutMs: 1000 });
      const slow = http.send('/slow');
      const assertion = expect(slow).rejects.toThrow('Request timed out');
      await vi.advanceTimersByTimeAsync(1001);
      await assertion;
      const controller = new AbortController();
      const aborted = http.send('/slow', {}, { signal: controller.signal, timeoutMs: 0 });
      const second = expect(aborted).rejects.toThrow('stop');
      controller.abort(new Error('stop'));
      await second;
    } finally { vi.useRealTimers(); }
  });
});

describe('a late 401 for an old credential cannot discard the new one', () => {
  it('ignores a refusal of a request that carried a different credential', () => {
    const session = createAuthSession(null);
    session.signInOwner(OWNER, false);
    const newer = 'y'.repeat(40);
    session.signOut();
    session.signInOwner(newer, false);
    session.unauthorized(`Bearer ${OWNER}`);           // the in-flight request used the first token
    expect(session.state.credential).toEqual({ kind: 'owner', token: newer });
    expect(session.state.challenged).toBe(false);
    session.unauthorized(`Bearer ${newer}`);           // a refusal of the current credential still signs out
    expect(session.state.credential).toBeNull();
    expect(session.state.failure).toBe('rejected');
  });

  it('a refusal of an unauthenticated request does not drop a credential entered since', () => {
    const session = createAuthSession(null);
    session.signInOwner(OWNER, false);
    session.unauthorized(null);
    expect(session.state.credential).not.toBeNull();
  });
});

describe('lenient rows', () => {
  it('validRows keeps the good rows and counts the bad ones', () => {
    const result = validRows([1, 'a', 2, null, 3], 4, (row): row is number => typeof row === 'number');
    expect(result).toEqual({ rows: [1, 2], dropped: 3 });
    expect(validRows('nope', 4, (row): row is number => typeof row === 'number')).toBeNull();
  });

  const entity = (name: string) => ({ entity_id: 'light.a', name, state: 'on', area: null, platform: null, last_changed: null, last_updated: null, power_capable: true, control_enabled: false });
  const device = (id: string, name: string, entities: unknown[]) => ({ device_id: id, upstream_id: 'u', name, manufacturer: null, model: null, area: null, mac_addresses: [], first_seen_at: 't', last_seen_at: 't', entities });
  const envelope = (devices: unknown[]) => ({ status: 'ready', detail: 'ok', source: null, updated_at: null, devices, areas: ['Kitchen'] });
  const good = '018f47a0-9b5c-7a22-8a33-aabbccdd0001';

  it('an over-long device name is clipped, not a reason to blank the whole inventory', () => {
    const parsed = sanitizeAutomationSnapshot(envelope([device(good, 'N'.repeat(5000), [entity('ok')]), device('not-a-uuid', 'bad', []), device('018f47a0-9b5c-7a22-8a33-aabbccdd0002', 'Fine', [entity('E'.repeat(3000)), { nope: 1 }])]));
    expect(parsed).not.toBeNull();
    expect(parsed!.snapshot.devices).toHaveLength(2);
    expect(parsed!.snapshot.devices[0]!.name).toHaveLength(1024);
    expect(parsed!.snapshot.devices[1]!.entities).toHaveLength(1);
    expect(parsed!.snapshot.devices[1]!.entities[0]!.name).toHaveLength(1024);
    expect(parsed!.dropped).toBe(2);
  });

  it('the automation API returns the usable part of the inventory', async () => {
    const api = createAutomationApi({ header }, vi.fn(async () => json(envelope([device(good, 'x'.repeat(2000), []), device('bad', 'y', [])]))) as never);
    const snapshot = await api.snapshot();
    expect(snapshot.devices).toHaveLength(1);
  });

  it('a host snapshot with one malformed application still shows the rest', () => {
    const base = { observed_at: 't', status: 'ready', detail: 'ok', interfaces: [], applications: [{ app_id: 'a', name: 'ok', executable: null, pid: 1, started: 't', cpu_time_ms: null, memory_bytes: null }, { app_id: 5 }], connections: [], upload_bytes_per_second: 1, download_bytes_per_second: 1, app_counters: 'ok', firewall_available: false, memory_total_bytes: null, memory_available_bytes: null };
    expect(sanitizeHostSnapshot(base)!.applications).toHaveLength(1);
    expect(sanitizeHostSnapshot('x')).toBeNull();
  });
});

describe('scan API and SNMP', () => {
  it('refuses SNMP without an explicit device list before any request is made', async () => {
    const fetchImpl = vi.fn();
    const api = createScanApi({ header }, fetchImpl as never);
    await expect(api.start({ port_mode: 'none', protocols: ['icmp', 'snmp'], snmp: { version: 'v2c', community: 'public' } })).rejects.toThrow(SNMP_NEEDS_DEVICES);
    await expect(api.start({ port_mode: 'none', protocols: ['snmp'], device_ids: [], snmp: { version: 'v2c', community: 'public' } })).rejects.toThrow(SNMP_NEEDS_DEVICES);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('sends SNMP with a chosen device list and surfaces the service problem text on a 4xx', async () => {
    const fetchImpl = vi.fn(async () => json({ error: 'SNMP needs an explicit device list' }, 400));
    const api = createScanApi({ header }, fetchImpl as never);
    await expect(api.start({ port_mode: 'none', protocols: ['snmp'], device_ids: ['a'], snmp: { version: 'v2c', community: 'public' } })).rejects.toThrow('SNMP needs an explicit device list');
    const [, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.parse(String(init.body)).device_ids).toEqual(['a']);
  });

  it('falls back to generic copy for a 4xx with no readable body, and to sign-in copy on 401', async () => {
    const api = createScanApi({ header }, vi.fn(async () => new Response('', { status: 400 })) as never);
    await expect(api.start({ port_mode: 'common', protocols: ['icmp'] })).rejects.toThrow(/Check the ports/);
    const unauthorized = createScanApi({ header }, vi.fn(async () => json({ error: 'nope' }, 401)) as never);
    await expect(unauthorized.status()).rejects.toThrow(/Sign in again/);
  });
});
