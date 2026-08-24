import { describe, expect, it, vi } from 'vitest';

import { createApiClient, isSequence } from './client';

describe('createApiClient', () => {
  it('authorizes only same-origin canonical playlist or segment media requests', () => {
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret' });
    const xhr = { setRequestHeader: vi.fn() } as unknown as XMLHttpRequest;
    expect(client.authorizeCameraMediaXhr(xhr, 'https://collector.example/api/v1/camera-sessions/018f47a0-9b5c-7a22-8a33-112233445500/playlist.m3u8')).toBeUndefined();
    expect(xhr.setRequestHeader).toHaveBeenCalledWith('Authorization', 'Bearer secret');
    expect(client.authorizeCameraMediaXhr(xhr, 'https://collector.example/api/v1/camera-sessions/018f47a0-9b5c-7a22-8a33-112233445500/segments/00001.ts')).toBeUndefined();
    for (const unsafe of ['https://elsewhere.invalid/api/v1/camera-sessions/018f47a0-9b5c-7a22-8a33-112233445500/playlist.m3u8', 'https://collector.example/api/v1/camera-sessions/018f47a0-9b5c-7a22-8a33-112233445500/segments/%2e%2e', 'https://collector.example/api/v1/camera-sessions/018f47a0-9b5c-7a22-8a33-112233445500/playlist.m3u8?x=1', 'https://user:secret@collector.example/api/v1/camera-sessions/018f47a0-9b5c-7a22-8a33-112233445500/playlist.m3u8']) {
      expect(() => client.authorizeCameraMediaXhr(xhr, unsafe)).toThrow('Camera media request rejected');
    }
  });
  const validDevice = {
    device_id: '018f47a0-9b5c-7a22-8a33-112233445599', first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:01Z',
    owner_name: null, owner_type: null, owner_confirmed: false,
    presence: { state: 'unknown', observed_at: null, source: null, kind: null }, evidence: null,
    identity: { available: false, classification: null, confidence: null },
    bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null },
    policy: null
  };

  it('rejects a camera detail with an extra field or without inventory', async () => {
    const camera = {
      camera_id: '018f47a0-9b5c-7a22-8a33-112233445599', classification: 'camera', confidence: 0.9,
      health: 'healthy', observed_at: '2026-01-01T00:00:00Z'
    };
    for (const malformed of [camera, { ...camera, inventory: null, endpoint: 'rtsp://unsafe.invalid' }]) {
      const fetchImpl = vi.fn(async () => new Response(JSON.stringify(malformed), { status: 200 }));
      await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl }).camera(camera.camera_id)).rejects.toThrow('Invalid camera response');
    }
  });

  it('requests and strictly validates camera health', async () => {
    const id = '018f47a0-9b5c-7a22-8a33-112233445599';
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ health: 'healthy', confidence: 0.9 }), { status: 200 }));
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl });
    await expect(client.cameraHealth(id)).resolves.toEqual({ health: 'healthy', confidence: 0.9 });
    expect(fetchImpl).toHaveBeenCalledWith(`https://collector.example/api/v1/cameras/${id}/health`, { method: 'GET', headers: { Authorization: 'Bearer secret' } });
  });

  it('uses only bounded opaque camera URLs and exact media/session contracts', async () => {
    const id = '018f47a0-9b5c-7a22-8a33-112233445599';
    const stream = '018f47a0-9b5c-7a22-8a33-112233445598';
    const inventory = { manufacturer: null, model: null, firmware: null, serial: null, capabilities: [], health: 'healthy' };
    const summary = { camera_id: id, classification: 'camera', confidence: 0.5, health: 'healthy', observed_at: '2026-01-01T00:00:00Z' };
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/snapshot')) return new Response(new Uint8Array([1, 2]), { status: 200, headers: { 'content-type': 'image/jpeg' } });
      if (init?.method === 'DELETE') return new Response(null, { status: 204 });
      if (init?.method === 'POST') return new Response(JSON.stringify({ session_id: stream }), { status: 201 });
      if (url.endsWith('/inventory')) return new Response(JSON.stringify(inventory), { status: 200 });
      if (url.endsWith('/health')) return new Response(JSON.stringify({ health: 'healthy', confidence: 0.5 }), { status: 200 });
      if (url.includes('/cameras?')) return new Response(JSON.stringify({ items: [summary], next_after: null }), { status: 200 });
      if (url.endsWith(id)) return new Response(JSON.stringify({ ...summary, inventory, streams: [{ stream_id: stream }] }), { status: 200 });
      return new Response(JSON.stringify({ items: [summary], next_after: null }), { status: 200 });
    });
    const client = createApiClient({ baseUrl: 'https://collector.example/base', serviceToken: 'secret', fetchImpl });
    await expect(client.cameras({ limit: 1, after: id })).resolves.toMatchObject({ items: [summary] });
    await expect(client.camera(id)).resolves.toMatchObject({ inventory, streams: [{ stream_id: stream }] });
    await expect(client.cameraHealth(id)).resolves.toEqual({ health: 'healthy', confidence: 0.5 });
    await expect(client.cameraInventory(id)).resolves.toEqual(inventory);
    await expect(client.cameraSnapshot(id, stream)).resolves.toBeInstanceOf(Blob);
    await expect(client.startCameraSession(id, stream)).resolves.toEqual({ session_id: stream });
    await expect(client.closeCameraSession(stream)).resolves.toBeUndefined();
    expect(fetchImpl.mock.calls[0][0]).toContain(`limit=1&after=${id}`);
    expect(fetchImpl.mock.calls.some(([, init]) => init?.body === JSON.stringify({ stream_id: stream }))).toBe(true);
    for (const invalid of ['not-opaque', '018F47A0-9B5C-7A22-8A33-112233445599']) await expect(client.camera(invalid)).rejects.toThrow('Invalid camera id');
  });

  it('rejects unsafe camera fields, bounds violations, media types, and error statuses', async () => {
    const id = '018f47a0-9b5c-7a22-8a33-112233445599';
    const base = { camera_id: id, classification: 'camera', confidence: 0.5, health: 'healthy', observed_at: '2026-01-01T00:00:00Z', inventory: null, streams: [] };
    for (const malformed of [{ ...base, endpoint: 'rtsp://unsafe' }, { ...base, confidence: 2 }, { ...base, classification: 'invented' }]) {
      await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl: vi.fn(async () => new Response(JSON.stringify(malformed), { status: 200 })) }).camera(id)).rejects.toThrow('Invalid camera response');
    }
    await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl: vi.fn(async () => new Response(new Uint8Array(1), { status: 200, headers: { 'content-type': 'image/png' } })) }).cameraSnapshot(id)).rejects.toThrow('media type');
    await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl: vi.fn(async () => new Response(null, { status: 503 })) }).closeCameraSession(id)).rejects.toThrow('503');
  });

  it('enforces lowercase canonical opaque IDs, confidence/enums, and 128-byte inventory bounds', async () => {
    const id = 'abcdef01-2345-0000-0000-000000000001';
    const inventory = (size: number) => ({ manufacturer: 'x'.repeat(size), model: null, firmware: null, serial: null, capabilities: ['x'.repeat(size)], health: 'healthy' });
    const summary = { camera_id: id, classification: 'camera', confidence: 0, health: 'healthy', observed_at: '2026-01-01T00:00:00Z' };
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/inventory')) return new Response(JSON.stringify(inventory(128)), { status: 200 });
      return new Response(JSON.stringify({ ...summary, inventory: inventory(128), streams: [] }), { status: 200 });
    });
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl });
    await expect(client.camera(id)).resolves.toMatchObject({ camera_id: id });
    await expect(client.cameraInventory(id)).resolves.toEqual(inventory(128));
    for (const invalid of [id.toUpperCase(), '00000000-0000-0000-0000-00000000001', 'not-an-id']) {
      await expect(client.camera(invalid)).rejects.toThrow('Invalid camera id');
    }
    for (const malformed of [
      { ...summary, confidence: -0.01, inventory: inventory(128), streams: [] },
      { ...summary, confidence: 1.01, inventory: inventory(128), streams: [] },
      { ...summary, classification: 'invented', inventory: inventory(128), streams: [] },
      { ...summary, health: 'invented', inventory: inventory(128), streams: [] },
      { ...summary, inventory: inventory(129), streams: [] },
      { ...summary, inventory: inventory(128), streams: Array.from({ length: 65 }, () => ({ stream_id: id })) },
      { ...summary, inventory: inventory(128), streams: [{ stream_id: 'not-an-id' }] },
      { ...summary, inventory: inventory(128), streams: [{ stream_id: id, source_ref: 'rtsp://secret.invalid' }] },
    ]) {
      const bad = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl: vi.fn(async () => new Response(JSON.stringify(malformed), { status: 200 })) });
      await expect(bad.camera(id)).rejects.toThrow('Invalid camera response');
    }
  });

  it('accepts a fully typed snapshot and rejects malformed nested projections', async () => {
    const snapshot = { sequence: 1, devices: [validDevice], next_after: null, service_status: 'ready' };
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(snapshot), { status: 200 }));
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl });
    await expect(client.snapshot()).resolves.toEqual(snapshot);
    for (const mutate of [
      (d: any) => { d.bandwidth = { ...d.bandwidth, available: false, upload: 0 }; },
      (d: any) => { d.bandwidth = { available: true, upload: 1, download: null, coverage: 'complete', observed_at: 'now' }; },
      (d: any) => { d.bandwidth = { available: true, upload: Number.MAX_SAFE_INTEGER + 1, download: 0, coverage: 'complete', observed_at: 'now' }; },
      (d: any) => { d.identity = { available: false, classification: 'router', confidence: null }; },
      (d: any) => { d.identity = { available: true, classification: null, confidence: 0.5 }; },
      (d: any) => { d.presence = { state: 'unknown', observed_at: 'bad', source: null, kind: null }; },
      (d: any) => { d.presence = { state: 'online', observed_at: null, source: null, kind: null }; },
      (d: any) => { d.evidence = { family: 'link_layer', source: 'mdns', confidence: 2, observed_at: 'now', expires_at: null }; }
    ]) {
      const malformed = structuredClone(snapshot);
      mutate(malformed.devices[0]);
      const badFetch = vi.fn(async () => new Response(JSON.stringify(malformed), { status: 200 }));
      await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl: badFetch }).snapshot()).rejects.toThrow('Invalid snapshot response');
    }
    for (const mutate of [
      (value: any) => { value.devices[0].device_id = 'not-a-device-id'; },
      (value: any) => { value.devices[0].evidence = { family: 'not-a-family', source: 'mdns', confidence: 0.5, observed_at: 'now', expires_at: null }; },
      (value: any) => { value.next_after = 'not-a-device-id'; }
    ]) {
      const malformed = structuredClone(snapshot);
      mutate(malformed);
      const badFetch = vi.fn(async () => new Response(JSON.stringify(malformed), { status: 200 }));
      await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl: badFetch }).snapshot()).rejects.toThrow('Invalid snapshot response');
    }
  });

  it('accepts a durable policy snapshot and rejects inconsistent nested policy state', async () => {
    const policy = {
      owner_decision: 'quarantined', protection: 'none',
      evaluation: { policy_version: 1, reason: 'owner_quarantined', requested_action: 'quarantine', deadline: null, warning: null },
      enforcement_result: 'verified', undo_available: true, delivery_pending: false
    };
    const snapshot = { sequence: 1, devices: [{ ...validDevice, policy }], next_after: null, service_status: 'ready' };
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(snapshot), { status: 200 }));
    await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl }).snapshot()).resolves.toEqual(snapshot);

    for (const malformedPolicy of [
      { ...policy, owner_decision: 'invented' },
      { ...policy, protection: 'administrator_laptop' },
      { ...policy, evaluation: { ...policy.evaluation, requested_action: 'permanent_ban', reason: 'owner_quarantined' } },
      { ...policy, enforcement_result: 'success' },
      { ...policy, delivery_pending: 'yes' }
    ]) {
      const malformed = { ...snapshot, devices: [{ ...validDevice, policy: malformedPolicy }] };
      const badFetch = vi.fn(async () => new Response(JSON.stringify(malformed), { status: 200 }));
      await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl: badFetch }).snapshot()).rejects.toThrow('Invalid snapshot response');
    }
  });

  it('accepts an unknown presence transition only with complete provenance', async () => {
    const transitioned: any = structuredClone(validDevice);
    transitioned.presence = {
      state: 'unknown',
      observed_at: '2026-01-01T00:00:02Z',
      source: 'sensor-impairment',
      kind: 'contradiction'
    };
    const snapshot = { sequence: 1, devices: [transitioned], next_after: null, service_status: 'ready' };
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(snapshot), { status: 200 }));

    await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl }).snapshot()).resolves.toEqual(snapshot);
  });

  it('accepts canonical UTC timestamps, including fractional seconds, in state projections', async () => {
    const device: any = structuredClone(validDevice);
    device.first_seen_at = '2026-01-01T00:00:00.123Z';
    device.last_seen_at = '2026-01-01T00:00:01.123456Z';
    device.presence = { state: 'online', observed_at: '2026-01-01T00:00:02.1Z', source: 'sensor', kind: 'reply' };
    device.evidence = { family: 'link_layer', source: 'neighbor', confidence: 0.5, observed_at: '2026-01-01T00:00:03.12Z', expires_at: '2026-01-01T00:00:04.123456789Z' };
    device.bandwidth = { available: true, upload: 1, download: 2, coverage: 'complete', observed_at: '2026-01-01T00:00:05.123Z' };
    const snapshot = { sequence: 1, devices: [device], next_after: null, service_status: 'ready' };
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(snapshot), { status: 200 }));

    await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl }).snapshot()).resolves.toEqual(snapshot);
  });

  it('rejects invalid, impossible, and non-UTC timestamps in nested projections', async () => {
    const snapshot = { sequence: 1, devices: [validDevice], next_after: null, service_status: 'ready' };
    for (const mutate of [
      (d: any) => { d.first_seen_at = 'bad'; },
      (d: any) => { d.last_seen_at = '2026-02-30T00:00:00Z'; },
      (d: any) => { d.presence = { state: 'online', observed_at: '2026-01-01T00:00:00+01:00', source: 'sensor', kind: 'reply' }; },
      (d: any) => { d.evidence = { family: 'link_layer', source: 'neighbor', confidence: 0.5, observed_at: '2026-01-01T00:00:00Z', expires_at: '2026-02-30T00:00:00Z' }; },
      (d: any) => { d.bandwidth = { available: true, upload: 1, download: 2, coverage: 'complete', observed_at: '2026-01-01T00:00:00+00:00' }; }
    ]) {
      const malformed = structuredClone(snapshot);
      mutate(malformed.devices[0]);
      const fetchImpl = vi.fn(async () => new Response(JSON.stringify(malformed), { status: 200 }));
      await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl }).snapshot()).rejects.toThrow('Invalid snapshot response');
    }
  });

  it('requests validated snapshot pages while keeping the default path unchanged', async () => {
    const snapshot = { sequence: 1, devices: [], next_after: null, service_status: 'ready' };
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(snapshot), { status: 200 }));
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl });

    await client.snapshot();
    await client.snapshot({ limit: 2, after: '018f47a0-9b5c-7a22-8a33-112233445599' });

    expect(fetchImpl).toHaveBeenNthCalledWith(1, 'https://collector.example/api/v1/state', {
      method: 'GET', headers: { Authorization: 'Bearer secret' }
    });
    expect(fetchImpl).toHaveBeenNthCalledWith(2, 'https://collector.example/api/v1/state?limit=2&after=018f47a0-9b5c-7a22-8a33-112233445599', {
      method: 'GET', headers: { Authorization: 'Bearer secret' }
    });
  });

  it('hydrates all snapshot pages at one sequence and rejects cursor cycles', async () => {
    const id = '018f47a0-9b5c-7a22-8a33-112233445599';
    const page = (devices: unknown[], next_after: string | null) => ({ sequence: 9, devices, next_after, service_status: 'ready' });
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(page([], id)), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(page([], null)), { status: 200 }));
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl });
    await expect(client.snapshotAll({ limit: 1 })).resolves.toMatchObject({ sequence: 9, devices: [] });
    expect(fetchImpl).toHaveBeenCalledTimes(2);

    const cycleFetch = vi.fn(async () => new Response(JSON.stringify(page([], id)), { status: 200 }));
    await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl: cycleFetch }).snapshotAll()).rejects.toThrow('cursor cycle');
  });

  it('rejects a paginated sequence watermark change', async () => {
    const id = '018f47a0-9b5c-7a22-8a33-445566778899';
    const response = (sequence: number) => new Response(JSON.stringify({ sequence, devices: [], next_after: null, service_status: 'ready' }), { status: 200 });
    const fetchImpl = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ sequence: 1, devices: [], next_after: id, service_status: 'ready' }), { status: 200 })).mockResolvedValueOnce(response(2));
    await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl }).snapshotAll()).rejects.toThrow('sequence changed');
  });

  it('rejects invalid snapshot pages before fetching', async () => {
    const fetchImpl = vi.fn();
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl });

    for (const options of [
      { limit: 0 }, { limit: 257 }, { limit: 1.5 }, { limit: Number.MAX_SAFE_INTEGER + 1 },
      { after: 'not-a-device-id' }, { after: '018F47A0-9B5C-7A22-8A33-112233445599' }
    ]) {
      await expect(client.snapshot(options)).rejects.toThrow('Invalid snapshot page');
    }
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('accepts only nonnegative safe integer sequences', () => {
    expect(isSequence(0)).toBe(true);
    expect(isSequence(Number.MAX_SAFE_INTEGER)).toBe(true);
    expect(isSequence(-1)).toBe(false);
    expect(isSequence(1.5)).toBe(false);
    expect(isSequence(Number.MAX_SAFE_INTEGER + 1)).toBe(false);
  });

  it('uses bearer authorization only for ticket issuance and puts only the ticket in the websocket URL', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ ticket: 'single-use ticket', expires_in_seconds: 60 }), { status: 200 }));
    const sockets: string[] = [];
    class FakeWebSocket {
      onopen: (() => void) | null = null;
      onclose: (() => void) | null = null;
      onerror: (() => void) | null = null;
      onmessage: ((event: MessageEvent<string>) => void) | null = null;
      constructor(url: string) { sockets.push(url); queueMicrotask(() => this.onopen?.()); }
    }
    const client = createApiClient({
      baseUrl: 'https://collector.example',
      serviceToken: 'secret-service-token',
      fetchImpl,
      WebSocketImpl: FakeWebSocket as unknown as typeof WebSocket
    });

    await client.openEvents(7, vi.fn(), vi.fn());

    expect(fetchImpl).toHaveBeenCalledWith('https://collector.example/api/v1/events/ticket', {
      method: 'POST',
      headers: { Authorization: 'Bearer secret-service-token' }
    });
    expect(sockets).toEqual(['wss://collector.example/api/v1/events?ticket=single-use+ticket&after_sequence=7']);
    expect(sockets[0]).not.toContain('secret-service-token');
  });

  it('rejects an invalid cursor before issuing a ticket or opening a socket', async () => {
    const fetchImpl = vi.fn();
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl });

    await expect(client.openEvents(-1, vi.fn(), vi.fn())).rejects.toThrow('Invalid event sequence');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('keeps openEvents working when destructured from the client', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ ticket: 'ticket', expires_in_seconds: 60 }), { status: 200 }));
    class FakeWebSocket { onopen = null; onclose = null; onerror = null; onmessage = null; constructor(_: string) {} }
    const { openEvents } = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl, WebSocketImpl: FakeWebSocket as unknown as typeof WebSocket });

    await expect(openEvents(0, vi.fn(), vi.fn())).resolves.toBeInstanceOf(FakeWebSocket);
  });

  it('rejects malformed health, snapshot, and ticket responses', async () => {
    const responses = [
      new Response(JSON.stringify({ status: 42, api_version: 'v1' }), { status: 200 }),
      new Response(JSON.stringify({ sequence: 1.5, devices: [], next_after: null, service_status: 'ready' }), { status: 200 }),
      new Response(JSON.stringify({ ticket: '', expires_in_seconds: Number.MAX_SAFE_INTEGER + 1 }), { status: 200 })
    ];
    const fetchImpl = vi.fn(async () => responses.shift()!);
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl });

    await expect(client.health()).rejects.toThrow('Invalid health response');
    await expect(client.snapshot()).rejects.toThrow('Invalid snapshot response');
    await expect(client.issueEventTicket()).rejects.toThrow('Invalid event ticket response');
  });

  it('ignores malformed payloads and unsafe event sequences in websocket frames', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ ticket: 'ticket', expires_in_seconds: 60 }), { status: 200 }));
    class FakeWebSocket { onopen = null; onclose = null; onerror = null; onmessage: ((event: MessageEvent<string>) => void) | null = null; constructor(_: string) {} }
    const onMessage = vi.fn();
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl, WebSocketImpl: FakeWebSocket as unknown as typeof WebSocket });
    const socket = await client.openEvents(0, onMessage, vi.fn()) as unknown as FakeWebSocket;

    for (const sequence of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      socket.onmessage?.({ data: JSON.stringify({ type: 'event', data: { sequence, occurred_at: '2026-08-23T00:00:00Z', payload: { type: 'service_status', data: { state: 'ready', detail: 'valid except sequence' } } } }) } as MessageEvent<string>);
    }
    for (const occurred_at of ['not-a-date', '2026-08-23T00:00:00+00:00']) {
      socket.onmessage?.({ data: JSON.stringify({ type: 'event', data: { sequence: 1, occurred_at, payload: { type: 'service_status', data: { state: 'ready', detail: 'valid except timestamp' } } } }) } as MessageEvent<string>);
    }
    socket.onmessage?.({ data: JSON.stringify({ type: 'event', data: { sequence: 1, occurred_at: '2026-08-23T00:00:00Z', payload: { type: 'service_status', data: { state: 1, detail: 'bad' } } } }) } as MessageEvent<string>);
    expect(onMessage).not.toHaveBeenCalled();
  });

  it('accepts a canonical fractional UTC timestamp in websocket frames', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ ticket: 'ticket', expires_in_seconds: 60 }), { status: 200 }));
    class FakeWebSocket { onopen = null; onclose = null; onerror = null; onmessage: ((event: MessageEvent<string>) => void) | null = null; constructor(_: string) {} }
    const onMessage = vi.fn();
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl, WebSocketImpl: FakeWebSocket as unknown as typeof WebSocket });
    const socket = await client.openEvents(0, onMessage, vi.fn()) as unknown as FakeWebSocket;
    const message = { type: 'event', data: { sequence: 1, occurred_at: '2026-08-23T00:00:00.123456789Z', payload: { type: 'service_status', data: { state: 'ready', detail: 'fractional UTC' } } } };

    socket.onmessage?.({ data: JSON.stringify(message) } as MessageEvent<string>);

    expect(onMessage).toHaveBeenCalledWith(message);
  });

  it('accepts a complete policy lifecycle event and rejects unsafe policy projections', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ ticket: 'ticket', expires_in_seconds: 60 }), { status: 200 }));
    class FakeWebSocket { onopen = null; onclose = null; onerror = null; onmessage: ((event: MessageEvent<string>) => void) | null = null; constructor(_: string) {} }
    const onMessage = vi.fn();
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl, WebSocketImpl: FakeWebSocket as unknown as typeof WebSocket });
    const socket = await client.openEvents(0, onMessage, vi.fn()) as unknown as FakeWebSocket;
    const policy = {
      device_id: validDevice.device_id,
      policy_version: 1,
      evaluation: {
        policy_version: 1,
        reason: 'pending_confirmation',
        requested_action: 'none',
        deadline: { kind: 'unknown48_hours', due_at: '2026-08-25T00:00:00Z' },
        warning: 'hours24'
      },
      requested_action: 'none',
      evidence_summary: 'identity=unknown;risk=none',
      enforcement_result: 'not_requested',
      undo_available: false
    };
    const event = (data: unknown) => ({ type: 'event', data: { sequence: 1, occurred_at: '2026-08-23T00:00:00Z', payload: { type: 'policy_changed', data } } });

    socket.onmessage?.({ data: JSON.stringify(event(policy)) } as MessageEvent<string>);
    socket.onmessage?.({ data: JSON.stringify(event({ ...policy, requested_action: 'invented_action' })) } as MessageEvent<string>);
    socket.onmessage?.({ data: JSON.stringify(event({ ...policy, evaluation: { ...policy.evaluation, deadline: { kind: 'unknown48_hours', due_at: 'not-a-date' } } })) } as MessageEvent<string>);
    socket.onmessage?.({ data: JSON.stringify(event({ ...policy, enforcement_result: 'success' })) } as MessageEvent<string>);

    expect(onMessage).toHaveBeenCalledTimes(1);
    expect(onMessage).toHaveBeenCalledWith(event(policy));
  });

  it('requires the canonical correction_of key on presence events', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ ticket: 'ticket', expires_in_seconds: 60 }), { status: 200 }));
    class FakeWebSocket { onopen = null; onclose = null; onerror = null; onmessage: ((event: MessageEvent<string>) => void) | null = null; constructor(_: string) {} }
    const onMessage = vi.fn();
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl, WebSocketImpl: FakeWebSocket as unknown as typeof WebSocket });
    const socket = await client.openEvents(0, onMessage, vi.fn()) as unknown as FakeWebSocket;
    const data = {
      transition_id: 1, device_id: validDevice.device_id, from: 'unknown', to: 'online', reason: 'observed',
      occurred_at: '2026-08-23T00:00:00Z', trigger_source: 'sensor', trigger_kind: 'reply',
      evidence_observed_at: '2026-08-23T00:00:00Z', evidence_valid_until: null, trigger_arrival_at: '2026-08-23T00:00:00Z', correction_of: null
    };
    const event = (presence: unknown) => ({ type: 'event', data: { sequence: 1, occurred_at: '2026-08-23T00:00:00Z', payload: { type: 'presence_changed', data: presence } } });
    const { correction_of: _correctionOf, ...withoutCorrectionOf } = data;

    socket.onmessage?.({ data: JSON.stringify(event(data)) } as MessageEvent<string>);
    socket.onmessage?.({ data: JSON.stringify(event(withoutCorrectionOf)) } as MessageEvent<string>);
    socket.onmessage?.({ data: JSON.stringify(event({ ...data, correction_of: -1 })) } as MessageEvent<string>);

    expect(onMessage).toHaveBeenCalledTimes(1);
    expect(onMessage).toHaveBeenCalledWith(event(data));
  });
});
