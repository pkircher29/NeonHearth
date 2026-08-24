import { describe, expect, it, vi } from 'vitest';

import { createApiClient, isSequence } from './client';

describe('createApiClient', () => {
  const validDevice = {
    device_id: '018f47a0-9b5c-7a22-8a33-112233445599', first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:01Z',
    owner_name: null, owner_type: null, owner_confirmed: false,
    presence: { state: 'unknown', observed_at: null, source: null, kind: null }, evidence: null,
    identity: { available: false, classification: null, confidence: null },
    bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null }
  };

  it('accepts a fully typed snapshot and rejects malformed nested projections', async () => {
    const snapshot = { sequence: 1, devices: [validDevice], next_after: null, service_status: 'ready' };
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(snapshot), { status: 200 }));
    const client = createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl });
    await expect(client.snapshot()).resolves.toEqual(snapshot);
    for (const mutate of [
      (d: any) => { d.bandwidth = { ...d.bandwidth, available: false, upload: 0 }; },
      (d: any) => { d.identity = { available: false, classification: 'router', confidence: null }; },
      (d: any) => { d.presence = { state: 'unknown', observed_at: 'bad', source: null, kind: null }; },
      (d: any) => { d.evidence = { family: 'link_layer', source: 'mdns', confidence: 2, observed_at: 'now', expires_at: null }; }
    ]) {
      const malformed = structuredClone(snapshot);
      mutate(malformed.devices[0]);
      const badFetch = vi.fn(async () => new Response(JSON.stringify(malformed), { status: 200 }));
      await expect(createApiClient({ baseUrl: 'https://collector.example', serviceToken: 'secret', fetchImpl: badFetch }).snapshot()).rejects.toThrow('Invalid snapshot response');
    }
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
    socket.onmessage?.({ data: JSON.stringify({ type: 'event', data: { sequence: 1, occurred_at: '2026-08-23T00:00:00Z', payload: { type: 'service_status', data: { state: 1, detail: 'bad' } } } }) } as MessageEvent<string>);
    expect(onMessage).not.toHaveBeenCalled();
  });
});
