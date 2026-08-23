import { describe, expect, it, vi } from 'vitest';

import { createApiClient } from './client';

describe('createApiClient', () => {
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
});
