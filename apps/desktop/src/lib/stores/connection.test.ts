import { describe, expect, it, vi } from 'vitest';
import type { ApiClient } from '../api/client';
import { createLiveConnection } from './connection';

const clientStub = (overrides: Partial<ApiClient> = {}) => ({
  snapshotAll: vi.fn(async () => ({ sequence: 4, devices: [], next_after: null, service_status: 'ready' })),
  openEvents: vi.fn(async () => ({ close: vi.fn() } as unknown as WebSocket)),
  ...overrides
}) as unknown as ApiClient;

describe('createLiveConnection', () => {
  it('hydrates before opening events and stops without reconnecting', async () => {
    const client = clientStub();
    const states: string[] = [];
    const connection = createLiveConnection({ client, onState: (state) => states.push(`${state.sequence}:${state.connected}`) });
    await connection.start();
    expect(client.openEvents).toHaveBeenCalledWith(4, expect.any(Function), expect.any(Function));
    connection.stop();
    expect(connection.getState().connected).toBe(false);
    expect(states).toContain('4:true');
  });

  it('resyncs after a server resync request without replaying commands', async () => {
    let receive: ((message: { type: 'resync_required' }) => void) | undefined;
    const client = clientStub({ openEvents: vi.fn(async (_sequence, onMessage) => { receive = onMessage as typeof receive; return { close: vi.fn() } as unknown as WebSocket; }) });
    const timers = { setTimeout: vi.fn(() => 1), clearTimeout: vi.fn() };
    const connection = createLiveConnection({ client, timers });
    await connection.start();
    receive?.({ type: 'resync_required' });
    await Promise.resolve();
    expect(client.snapshotAll).toHaveBeenCalledTimes(2);
    expect(client.openEvents).toHaveBeenCalledTimes(2);
    connection.stop();
    expect(timers.setTimeout).not.toHaveBeenCalled();
  });
});
