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
    expect(states).toContain('4:false');
  });

  it('keeps a hydrated snapshot disconnected until the websocket opens', async () => {
    let onState: ((state: 'open' | 'closed' | 'error') => void) | undefined;
    const client = clientStub({ openEvents: vi.fn(async (_sequence, _onMessage, callback) => {
      onState = callback;
      return { close: vi.fn() } as unknown as WebSocket;
    }) });
    const connection = createLiveConnection({ client });

    await connection.start();
    expect(connection.getState().connected).toBe(false);
    onState?.('open');
    expect(connection.getState().connected).toBe(true);
    connection.stop();
  });

  it('marks a failed websocket attempt disconnected before retrying', async () => {
    const timers = { setTimeout: vi.fn(() => 1), clearTimeout: vi.fn() };
    const client = clientStub({ openEvents: vi.fn(async () => { throw new Error('ticket rejected'); }) });
    const connection = createLiveConnection({ client, timers });

    await connection.start();
    expect(connection.getState().connected).toBe(false);
    expect(timers.setTimeout).toHaveBeenCalledTimes(1);
    connection.stop();
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

  it('ignores a stale close during resync and clears the stale retry before opening one replacement stream', async () => {
    let receive: ((message: { type: 'resync_required' }) => void) | undefined;
    let close: (() => void) | undefined;
    const timers = { setTimeout: vi.fn(() => 1), clearTimeout: vi.fn() };
    const client = clientStub({
      openEvents: vi.fn(async (_sequence, onMessage, onState) => {
        receive = onMessage as typeof receive;
        close = () => onState('closed');
        return { close } as unknown as WebSocket;
      })
    });
    const connection = createLiveConnection({ client, timers });

    await connection.start();
    receive?.({ type: 'resync_required' });
    close?.();
    await Promise.resolve();
    await Promise.resolve();

    expect(client.snapshotAll).toHaveBeenCalledTimes(2);
    expect(client.openEvents).toHaveBeenCalledTimes(2);
    expect(timers.setTimeout).not.toHaveBeenCalled();
    connection.stop();
  });

  it('cancels a pending retry when an explicit resync succeeds and ignores its late timer callback', async () => {
    let receive: ((message: { type: 'resync_required' }) => void) | undefined;
    let close: (() => void) | undefined;
    let retryCallback: (() => void) | undefined;
    const timers = {
      setTimeout: vi.fn((callback: () => void) => { retryCallback = callback; return 7; }),
      clearTimeout: vi.fn()
    };
    const client = clientStub({
      openEvents: vi.fn(async (_sequence, onMessage, onState) => {
        receive = onMessage as typeof receive;
        close = () => onState('closed');
        return { close } as unknown as WebSocket;
      })
    });
    const connection = createLiveConnection({ client, timers });

    await connection.start();
    close?.();
    expect(timers.setTimeout).toHaveBeenCalledTimes(1);
    receive?.({ type: 'resync_required' });
    await Promise.resolve();
    await Promise.resolve();
    retryCallback?.();
    await Promise.resolve();

    expect(timers.clearTimeout).toHaveBeenCalledWith(7);
    expect(client.snapshotAll).toHaveBeenCalledTimes(2);
    expect(client.openEvents).toHaveBeenCalledTimes(2);
    connection.stop();
  });

  it('closes an errored stream before a retry opens its replacement', async () => {
    let fail: (() => void) | undefined;
    let retryCallback: (() => void) | undefined;
    const firstClose = vi.fn();
    const timers = { setTimeout: vi.fn((callback: () => void) => { retryCallback = callback; return 9; }), clearTimeout: vi.fn() };
    const client = clientStub({
      openEvents: vi.fn(async (_sequence, _onMessage, onState) => {
        fail = () => onState('error');
        return { close: firstClose } as unknown as WebSocket;
      })
    });
    const connection = createLiveConnection({ client, timers });

    await connection.start();
    fail?.();
    retryCallback?.();
    await Promise.resolve();
    await Promise.resolve();

    expect(firstClose).toHaveBeenCalledTimes(1);
    expect(client.openEvents).toHaveBeenCalledTimes(2);
    connection.stop();
  });

  it('backs off repeated pre-open failures and resets only after a socket opens', async () => {
    const socketStates: Array<(state: 'open' | 'closed' | 'error') => void> = [];
    const retryCallbacks: Array<() => void> = [];
    const delays: number[] = [];
    const timers = {
      setTimeout: vi.fn((callback: () => void, delay: number) => {
        retryCallbacks.push(callback);
        delays.push(delay);
        return retryCallbacks.length;
      }),
      clearTimeout: vi.fn()
    };
    const client = clientStub({
      openEvents: vi.fn(async (_sequence, _onMessage, onState) => {
        socketStates.push(onState);
        return { close: vi.fn() } as unknown as WebSocket;
      })
    });
    const connection = createLiveConnection({ client, timers });

    await connection.start();
    socketStates[0]?.('closed');
    expect(delays).toEqual([250]);

    retryCallbacks[0]?.();
    await Promise.resolve();
    await Promise.resolve();
    socketStates[1]?.('error');
    expect(delays).toEqual([250, 500]);

    retryCallbacks[1]?.();
    await Promise.resolve();
    await Promise.resolve();
    socketStates[2]?.('open');
    socketStates[2]?.('closed');
    expect(delays).toEqual([250, 500, 250]);

    connection.stop();
  });
});
