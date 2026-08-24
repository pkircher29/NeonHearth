import type { ApiClient } from '../api/client';
import type { ServerMessage } from '../api/types';
import { applySnapshot, initialLiveState, reduceLiveMessage, type LiveState } from './live';

export interface SessionTimers { setTimeout: (callback: () => void, delay: number) => unknown; clearTimeout: (timer: unknown) => void }
export interface LiveConnectionOptions { client: ApiClient; onState?: (state: LiveState) => void; timers?: SessionTimers; maxReconnectDelayMs?: number }
export interface LiveConnection { start(): Promise<void>; stop(): void; getState(): LiveState }

const defaultTimers: SessionTimers = { setTimeout: (callback, delay) => globalThis.setTimeout(callback, delay), clearTimeout: (timer) => globalThis.clearTimeout(timer as ReturnType<typeof setTimeout>) };

export function createLiveConnection({ client, onState, timers = defaultTimers, maxReconnectDelayMs = 30_000 }: LiveConnectionOptions): LiveConnection {
  let state = initialLiveState;
  let socket: WebSocket | undefined;
  let retryTimer: unknown;
  let stopped = true;
  let generation = 0;
  let retry = 0;
  let hydrationGeneration: number | undefined;
  let pendingHydration = false;
  const publish = () => onState?.(state);
  const isCurrent = (token: number) => !stopped && token === generation;
  const cancelRetry = () => { if (retryTimer !== undefined) { timers.clearTimeout(retryTimer); retryTimer = undefined; } };
  const closeSocket = () => { const closing = socket; socket = undefined; closing?.close(); };

  const hydrateAndOpen = async (token: number): Promise<void> => {
    if (!isCurrent(token)) return;
    if (hydrationGeneration !== undefined) { pendingHydration = true; return; }
    hydrationGeneration = token;
    try {
      const snapshot = await client.snapshotAll();
      if (!isCurrent(token)) return;
      state = applySnapshot(state, snapshot);
      publish();
      const opened = await client.openEvents(state.sequence, handleMessage, (socketState) => handleSocketState(token, socketState));
      if (!isCurrent(token)) { opened.close(); return; }
      socket = opened;
      retry = 0;
      cancelRetry();
    } catch {
      scheduleReconnect(token);
    } finally {
      hydrationGeneration = undefined;
      if (pendingHydration) { pendingHydration = false; if (!stopped) void hydrateAndOpen(generation); }
    }
  };
  const resync = () => { if (stopped) return; generation += 1; cancelRetry(); closeSocket(); state = { ...state, connected: false }; publish(); void hydrateAndOpen(generation); };
  const handleMessage = (message: ServerMessage) => { const next = reduceLiveMessage(state, message); state = next; publish(); if (next.needsResync) resync(); };
  const handleSocketState = (token: number, socketState: 'open' | 'closed' | 'error') => { if (!isCurrent(token)) return; if (socketState === 'open') { state = { ...state, connected: true }; retry = 0; publish(); } else { state = { ...state, connected: false }; publish(); scheduleReconnect(token); } };
  const scheduleReconnect = (token: number) => { if (!isCurrent(token) || retryTimer !== undefined) return; const delay = Math.min(maxReconnectDelayMs, 250 * (2 ** retry)); retry += 1; retryTimer = timers.setTimeout(() => { retryTimer = undefined; if (isCurrent(token)) void hydrateAndOpen(token); }, delay); };
  return {
    async start() { if (!stopped) return; stopped = false; generation += 1; retry = 0; await hydrateAndOpen(generation); },
    stop() { stopped = true; generation += 1; pendingHydration = false; cancelRetry(); closeSocket(); state = { ...state, connected: false }; publish(); },
    getState() { return state; }
  };
}
