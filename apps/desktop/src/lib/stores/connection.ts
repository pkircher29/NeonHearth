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
  let hydrating = false;
  let suppressSocketState = false;
  const publish = () => onState?.(state);
  const closeSocket = () => { suppressSocketState = true; socket?.close(); socket = undefined; suppressSocketState = false; };

  const hydrateAndOpen = async (token: number): Promise<void> => {
    if (stopped || token !== generation || hydrating) return;
    hydrating = true;
    try {
      const snapshot = await client.snapshotAll();
      if (stopped || token !== generation) return;
      state = applySnapshot(state, snapshot);
      publish();
      socket = await client.openEvents(state.sequence, handleMessage, handleSocketState);
      if (stopped || token !== generation) { socket.close(); socket = undefined; return; }
      retry = 0;
    } catch {
      scheduleReconnect();
    } finally { hydrating = false; }
  };
  const resync = () => { if (stopped) return; generation += 1; closeSocket(); state = { ...state, connected: false }; publish(); void hydrateAndOpen(generation); };
  const handleMessage = (message: ServerMessage) => { const next = reduceLiveMessage(state, message); state = next; publish(); if (next.needsResync) resync(); };
  const handleSocketState = (socketState: 'open' | 'closed' | 'error') => { if (stopped || suppressSocketState) return; if (socketState === 'open') { state = { ...state, connected: true }; retry = 0; publish(); } else { state = { ...state, connected: false }; publish(); scheduleReconnect(); } };
  const scheduleReconnect = () => { if (stopped || retryTimer !== undefined) return; const delay = Math.min(maxReconnectDelayMs, 250 * (2 ** retry)); retry += 1; retryTimer = timers.setTimeout(() => { retryTimer = undefined; void hydrateAndOpen(generation); }, delay); };
  return {
    async start() { if (!stopped) return; stopped = false; generation += 1; retry = 0; await hydrateAndOpen(generation); },
    stop() { stopped = true; generation += 1; if (retryTimer !== undefined) { timers.clearTimeout(retryTimer); retryTimer = undefined; } closeSocket(); state = { ...state, connected: false }; publish(); },
    getState() { return state; }
  };
}
