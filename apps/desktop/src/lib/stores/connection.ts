import type { ApiClient } from '../api/client';
import type { ServerMessage } from '../api/types';
import { applySnapshot, initialLiveState, reduceLiveMessage, type LiveState } from './live';

export interface SessionTimers { setTimeout: (callback: () => void, delay: number) => unknown; clearTimeout: (timer: unknown) => void }
export interface LiveConnectionOptions {
  client: ApiClient;
  onState?: (state: LiveState) => void;
  timers?: SessionTimers;
  maxReconnectDelayMs?: number;
  /** Jitter source in [0, 1); injected by tests. Retries wait `base * (0.5 + random())`. */
  random?: () => number;
  /** A socket that reports no `open` within this window is treated as failed (0 disables). */
  openTimeoutMs?: number;
  /** No server message for this long on an open socket triggers a resync (0 disables). */
  staleAfterMs?: number;
}
export interface LiveConnection { start(): Promise<void>; stop(): void; getState(): LiveState }

const defaultTimers: SessionTimers = { setTimeout: (callback, delay) => globalThis.setTimeout(callback, delay), clearTimeout: (timer) => globalThis.clearTimeout(timer as ReturnType<typeof setTimeout>) };

export function createLiveConnection({ client, onState, timers = defaultTimers, maxReconnectDelayMs = 30_000, random = Math.random, openTimeoutMs = 10_000, staleAfterMs = 20_000 }: LiveConnectionOptions): LiveConnection {
  let state = initialLiveState;
  let socket: WebSocket | undefined;
  let retryTimer: unknown;
  let openTimer: unknown;
  let staleTimer: unknown;
  let stopped = true;
  let generation = 0;
  let retry = 0;
  let socketEpoch = 0;
  let hydrationGeneration: number | undefined;
  let hydrationAbort: AbortController | undefined;
  let pendingHydration = false;
  const publish = () => onState?.(state);
  const isCurrent = (token: number) => !stopped && token === generation;
  const cancelRetry = () => { if (retryTimer !== undefined) { timers.clearTimeout(retryTimer); retryTimer = undefined; } };
  const cancelWatchdogs = () => {
    if (openTimer !== undefined) { timers.clearTimeout(openTimer); openTimer = undefined; }
    if (staleTimer !== undefined) { timers.clearTimeout(staleTimer); staleTimer = undefined; }
  };
  const closeSocket = () => { cancelWatchdogs(); socketEpoch += 1; const closing = socket; socket = undefined; closing?.close(); };

  // A half-open socket (sleep, NAT expiry) fires neither close nor error, so
  // liveness is inferred from traffic: silence past the window means resync.
  const armStaleWatchdog = (token: number, epoch: number) => {
    if (staleAfterMs <= 0) return;
    if (staleTimer !== undefined) timers.clearTimeout(staleTimer);
    staleTimer = timers.setTimeout(() => {
      staleTimer = undefined;
      if (!isCurrent(token) || epoch !== socketEpoch) return;
      resync();
    }, staleAfterMs);
  };

  const hydrateAndOpen = async (token: number): Promise<void> => {
    if (!isCurrent(token)) return;
    if (hydrationGeneration !== undefined) { pendingHydration = true; return; }
    hydrationGeneration = token;
    const abort = new AbortController();
    hydrationAbort = abort;
    try {
      const snapshot = await client.snapshotAll({ signal: abort.signal });
      if (!isCurrent(token)) return;
      state = applySnapshot(state, snapshot);
      publish();
      const epoch = ++socketEpoch;
      const opened = await client.openEvents(state.sequence, handleMessage, (socketState) => handleSocketState(token, epoch, socketState));
      if (!isCurrent(token) || epoch !== socketEpoch) { opened.close(); return; }
      socket = opened;
      cancelRetry();
      // Construction is not connection: the backoff resets only in the open
      // handler, so a socket that closes immediately keeps escalating.
      if (openTimeoutMs > 0) {
        openTimer = timers.setTimeout(() => {
          openTimer = undefined;
          if (!isCurrent(token) || epoch !== socketEpoch) return;
          handleSocketState(token, epoch, 'error');
        }, openTimeoutMs);
      }
    } catch {
      if (!abort.signal.aborted) scheduleReconnect(token);
    } finally {
      if (hydrationAbort === abort) hydrationAbort = undefined;
      hydrationGeneration = undefined;
      if (pendingHydration) { pendingHydration = false; if (!stopped) void hydrateAndOpen(generation); }
    }
  };
  const resync = () => { if (stopped) return; generation += 1; cancelRetry(); closeSocket(); state = { ...state, connected: false }; publish(); void hydrateAndOpen(generation); };
  const handleMessage = (message: ServerMessage) => {
    const next = reduceLiveMessage(state, message); state = next; publish();
    if (next.needsResync) { resync(); return; }
    if (socket) armStaleWatchdog(generation, socketEpoch);
  };
  const handleSocketState = (token: number, epoch: number, socketState: 'open' | 'closed' | 'error') => {
    if (!isCurrent(token) || epoch !== socketEpoch) return;
    if (socketState === 'open') {
      if (openTimer !== undefined) { timers.clearTimeout(openTimer); openTimer = undefined; }
      state = { ...state, connected: true }; retry = 0; publish();
      armStaleWatchdog(token, epoch);
    } else {
      cancelWatchdogs();
      const closing = socket; socket = undefined; socketEpoch += 1; closing?.close();
      state = { ...state, connected: false }; publish();
      scheduleReconnect(token);
    }
  };
  const scheduleReconnect = (token: number) => {
    if (!isCurrent(token) || retryTimer !== undefined) return;
    const base = Math.min(maxReconnectDelayMs, 250 * (2 ** retry));
    // Jitter keeps the desktop and phone from reconnecting in lockstep.
    const delay = Math.round(base * (0.5 + random()));
    retry += 1;
    retryTimer = timers.setTimeout(() => { retryTimer = undefined; if (isCurrent(token)) void hydrateAndOpen(token); }, delay);
  };
  return {
    async start() { if (!stopped) return; stopped = false; generation += 1; retry = 0; await hydrateAndOpen(generation); },
    stop() {
      stopped = true; generation += 1; pendingHydration = false;
      cancelRetry(); closeSocket();
      hydrationAbort?.abort(new Error('Connection stopped')); hydrationAbort = undefined;
      state = { ...state, connected: false }; publish();
    },
    getState() { return state; }
  };
}
