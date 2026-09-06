<script lang="ts" module>
  import type { LiveState } from '../stores/live';
  export type CollectorState = 'ready' | 'connecting' | 'offline';
  /**
   * Derived from the live connection, not a one-shot health probe: `ready`
   * while the event socket is open, `connecting` before the first snapshot
   * ever arrived, `offline` once a known collector stops answering.
   */
  export function collectorStateFor(live: Pick<LiveState, 'connected' | 'serviceStatus' | 'sequence'>): CollectorState {
    if (live.connected) return 'ready';
    return live.serviceStatus === 'unknown' && live.sequence === 0 ? 'connecting' : 'offline';
  }
</script>

<script lang="ts">
  interface Props { state?: CollectorState; }
  let { state = 'connecting' }: Props = $props();
  const statusText: Record<CollectorState, string> = { ready: 'Collector connected', connecting: 'Reaching collector', offline: 'Collector unavailable' };
</script>

<section class:ready={state === 'ready'} class:offline={state === 'offline'} class="collector-status" aria-live="polite" aria-atomic="true">
  <div class="signal" aria-hidden="true"><span></span><span></span><span></span></div>
  <div class="status-copy">
    <p class="status-label">{statusText[state]}</p>
    <p class="status-detail">{state === 'ready' ? 'The live event stream is open. Readings update as your home changes.' : state === 'offline' ? 'The live stream dropped. Reconnecting with backoff; readings shown may be stale.' : 'Loading the first snapshot from the local collector.'}</p>
  </div>
</section>
