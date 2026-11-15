<script lang="ts">
  export type CollectorState = 'ready' | 'connecting' | 'offline';
  interface Props { state?: CollectorState; }
  let { state = 'connecting' }: Props = $props();
  const statusText: Record<CollectorState, string> = { ready: 'Collector reachable', connecting: 'Checking collector', offline: 'Collector unavailable' };
</script>

<section class:ready={state === 'ready'} class:offline={state === 'offline'} class="collector-status" aria-live="polite" aria-atomic="true">
  <div class="signal" aria-hidden="true"><span></span><span></span><span></span></div>
  <div class="status-copy">
    <p class="status-label">{statusText[state]}</p>
    <p class="status-detail">{state === 'ready' ? 'The local collector is responding. Live data requires an authorized connection.' : state === 'offline' ? 'The local collector is not responding. Check that NeonHearth is running.' : 'Checking the local collector connection.'}</p>
  </div>
</section>
