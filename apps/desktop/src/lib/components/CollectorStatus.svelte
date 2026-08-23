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
    <p class="status-detail">{state === 'ready' ? 'Public collector health is responding. Protected live data remains paired on this device.' : state === 'offline' ? 'The public health check is not responding. Protected live data has not been requested.' : 'Contacting the public health endpoint. Protected live data has not been requested.'}</p>
  </div>
</section>
