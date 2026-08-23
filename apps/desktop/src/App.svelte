<script lang="ts">
  import { onMount } from 'svelte';
  import { createApiClient } from './lib/api/client';
  import CollectorStatus, { type CollectorState } from './lib/components/CollectorStatus.svelte';

  let collectorState: CollectorState = $state('connecting');
  onMount(() => {
    const publicClient = createApiClient({ baseUrl: window.location.origin, serviceToken: '' });
    void publicClient.health().then(() => { collectorState = 'ready'; }, () => { collectorState = 'offline'; });
  });
</script>

<svelte:head><title>NeonHearth — See your network breathe.</title></svelte:head>

<main>
  <header class="masthead">
    <p class="eyebrow">NEONHEARTH COLLECTOR</p>
    <span class="coordinate" aria-hidden="true">LIVE / LOCAL / PAIRING REQUIRED</span>
  </header>
  <div class="instrument" aria-hidden="true"><div class="orbit orbit-one"></div><div class="orbit orbit-two"></div><div class="trace"><i></i><i></i><i></i><i></i><i></i></div></div>
  <section class="hero" aria-labelledby="hero-title">
    <p class="thesis-mark" aria-hidden="true">∿</p>
    <h1 id="hero-title">See your<br />network breathe.</h1>
    <p class="lede">A quiet surface for the signals that matter. NeonHearth is standing by for its protected desktop pairing.</p>
  </section>
  <CollectorStatus state={collectorState} />
  <footer><span>Protected live data connects after secure desktop pairing is wired.</span><span class="footer-rule" aria-hidden="true"></span><span>NO DEVICE DATA YET</span></footer>
</main>
