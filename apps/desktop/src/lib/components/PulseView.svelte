<script lang="ts">
  import NetworkLung from './NetworkLung.svelte';
  export interface PulseEvent { time: string; title: string; detail: string; kind: 'info'|'watch'|'secure'; }
  interface Props { throughput?: number; events?: PulseEvent[]; paused?: boolean; }
  let { throughput = 0, events = [], paused = false }: Props = $props();
</script>
<section class="pulse-view" aria-labelledby="pulse-heading">
  <div class="view-heading"><div><p class="kicker">PULSE / NOW</p><h1 id="pulse-heading">Your network, breathing.</h1><p class="muted">A calm read of what is happening at home.</p></div><button class="pause-button" aria-pressed={paused} title="Pause animation">{paused ? 'Resume motion' : 'Pause motion'}</button></div>
  <div class="lung-panel"><NetworkLung {throughput} {paused}/><div class="lung-caption"><span class="status-dot"></span><strong>Protected pairing is waiting</strong><span class="muted">Live readings appear after setup.</span></div></div>
  <div class="metrics"><article><span class="metric-label">THROUGHPUT</span><strong>{throughput} <small>Mbps</small></strong><span class="metric-note">No live signal yet</span></article><article><span class="metric-label">PROTOCOLS</span><strong>— <small>available</small></strong><span class="metric-note">Collector is unpaired</span></article><article><span class="metric-label">COVERAGE</span><strong class="coverage">UNPAIRED</strong><span class="metric-note">Secure desktop pairing required</span></article></div>
  <div class="section-title"><h2>Devices that may need you</h2><span class="muted">0 online</span></div><div class="empty-state"><span class="empty-icon">⌁</span><div><strong>No device signal yet</strong><p class="muted">Once paired, NeonHearth will surface attention here without turning your home into a dashboard.</p></div></div>
  {#if events.length}<div class="event-list" aria-label="Live events">{#each events as event}<div class="event-row"><span class="event-kind {event.kind}"></span><span><strong>{event.title}</strong><small>{event.detail}</small></span><time>{event.time}</time></div>{/each}</div>{/if}
</section>
