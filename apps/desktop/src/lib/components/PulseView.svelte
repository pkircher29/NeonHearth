<script lang="ts">
  import type { ServerMessage } from '../api/types';
  import { topDevices, type LiveState } from '../stores/live';
  import HearthPulse from './HearthPulse.svelte';
  import { formatThroughput } from './networkFormat';

  interface Props { state?: LiveState | null; onselectdevice?: (deviceId: string) => void; }
  let { state: liveState = null, onselectdevice }: Props = $props();
  let animationPaused = $state(false);
  const hasThroughput = $derived(Boolean(liveState?.connected && liveState.throughput.length));
  const currentBps = $derived(hasThroughput && liveState ? liveState.aggregate.upload + liveState.aggregate.download : null);
  const allDevices = $derived(liveState ? liveState.deviceOrder.map((id) => liveState.devices[id]).filter((device): device is NonNullable<typeof device> => Boolean(device)) : []);
  const devices = $derived(liveState ? topDevices(liveState, 4) : []);
  const presenceCounts = $derived(allDevices.reduce((acc, device) => { const key = device.presence.state === 'online' ? 'online' : device.presence.state === 'quiet' ? 'quiet' : device.presence.state === 'blocked' ? 'blocked' : 'other'; acc[key] += 1; return acc; }, { online: 0, quiet: 0, blocked: 0, other: 0 }));
  const recentEvents = $derived(liveState?.timeline.slice(-8).reverse() ?? []);
  const curvePath = $derived(pathFor(liveState ? liveState.throughput : []));

  function pathFor(points: LiveState['throughput']): string {
    const bounded = points.slice(-60); if (bounded.length < 2) return '';
    const max = Math.max(...bounded.map((point) => point.upload + point.download), 1);
    return bounded.map((point, index) => `${index ? 'L' : 'M'} ${(index / (bounded.length - 1)) * 600} ${118 - ((point.upload + point.download) / max) * 98}`).join(' ');
  }
  function widthFor(device: LiveState['devices'][string]): number {
    return Math.min(100, (((device.bandwidth.upload ?? 0) + (device.bandwidth.download ?? 0)) / Math.max(currentBps ?? 1, 1)) * 100);
  }
  function protocolShare(value: number): number {
    const total = liveState?.protocolMix ? Object.values(liveState.protocolMix).reduce((sum, amount) => sum + amount, 0) : 0;
    return total ? (value / total) * 100 : 0;
  }
  function eventCopy(event: ServerMessage): { title: string; detail: string; cue: string } {
    if (event.type === 'resync_required') return { title: 'Live stream needs a refresh', detail: 'Waiting for a safe resync', cue: 'watch' };
    const payload = event.data.payload;
    if (payload.type === 'presence_changed') return { title: `${payload.data.device_id.slice(0, 8)} is ${payload.data.to}`, detail: payload.data.reason, cue: payload.data.to === 'blocked' ? 'risk' : 'info' };
    if (payload.type === 'service_status') return { title: `Collector ${payload.data.state}`, detail: payload.data.detail, cue: payload.data.state === 'ready' ? 'secure' : 'watch' };
    if (payload.type === 'policy_changed') return { title: `Guard: ${payload.data.evaluation.reason.replaceAll('_', ' ')}`, detail: `${payload.data.requested_action.replaceAll('_', ' ')} · ${payload.data.enforcement_result.replaceAll('_', ' ')}`, cue: payload.data.enforcement_result === 'failed' ? 'risk' : payload.data.requested_action === 'none' ? 'secure' : 'watch' };
    return { title: 'Bandwidth reading updated', detail: `${payload.data.samples.length} device${payload.data.samples.length === 1 ? '' : 's'} reported`, cue: 'info' };
  }
</script>

<section class="pulse-view" aria-labelledby="pulse-heading">
  <div class="view-heading"><div><p class="kicker">PULSE / NOW</p><h1 id="pulse-heading">Your network, breathing.</h1><p class="muted">A calm read of what is happening at home.</p></div><button class="pause-button" type="button" aria-pressed={animationPaused} aria-label={animationPaused ? 'Resume decorative animation; data continues' : 'Pause decorative animation; data continues'} onclick={() => animationPaused = !animationPaused}>{animationPaused ? 'Resume motion' : 'Pause motion'}</button></div>
  <div class="hearth-panel">
    <div class="hearth-stage"><HearthPulse devices={allDevices} upload={hasThroughput && liveState ? liveState.aggregate.upload : null} download={hasThroughput && liveState ? liveState.aggregate.download : null} connected={Boolean(liveState?.connected)} paused={animationPaused} onselect={onselectdevice}/></div>
    <aside class="hearth-legend" aria-label="How to read the hearth">
      <p class="kicker">READING THE HEARTH</p>
      <dl>
        <div><dt><i class="swatch arc cyan"></i>Download</dt><dd>Inner arc, 100 kbps to 1 Gbps on a log scale.</dd></div>
        <div><dt><i class="swatch arc gold"></i>Upload</dt><dd>Outer arc, same scale.</dd></div>
        <div><dt><i class="swatch spark"></i>Sparks</dt><dd>One per device. Size is its share of traffic; a glow means online; a dashed ring means blocked by Guard.</dd></div>
      </dl>
      <p class="kicker">EMBER WARMTH</p>
      <ol class="tiers">
        <li><i style="background: var(--tier-blue)"></i><span>Quiet</span><small>under 1 Mbps</small></li>
        <li><i style="background: var(--tier-cyan)"></i><span>Active</span><small>1 to 10</small></li>
        <li><i style="background: var(--tier-gold)"></i><span>Busy</span><small>10 to 30</small></li>
        <li><i style="background: var(--tier-pink)"></i><span>Saturating</span><small>over 30</small></li>
      </ol>
      <p class="counts"><b>{presenceCounts.online}</b> online · <b>{presenceCounts.quiet}</b> quiet · <b>{presenceCounts.blocked}</b> blocked</p>
    </aside>
    <div class="hearth-caption"><span class="status-cue watch">△</span><strong>{liveState?.connected ? 'Live readings connected' : 'Protected pairing is waiting'}</strong><span class="muted">{liveState?.connected ? 'Data updates continue when motion is paused.' : 'Live readings appear after setup.'}</span></div>
  </div>
  <div class="metrics"><article><span class="metric-label">THROUGHPUT</span><strong>{formatThroughput(currentBps)}</strong><span class="metric-note">{hasThroughput ? 'Upload + download now' : 'Unavailable until paired'}</span></article><article><span class="metric-label">PROTOCOL MIX</span>{#if liveState?.protocolMix}<strong>{Object.keys(liveState.protocolMix).length} <small>observed</small></strong><span class="metric-note">Traffic categories from collector</span>{:else}<strong>Unavailable</strong><span class="metric-note">No protocol data received</span>{/if}</article><article><span class="metric-label">COVERAGE</span><strong class="coverage-badge {liveState?.coverage ?? 'unavailable'}"><span aria-hidden="true">{liveState?.coverage === 'complete' ? '✓' : liveState?.coverage === 'mixed' ? '△' : '○'}</span> {liveState?.coverage ?? 'UNAVAILABLE'}</strong><span class="metric-note">Evidence quality, not a heat score</span></article></div>
  <div class="pulse-lower"><div><div class="section-title"><h2>Throughput curve</h2><span class="muted">{hasThroughput ? 'last 60 readings' : 'waiting for readings'}</span></div><div class="curve-panel">{#if hasThroughput}<svg viewBox="0 0 600 130" role="img" aria-label="Bounded throughput curve"><path class="curve-grid" d="M0 20h600M0 69h600M0 118h600"/><path class="curve-path" d={curvePath}/></svg>{:else}<p class="unavailable-copy">Throughput stays quiet here until the collector has a protected connection.</p>{/if}</div></div><div><div class="section-title"><h2>Protocol availability</h2></div>{#if liveState?.protocolMix}<div class="protocol-bars">{#each Object.entries(liveState.protocolMix) as pair}<div><span>{pair[0]}</span><progress max="100" value={protocolShare(pair[1])}></progress><b>{Math.round(protocolShare(pair[1]))}%</b></div>{/each}</div>{:else}<p class="unavailable-copy">Unavailable — no protocol mix has arrived.</p>{/if}</div></div>
  <div class="section-title"><h2>Devices using the most</h2><span class="muted">{devices.length ? `${devices.length} observed` : 'no usage data'}</span></div>{#if devices.length}<div class="top-devices">{#each devices as device}<div class="top-device"><span class="device-symbol">◌</span><span class="device-label"><strong>{device.owner_name ?? `Device ${device.device_id.slice(0, 6)}`}</strong><small>{device.presence.state}</small></span><span class="device-bar"><i style={'width: ' + widthFor(device) + '%'}></i></span><b>{formatThroughput((device.bandwidth.upload ?? 0) + (device.bandwidth.download ?? 0))}</b></div>{/each}</div>{:else}<div class="empty-state"><span class="empty-icon">⌁</span><div><strong>No usage data yet</strong><p class="muted">Usage bars appear only after the collector reports available bandwidth.</p></div></div>{/if}
  <div class="section-title event-heading"><h2>Recent events</h2><span class="muted">bounded to 8</span></div>{#if recentEvents.length}<div class="event-list" aria-label="Recent network events">{#each recentEvents as event}<div class="event-row"><span class="event-kind {eventCopy(event).cue}" aria-label={`${eventCopy(event).cue} status`}>{eventCopy(event).cue === 'risk' ? '!' : eventCopy(event).cue === 'watch' ? '△' : eventCopy(event).cue === 'secure' ? '✓' : '·'}</span><span><strong>{eventCopy(event).title}</strong><small>{eventCopy(event).detail}</small></span><time>{event.type === 'event' ? new Date(event.data.occurred_at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }) : 'now'}</time></div>{/each}</div>{:else}<p class="unavailable-copy">No recent events — the event stream will appear after pairing.</p>{/if}
</section>
<style>
  .pause-button { border: 1px solid var(--line-strong); border-radius: 5px; color: var(--ink); background: var(--surface); min-height: 44px; padding: 0 13px; cursor: pointer; }
  .pause-button:focus-visible, :global(button:focus-visible), :global(input:focus-visible) { outline: 3px solid var(--gold); outline-offset: 3px; }
  .status-cue { display: inline-grid; place-items: center; width: 21px; height: 21px; border: 1px solid currentColor; border-radius: 50%; }
  .status-cue.watch, .coverage-badge.mixed, .coverage-badge.estimated { color: var(--gold); }
  .coverage-badge.complete { color: var(--accent); }.coverage-badge.unavailable,.coverage-badge.local-only { color: var(--pink); }
  .pulse-lower { display: grid; grid-template-columns: 1.5fr 1fr; gap: 23px; }.curve-panel { margin-top: 13px; min-height: 151px; border: 1px solid var(--line); border-radius: 7px; padding: 10px; background: var(--surface); }.curve-panel svg { width: 100%; height: 130px; }.curve-grid { fill: none; stroke: var(--line); stroke-dasharray: 3 6; }.curve-path { fill: none; stroke: var(--accent); stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }.unavailable-copy { color: var(--muted); font-size: 12px; line-height: 1.5; padding: 18px 0; }.protocol-bars { display: grid; gap: 11px; margin-top: 14px; }.protocol-bars div { display: grid; grid-template-columns: 75px 1fr 33px; gap: 8px; align-items: center; font: 11px var(--font-mono); }.protocol-bars progress { width: 100%; height: 7px; accent-color: var(--blue); }.protocol-bars b { color: var(--ink); font-size: 10px; }.top-devices { border-top: 1px solid var(--line); }.top-device { min-height: 57px; border-bottom: 1px solid var(--line); display: grid; grid-template-columns: 25px 1fr minmax(80px, 1fr) auto; align-items: center; gap: 11px; }.device-label strong,.device-label small { display: block; }.device-label small { color: var(--muted); margin-top: 3px; font-size: 11px; }.device-bar { height: 7px; border: 1px solid var(--line-strong); background: var(--surface); }.device-bar i { display: block; height: 100%; background: var(--blue); }.top-device>b { font: 11px var(--font-mono); color: var(--muted-strong); }.event-heading { margin-top: 32px; }.event-list { border-top: 1px solid var(--line); }.event-row { min-height: 57px; border-bottom: 1px solid var(--line); display: grid; grid-template-columns: 25px 1fr auto; align-items: center; gap: 10px; }.event-row strong,.event-row small { display: block; }.event-row small { margin-top: 4px; color: var(--muted); font-size: 11px; }.event-row time { color: var(--faint); font: 10px var(--font-mono); }.event-kind { display: inline-grid; place-items: center; width: 21px; height: 21px; border: 1px solid currentColor; border-radius: 4px; font: 11px var(--font-mono); }.event-kind.info { color: var(--blue); }.event-kind.secure { color: var(--accent); }.event-kind.watch { color: var(--gold); border-style: dashed; }.event-kind.risk { color: var(--pink); border-width: 2px; }
  @media (max-width: 850px) { .view-heading { flex-wrap: wrap; }.pause-button { width: 100%; }.pulse-lower { grid-template-columns: 1fr; }.top-device { grid-template-columns: 25px 1fr auto; }.device-bar { grid-column: 2 / -1; }.top-device>b { grid-column: 3; grid-row: 1; } }
</style>
