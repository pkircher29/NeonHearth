<script lang="ts">
  import type { ServerMessage } from '../api/types';
  import { bandwidthTier, topDevices, type LiveState } from '../stores/live';
  import NetworkLung, { type ThroughputTier } from './NetworkLung.svelte';
  import { formatThroughput } from './networkFormat';

  interface Props { state?: LiveState | null; }
  let { state: liveState = null }: Props = $props();
  let animationPaused = $state(false);
  let scrubIdx = $state(-1); // -1 = follow the live edge
  const hasThroughput = $derived(Boolean(liveState?.connected && liveState.throughput.length));
  const currentBps = $derived(hasThroughput && liveState ? liveState.aggregate.upload + liveState.aggregate.download : null);
  const tier = $derived<ThroughputTier>(currentBps === null ? 'unavailable' : bandwidthTier(currentBps));
  const devices = $derived(liveState ? topDevices(liveState, 4) : []);
  const recentEvents = $derived(liveState?.timeline.slice(-8).reverse() ?? []);
  const downNow = $derived(hasThroughput && liveState ? liveState.aggregate.download : null);
  const upNow = $derived(hasThroughput && liveState ? liveState.aggregate.upload : null);
  const downShare = $derived(currentBps ? (downNow ?? 0) / currentBps : 0);
  const points = $derived(hasThroughput && liveState ? liveState.throughput.slice(-240) : []);
  const avg = $derived.by(() => {
    if (points.length === 0) return null;
    const down = points.reduce((sum, point) => sum + point.download, 0) / points.length;
    const up = points.reduce((sum, point) => sum + point.upload, 0) / points.length;
    return { down, up };
  });
  const scrubMax = $derived(Math.max(points.length - 1, 0));
  const scrubAt = $derived(scrubIdx < 0 ? scrubMax : Math.min(scrubIdx, scrubMax));
  const scrubPoint = $derived(points[scrubAt] ?? null);

  // --- Stacked soft-area timeline (amber download under rose upload) ---
  const TL_W = 1000; const TL_H = 110;
  function smoothPath(pts: Array<{ x: number; y: number }>): string {
    let d = `M ${pts[0].x.toFixed(1)} ${pts[0].y.toFixed(1)}`;
    for (let i = 1; i < pts.length - 1; i++) {
      const mx = (pts[i].x + pts[i + 1].x) / 2; const my = (pts[i].y + pts[i + 1].y) / 2;
      d += ` Q ${pts[i].x.toFixed(1)} ${pts[i].y.toFixed(1)} ${mx.toFixed(1)} ${my.toFixed(1)}`;
    }
    const last = pts[pts.length - 1];
    return `${d} L ${last.x.toFixed(1)} ${last.y.toFixed(1)}`;
  }
  function areaFor(values: number[], max: number): string {
    if (values.length < 2) return '';
    const pts = values.map((value, index) => ({ x: (index / (values.length - 1)) * TL_W, y: TL_H - (value / max) * (TL_H - 10) }));
    return `${smoothPath(pts)} L ${TL_W} ${TL_H} L 0 ${TL_H} Z`;
  }
  const timeline = $derived.by(() => {
    if (points.length < 2) return null;
    const max = Math.max(...points.map((point) => point.upload + point.download), 1);
    return {
      total: areaFor(points.map((point) => point.upload + point.download), max), // rose: upload rides on top
      down: areaFor(points.map((point) => point.download), max)
    };
  });
  const timeLabel = (at: string) => new Date(at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

  // --- Arc gauge: amber sweep for download share, rose for upload ---
  function arcPoint(f: number): { x: number; y: number } {
    const angle = Math.PI * (1 - f);
    return { x: 60 + 48 * Math.cos(angle), y: 58 - 48 * Math.sin(angle) };
  }
  function arcPath(f0: number, f1: number): string {
    const from = arcPoint(f0); const to = arcPoint(f1);
    return `M ${from.x.toFixed(2)} ${from.y.toFixed(2)} A 48 48 0 0 1 ${to.x.toFixed(2)} ${to.y.toFixed(2)}`;
  }

  function deviceMix(device: LiveState['devices'][string]): { width: number; down: number } {
    const top = devices[0];
    const maxTotal = top ? (top.bandwidth.upload ?? 0) + (top.bandwidth.download ?? 0) : 0;
    const total = (device.bandwidth.upload ?? 0) + (device.bandwidth.download ?? 0);
    return { width: maxTotal ? Math.max((total / maxTotal) * 100, 3) : 0, down: total ? ((device.bandwidth.download ?? 0) / total) * 100 : 0 };
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
  <div class="pulse-hero hero-bleed">
    <NetworkLung throughput={currentBps} tier={tier} paused={animationPaused}/>
    <div class="hero-overlay">
      <div class="view-heading"><p class="kicker">PULSE / NOW</p><h1 id="pulse-heading">Your network, breathing.</h1><p class="muted">A calm read of what is happening at home.</p></div>
      <button class="pill-control" type="button" aria-pressed={animationPaused} aria-label={animationPaused ? 'Resume decorative animation; data continues' : 'Pause decorative animation; data continues'} onclick={() => animationPaused = !animationPaused}>{animationPaused ? 'Resume motion' : 'Pause motion'}</button>
    </div>
    <div class="hero-caption"><span class="presence-dot {liveState?.connected ? 'online' : 'quiet'}" aria-hidden="true"></span><strong>{liveState?.connected ? 'Live readings connected' : 'Protected pairing is waiting'}</strong></div>
  </div>

  <div class="stat-band">
    <div class="band-stats">
      <div class="stat">
        <span class="stat-arrow down-arrow" aria-hidden="true">↓</span>
        <div><strong>{downNow === null ? '—' : formatThroughput(downNow)}</strong><small>{downNow === null ? 'coverage unavailable' : 'download now'}</small></div>
      </div>
      <div class="stat-arc" role="img" aria-label={currentBps === null ? 'Total throughput unavailable' : `Total throughput ${formatThroughput(currentBps)}, ${Math.round(downShare * 100)}% download`}>
        <svg viewBox="0 0 120 66" aria-hidden="true">
          <path class="arc-track" d={arcPath(0, 1)} />
          {#if currentBps !== null}
            <path class="arc-down" d={arcPath(0, Math.max(Math.min(downShare, 0.98), 0.02))} />
            <path class="arc-up" d={arcPath(Math.max(Math.min(downShare, 0.98), 0.02), 1)} />
          {/if}
        </svg>
        <span class="arc-total">{currentBps === null ? '—' : formatThroughput(currentBps)}</span>
      </div>
      <div class="stat">
        <span class="stat-arrow up-arrow" aria-hidden="true">↑</span>
        <div><strong>{upNow === null ? '—' : formatThroughput(upNow)}</strong><small>{upNow === null ? 'coverage unavailable' : 'upload now'}</small></div>
      </div>
      <div class="band-divider" aria-hidden="true"></div>
      <div class="band-mix">
        <div class="mix-row"><span>NOW</span>{#if currentBps}<span class="mix-bar"><i class="mix-down" style={`width:${downShare * 100}%`}></i><i class="mix-up" style={`width:${(1 - downShare) * 100}%`}></i></span><b>{formatThroughput(currentBps)}</b>{:else}<b class="mix-dash">— coverage unavailable</b>{/if}</div>
        <div class="mix-row"><span>AVG</span>{#if avg}<span class="mix-bar"><i class="mix-down" style={`width:${((avg.down) / Math.max(avg.down + avg.up, 1)) * 100}%`}></i><i class="mix-up" style={`width:${((avg.up) / Math.max(avg.down + avg.up, 1)) * 100}%`}></i></span><b>{formatThroughput(avg.down + avg.up)}</b>{:else}<b class="mix-dash">— coverage unavailable</b>{/if}</div>
      </div>
    </div>
    {#if timeline}
      <div class="band-timeline">
        <svg viewBox="0 0 {TL_W} {TL_H}" preserveAspectRatio="none" role="img" aria-label="Throughput timeline, download and upload stacked">
          <path class="area-total" d={timeline.total} />
          <path class="area-down" d={timeline.down} />
          {#if scrubPoint}<line class="scrub-line" x1={(scrubAt / Math.max(points.length - 1, 1)) * TL_W} y1="0" x2={(scrubAt / Math.max(points.length - 1, 1)) * TL_W} y2={TL_H} />{/if}
        </svg>
        <div class="timeline-times"><span>{timeLabel(points[0].at)}</span>{#if scrubPoint}<span class="scrub-readout">{timeLabel(scrubPoint.at)} · <b class="down-text">↓ {formatThroughput(scrubPoint.download)}</b> · <b class="up-text">↑ {formatThroughput(scrubPoint.upload)}</b></span>{/if}<span>{timeLabel(points[points.length - 1].at)}</span></div>
        <input class="scrubber" type="range" min="0" max={scrubMax} value={scrubAt} aria-label="Scrub the throughput timeline" oninput={(event) => scrubIdx = Number((event.currentTarget as HTMLInputElement).value)} />
      </div>
    {:else}
      <p class="unavailable-copy band-empty">Throughput stays quiet here until the collector has a protected connection.</p>
    {/if}
  </div>

  <div class="pulse-lower">
    <div>
      <div class="section-title"><h2>Evidence coverage</h2></div>
      <p class="coverage-line"><span class="coverage-badge {liveState?.coverage ?? 'unavailable'}"><span aria-hidden="true">{liveState?.coverage === 'complete' ? '✓' : liveState?.coverage === 'mixed' ? '△' : '—'}</span> {liveState?.coverage ?? 'unavailable'}</span><span class="muted">Evidence quality, not a heat score</span></p>
    </div>
    <div>
      <div class="section-title"><h2>Protocol availability</h2></div>
      {#if liveState?.protocolMix}<div class="protocol-bars">{#each Object.entries(liveState.protocolMix) as pair}<div><span>{pair[0]}</span><progress max="100" value={protocolShare(pair[1])}></progress><b>{Math.round(protocolShare(pair[1]))}%</b></div>{/each}</div>{:else}<p class="unavailable-copy">Unavailable — no protocol mix has arrived.</p>{/if}
    </div>
  </div>

  <div class="section-title"><h2>Devices using the most</h2><span class="muted">{devices.length ? `${devices.length} observed` : 'no usage data'}</span></div>
  {#if devices.length}<div class="top-devices">{#each devices as device}{@const mix = deviceMix(device)}<div class="top-device"><span class="presence-dot {device.presence.state}" aria-hidden="true"></span><span class="device-label"><strong>{device.owner_name ?? `Device …${device.device_id.slice(-8)}`}</strong><small>{device.presence.state}</small></span><span class="device-bar"><span class="device-bar-fill" style={`width:${mix.width}%`}><i class="mix-down" style={`width:${mix.down}%`}></i><i class="mix-up" style={`width:${100 - mix.down}%`}></i></span></span><b>{formatThroughput((device.bandwidth.upload ?? 0) + (device.bandwidth.download ?? 0))}</b></div>{/each}</div>{:else}<div class="empty-state"><span class="empty-icon">⌁</span><div><strong>No usage data yet</strong><p class="muted">Usage bars appear only after the collector reports available bandwidth.</p></div></div>{/if}

  <div class="section-title event-heading"><h2>Recent events</h2><span class="muted">bounded to 8</span></div>
  {#if recentEvents.length}<div class="event-list" aria-label="Recent network events">{#each recentEvents as event}<div class="event-row"><span class="event-kind {eventCopy(event).cue}" aria-label={`${eventCopy(event).cue} status`}>{eventCopy(event).cue === 'risk' ? '!' : eventCopy(event).cue === 'watch' ? '△' : eventCopy(event).cue === 'secure' ? '✓' : '·'}</span><span><strong>{eventCopy(event).title}</strong><small>{eventCopy(event).detail}</small></span><time>{event.type === 'event' ? new Date(event.data.occurred_at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }) : 'now'}</time></div>{/each}</div>{:else}<p class="unavailable-copy">No recent events — the event stream will appear after pairing.</p>{/if}
</section>
<style>
  /* Hero: the hearth fills the view; controls float over it as white pills. */
  .pulse-hero { position: relative; min-height: 400px; display: grid; }
  .pulse-hero :global(.lung-wrap) { min-height: 400px; }
  .hero-overlay { position: absolute; inset: 0 0 auto 0; display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; padding: 26px var(--main-pad-x) 0; pointer-events: none; }
  .hero-overlay .view-heading { max-width: 60%; }
  .hero-overlay .pill-control { pointer-events: auto; flex: none; }
  .hero-caption { position: absolute; left: var(--main-pad-x); bottom: 18px; display: flex; align-items: center; gap: 9px; background: var(--surface); border-radius: var(--radius-pill); box-shadow: var(--shadow); padding: 10px 18px; font-size: 12.5px; }

  /* Stat band: the GlassWire moment — big numbers, arc gauge, mix bars, timeline. */
  .stat-band { margin: 0 calc(-1 * var(--main-pad-x)); padding: 18px var(--main-pad-x) 8px; background: var(--surface); box-shadow: var(--shadow); }
  .band-stats { display: flex; align-items: center; gap: clamp(14px, 3vw, 34px); flex-wrap: wrap; }
  .stat { display: flex; align-items: center; gap: 10px; }
  .stat strong { display: block; font: 600 var(--text-stat)/1.1 var(--font-display); color: var(--ink); }
  .stat small { color: var(--ink-mute); font: 400 11px var(--font-mono); }
  .stat-arrow { font-size: 19px; font-weight: 600; }
  .down-arrow { color: var(--down); }
  .up-arrow { color: var(--up); }
  .stat-arc { position: relative; width: 132px; text-align: center; }
  .stat-arc svg { width: 120px; height: 66px; display: block; margin: 0 auto; }
  .arc-track { fill: none; stroke: var(--surface-2); stroke-width: 10; stroke-linecap: round; }
  .arc-down { fill: none; stroke: var(--down); stroke-width: 10; stroke-linecap: round; }
  .arc-up { fill: none; stroke: var(--up); stroke-width: 10; stroke-linecap: round; }
  .arc-total { position: absolute; left: 0; right: 0; bottom: 2px; font: 600 15px var(--font-display); color: var(--ink); }
  .band-divider { width: 1px; align-self: stretch; min-height: 46px; background: var(--line); }
  .band-mix { display: grid; gap: 9px; min-width: 220px; flex: 1; }
  .mix-row { display: grid; grid-template-columns: 34px 1fr auto; gap: 10px; align-items: center; font: 500 10px var(--font-mono); color: var(--ink-mute); letter-spacing: 0.08em; }
  .mix-row b { font: 500 11px var(--font-mono); color: var(--ink); }
  .mix-bar { display: flex; height: 8px; border-radius: 4px; overflow: hidden; background: var(--surface-2); }
  .mix-down { display: block; height: 100%; background: var(--down); }
  .mix-up { display: block; height: 100%; background: var(--up); }
  .mix-dash { grid-column: 2 / -1; color: var(--ink-mute); font: 400 11px var(--font-mono); }

  .band-timeline { margin-top: 14px; }
  .band-timeline svg { display: block; width: 100%; height: 88px; }
  .area-total { fill: color-mix(in srgb, var(--up) 60%, transparent); }
  .area-down { fill: color-mix(in srgb, var(--down) 60%, transparent); }
  .scrub-line { stroke: var(--ink-mute); stroke-width: 1.5; stroke-dasharray: 3 3; }
  .timeline-times { display: flex; justify-content: space-between; gap: 10px; margin-top: 6px; color: var(--ink-mute); font: 400 10.5px var(--font-mono); }
  .scrub-readout { color: var(--ink); }
  .down-text { color: color-mix(in srgb, var(--down) 60%, var(--ink)); font-weight: 500; }
  .up-text { color: color-mix(in srgb, var(--up) 65%, var(--ink)); font-weight: 500; }
  .scrubber { width: 100%; margin: 8px 0 10px; accent-color: var(--ember); }
  .band-empty { padding: 14px 0; }

  .coverage-line { display: flex; align-items: center; gap: 12px; margin-top: 14px; }
  .coverage-badge { padding: 6px 12px; border: 1px solid var(--line); border-radius: var(--radius-pill); font: 500 11px var(--font-mono); text-transform: uppercase; letter-spacing: 0.06em; color: var(--ink-mute); background: var(--surface); }
  .coverage-badge.complete { color: var(--sage-text); border-color: var(--sage); }
  .coverage-badge.mixed, .coverage-badge.estimated { color: var(--ink); border-color: var(--ink-mute); }
  .pulse-lower { display: grid; grid-template-columns: 1fr 1.5fr; gap: 24px; }
  .unavailable-copy { color: var(--ink-mute); font-size: 12.5px; line-height: 1.5; padding: 14px 0; }
  .protocol-bars { display: grid; gap: 11px; margin-top: 14px; }
  .protocol-bars div { display: grid; grid-template-columns: 75px 1fr 33px; gap: 8px; align-items: center; font: 11px var(--font-mono); color: var(--ink-mute); }
  .protocol-bars progress { width: 100%; height: 7px; accent-color: var(--down); }
  .protocol-bars b { color: var(--ink); font-size: 10px; }
  .top-devices { margin-top: 6px; border-radius: var(--radius-card); background: var(--surface); box-shadow: var(--shadow); padding: 6px var(--pad-card); }
  .top-device { min-height: 57px; border-bottom: 1px solid var(--line); display: grid; grid-template-columns: 18px 1fr minmax(80px, 1fr) auto; align-items: center; gap: 12px; }
  .top-device:last-child { border-bottom: 0; }
  .device-label strong, .device-label small { display: block; }
  .device-label small { color: var(--ink-mute); margin-top: 3px; font-size: 11px; }
  .device-bar { display: block; height: 8px; border-radius: 4px; background: var(--surface-2); overflow: hidden; }
  .device-bar-fill { display: flex; height: 100%; border-radius: 4px; overflow: hidden; }
  .top-device > b { font: 500 11px var(--font-mono); color: var(--ink-mute); }
  .event-heading { margin-top: 32px; }
  .event-list { border-top: 1px solid var(--line); }
  .event-row { min-height: 57px; border-bottom: 1px solid var(--line); display: grid; grid-template-columns: 25px 1fr auto; align-items: center; gap: 10px; }
  .event-row strong, .event-row small { display: block; }
  .event-row strong { font-size: 13.5px; }
  .event-row small { margin-top: 4px; color: var(--ink-mute); font-size: 11px; }
  .event-row time { color: var(--ink-mute); font: 10px var(--font-mono); }
  .event-kind { display: inline-grid; place-items: center; width: 21px; height: 21px; border: 1px solid currentColor; border-radius: 6px; font: 11px var(--font-mono); }
  .event-kind.info { color: var(--ink-mute); }
  .event-kind.secure { color: var(--sage-text); }
  .event-kind.watch { color: var(--ink); border-style: dashed; }
  .event-kind.risk { color: var(--alert-text); border-width: 2px; }

  @media (max-width: 850px) {
    .pulse-hero, .pulse-hero :global(.lung-wrap) { min-height: 400px; }
    .pulse-hero :global(.lung-readout) { margin-top: 90px; }
    .hero-overlay { flex-wrap: wrap; }
    .hero-overlay .view-heading { max-width: 100%; }
    .band-divider { display: none; }
    .band-mix { min-width: 100%; }
    .pulse-lower { grid-template-columns: 1fr; }
    .top-device { grid-template-columns: 18px 1fr auto; }
    .device-bar { grid-column: 2 / -1; }
    .top-device > b { grid-column: 3; grid-row: 1; }
  }
</style>
