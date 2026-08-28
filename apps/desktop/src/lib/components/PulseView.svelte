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

  // --- Arc gauge: chrome outer ring, flame-ramp sweep. The sweep length is
  // honest data: current total relative to the highest total in the window.
  function arcPoint(f: number, r: number): { x: number; y: number } {
    const angle = Math.PI * (1 - f);
    return { x: 60 + r * Math.cos(angle), y: 60 - r * Math.sin(angle) };
  }
  function arcPath(f0: number, f1: number, r: number): string {
    const from = arcPoint(f0, r); const to = arcPoint(f1, r);
    return `M ${from.x.toFixed(2)} ${from.y.toFixed(2)} A ${r} ${r} 0 0 1 ${to.x.toFixed(2)} ${to.y.toFixed(2)}`;
  }
  const peakRecent = $derived(points.length ? Math.max(...points.map((point) => point.upload + point.download), 1) : null);
  const arcSweep = $derived(currentBps !== null && peakRecent ? Math.min(Math.max(currentBps / peakRecent, 0.04), 1) : 0);

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
        <div><strong class:dash={downNow === null}>{downNow === null ? '—' : formatThroughput(downNow)}</strong><small>{downNow === null ? 'coverage unavailable' : 'download now'}</small></div>
      </div>
      <div class="stat-arc" role="img" aria-label={currentBps === null ? 'Total throughput unavailable' : `Total throughput ${formatThroughput(currentBps)}, ${Math.round(arcSweep * 100)}% of the last minute's peak`}>
        <svg viewBox="0 0 120 68" aria-hidden="true">
          <defs>
            <linearGradient id="pulse-chrome" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" class="chrome-stop-1" /><stop offset="0.32" class="chrome-stop-2" /><stop offset="0.5" class="chrome-stop-3" /><stop offset="0.68" class="chrome-stop-4" /><stop offset="1" class="chrome-stop-5" />
            </linearGradient>
            <linearGradient id="pulse-flame" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0" class="stop-blue" /><stop offset="0.25" class="stop-violet" /><stop offset="0.5" class="stop-magenta" /><stop offset="0.75" class="stop-orange" /><stop offset="1" class="stop-gold" />
            </linearGradient>
          </defs>
          <path class="arc-ring" d={arcPath(0, 1, 57)} />
          <path class="arc-ring-shade" d={arcPath(0, 1, 53.2)} />
          <path class="arc-track" d={arcPath(0, 1, 45)} />
          {#if currentBps !== null}
            <path class="arc-sweep-glow" d={arcPath(0, arcSweep, 45)} />
            <path class="arc-sweep" d={arcPath(0, arcSweep, 45)} />
          {/if}
        </svg>
        <span class="arc-total" class:dash={currentBps === null}>{currentBps === null ? '—' : formatThroughput(currentBps)}</span>
      </div>
      <div class="stat">
        <span class="stat-arrow up-arrow" aria-hidden="true">↑</span>
        <div><strong class:dash={upNow === null}>{upNow === null ? '—' : formatThroughput(upNow)}</strong><small>{upNow === null ? 'coverage unavailable' : 'upload now'}</small></div>
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
          <defs>
            <linearGradient id="tl-down" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" class="stop-gold" /><stop offset="1" class="stop-orange" />
            </linearGradient>
            <linearGradient id="tl-up" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" class="stop-magenta" /><stop offset="1" class="stop-violet" />
            </linearGradient>
          </defs>
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
  /* Hero: the hearth fills the view; controls float over it as glass pills. */
  .pulse-hero { position: relative; min-height: 560px; display: grid; }
  .pulse-hero :global(.lung-wrap) { min-height: 560px; }
  /* A scrim that darkens the top-left of the hero — where the copy lives — and
     feathers away down and to the right so the flame stays untouched. This is
     what keeps the muted subhead at AA over the fire. */
  .pulse-hero::before {
    content: ''; position: absolute; inset: 0 0 auto 0; height: 270px; z-index: 1; pointer-events: none;
    background: linear-gradient(100deg, rgb(6 5 11 / 0.96) 0%, rgb(6 5 11 / 0.92) 26%, rgb(6 5 11 / 0.55) 44%, rgb(6 5 11 / 0) 64%);
    -webkit-mask-image: linear-gradient(180deg, #000 0%, #000 48%, transparent 100%);
    mask-image: linear-gradient(180deg, #000 0%, #000 48%, transparent 100%);
  }
  .hero-overlay { position: absolute; inset: 0 0 auto 0; z-index: 2; display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; padding: 26px var(--main-pad-x) 0; pointer-events: none; }
  .hero-overlay .view-heading { max-width: min(600px, 56%); }
  /* Over the fire, secondary copy steps up a notch so it stays AA even where
     the scrim has feathered away. Still a neutral — never a fire colour. */
  .hero-overlay .view-heading .muted, .hero-overlay .view-heading .kicker { color: var(--ink-mute-strong); }
  .hero-overlay .pill-control { pointer-events: auto; flex: none; }
  .hero-caption { position: absolute; left: var(--main-pad-x); bottom: 76px; display: flex; align-items: center; gap: 9px; background: var(--panel); border: 1px solid var(--line); border-top-color: var(--glass-edge); border-radius: var(--radius-pill); box-shadow: var(--shadow); padding: 10px 18px; font-size: 12.5px; }

  /* Stat band: the GlassWire moment — a glass slab floating over the hearth's
     spill, with big numbers, the machined gauge, mix bars and the timeline. */
  /* Pulled up over the hearth's spill so the glass has live light to blur. */
  .stat-band { position: relative; z-index: 1; margin: -54px calc(-1 * var(--main-pad-x)) 0; padding: 22px var(--main-pad-x) 10px; background: var(--panel); border-block: 1px solid var(--line); border-top-color: var(--glass-edge); box-shadow: var(--shadow); }
  .band-stats { display: flex; align-items: center; gap: clamp(14px, 3vw, 34px); flex-wrap: wrap; }
  .stat { display: flex; align-items: center; gap: 10px; }
  .stat strong { display: block; font: 600 var(--text-stat)/1.1 var(--font-display); color: var(--ink); letter-spacing: -0.01em; }
  .stat strong.dash { background: var(--chrome); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .stat small { color: var(--ink-mute); font: 400 11px var(--font-mono); }
  .stat-arrow { font-size: 21px; font-weight: 600; }
  .down-arrow { color: var(--fire-gold); text-shadow: 0 0 12px rgb(255 197 61 / 0.6); }
  .up-arrow { color: var(--fire-magenta); text-shadow: 0 0 12px rgb(224 64 251 / 0.6); }
  .stat-arc { position: relative; width: 168px; text-align: center; }
  .stat-arc svg { width: 156px; height: 86px; display: block; margin: 0 auto; overflow: visible; }
  /* Machined bezel: a bright chrome band with a dark shadow line cut just
     inside it, the way a turned metal ring catches light. */
  .arc-ring { fill: none; stroke: url(#pulse-chrome); stroke-width: 4.5; stroke-linecap: round; filter: drop-shadow(0 1px 1px rgb(0 0 0 / 0.85)); }
  .arc-ring-shade { fill: none; stroke: rgb(0 0 0 / 0.55); stroke-width: 1.6; stroke-linecap: round; }
  .arc-track { fill: none; stroke: rgb(255 255 255 / 0.09); stroke-width: 10; stroke-linecap: round; }
  .arc-sweep { fill: none; stroke: url(#pulse-flame); stroke-width: 10; stroke-linecap: round; }
  .arc-sweep-glow { fill: none; stroke: url(#pulse-flame); stroke-width: 10; stroke-linecap: round; filter: blur(7px); opacity: 0.85; }
  .chrome-stop-1 { stop-color: var(--chrome-1); }
  .chrome-stop-2 { stop-color: var(--chrome-2); }
  .chrome-stop-3 { stop-color: var(--chrome-3); }
  .chrome-stop-4 { stop-color: var(--chrome-4); }
  .chrome-stop-5 { stop-color: var(--chrome-5); }
  .stop-blue { stop-color: var(--fire-blue); }
  .stop-violet { stop-color: var(--fire-violet); }
  .stop-magenta { stop-color: var(--fire-magenta); }
  .stop-orange { stop-color: var(--fire-orange); }
  .stop-gold { stop-color: var(--fire-gold); }
  .arc-total { position: absolute; left: 0; right: 0; bottom: 2px; font: 700 17px var(--font-display); color: var(--ink); }
  /* No reading: the em-dash still gets machined chrome, never a grey dash. */
  .arc-total.dash { background: var(--chrome); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .band-divider { width: 1px; align-self: stretch; min-height: 46px; background: var(--line); }
  .band-mix { display: grid; gap: 9px; min-width: 220px; flex: 1; }
  .mix-row { display: grid; grid-template-columns: 34px 1fr auto; gap: 10px; align-items: center; font: 500 10px var(--font-mono); color: var(--ink-mute); letter-spacing: 0.08em; }
  .mix-row b { font: 500 11px var(--font-mono); color: var(--ink); }
  .mix-bar { display: flex; height: 8px; border-radius: 4px; overflow: hidden; background: var(--surface-2); }
  .mix-down { display: block; height: 100%; background: var(--down-ramp); }
  .mix-up { display: block; height: 100%; background: var(--up-ramp); }
  .mix-dash { grid-column: 2 / -1; color: var(--ink-mute); font: 400 11px var(--font-mono); }

  .band-timeline { margin-top: 14px; }
  .band-timeline svg { display: block; width: 100%; height: 96px; filter: drop-shadow(0 0 14px rgb(255 109 59 / 0.35)) drop-shadow(0 0 22px rgb(224 64 251 / 0.3)); }
  .area-total { fill: url(#tl-up); opacity: 0.72; }
  .area-down { fill: url(#tl-down); opacity: 0.72; }
  .scrub-line { stroke: var(--ink); stroke-width: 1.5; stroke-dasharray: 3 3; opacity: 0.7; }
  .timeline-times { display: flex; justify-content: space-between; gap: 10px; margin-top: 6px; color: var(--ink-mute); font: 400 10.5px var(--font-mono); }
  .scrub-readout { color: var(--ink); }
  .down-text { color: var(--fire-gold); font-weight: 500; }
  .up-text { color: var(--fire-magenta); font-weight: 500; }
  .scrubber { width: 100%; margin: 8px 0 10px; height: 18px; appearance: none; -webkit-appearance: none; background: transparent; cursor: pointer; }
  .scrubber::-webkit-slider-runnable-track { height: 5px; border-radius: 3px; background: var(--surface-2); box-shadow: inset 0 1px 2px rgb(0 0 0 / 0.6); }
  .scrubber::-webkit-slider-thumb { -webkit-appearance: none; appearance: none; margin-top: -8px; width: 21px; height: 21px; border-radius: 50%; background: var(--chrome); border: 1px solid rgb(255 255 255 / 0.55); box-shadow: var(--chrome-bevel), 0 3px 10px rgb(0 0 0 / 0.7); }
  .scrubber::-moz-range-track { height: 5px; border-radius: 3px; background: var(--surface-2); }
  .scrubber::-moz-range-thumb { width: 21px; height: 21px; border-radius: 50%; background: var(--chrome); border: 1px solid rgb(255 255 255 / 0.55); box-shadow: var(--chrome-bevel), 0 3px 10px rgb(0 0 0 / 0.7); }
  .band-empty { padding: 14px 0; }

  .coverage-line { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; margin-top: 14px; }
  .coverage-badge { display: inline-flex; align-items: center; gap: 7px; flex: none; padding: 7px 14px; border: 1px solid var(--line); border-top-color: var(--glass-edge); border-radius: var(--radius-pill); font: 500 11px var(--font-mono); text-transform: uppercase; letter-spacing: 0.06em; color: var(--ink-mute); background: var(--panel); box-shadow: inset 0 1px 0 var(--glass-edge); }
  .coverage-badge.complete { color: var(--safe-text); border-color: var(--safe); }
  .coverage-badge.mixed, .coverage-badge.estimated { color: var(--ink); border-color: var(--ink-mute); }
  /* Lower sections are glass cards too — the page never falls back to bare
     text floating on black. */
  .pulse-lower { display: grid; grid-template-columns: 1fr 1.5fr; gap: var(--gap-card); margin-top: 28px; }
  .pulse-lower > div { padding: 4px var(--pad-card) 22px; border: 1px solid var(--line); border-top-color: var(--glass-edge); border-radius: var(--radius-card); background: var(--panel); box-shadow: var(--shadow); backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur); }
  .pulse-lower .section-title { margin-top: 20px; }
  .unavailable-copy { color: var(--ink-mute); font-size: 12.5px; line-height: 1.5; padding: 14px 0; }
  .protocol-bars { display: grid; gap: 11px; margin-top: 14px; }
  .protocol-bars div { display: grid; grid-template-columns: 75px 1fr 33px; gap: 8px; align-items: center; font: 11px var(--font-mono); color: var(--ink-mute); }
  .protocol-bars progress { width: 100%; height: 7px; accent-color: var(--down); }
  .protocol-bars b { color: var(--ink); font-size: 10px; }
  .top-devices { margin-top: 6px; border: 1px solid var(--line); border-top-color: var(--glass-edge); border-radius: var(--radius-card); background: var(--panel); box-shadow: var(--shadow); padding: 6px var(--pad-card); }
  .top-device { min-height: 57px; border-bottom: 1px solid var(--line); display: grid; grid-template-columns: 18px 1fr minmax(80px, 1fr) auto; align-items: center; gap: 12px; }
  .top-device:last-child { border-bottom: 0; }
  .device-label strong, .device-label small { display: block; }
  .device-label small { color: var(--ink-mute); margin-top: 3px; font-size: 11px; }
  .device-bar { display: block; height: 8px; border-radius: 4px; background: var(--surface-2); overflow: hidden; }
  .device-bar-fill { display: flex; height: 100%; border-radius: 4px; overflow: hidden; }
  .top-device > b { font: 500 11px var(--font-mono); color: var(--ink-mute); }
  .event-heading { margin-top: 32px; }
  .event-list { margin-top: 6px; padding: 4px var(--pad-card); border: 1px solid var(--line); border-top-color: var(--glass-edge); border-radius: var(--radius-card); background: var(--panel); box-shadow: var(--shadow); backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur); }
  .event-row { min-height: 57px; border-bottom: 1px solid var(--line); display: grid; grid-template-columns: 25px 1fr auto; align-items: center; gap: 10px; }
  .event-row:last-child { border-bottom: 0; }
  .event-row strong, .event-row small { display: block; }
  .event-row strong { font-size: 13.5px; }
  .event-row small { margin-top: 4px; color: var(--ink-mute); font-size: 11px; }
  .event-row time { color: var(--ink-mute); font: 10px var(--font-mono); }
  .event-kind { display: inline-grid; place-items: center; width: 21px; height: 21px; border: 1px solid currentColor; border-radius: 6px; font: 11px var(--font-mono); }
  .event-kind.info { color: var(--ink-mute); }
  .event-kind.secure { color: var(--safe-text); }
  .event-kind.watch { color: var(--fire-gold); border-style: dashed; }
  .event-kind.risk { color: var(--alert-text); border-width: 2px; }

  @media (max-width: 850px) {
    /* On a phone the copy sits fully above the flame, so the scrim is a simple
       vertical fade that clears before the fire starts. */
    .pulse-hero::before { height: 190px; background: linear-gradient(180deg, rgb(6 5 11 / 0.96) 0%, rgb(6 5 11 / 0.88) 56%, rgb(6 5 11 / 0) 100%); -webkit-mask-image: none; mask-image: none; }
    .pulse-hero, .pulse-hero :global(.lung-wrap) { min-height: 440px; }
    .pulse-hero :global(.lung-readout) { translate: 0 70px; }
    .hero-caption { bottom: 52px; }
    .stat-band { margin-top: -30px; }
    .pulse-lower { grid-template-columns: 1fr; }
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
