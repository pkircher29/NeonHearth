<script lang="ts">
  import type { ServerMessage } from '../api/types';
  import type { NetworkSnapshot } from '../api/networkMonitor';
  import { liveStatus, topDevices, type LiveState } from '../stores/live';
  import type { HostApi } from '../api/hostMonitor';
  import type { AutomationApi } from '../api/automation';
  import { deviceMetaFrom, hostFlowFrom, type DeviceMeta, type HostFlow, type HostSample } from './flowMap';
  import HearthPulse from './HearthPulse.svelte';
  import FlowMap from './FlowMap.svelte';
  import TrafficScope from './TrafficScope.svelte';
  import { formatThroughput } from './networkFormat';

  interface Props { state?: LiveState | null; network?: NetworkSnapshot | null; onselectdevice?: (deviceId: string) => void; onopentraffic?: () => void; hostApi?: HostApi | null; automationApi?: AutomationApi | null; }
  let { state: liveState = null, network = null, onselectdevice, onopentraffic, hostApi = null, automationApi = null }: Props = $props();
  const HERO_KEY = 'neonhearth.pulse.hero';
  type Hero = 'flow' | 'hearth';
  function readHero(): Hero { try { return globalThis.localStorage?.getItem(HERO_KEY) === 'hearth' ? 'hearth' : 'flow'; } catch { return 'flow'; } }
  let hero = $state<Hero>(readHero());
  function chooseHero(next: Hero) { hero = next; try { globalThis.localStorage?.setItem(HERO_KEY, next); } catch { /* storage unavailable: choice lasts for this session */ } }
  // Inventory details (MAC maker, IP) name and group devices that carry no stated type.
  let meta = $state<ReadonlyMap<string, DeviceMeta> | undefined>(undefined);
  // This computer's live traffic: the labelled fallback when per-device counters need a router feed that is not there.
  let hostFlow = $state<HostFlow | null>(null);
  const status = $derived(liveStatus(liveState));
  const hasThroughput = $derived(Boolean(liveState && status === 'live' && (liveState.aggregate.upload !== null || liveState.aggregate.download !== null)));
  // A one-sided reading is not a total: say which side is missing instead of adding a fake zero.
  const currentBps = $derived(hasThroughput && liveState && liveState.aggregate.upload !== null && liveState.aggregate.download !== null ? liveState.aggregate.upload + liveState.aggregate.download : null);
  const oneSided = $derived(hasThroughput && liveState && currentBps === null ? (liveState.aggregate.upload === null ? 'Only download is reported' : 'Only upload is reported') : null);
  const routerName = $derived(network?.router.source?.trim() || 'The router');
  const devices = $derived(liveState ? topDevices(liveState, 4) : []);
  const recentEvents = $derived(liveState?.timeline.slice(-8).reverse() ?? []);
  const allDevices = $derived(liveState ? liveState.deviceOrder.map((id) => liveState.devices[id]).filter((device): device is NonNullable<typeof device> => Boolean(device)) : []);
  const presenceCounts = $derived(allDevices.reduce((acc, device) => { const key = device.presence.state === 'online' ? 'online' : device.presence.state === 'quiet' ? 'quiet' : device.presence.state === 'blocked' ? 'blocked' : 'other'; acc[key] += 1; return acc; }, { online: 0, quiet: 0, blocked: 0, other: 0 }));
  const hostSource = $derived(!hasThroughput && Boolean(liveState?.connected) && hostFlow !== null);
  const flowUpload = $derived(hasThroughput && liveState ? liveState.aggregate.upload : hostSource && hostFlow ? hostFlow.up : null);
  const flowDownload = $derived(hasThroughput && liveState ? liveState.aggregate.download : hostSource && hostFlow ? hostFlow.down : null);
  const makerGrouped = $derived(Boolean(meta) && allDevices.some((device) => !device.owner_type && !device.identity.classification));
  const householdReady = $derived(network?.router.status === 'ready' && network.router.download !== null && network.router.upload !== null);

  $effect(() => {
    const api = automationApi;
    if (!api) { meta = undefined; return; }
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function load() {
      try {
        const details = await api!.network();
        if (alive) meta = new Map(details.devices.map((device) => [device.device_id, deviceMetaFrom(device)]));
      } catch { /* inventory unavailable: devices keep their short ids */ }
      if (alive) timer = setTimeout(() => void load(), 30_000);
    }
    void load();
    return () => { alive = false; clearTimeout(timer); };
  });

  $effect(() => {
    const api = hostApi;
    const wanted = !hasThroughput && Boolean(liveState?.connected);
    if (!api || !wanted) { hostFlow = null; return; }
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let previous: HostSample | null = null;
    async function tick() {
      if (typeof document === 'undefined' || !document.hidden) {
        try {
          const snapshot = await api!.snapshot();
          if (alive) { hostFlow = hostFlowFrom(previous, snapshot); previous = snapshot; }
        } catch { if (alive) { hostFlow = null; previous = null; } }
      }
      if (alive) timer = setTimeout(() => void tick(), 5_000);
    }
    void tick();
    return () => { alive = false; clearTimeout(timer); };
  });

  const deviceTotal = (device: LiveState['devices'][string]): number | null => (device.bandwidth.upload === null && device.bandwidth.download === null ? null : (device.bandwidth.upload ?? 0) + (device.bandwidth.download ?? 0));
  function widthFor(device: LiveState['devices'][string]): number {
    return Math.min(100, ((deviceTotal(device) ?? 0) / Math.max(currentBps ?? 1, 1)) * 100);
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
  <div class="view-heading"><div><p class="kicker">NETWORK / OVERVIEW</p><h1 id="pulse-heading">Network control.</h1><p class="muted">Traffic, devices, and connection status.</p></div></div>
  {#if onopentraffic}
    <section class="household-source" aria-label="Household internet traffic">
      <div><p class="kicker">HOUSEHOLD INTERNET / ROUTER SOURCE</p>
        {#if householdReady}
          <h2>Household traffic is available</h2>
          <p class="household-rates"><span>Download <strong>{formatThroughput(network?.router.download)}</strong></span><span>Upload <strong>{formatThroughput(network?.router.upload)}</strong></span></p>
          <p>{routerName} · router-reported internet totals. These readings do not measure individual devices or traffic between LAN devices.</p>
        {:else}
          <h2>No fresh router readings</h2>
          <p>Household internet totals require a supported router feed. Open Traffic, then Network preferences to connect it. Device discovery and this computer's monitoring do not require that feed.</p>
        {/if}
      </div>
      <button class="pause-button" type="button" onclick={onopentraffic}>Open Traffic</button>
    </section>
  {/if}
<p class="connection-summary" role="status">{liveState?.connected ? 'Live readings connected' : 'Live readings unavailable — check your collector connection.'}</p>
  <div class="metrics"><article><span class="metric-label">THROUGHPUT</span><strong>{formatThroughput(currentBps)}</strong><span class="metric-note">{oneSided ?? (hasThroughput ? 'Measured devices · upload + download now' : liveState?.connected ? 'No per-device counter source' : 'Collector connection unavailable')}</span></article><article><span class="metric-label">COVERAGE</span><strong class="coverage-badge {liveState?.coverage ?? 'unavailable'}"><span aria-hidden="true">{liveState?.coverage === 'complete' ? '✓' : liveState?.coverage === 'mixed' ? '△' : '○'}</span> {liveState?.coverage ?? 'UNAVAILABLE'}</strong><span class="metric-note">Evidence quality, not a heat score</span></article></div>
  <TrafficScope points={currentBps !== null ? liveState?.throughput ?? [] : []} connected={Boolean(liveState?.connected)}/>

  <section class="hearth-panel" class:flow-panel={hero === 'flow'} aria-labelledby="pulse-visual-heading">
    <header class="visual-head">
      <div><p class="kicker">PULSE / DEVICES</p><h2 id="pulse-visual-heading">{hero === 'flow' ? 'Flow map' : 'Hearth'}</h2></div>
      <div class="hearth-switch" role="group" aria-label="Pulse visual"><button type="button" aria-pressed={hero === 'flow'} onclick={() => chooseHero('flow')}>Flow</button><button type="button" aria-pressed={hero === 'hearth'} onclick={() => chooseHero('hearth')}>Hearth</button></div>
    </header>
    <p class="source-note" role="note">{#if hasThroughput}The {hero === 'flow' ? 'flow map' : 'hearth'} below uses per-device counters. Router totals are kept separate.{:else if hero === 'flow' && hostSource}Per-device traffic is unavailable: no per-device counter source is reporting. The flow map below shows this computer's live traffic instead. It is not whole-home traffic.{:else if liveState?.connected}Per-device traffic is unavailable: no per-device counter source is reporting, so devices are shown without flows. Nothing is estimated or invented. Router totals are kept separate.{:else}Per-device traffic is unavailable while the collector connection is down.{/if}</p>
    <div class="hearth-stage">{#if hero === 'flow'}<FlowMap devices={allDevices} upload={flowUpload} download={flowDownload} connected={Boolean(liveState?.connected)} onselect={onselectdevice} {meta} hostApps={hostSource && hostFlow ? hostFlow.apps : []} coreLabel={hostSource ? 'This computer' : null}/>{:else}<HearthPulse devices={allDevices} upload={hasThroughput && liveState ? liveState.aggregate.upload : null} download={hasThroughput && liveState ? liveState.aggregate.download : null} connected={Boolean(liveState?.connected)} onselect={onselectdevice}/>{/if}</div>
    {#if hero === 'flow'}
    <aside class="hearth-legend" aria-label="How to read the flow map">
      <p class="kicker">READING THE FLOW MAP</p>
      <dl>
        <div><dt><i class="swatch down"></i>Download</dt><dd>Orange to gold particles travel out from the core to a device. Faster rate, more and quicker particles.</dd></div>
        <div><dt><i class="swatch up"></i>Upload</dt><dd>Violet to magenta particles travel in from a device to the core.</dd></div>
        <div><dt><i class="swatch width"></i>Stream width</dt><dd>The device's share of measured device traffic, on a log scale. Idle devices keep a hairline; no line means no counters.</dd></div>
        <div><dt><i class="swatch ring"></i>History ring</dt><dd>The last 60 seconds around the core, newest at 12 o'clock and sweeping clockwise. Download rises outside the baseline, upload dips inside it.</dd></div>
        <div><dt><i class="swatch sector"></i>Sectors</dt><dd>Devices are grouped by type. The busiest sit closest to the core, idle ones further out.</dd></div>
        {#if makerGrouped}<div><dt><i class="swatch maker"></i>Grouped by maker</dt><dd>Devices with no stated type are grouped by the maker of their network card (MAC vendor). That is inferred, not confirmed.</dd></div>{/if}
        {#if hostSource}<div><dt><i class="swatch computer"></i>This computer</dt><dd>Showing this computer's traffic. Per-device traffic needs the router feed. The core and ring are not whole-home traffic; diamonds are its busiest applications.</dd></div>{/if}
      </dl>
      <p class="kicker">NODES</p>
      <ol class="tiers">
        <li><i class="node online"></i><span>Online</span><small>filled, glowing</small></li>
        <li><i class="node quiet"></i><span>Quiet</span><small>violet ember</small></li>
        <li><i class="node offline"></i><span>Offline</span><small>hollow ring</small></li>
        <li><i class="node blocked"></i><span>Blocked</span><small>red ring</small></li>
        <li><i class="node unknown"></i><span>Unknown</span><small>dashed ring</small></li>
        <li><i class="node present"></i><span>Online, no counters</span><small>dim, no stream</small></li>
      </ol>
      <p class="counts"><b>{presenceCounts.online}</b> online · <b>{presenceCounts.quiet}</b> quiet · <b>{presenceCounts.blocked}</b> blocked</p>
    </aside>
    {:else}
    <aside class="hearth-legend" aria-label="How to read the hearth">
      <p class="kicker">READING THE HEARTH</p>
      <dl>
        <div><dt><i class="swatch cyan"></i>Download</dt><dd>Inner arc, 100 kbps to 1 Gbps on a log scale.</dd></div>
        <div><dt><i class="swatch gold"></i>Upload</dt><dd>Outer arc, same scale.</dd></div>
        <div><dt><i class="swatch spark"></i>Sparks</dt><dd>One per device. Size is its share of measured device traffic, when available; a glow means online; a dashed ring means a verified block.</dd></div>
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
    {/if}
  </section>
  <div class="section-title"><h2>Devices using the most</h2><span class="muted">{devices.length ? `${devices.length} observed` : 'no usage data'}</span></div>{#if devices.length}<div class="top-devices">{#each devices as device}<div class="top-device"><span class="device-symbol">◌</span><span class="device-label"><strong>{device.owner_name ?? `Device ${device.device_id.slice(0, 6)}`}</strong><small>{device.presence.state}</small></span><span class="device-bar"><i style={'width: ' + widthFor(device) + '%'}></i></span><b>{formatThroughput(deviceTotal(device))}</b></div>{/each}</div>{:else}<div class="empty-state"><span class="empty-icon">⌁</span><div><strong>No usage data yet</strong><p class="muted">Usage bars appear only after the collector reports available bandwidth.</p></div></div>{/if}
  <div class="section-title event-heading"><h2>Recent events</h2><span class="muted">bounded to 8</span></div>{#if recentEvents.length}<div class="event-list" aria-label="Recent network events">{#each recentEvents as event}<div class="event-row"><span class="event-kind {eventCopy(event).cue}" aria-label={`${eventCopy(event).cue} status`}>{eventCopy(event).cue === 'risk' ? '!' : eventCopy(event).cue === 'watch' ? '△' : eventCopy(event).cue === 'secure' ? '✓' : '·'}</span><span><strong>{eventCopy(event).title}</strong><small>{eventCopy(event).detail}</small></span><time>{event.type === 'event' ? new Date(event.data.occurred_at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }) : 'now'}</time></div>{/each}</div>{:else}<p class="unavailable-copy">{liveState?.connected ? 'No recent events. The collector is connected.' : 'Recent events are unavailable while the collector reconnects.'}</p>{/if}

</section>
<style>
  .household-source { display:flex;align-items:center;gap:24px;padding:20px 24px;border:1px solid var(--line-strong);border-radius:7px;background:var(--surface);margin:20px 0 14px; }.household-source>div { flex:1;min-width:0; }.household-source h2 { font-size:20px;margin:8px 0; }.household-source p:not(.kicker) { color:var(--muted);font-size:12px;line-height:1.6; }.household-rates { display:flex;gap:24px;flex-wrap:wrap; }.household-rates span { display:grid;gap:3px; }.household-rates strong { color:var(--ink);font:500 22px var(--font-display); }.household-source>button { flex-shrink:0; }
  @media(max-width:850px) { .household-source { flex-direction:column;align-items:stretch;gap:10px;padding:18px; } }
  .pause-button { border: 1px solid var(--line-strong); border-radius: 5px; color: var(--ink); background: var(--surface); min-height: 44px; padding: 0 13px; cursor: pointer; }
  .pause-button:focus-visible, :global(button:focus-visible), :global(input:focus-visible) { outline: 3px solid var(--gold); outline-offset: 3px; }

  .coverage-badge.mixed, .coverage-badge.estimated { color: var(--gold); }
  .coverage-badge.complete { color: var(--accent); }.coverage-badge.unavailable,.coverage-badge.local-only { color: var(--pink); }
  .unavailable-copy { color: var(--muted); font-size: 12px; line-height: 1.5; padding: 18px 0; }.top-devices { border-top: 1px solid var(--line); }.top-device { min-height: 57px; border-bottom: 1px solid var(--line); display: grid; grid-template-columns: 25px 1fr minmax(80px, 1fr) auto; align-items: center; gap: 11px; }.device-label strong,.device-label small { display: block; }.device-label small { color: var(--muted); margin-top: 3px; font-size: 11px; }.device-bar { height: 7px; border: 1px solid var(--line-strong); background: var(--surface); }.device-bar i { display: block; height: 100%; background: var(--blue); }.top-device>b { font: 11px var(--font-mono); color: var(--muted-strong); }.event-heading { margin-top: 32px; }.event-list { border-top: 1px solid var(--line); }.event-row { min-height: 57px; border-bottom: 1px solid var(--line); display: grid; grid-template-columns: 25px 1fr auto; align-items: center; gap: 10px; }.event-row strong,.event-row small { display: block; }.event-row small { margin-top: 4px; color: var(--muted); font-size: 11px; }.event-row time { color: var(--faint); font: 10px var(--font-mono); }.event-kind { display: inline-grid; place-items: center; width: 21px; height: 21px; border: 1px solid currentColor; border-radius: 4px; font: 11px var(--font-mono); }.event-kind.info { color: var(--blue); }.event-kind.secure { color: var(--accent); }.event-kind.watch { color: var(--gold); border-style: dashed; }.event-kind.risk { color: var(--pink); border-width: 2px; }
  @media (max-width: 850px) { .view-heading { flex-wrap: wrap; }.pause-button { width: 100%; }.top-device { grid-template-columns: 25px 1fr auto; }.device-bar { grid-column: 2 / -1; }.top-device>b { grid-column: 3; grid-row: 1; } }
  .hearth-panel { margin:28px 0 0; border:1px solid var(--line-mid); border-top:3px solid var(--accent); background:var(--surface); min-width:0; display:grid; grid-template-columns:minmax(0,1fr) 250px; grid-template-areas:'head head' 'note note' 'stage legend'; }
  .visual-head { grid-area:head; display:flex; justify-content:space-between; align-items:center; gap:12px; padding:18px 22px; border-bottom:1px solid var(--line); }
  .visual-head h2 { margin:6px 0 0; font:700 25px var(--font-display); text-transform:uppercase; letter-spacing:-.02em; }
  .hearth-switch { display:inline-flex; border:1px solid var(--line-strong); flex:none; }
  .hearth-switch button { min-height:44px; min-width:76px; padding:0 14px; border:0; background:none; color:var(--muted); font:600 11px var(--font-mono); letter-spacing:.08em; text-transform:uppercase; cursor:pointer; }
  .hearth-switch button+button { border-left:1px solid var(--line-strong); }
  .hearth-switch button[aria-pressed="true"] { color:var(--accent-ink); background:var(--accent); }
  .source-note { grid-area:note; margin:0; padding:12px 22px; border-bottom:1px solid var(--line); color:var(--muted); font-size:12px; line-height:1.55; }
  .hearth-stage { grid-area:stage; min-width:0; display:grid; place-items:center; padding:8px 0 0; background:radial-gradient(ellipse at center, var(--surface-raised), transparent 66%); }
  .hearth-stage > :global(*) { width:100%; max-width:900px; min-width:0; }
  .hearth-legend { grid-area:legend; border-left:1px solid var(--line); padding:18px 20px 16px; display:grid; align-content:start; gap:10px; font-size:12px; min-width:0; }
  .hearth-legend dl { margin:0 0 8px; display:grid; gap:10px; }
  .hearth-legend dt { display:flex; align-items:center; gap:8px; color:var(--ink); font-weight:600; }
  .hearth-legend dd { margin:3px 0 0 24px; color:var(--muted); line-height:1.45; }
  .hearth-legend .swatch { display:inline-block; flex:none; width:16px; height:6px; }
  .hearth-legend .swatch.cyan { background:var(--tier-cyan); } .hearth-legend .swatch.gold { background:var(--tier-gold); }
  .hearth-legend .swatch.spark { width:10px; height:10px; border-radius:50%; background:var(--accent); box-shadow:0 0 8px var(--accent); margin-inline:3px; }
  .hearth-legend .swatch.down { background:linear-gradient(90deg,#ff6d3b,#ffc53d); } .hearth-legend .swatch.up { background:linear-gradient(90deg,#7c4dff,#e040fb); }
  .hearth-legend .swatch.width { height:8px; background:linear-gradient(90deg,rgba(233,251,252,.25),rgba(233,251,252,.8)); clip-path:polygon(0 40%,100% 0,100% 100%,0 60%); }
  .hearth-legend .swatch.ring { width:10px; height:10px; border-radius:50%; border:2px solid #ffc53d; border-right-color:#7c4dff; border-bottom-color:#7c4dff; margin-inline:3px; background:none; }
  .hearth-legend .swatch.sector { background:rgba(233,251,252,.5); }
  .hearth-legend .swatch.maker { background:repeating-linear-gradient(90deg,rgba(233,251,252,.6) 0 3px,transparent 3px 5px); }
  .hearth-legend .swatch.computer { width:10px; height:10px; transform:rotate(45deg); background:#0e101a; border:2px solid #ff9d3b; margin-inline:3px; }
  .hearth-legend .tiers { list-style:none; margin:0 0 8px; padding:0; display:grid; gap:5px; }
  .hearth-legend .tiers li { display:grid; grid-template-columns:10px 1fr auto; align-items:center; gap:8px; }
  .hearth-legend .tiers i { width:10px; height:10px; border-radius:50%; box-sizing:border-box; }
  .hearth-legend .tiers small { color:var(--faint); font:10px var(--font-mono); }
  .hearth-legend .tiers i.node.online { background:radial-gradient(circle at 35% 35%,#fff 0,#ffc53d 35%,#ff6d3b); box-shadow:0 0 6px rgba(255,109,59,.6); }
  .hearth-legend .tiers i.node.quiet { background:#7c4dff; box-shadow:0 0 5px rgba(124,77,255,.5); }
  .hearth-legend .tiers i.node.offline { border:1.5px solid rgba(233,251,252,.45); }
  .hearth-legend .tiers i.node.blocked { border:2px solid #ff4757; background:rgba(255,71,87,.14); }
  .hearth-legend .tiers i.node.unknown { border:1.5px dashed rgba(233,251,252,.6); }
  .hearth-legend .tiers i.node.present { background:#ff6d3b; opacity:.7; }
  .hearth-legend .counts { margin:0; padding-top:10px; border-top:1px solid var(--line); color:var(--muted); font:11px var(--font-mono); }
  .hearth-legend .counts b { color:var(--ink); font-weight:600; }
  @media (max-width:850px) { .hearth-panel { grid-template-columns:minmax(0,1fr); grid-template-areas:'head' 'note' 'stage' 'legend'; }.hearth-legend { border-left:0; border-top:1px solid var(--line); }.visual-head { padding:16px; }.source-note { padding:12px 16px; } }
</style>
