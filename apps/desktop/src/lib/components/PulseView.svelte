<script lang="ts">
  import type { ServerMessage } from '../api/types';
  import type { NetworkSnapshot } from '../api/networkMonitor';
  import { liveStatus, topDevices, type LiveState } from '../stores/live';
  import TrafficScope from './TrafficScope.svelte';
  import { formatThroughput } from './networkFormat';

  interface Props { state?: LiveState | null; network?: NetworkSnapshot | null; onopentraffic?: () => void; }
  let { state: liveState = null, network = null, onopentraffic }: Props = $props();
  const status = $derived(liveStatus(liveState));
  const hasThroughput = $derived(Boolean(liveState && status === 'live' && (liveState.aggregate.upload !== null || liveState.aggregate.download !== null)));
  // A one-sided reading is not a total: say which side is missing instead of adding a fake zero.
  const currentBps = $derived(hasThroughput && liveState && liveState.aggregate.upload !== null && liveState.aggregate.download !== null ? liveState.aggregate.upload + liveState.aggregate.download : null);
  const oneSided = $derived(hasThroughput && liveState && currentBps === null ? (liveState.aggregate.upload === null ? 'Only download is reported' : 'Only upload is reported') : null);
  const routerName = $derived(network?.router.source?.trim() || 'The router');
  const devices = $derived(liveState ? topDevices(liveState, 4) : []);
  const recentEvents = $derived(liveState?.timeline.slice(-8).reverse() ?? []);
  const householdReady = $derived(network?.router.status === 'ready' && network.router.download !== null && network.router.upload !== null);

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
</style>
