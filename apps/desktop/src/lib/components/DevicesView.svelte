<script lang="ts">
  import type { DeviceSnapshot, PresenceState } from '../api/types';
  import type { NetworkDetails } from '../api/automation';
  import type {NetworkSnapshot} from '../api/networkMonitor';
  import {responseLabel} from '../networkInventory';
  import type { ScanApi, ScanFinding, ScanStatus } from '../api/networkScan';
  import Icon from './Icon.svelte';
  import DeviceNameConfirmation from './DeviceNameConfirmation.svelte';
  import DeviceWebLinks from './DeviceWebLinks.svelte';
  import { recognizeDevice } from '../deviceRecognition';
  import type { DeviceLabel, DeviceLabelsApi } from '../api/deviceLabels';
  import NetworkScanPanel from './NetworkScanPanel.svelte';
  let scan = $state<ScanStatus | null>(null);
  import type { LiveState } from '../stores/live';
  import { formatThroughput } from './networkFormat';
  import { compareIpKeys, deviceIpSortKey } from '../ipSort';
  let { discovery = null, ondiscover, liveState = null, network = null, scanApi = null, initialQuery = '', labelsApi = null, onsaved }: { discovery?: NetworkSnapshot | null; ondiscover?: () => void; labelsApi?: DeviceLabelsApi | null; onsaved?: (label: DeviceLabel) => void; scanApi?: ScanApi | null; initialQuery?: string; liveState?: LiveState | null; network?: NetworkDetails | null } = $props();
  let query = $state('');
  $effect(() => { query = initialQuery; });
  let tab = $state('all' as 'all' | 'confirmed' | 'needs-confirm');
  let sort = $state('ip-asc' as 'ip-asc' | 'ip-desc' | 'discovery');
  const details = $derived(new Map(network?.devices.map(device => [device.device_id, device]) ?? []));
  const ipKeys = $derived(new Map(network?.devices.map(device => [device.device_id, deviceIpSortKey(device.ip_addresses)]) ?? []));
  const findingsByDevice = $derived.by(() => {
    const grouped = new Map<string, ScanFinding[]>();
    for (const finding of scan?.findings ?? []) {
      if (!finding.device_id) continue;
      const rows = grouped.get(finding.device_id) ?? [];
      rows.push(finding); grouped.set(finding.device_id, rows);
    }
    return grouped;
  });
  const devices = $derived(liveState ? liveState.deviceOrder.map(id => liveState.devices[id]).filter((device): device is DeviceSnapshot => Boolean(device)) : []);
  const recognition = $derived(new Map(devices.map(device => [device.device_id, recognizeDevice(device, details.get(device.device_id), findingsByDevice.get(device.device_id))])));
  const responses = $derived(discovery?.devices.filter(r => responseLabel(r,discovery.settings.interval_seconds) === 'Responding').length ?? null);
  const counts = $derived({ online: devices.filter(d => d.presence.state === 'online').length, confirmed: devices.filter(d => d.owner_confirmed).length, named: [...recognition.values()].filter(r => r.suggestion).length });
  const filtered = $derived(devices.filter(device => {
    const info = details.get(device.device_id);
    const hint = info?.home_assistant;
    const webClues = findingsByDevice.get(device.device_id)?.flatMap(f => Object.values(f.facts)).join(' ') ?? '';
    const text = `${device.owner_name ?? ''} ${device.identity.classification ?? ''} ${device.device_id} ${info?.mac_addresses.join(' ') ?? ''} ${info?.ip_addresses.join(' ') ?? ''} ${info?.mac_assignments?.map(a=>a.organization??'').join(' ')??''} ${hint?.name ?? ''} ${hint?.manufacturer ?? ''} ${hint?.model ?? ''} ${hint?.area ?? ''} ${recognition.get(device.device_id)?.kind ?? ''} ${webClues}`.toLowerCase();
    const matchesTab = tab === 'all' || (tab === 'confirmed' ? device.owner_confirmed : !device.owner_confirmed);
    return matchesTab && text.includes(query.toLowerCase());
  }));
  const visible = $derived(sort === 'discovery' ? filtered : [...filtered].sort((left, right) =>
    compareIpKeys(ipKeys.get(left.device_id) ?? null, ipKeys.get(right.device_id) ?? null, sort === 'ip-desc') || left.device_id.localeCompare(right.device_id)));
  function confidence(device: DeviceSnapshot): string {
    if (device.owner_confirmed) return 'Confirmed';
    if (device.evidence?.family === 'link_layer') return 'Address observed';
    if (device.evidence) return `${Math.round(device.evidence.confidence * 100)}% likely`;
    return 'Needs evidence';
  }
  function presenceLabel(value: PresenceState): string { return value === 'unknown' ? 'Presence unavailable' : value; }
  function bytes(device: DeviceSnapshot): string { return device.bandwidth.available ? formatThroughput((device.bandwidth.upload ?? 0) + (device.bandwidth.download ?? 0)) : 'Not measured'; }
  function seen(value: string): string { return new Date(value).toLocaleString([], { dateStyle:'medium', timeStyle:'short' }); }
</script>

<section class="devices-view" aria-labelledby="devices-heading">
  <div class="view-heading"><div><p class="kicker">DEVICES / IDENTITY</p><h1 id="devices-heading">Know what is home.</h1><p class="muted">Live presence, reported identities, and the first time each device was observed.</p></div></div>
  {#if ondiscover}<button class="discovery-launch" type="button" onclick={ondiscover}>Find devices across the LAN</button>{/if}
  <div class="inventory-summary" aria-label="Network overview"><div><strong>{devices.length}</strong><span>devices observed</span></div><div><strong>{discovery?.devices.length ? responses : counts.online}</strong><span>{discovery?.devices.length ? 'responding to discovery' : 'online now'}</span></div><div><strong>{counts.named}</strong><span>reported names</span></div><div><strong>{counts.confirmed}</strong><span>names confirmed</span></div></div>
  {#if scanApi}<NetworkScanPanel api={scanApi} onchange={value => scan = value}/>{/if}
  <label class="search"><span>Search devices</span><input bind:value={query} placeholder="Name, IP, MAC, room, or web identity" /></label>
  <div class="device-controls">
    <div class="tabs" role="group" aria-label="Filter devices">{#each [['all','All'],['confirmed','Confirmed'],['needs-confirm','Needs confirm']] as item}<button class:active={tab === item[0]} onclick={() => tab = item[0] as typeof tab} aria-pressed={tab === item[0]}>{item[1]}</button>{/each}</div>
    <label class="sort-control"><span>Sort by</span><select aria-label="Sort devices" bind:value={sort}><option value="ip-asc">IP address: low to high</option><option value="ip-desc">IP address: high to low</option><option value="discovery">Discovery order</option></select></label>
  </div>
  {#if network?.status === 'unavailable'}<p class="muted" role="status">Current IP addresses are unavailable. Saved hardware addresses remain visible.</p>{/if}
  {#if visible.length === 0}
    <div class="empty-state device-empty"><span class="empty-icon" aria-hidden="true">⌁</span><div><strong>{liveState?.connected ? 'No devices match' : 'No devices to show'}</strong><p class="muted">{liveState?.connected ? 'Try a different name or address.' : 'Pair NeonHearth to begin building a private device list.'}</p></div></div>
  {:else}
    <div class="device-table">{#each visible as device (device.device_id)}
      {@const info = details.get(device.device_id)}
      {@const hint = info?.home_assistant}
      {@const findings = findingsByDevice.get(device.device_id) ?? []}
      {@const identity = recognition.get(device.device_id)!}
      {@const response = discovery?.devices.find(r => info?.mac_addresses.includes(r.mac)) ?? null}
      {@const webFindings = findings.filter(f => f.facts.web_status)}
      <article class="device-card">
        <div class="device-name"><span class="device-glyph {device.presence.state}"><Icon name={identity.icon} size={26}/><span class="presence-dot {device.presence.state}" aria-hidden="true"></span></span><div><strong>{identity.name}</strong><span>{identity.kind} · {presenceLabel(device.presence.state)}</span></div></div>
        <span class="confidence {device.owner_confirmed ? 'confirmed' : 'likely'}"><span aria-hidden="true">{device.owner_confirmed ? '✓' : '△'}</span> {confidence(device)}</span>
        <p class="addresses"><b>IP address</b>{info?.ip_addresses.length ? info.ip_addresses.join(' · ') : 'Not currently observed'}</p>
        <p class="addresses"><b>Hardware address</b>{info?.mac_addresses.length ? info.mac_addresses.join(' · ') : 'Details unavailable'}</p>
        {#if info?.mac_assignments?.length}<p><b>Network interface maker · IEEE</b>{info.mac_assignments.map(a => a.organization ?? (a.status === 'locally_administered' ? 'Private / locally administered address' : 'No unambiguous assignment')).join(' · ')}<small class="maker-note">Identifies the address registration; the finished device may use another brand.</small></p>{/if}
        {#if identity.manufacturer || identity.model}<p><b>Reported maker / model</b>{[identity.manufacturer,identity.model].filter(Boolean).join(' · ')}</p>{/if}
        {#if hint}<p><b>Home Assistant match</b>{hint.area ?? 'Room unassigned'} · matched by reported MAC; verify the physical device</p>{/if}
        <DeviceWebLinks {findings}/>
        <DeviceNameConfirmation {device} suggestion={identity.suggestion} api={labelsApi} {onsaved}/>
        {#each webFindings as web}
          <p class="web-identity"><b>Web identification · {web.facts.web_scheme?.toUpperCase()} {web.port}</b>
            {web.facts.web_identity_hint ? `${web.facts.web_identity_hint} · ` : ''}{web.facts.web_title ?? web.facts.web_auth_realm ?? web.facts.web_server ?? `HTTP ${web.facts.web_status}`}
            <small>Reported by device · {web.facts.certificate_trust === 'unverified' ? 'certificate unverified · ' : ''}needs your verification</small>
          </p>
        {/each}
        <p><b>Identification sources</b>{identity.sources.join(' · ') || 'Waiting for reported identity'}</p>
        <p><b>Evidence</b>{device.evidence ? `${device.evidence.family.replaceAll('_', ' ')} via ${device.evidence.source}` : 'No identity evidence'}</p>
        <p><b>Bandwidth</b>{bytes(device)}{device.bandwidth.coverage ? ` · ${device.bandwidth.coverage}` : ''}</p>
        {#if response}<p><b>Active LAN discovery</b>{responseLabel(response,discovery?.settings.interval_seconds ?? 120)} · last response {seen(response.last_seen)}</p>{/if}
        <p><b>First / last seen</b>{seen(device.first_seen_at)} → {seen(device.last_seen_at)}</p>
        {#if findings.length}
          <details class="scan-findings"><summary>Discovery results · {findings.filter(f => f.status === 'open').length} open ports</summary>
            {#each findings as finding}<p><b>{finding.protocol === 'tcp' ? `TCP ${finding.port}` : finding.protocol.replaceAll('_',' ')} · {finding.status.replaceAll('_',' ')}</b>{finding.service_hint ? `${finding.service_hint} (port hint)` : ''}{Object.entries(finding.facts).map(([key,value]) => `${key}: ${value}`).join(' · ')}</p>{/each}
            <small>Observed {scan?.finished_at ? seen(scan.finished_at) : 'during the current scan'}. Reported metadata needs your verification.</small>
          </details>
        {/if}
        <p><b>Owner confirmation</b>{device.owner_confirmed ? 'Confirmed by you' : 'Needs your confirmation'}</p>
      </article>
    {/each}</div>
  {/if}
</section>
<style>
  .discovery-launch{padding:10px 14px;margin:0 0 18px;border:1px solid var(--line-strong);border-radius:7px;background:var(--surface);color:var(--accent);font:inherit;cursor:pointer}
  .inventory-summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}.inventory-summary div{padding:18px;border:1px solid var(--line);border-radius:10px;background:var(--surface)}.inventory-summary strong{display:block;font:600 28px var(--font-display);color:var(--accent)}.inventory-summary span{font-size:11px;color:var(--muted-strong)}.device-glyph{position:relative;width:44px;height:44px;display:grid;place-items:center;background:var(--surface);border:1px solid var(--line-strong);border-radius:10px;color:var(--accent);flex:none}.device-glyph .presence-dot{position:absolute;right:-3px;bottom:-3px}.device-card{min-width:0}.device-name{align-items:center}@media(max-width:650px){.inventory-summary{grid-template-columns:repeat(2,1fr)}}
  .scan-findings{overflow-wrap:anywhere;border-top:1px solid var(--line);padding-top:10px}.scan-findings summary{cursor:pointer}.scan-findings p{display:block}
  .web-identity{overflow-wrap:anywhere}.web-identity small{display:block;color:var(--muted-strong,var(--ink-mute))}
  .addresses { overflow-wrap:anywhere }.device-name>div { min-width:0;overflow-wrap:anywhere }.maker-note{display:block;font-size:11px;margin-top:6px}.device-card :global(.name-confirmation),.device-card :global(.web-links),.device-card .scan-findings{grid-column:1/-1}
  .device-controls { display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem }
  .device-controls .tabs { margin-bottom:0 }
  .sort-control { display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;font-size:.8rem }
  .sort-control select { max-width:100%;padding:.65rem;border:1px solid var(--border, #44454b);border-radius:10px;background:var(--surface, #1b1c20);color:var(--text, #f2f2f8) }
</style>
