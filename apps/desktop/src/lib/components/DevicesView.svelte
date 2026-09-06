<script lang="ts">
  import type { DeviceSnapshot, PresenceState } from '../api/types';
  import type { NetworkDetails } from '../api/automation';
  import type { LiveState } from '../stores/live';
  import { compareIpKeys, deviceIpSortKey } from '../ipSort';
  let { liveState = null, network = null }: { liveState?: LiveState | null; network?: NetworkDetails | null } = $props();
  let query = $state('');
  let tab = $state('all' as 'all' | 'confirmed' | 'needs-confirm');
  let sort = $state('ip-asc' as 'ip-asc' | 'ip-desc' | 'discovery');
  const details = $derived(new Map(network?.devices.map(device => [device.device_id, device]) ?? []));
  const ipKeys = $derived(new Map(network?.devices.map(device => [device.device_id, deviceIpSortKey(device.ip_addresses)]) ?? []));
  const devices = $derived(liveState ? liveState.deviceOrder.map(id => liveState.devices[id]).filter((device): device is DeviceSnapshot => Boolean(device)) : []);
  const filtered = $derived(devices.filter(device => {
    const info = details.get(device.device_id);
    const hint = info?.home_assistant;
    const text = `${device.owner_name ?? ''} ${device.identity.classification ?? ''} ${device.device_id} ${info?.mac_addresses.join(' ') ?? ''} ${info?.ip_addresses.join(' ') ?? ''} ${hint?.name ?? ''} ${hint?.manufacturer ?? ''} ${hint?.model ?? ''} ${hint?.area ?? ''}`.toLowerCase();
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
  function bytes(device: DeviceSnapshot): string { return device.bandwidth.available ? `${Math.round(((device.bandwidth.upload ?? 0) + (device.bandwidth.download ?? 0)) / 1_000_000)} Mbps` : 'Not measured'; }
  function seen(value: string): string { return new Date(value).toLocaleString([], { dateStyle:'medium', timeStyle:'short' }); }
</script>

<section class="devices-view" aria-labelledby="devices-heading">
  <div class="view-heading"><div><p class="kicker">DEVICES / IDENTITY</p><h1 id="devices-heading">Know what is home.</h1><p class="muted">See network addresses, first observations, and device names reported by Home Assistant.</p></div></div>
  <label class="search"><span>Search devices</span><input bind:value={query} placeholder="Name, IP, MAC address, or room" /></label>
  <div class="device-controls">
    <div class="tabs" role="tablist">{#each [['all','All'],['confirmed','Confirmed'],['needs-confirm','Needs confirm']] as item}<button class:active={tab === item[0]} onclick={() => tab = item[0] as typeof tab} role="tab" aria-selected={tab === item[0]}>{item[1]}</button>{/each}</div>
    <label class="sort-control"><span>Sort by</span><select aria-label="Sort devices" bind:value={sort}><option value="ip-asc">IP address: low to high</option><option value="ip-desc">IP address: high to low</option><option value="discovery">Discovery order</option></select></label>
  </div>
  {#if network?.status === 'unavailable'}<p class="muted" role="status">Current IP addresses are unavailable. Saved hardware addresses remain visible.</p>{/if}
  {#if visible.length === 0}
    <div class="empty-state device-empty"><span class="empty-icon" aria-hidden="true">⌁</span><div><strong>{liveState?.connected ? 'No devices match' : 'No devices to show'}</strong><p class="muted">{liveState?.connected ? 'Try a different name or address.' : 'Pair NeonHearth to begin building a private device list.'}</p></div></div>
  {:else}
    <div class="device-table">{#each visible as device (device.device_id)}
      {@const info = details.get(device.device_id)}
      {@const hint = info?.home_assistant}
      <article class="device-card">
        <div class="device-name"><span class="presence-dot {device.presence.state}" aria-hidden="true"></span><div><strong>{device.owner_name ?? hint?.name ?? (info?.mac_addresses[0] ? `Device ${info.mac_addresses[0]}` : `Device …${device.device_id.slice(-8)}`)}</strong><span>{device.identity.classification ?? (hint ? [hint.manufacturer,hint.model].filter(Boolean).join(' · ') || 'Home Assistant device' : 'Type not yet identified')} · {presenceLabel(device.presence.state)}</span></div></div>
        <span class="confidence {device.owner_confirmed ? 'confirmed' : 'likely'}"><span aria-hidden="true">{device.owner_confirmed ? '✓' : '△'}</span> {confidence(device)}</span>
        <p class="addresses"><b>IP address</b>{info?.ip_addresses.length ? info.ip_addresses.join(' · ') : 'Not currently observed'}</p>
        <p class="addresses"><b>Hardware address</b>{info?.mac_addresses.length ? info.mac_addresses.join(' · ') : 'Details unavailable'}</p>
        {#if hint}<p><b>Home Assistant match</b>{hint.area ?? 'Room unassigned'} · matched by reported MAC; verify the physical device</p>{/if}
        <p><b>Evidence</b>{device.evidence ? `${device.evidence.family.replaceAll('_', ' ')} via ${device.evidence.source}` : 'No identity evidence'}</p>
        <p><b>Bandwidth</b>{bytes(device)}{device.bandwidth.coverage ? ` · ${device.bandwidth.coverage}` : ''}</p>
        <p><b>First / last seen</b>{seen(device.first_seen_at)} → {seen(device.last_seen_at)}</p>
        <p><b>Owner confirmation</b>{device.owner_confirmed ? 'Confirmed by you' : 'Needs your confirmation'}</p>
      </article>
    {/each}</div>
  {/if}
</section>
<style>
  .addresses { overflow-wrap:anywhere }.device-name>div { min-width:0;overflow-wrap:anywhere }
  .device-controls { display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem }
  .device-controls .tabs { margin-bottom:0 }
  .sort-control { display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;font-size:.8rem }
  .sort-control select { max-width:100%;padding:.65rem;border:1px solid var(--border, #44454b);border-radius:10px;background:var(--surface, #1b1c20);color:var(--text, #f2f2f8) }
</style>
