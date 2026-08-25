<script lang="ts">
  import type { DeviceSnapshot, PresenceState } from '../api/types';
  import type { LiveState } from '../stores/live';
  interface Props { state?: LiveState | null; }
  let { liveState = null }: { liveState?: LiveState | null } = $props();
  let query = $state(''); let tab = $state('all' as 'all' | 'confirmed' | 'needs-confirm');
  const devices = $derived(liveState ? liveState.deviceOrder.map((id) => liveState.devices[id]).filter((device): device is DeviceSnapshot => Boolean(device)) : []);
  const visible = $derived(devices.filter((device) => {
    const text = `${device.owner_name ?? ''} ${device.identity.classification ?? ''} ${device.device_id}`.toLowerCase();
    const matchesTab = tab === 'all' || (tab === 'confirmed' ? device.owner_confirmed : !device.owner_confirmed);
    return matchesTab && text.includes(query.toLowerCase());
  }));
  function confidence(device: DeviceSnapshot): string { if (device.owner_confirmed) return 'Confirmed'; if (device.evidence) return `${Math.round(device.evidence.confidence * 100)}% likely`; return 'Needs evidence'; }
  function presenceLabel(value: PresenceState): string { return value === 'unknown' ? 'Presence unavailable' : value; }
  function bytes(device: DeviceSnapshot): string { if (!device.bandwidth.available) return 'Unavailable'; return `${Math.round(((device.bandwidth.upload ?? 0) + (device.bandwidth.download ?? 0)) / 1_000_000)} Mbps`; }
  function seen(value: string): string { return new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }); }
  </script>

<section class="devices-view" aria-labelledby="devices-heading"><div class="view-heading"><div><p class="kicker">DEVICES / IDENTITY</p><h1 id="devices-heading">Know what is home.</h1><p class="muted">Identity is earned from evidence, never guessed from a name alone.</p></div></div><label class="search"><span>Search devices</span><input bind:value={query} placeholder="e.g. living room TV" /></label><div class="tabs" role="tablist">{#each [['all','All'],['confirmed','Confirmed'],['needs-confirm','Needs confirm']] as item}<button class:active={tab === item[0]} onclick={() => tab = item[0] as typeof tab} role="tab" aria-selected={tab === item[0]}>{item[1]}</button>{/each}</div>{#if visible.length === 0}<div class="empty-state device-empty"><span class="empty-icon">⌁</span><div><strong>{liveState?.connected ? 'No devices match' : 'No devices to show'}</strong><p class="muted">{liveState?.connected ? 'Try a different name or identity filter.' : 'Pair NeonHearth to begin building a private device list.'}</p></div></div>{:else}<div class="device-table">{#each visible as device}<article class="device-card"><div class="device-name"><span class="presence-dot {device.presence.state}" aria-hidden="true"></span><div><strong>{device.owner_name ?? `Device …${device.device_id.slice(-8)}`}</strong><span>{device.identity.classification ?? 'Identity unavailable'} · {presenceLabel(device.presence.state)}</span></div></div><span class="confidence {device.owner_confirmed ? 'confirmed' : 'likely'}"><span aria-hidden="true">{device.owner_confirmed ? '✓' : '△'}</span> {confidence(device)}</span><p><b>Evidence</b>{device.evidence ? `${device.evidence.family} via ${device.evidence.source}` : 'Unavailable — no identity evidence'}</p><p><b>Availability</b>{bytes(device)} · {device.bandwidth.coverage ?? 'coverage unavailable'}</p><p><b>First / last seen</b>{seen(device.first_seen_at)} → {seen(device.last_seen_at)}</p><p><b>Owner confirmation</b>{device.owner_confirmed ? 'Confirmed by you' : 'Needs your confirmation'}</p></article>{/each}</div>{/if}</section>
