<script lang="ts">
  import { onMount } from 'svelte';
  import { createApiClient } from './lib/api/client';
  import { initialLiveState, type LiveState } from './lib/stores/live';
  import { createLiveConnection } from './lib/stores/connection';
  import CollectorStatus, { type CollectorState } from './lib/components/CollectorStatus.svelte';
  import PulseView from './lib/components/PulseView.svelte';
  import DevicesView from './lib/components/DevicesView.svelte';
  import GuardView from './lib/components/GuardView.svelte';
  import CamerasView from './lib/components/CamerasView.svelte';
  import HomeView from './lib/components/HomeView.svelte';
  import DoctorView from './lib/components/DoctorView.svelte';

  type Destination = 'pulse' | 'devices' | 'guard' | 'cameras' | 'home' | 'doctor' | 'history' | 'settings';
  const nav: Array<[Destination, string, string]> = [['pulse', 'Pulse', '◒'], ['devices', 'Devices', '◌'], ['guard', 'Guard', '⌁'], ['cameras', 'Cameras', '□'], ['home', 'Home', '⌂'], ['doctor', 'Doctor', '✚'], ['history', 'History', '↺'], ['settings', 'Settings', '⚙']];
  let collectorState: CollectorState = $state('connecting'); let view: Destination = $state('pulse'); let liveState: LiveState = $state(initialLiveState); let moreOpen = $state(false); let cameraClient = $state<ReturnType<typeof createApiClient> | null>(null);
  function eventDetail(event: LiveState['timeline'][number]): string {
    if (event.type === 'resync_required') return 'Waiting for safe recovery';
    if (event.data.payload.type === 'service_status') return event.data.payload.data.detail;
    if (event.data.payload.type === 'presence_changed') return event.data.payload.data.reason;
    if (event.data.payload.type === 'policy_changed') return `${event.data.payload.data.requested_action.replaceAll('_', ' ')} · ${event.data.payload.data.enforcement_result.replaceAll('_', ' ')}`;
    return `${event.data.payload.data.samples.length} samples received`;
  }
  onMount(() => {
    let active = true;
    const client = createApiClient({ baseUrl: window.location.origin, serviceToken: '' }); cameraClient = client;
    const connection = createLiveConnection({ client, onState: (state) => { if (active) liveState = state; } });
    void client.health().then(() => { if (active) collectorState = 'ready'; }).catch(() => { if (active) collectorState = 'offline'; });
    void connection.start();
    return () => { active = false; connection.stop(); };
  });
</script>
<svelte:head><title>NeonHearth — {view}</title></svelte:head>
<div class="app-shell"><aside class="rail"><div class="brand"><span class="brand-mark">✦</span><span>NEON<br/>HEARTH</span></div><nav aria-label="Primary">{#each nav as item}<button class:active={view === item[0]} type="button" onclick={() => { view = item[0]; moreOpen = false; }}><span class="nav-icon">{item[2]}</span><span>{item[1]}</span></button>{/each}</nav><div class="rail-foot"><span class="secure-icon">⌾</span><span>LOCAL<br/>ONLY</span></div></aside><header class="mobile-head"><div class="brand"><span class="brand-mark">✦</span><span>NEONHEARTH</span></div><span class="kicker">{view.toUpperCase()}</span></header><main>{#if view === 'pulse'}<PulseView state={liveState}/>{:else if view === 'devices'}<DevicesView liveState={liveState}/>{:else if view === 'guard'}<GuardView state={liveState} client={cameraClient} />{:else if view === 'cameras'}{#if cameraClient}<CamerasView client={cameraClient} />{:else}<section class="not-ready"><p class="muted">Connecting to the local collector…</p></section>{/if}{:else if view === 'home'}<HomeView liveState={liveState}/>{:else if view === 'doctor'}{#if cameraClient}<DoctorView client={cameraClient} />{:else}<section class="not-ready"><p class="muted">Connecting to the local collector…</p></section>{/if}{:else}<section class="not-ready"><span class="not-ready-mark">⌁</span><p class="kicker">{view.toUpperCase()}</p><h1>This room is still being wired.</h1><p class="muted">This view is not available in this build yet. Your secure pairing and private network data remain untouched.</p></section>{/if}</main><aside class="events-rail"><div class="section-title"><h2>Live thread</h2><span class="live-pill">● {liveState.timeline.length ? 'ACTIVE' : 'QUIET'}</span></div>{#if liveState.timeline.length}<div class="event-list" aria-label="Live events">{#each liveState.timeline.slice(-5).reverse() as event}<div class="event-row"><span class="event-kind info" aria-hidden="true">·</span><span><strong>{event.type === 'resync_required' ? 'Stream resync requested' : event.data.payload.type === 'service_status' ? `Collector ${event.data.payload.data.state}` : event.data.payload.type === 'presence_changed' ? `Presence: ${event.data.payload.data.to}` : event.data.payload.type === 'policy_changed' ? `Guard: ${event.data.payload.data.evaluation.reason.replaceAll('_', ' ')}` : 'Bandwidth updated'}</strong><small>{eventDetail(event)}</small></span><time>{event.type === 'event' ? new Date(event.data.occurred_at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }) : 'now'}</time></div>{/each}</div>{:else}<div class="event-quiet"><span>⌁</span><strong>Nothing needs attention</strong><p class="muted">Events will appear here as your home changes.</p></div>{/if}<CollectorStatus state={collectorState}/></aside><nav class="mobile-nav" aria-label="Mobile navigation">{#each nav.slice(0, 2) as item}<button class:active={view === item[0]} type="button" onclick={() => { view = item[0]; moreOpen = false; }}><span>{item[2]}</span>{item[1]}</button>{/each}<button class:active={moreOpen} type="button" aria-expanded={moreOpen} aria-controls="mobile-drawer" onclick={() => moreOpen = !moreOpen}><span>⋯</span>More</button></nav>{#if moreOpen}<div class="mobile-drawer" id="mobile-drawer" aria-label="More destinations">{#each nav.slice(2) as item}<button class:active={view === item[0]} type="button" onclick={() => { view = item[0]; moreOpen = false; }}><span>{item[2]}</span>{item[1]}</button>{/each}</div>{/if}</div>
<style>
  :global(button:focus-visible), :global(input:focus-visible) { outline: 3px solid #ffcd66; outline-offset: 3px; }
  .events-rail .event-list { border-top: 1px solid #17323d; }
  .events-rail .event-row { min-height: 57px; border-bottom: 1px solid #17323d; display: grid; grid-template-columns: 25px 1fr auto; align-items: center; gap: 10px; }
  .events-rail .event-row strong, .events-rail .event-row small { display: block; }
  .events-rail .event-row small { margin-top: 4px; color: #77959d; font-size: 11px; }
  .events-rail .event-row time { color: #64838b; font: 10px monospace; }
  .events-rail .event-kind { display: inline-grid; place-items: center; width: 21px; height: 21px; border: 1px solid #548cff; border-radius: 4px; color: #548cff; font: 11px monospace; }
  .mobile-drawer { display: none; }
  @media (max-width: 850px) { .mobile-drawer { position: fixed; z-index: 6; right: 8px; bottom: 73px; display: grid; grid-template-columns: 1fr 1fr; gap: 5px; padding: 8px; background: #0b1c26; border: 1px solid #28505a; border-radius: 8px; box-shadow: 0 8px 30px #0008; }.mobile-drawer button { min-height: 44px; padding: 9px 12px; border: 0; border-radius: 5px; color: #9bb7bb; background: #102a35; font: 600 12px Arial; text-align: left; }.mobile-drawer button.active { color: #e9fbfc; outline: 1px solid #63f3f0; }.mobile-drawer button span { display: inline-block; width: 22px; color: #63f3f0; } }
</style>
