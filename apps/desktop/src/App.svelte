<script lang="ts">
  import { onMount } from 'svelte';
  import { createApiClient } from './lib/api/client';
  import { createAuthSession, type AuthState } from './lib/auth/session';
  import { bootstrapServiceToken, clearStoredToken } from './lib/pairing';
  import { initialLiveState, type LiveState } from './lib/stores/live';
  import { createLiveConnection, type LiveConnection } from './lib/stores/connection';
  import { createHomeApi, type HomeApi } from './lib/stores/home';
  import CollectorStatus, { collectorStateFor } from './lib/components/CollectorStatus.svelte';
  import NetworkTrafficView from './lib/components/NetworkTrafficView.svelte';
  import {createNetworkApi,type NetworkApi} from './lib/api/networkMonitor';
  let networkApi=$state<NetworkApi|null>(null);
  let networkSnapshot=$state<import('./lib/api/networkMonitor').NetworkSnapshot|null>(null);
  import {createHostApi,type HostApi} from './lib/api/hostMonitor';
  let hostApi=$state<HostApi|null>(null);
  import PulseView from './lib/components/PulseView.svelte';
  import DevicesView from './lib/components/DevicesView.svelte';
  import GuardView from './lib/components/GuardView.svelte';
  import CamerasView from './lib/components/CamerasView.svelte';
  import HomeView from './lib/components/HomeView.svelte';
  import DoctorView from './lib/components/DoctorView.svelte';
  import SettingsView from './lib/components/SettingsView.svelte';
  import HistoryView from './lib/components/HistoryView.svelte';
  import { applyMotion, readMotion } from './lib/stores/preferences';
  import SignInView from './lib/components/SignInView.svelte';
  import StepUpPrompt from './lib/components/StepUpPrompt.svelte';
  import Icon, { type IconName } from './lib/components/Icon.svelte';
  import { formatThreadTime, threadEntries } from './lib/components/liveThread';

  import { createDeviceLabelsApi, type DeviceLabelsApi, type DeviceLabel } from './lib/api/deviceLabels';
  let labelsApi = $state<DeviceLabelsApi | null>(null);
  let labels = $state<Record<string, DeviceLabel>>({});
  let guardScan = $state<import('./lib/api/networkScan').ScanStatus | null>(null);
  function labelSaved(label: DeviceLabel) { labels = {...labels, [label.device_id]:label}; }
  import AutomationView from './lib/components/AutomationView.svelte';
  import { createScanApi, type ScanApi } from './lib/api/networkScan';
  let scanApi = $state<ScanApi | null>(null);
  import { createAutomationApi, type AutomationApi, type AutomationSnapshot, type NetworkDetails } from './lib/api/automation';
  let automationApi = $state<AutomationApi | null>(null);
  let automationSnapshot = $state<AutomationSnapshot | null>(null);
  let networkDetails = $state<NetworkDetails | null>(null);
  async function refreshAutomation() { if (automationApi) automationSnapshot = await automationApi.snapshot(); }

  type Destination = 'traffic' | 'pulse' | 'devices' | 'guard' | 'cameras' | 'home' | 'doctor' | 'history' | 'settings' | 'automation';
  const nav: Array<[Destination, string, IconName]> = [['pulse', 'Pulse', 'pulse'], ['devices', 'Devices', 'devices'], ['traffic', 'Traffic', 'pulse'], ['guard', 'Guard', 'guard'], ['cameras', 'Cameras', 'cameras'], ['home', 'Home', 'home'], ['automation', 'Automation', 'home'], ['doctor', 'Doctor', 'doctor'], ['history', 'History', 'history'], ['settings', 'Settings', 'settings']];
  let view: Destination = $state('pulse'); let liveState: LiveState = $state(initialLiveState); let moreOpen = $state(false);
  const namedState = $derived({...liveState, devices: Object.fromEntries(Object.entries(liveState.devices).map(([id, device]) => [id, {...device, ...labels[id]}]))});
  let deviceQuery = $state('');
  const thread = $derived(threadEntries(liveState.timeline, 6));
  function showDevice(deviceId: string) { const device = liveState.devices[deviceId]; deviceQuery = device?.owner_name ?? deviceId.slice(0, 8); view = 'devices'; moreOpen = false; }
  let cameraClient = $state<ReturnType<typeof createApiClient> | null>(null);
  let homeApi = $state<HomeApi | null>(null);
  let authState = $state<AuthState | null>(null);
  let session: ReturnType<typeof createAuthSession> | null = null;
  let connection: LiveConnection | null = null;
  // The collector status is derived from the live connection itself, so it
  // stays truthful over a multi-day session instead of a one-shot health probe.
  const collectorState = $derived(collectorStateFor(liveState));
  const signedOut = $derived(Boolean(authState?.challenged && !authState.credential));

  // A new credential is proven by the first request: restart the live
  // connection and let a 401 bring the sign-in screen back with a reason.
  function restartConnection() { connection?.stop(); void connection?.start(); }
  function signInOwner(token: string, remember: boolean) { if (session?.signInOwner(token, remember)) restartConnection(); }
  function signInPhone(code: string, remember: boolean) { if (session?.signInPhone(code, remember)) restartConnection(); }
  function signOut() { networkSnapshot = null; labels = {}; guardScan = null; automationSnapshot = null; networkDetails = null; session?.signOut(); connection?.stop(); liveState = initialLiveState; }
  async function stepUp(pin: string) { if (!cameraClient) return; const result = await cameraClient.stepUp(pin); session?.stepupGranted(result.expires_at); }

  onMount(() => {
    let active = true;
    applyMotion(readMotion());
    let storage: Storage | null = null;
    try { storage = window.sessionStorage; } catch { storage = null; }
    const auth = createAuthSession(storage); session = auth;
    // Local pairing: the installed service serves this page and the Start-menu
    // launcher passes the owner token in the URL fragment (never sent over the
    // network). It becomes a remembered owner sign-in for this tab.
    const launcherToken = bootstrapServiceToken(window);
    if (launcherToken) { auth.signInOwner(launcherToken, true); clearStoredToken(window); }
    const unsubscribe = auth.subscribe((next) => { if (active) authState = next; });
    const client = createApiClient({ baseUrl: window.location.origin, auth }); cameraClient = client;
    homeApi = createHomeApi({ baseUrl: window.location.origin, auth });
    connection = createLiveConnection({ client, onState: (state) => { if (active) liveState = state; } });
    automationApi = createAutomationApi(auth);
    scanApi = createScanApi(auth);
    labelsApi = createDeviceLabelsApi(auth);
    hostApi = createHostApi(auth);
    networkApi = createNetworkApi(auth);
    let automationTimer: ReturnType<typeof setTimeout>;
    async function pollAutomation() {
      if (!active) return;
      if (auth.state.credential?.kind === 'owner' && ['automation', 'home', 'devices', 'guard', 'traffic'].includes(view)) {
        const result = await Promise.allSettled([automationApi!.snapshot(), automationApi!.network(), labelsApi!.list(), ['guard','traffic'].includes(view) ? scanApi!.status() : Promise.resolve(null), view === 'devices' ? networkApi!.snapshot() : Promise.resolve(null)]);
        if (active && auth.state.credential?.kind === 'owner') {
          automationSnapshot = result[0].status === 'fulfilled' ? result[0].value : null;
          networkDetails = result[1].status === 'fulfilled' ? result[1].value : null;
          if (result[2].status === 'fulfilled') labels = Object.fromEntries(result[2].value.map(label => [label.device_id,label]));
          guardScan = result[3].status === 'fulfilled' ? result[3].value : null;
          networkSnapshot = result[4].status === 'fulfilled' ? result[4].value : null;
        }
      } else if (auth.state.credential?.kind !== 'owner') { networkSnapshot = null; automationSnapshot = null; networkDetails = null; labels = {}; guardScan = null; }
      if (active) automationTimer = setTimeout(() => void pollAutomation(), 2000);
    }
    void pollAutomation();
    void connection.start();
    return () => { active = false; clearTimeout(automationTimer); unsubscribe(); connection?.stop(); };
  });
</script>
<svelte:head><title>NeonHearth — {view}</title></svelte:head>
<div class="app-shell"><aside class="rail"><div class="brand"><span class="brand-mark"><Icon name="hearth" size={22} strokeWidth={1.6} /></span><span>NEON<br/>HEARTH</span></div><nav aria-label="Primary">{#each nav as item}<button class:active={view === item[0]} type="button" aria-current={view === item[0] ? 'page' : undefined} onclick={() => { view = item[0]; moreOpen = false; }}><span class="nav-icon"><Icon name={item[2]} /></span><span>{item[1]}</span></button>{/each}</nav><div class="rail-foot"><span class="secure-icon"><Icon name="lock" size={18} /></span><span>LOCAL<br/>ONLY</span></div></aside><header class="mobile-head"><div class="brand"><span class="brand-mark"><Icon name="hearth" size={20} strokeWidth={1.6} /></span><span>NEONHEARTH</span></div><span class="kicker">{view.toUpperCase()}</span></header><main>{#if signedOut}<SignInView failure={authState?.failure ?? null} onowner={signInOwner} onphone={signInPhone} />{:else if view === 'pulse'}<PulseView state={namedState} onselectdevice={showDevice}/>{:else if view === 'traffic'}{#if hostApi && networkApi && authState?.credential?.kind === 'owner'}<NetworkTrafficView api={networkApi} {hostApi} liveState={namedState} network={networkDetails} scan={guardScan} onselectdevice={showDevice}/>{:else}<p class="muted">Sign in as the owner to view your network and this computer's applications.</p>{/if}{:else if view === 'devices'}<DevicesView discovery={networkSnapshot} ondiscover={() => view = 'traffic'} liveState={namedState} labelsApi={authState?.credential?.kind === 'owner' ? labelsApi : null} onsaved={labelSaved} initialQuery={deviceQuery} network={networkDetails} scanApi={authState?.credential?.kind === 'owner' ? scanApi : null}/>{:else if view === 'guard'}<GuardView state={namedState} client={cameraClient} network={networkDetails} scan={guardScan} labelsApi={authState?.credential?.kind === 'owner' ? labelsApi : null} onsaved={labelSaved} />{:else if view === 'cameras'}{#if cameraClient}<CamerasView client={cameraClient} />{:else}<section class="not-ready"><p class="muted">Connecting to the local collector…</p></section>{/if}{:else if view === 'home'}<HomeView liveState={namedState} api={homeApi} automation={automationSnapshot} network={networkDetails}/>{:else if view === 'automation'}{#if automationApi && authState?.credential?.kind === 'owner'}<AutomationView api={automationApi} snapshot={automationSnapshot} refresh={refreshAutomation} openHome={() => view = 'home'}/>{:else}<p class="muted">Sign in as the owner to configure home automation.</p>{/if}{:else if view === 'doctor'}{#if cameraClient}<DoctorView client={cameraClient} />{:else}<section class="not-ready"><p class="muted">Connecting to the local collector…</p></section>{/if}{:else if view === 'history'}{#if cameraClient}<HistoryView client={cameraClient} />{:else}<section class="not-ready"><p class="muted">Connecting to the local collector…</p></section>{/if}{:else if view === 'settings'}{#if cameraClient && authState}<SettingsView client={cameraClient} auth={authState} onsignout={signOut} />{:else}<section class="not-ready"><p class="muted">Connecting to the local collector…</p></section>{/if}{/if}</main><aside class="events-rail"><div class="section-title"><h2>Live thread</h2><span class="live-pill">● {thread.length ? 'ACTIVE' : 'QUIET'}</span></div>{#if thread.length}<div class="event-list" aria-label="Live events">{#each thread as entry (entry.key)}<div class="event-row"><span class="event-kind {entry.cue}" aria-label={`${entry.cue} status`}><Icon name={entry.cue === 'risk' ? 'alert' : entry.cue === 'secure' ? 'check' : entry.cue === 'watch' ? 'alert' : 'dot'} size={12} strokeWidth={2.2} /></span><span><strong>{entry.title}</strong><small>{entry.detail}</small></span><time>{formatThreadTime(entry.at)}</time></div>{/each}</div>{:else}<div class="event-quiet"><span><Icon name="hearth" size={26} /></span><strong>Nothing needs attention</strong><p class="muted">Presence and Guard changes will appear here as your home changes.</p></div>{/if}<CollectorStatus state={collectorState}/></aside><nav class="mobile-nav" aria-label="Mobile navigation">{#each nav.slice(0, 2) as item}<button class:active={view === item[0]} type="button" aria-current={view === item[0] ? 'page' : undefined} onclick={() => { view = item[0]; moreOpen = false; }}><span><Icon name={item[2]} /></span>{item[1]}</button>{/each}<button class:active={moreOpen} type="button" aria-expanded={moreOpen} aria-controls="mobile-drawer" onclick={() => moreOpen = !moreOpen}><span><Icon name="more" /></span>More</button></nav>{#if moreOpen}<div class="mobile-drawer" id="mobile-drawer" aria-label="More destinations">{#each nav.slice(2) as item}<button class:active={view === item[0]} type="button" onclick={() => { view = item[0]; moreOpen = false; }}><span><Icon name={item[2]} size={18} /></span>{item[1]}</button>{/each}</div>{/if}{#if authState?.stepupRequired}<StepUpPrompt onsubmit={stepUp} oncancel={() => session?.dismissStepup()} />{/if}</div>
<style>
  :global(button:focus-visible), :global(input:focus-visible) { outline: 3px solid #ffcd66; outline-offset: 3px; }
  .events-rail .event-list { border-top: 1px solid #17323d; }
  .events-rail .event-row { min-height: 57px; border-bottom: 1px solid #17323d; display: grid; grid-template-columns: 25px 1fr auto; align-items: center; gap: 10px; }
  .events-rail .event-row strong, .events-rail .event-row small { display: block; }
  .events-rail .event-row small { margin-top: 4px; color: #77959d; font-size: 11px; }
  .events-rail .event-row time { color: #64838b; font: 10px monospace; }
  .events-rail .event-kind { display: inline-grid; place-items: center; width: 21px; height: 21px; border: 1px solid currentColor; border-radius: 4px; color: var(--info); }
  .events-rail .event-kind.secure { color: var(--ok); }
  .events-rail .event-kind.watch { color: var(--watch); border-style: dashed; }
  .events-rail .event-kind.risk { color: var(--risk); border-width: 2px; }
  .mobile-drawer { display: none; }
  @media (max-width: 850px) { .mobile-drawer { position: fixed; z-index: 6; right: 8px; bottom: 73px; display: grid; grid-template-columns: 1fr 1fr; gap: 5px; padding: 8px; background: #0b1c26; border: 1px solid #28505a; border-radius: 8px; box-shadow: 0 8px 30px #0008; }.mobile-drawer button { min-height: 44px; padding: 9px 12px; border: 0; border-radius: 5px; color: #9bb7bb; background: #102a35; font: 600 12px Arial; text-align: left; }.mobile-drawer button.active { color: #e9fbfc; outline: 1px solid #63f3f0; }.mobile-drawer button span { display: inline-block; width: 22px; color: #63f3f0; } }
</style>
