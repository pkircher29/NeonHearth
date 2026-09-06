<script lang="ts">
  // Home tab: 2D plan editor + 3D twin over one shared HomeApi and live state (M5 integration · H8).
  import { onMount } from 'svelte';
  import { createHomeApi, type HomeApi, type HomeSnapshot } from '../stores/home';
  import type { LiveState } from '../stores/live';
  import type { AutomationSnapshot, NetworkDetails } from '../api/automation';
  import type { TwinDevice } from '../twin/geometry';
  import HomeEditorView from './HomeEditorView.svelte';
  import HomeTwin3D from './HomeTwin3D.svelte';
  import { sameTwinDevices, toBandwidthMap, toHomeDeviceRefs, toPresenceMap, toTwinDevices, withEmptyPlanOn404 } from './homeViewData';

  // `api` is a test seam: when absent, the view builds the real loopback client on mount
  // exactly the way App builds the camera client.
  let { liveState, api = null, automation = null, network = null }: { liveState: LiveState; api?: HomeApi | null; automation?: AutomationSnapshot | null; network?: NetworkDetails | null } = $props();

  type HomeTab = 'editor' | 'twin';
  let tab = $state<HomeTab>('editor');
  let twinVisited = $state(false); // the twin mounts on first visit, then stays alive so selection survives tab switches
  let homeApi = $state<HomeApi | null>(null);
  // One snapshot, loaded once here, shared by the editor and the twin (audit M-27).
  let snapshot = $state<HomeSnapshot | null>(null);
  let loading = $state(true);
  let snapshotError = $state(false);
  let fallbackNotice = $state(false);
  let selectedDeviceId = $state<string | null>(null);
  let reducedMotion = $state(false);

  const addresses = $derived(new Map(network?.devices.map(device => [device.device_id, device]) ?? []));
  function knownName(id: string): string | null {
    const info = addresses.get(id);
    return liveState.devices[id]?.owner_name ?? info?.home_assistant?.name ?? info?.mac_addresses[0] ?? null;
  }
  const deviceRefs = $derived([...toHomeDeviceRefs(liveState.devices).map(d => ({ ...d, name: knownName(d.device_id) ?? d.name })), ...(automation?.devices ?? []).map(d => ({ device_id: d.device_id, name: d.name }))]);
  // Memoized by content (audit H-5): a fresh array per bandwidth frame would
  // make the twin rebuild its scene and reset the camera several times a second.
  let twinCache: TwinDevice[] = [];
  const twinDevices = $derived.by(() => {
    const next = [...toTwinDevices(liveState.devices).map(d => ({ ...d, label: knownName(d.device_id) ?? d.label })), ...(automation?.devices ?? []).map(d => ({ device_id: d.device_id, label: d.name, is_camera: d.entities.some(e => e.entity_id.startsWith('camera.')) }))];
    if (!sameTwinDevices(twinCache, next)) twinCache = next;
    return twinCache;
  });
  const presence = $derived(toPresenceMap(liveState.devices));
  const bandwidth = $derived(toBandwidthMap(liveState.devices));
  const selectedName = $derived(
    selectedDeviceId === null
      ? null
      : knownName(selectedDeviceId) ?? automation?.devices.find(d => d.device_id === selectedDeviceId)?.name ?? `Device ${selectedDeviceId.slice(0, 8)}`
  );

  function openTab(next: HomeTab) {
    tab = next;
    if (next === 'twin') twinVisited = true;
  }
  function onTwinSelect(device_id: string) {
    selectedDeviceId = device_id;
  }
  function onTwinFallback() {
    fallbackNotice = true;
    tab = 'editor';
  }
  function onSnapshot(next: HomeSnapshot) {
    snapshot = next;
  }

  async function loadSnapshot() {
    const current = homeApi;
    if (!current) return;
    snapshotError = false;
    loading = true;
    try {
      snapshot = await current.fetchHome(); // a 404 already degraded to an empty plan in the wrapper
    } catch {
      snapshot = null;
      snapshotError = true;
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    if (typeof window.matchMedia === 'function') {
      reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }
    homeApi = withEmptyPlanOn404(api ?? createHomeApi({ baseUrl: window.location.origin }));
    void loadSnapshot();
  });
</script>

<section class="home-view" aria-label="Home">
  <div class="home-topbar">
    <div class="home-tabs" role="tablist" aria-label="Home views">
      <button type="button" role="tab" id="home-tab-editor" aria-selected={tab === 'editor'} aria-controls="home-panel-editor" onclick={() => openTab('editor')}>Plan editor</button>
      <button type="button" role="tab" id="home-tab-twin" aria-selected={tab === 'twin'} aria-controls="home-panel-twin" onclick={() => openTab('twin')}>3D view</button>
    </div>
    {#if selectedName}
      <p class="home-selection" role="status">Selected device: <strong>{selectedName}</strong></p>
    {/if}
  </div>

  {#if fallbackNotice}
    <div class="home-banner" role="status">
      3D unavailable on this device. The plan editor shows the same devices and placements.
      <button type="button" onclick={() => (fallbackNotice = false)}>Dismiss</button>
    </div>
  {/if}

  {#if !homeApi}
    <p class="home-connecting muted">Connecting to the local collector…</p>
  {:else if loading}
    <div class="editor-state" role="status">Reading home plan…</div>
  {:else if snapshotError || !snapshot}
    <div class="editor-state error" role="alert">The home plan is unavailable right now. Try again shortly. <button type="button" onclick={() => void loadSnapshot()}>Retry</button></div>
  {:else}
    {#if automation?.devices.length}
      <p class="home-banner">{automation.devices.length} Home Assistant devices are available in the placement tray. Reported rooms: {automation.areas.join(', ') || 'none'}. Draw the rooms to match your home, then place each device. Room names do not establish physical coordinates.</p>
    {/if}
    <div id="home-panel-editor" role="tabpanel" aria-labelledby="home-tab-editor" hidden={tab !== 'editor'}>
      <HomeEditorView api={homeApi} devices={deviceRefs} {snapshot} onsnapshot={onSnapshot} />
    </div>
    {#if twinVisited}
      <div id="home-panel-twin" role="tabpanel" aria-labelledby="home-tab-twin" hidden={tab !== 'twin'}>
        <div class="view-heading">
          <p class="kicker">HOME / 3D VIEW</p>
        </div>
        <HomeTwin3D
          plan={snapshot.plan}
          placements={snapshot.placements}
          devices={twinDevices}
          {presence}
          {bandwidth}
          {reducedMotion}
          visible={tab === 'twin'}
          onselect={onTwinSelect}
          onfallback={onTwinFallback}
        />
      </div>
    {/if}
  {/if}
</section>

<style>
  .home-view { display: grid; gap: 14px; align-content: start; }
  .home-topbar { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; }
  .home-tabs { display: flex; gap: 7px; }
  .home-tabs button { min-height: 44px; padding: 9px 15px; border: 1px solid var(--line-strong); border-radius: 5px; background: transparent; color: var(--ink); font: 600 12px var(--font-display); cursor: pointer; }
  .home-tabs button[aria-selected='true'] { border-color: var(--accent); color: var(--accent); box-shadow: inset 0 0 14px var(--accent)14; }
  .home-selection { margin: 0; color: var(--muted-strong); font: 11px var(--font-mono); }
  .home-selection strong { color: var(--accent); font-weight: 700; }
  .home-banner { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding: 12px 14px; border: 1px solid var(--gold); border-radius: 8px; background: var(--surface); color: var(--ink); font-size: 12px; }
  .home-banner button { min-height: 38px; padding: 7px 12px; border: 1px solid var(--accent); border-radius: 5px; background: transparent; color: var(--accent); font: 600 12px var(--font-display); cursor: pointer; }
  .editor-state { margin-top: 14px; padding: 18px; border: 1px dashed var(--line-strong); color: var(--muted-strong); display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  .editor-state.error { border-color: var(--pink); color: #ffb4cc; }
  .editor-state button { min-height: 40px; padding: 8px 14px; border: 1px solid var(--accent); border-radius: 5px; background: transparent; color: var(--accent); font: 600 12px var(--font-display); cursor: pointer; }
  .home-connecting { margin: 18px 0 0; }
  [role='tabpanel'][hidden] { display: none; }
</style>
