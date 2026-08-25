<script lang="ts">
  // Home tab: 2D plan editor + 3D twin over one shared HomeApi and live state (M5 integration · H8).
  import { onMount } from 'svelte';
  import { createHomeApi, type HomeApi, type HomeSnapshot } from '../stores/home';
  import type { LiveState } from '../stores/live';
  import HomeEditorView from './HomeEditorView.svelte';
  import HomeTwin3D from './HomeTwin3D.svelte';
  import { toBandwidthMap, toHomeDeviceRefs, toPresenceMap, toTwinDevices, withEmptyPlanOn404 } from './homeViewData';

  // `api` is a test seam: when absent, the view builds the real loopback client on mount
  // exactly the way App builds the camera client.
  let { liveState, api = null }: { liveState: LiveState; api?: HomeApi | null } = $props();

  type HomeTab = 'editor' | 'twin';
  let tab = $state<HomeTab>('editor');
  let twinVisited = $state(false); // the twin mounts on first visit, then stays alive so selection survives tab switches
  let homeApi = $state<HomeApi | null>(null);
  let snapshot = $state<HomeSnapshot | null>(null);
  let snapshotError = $state(false);
  let fallbackNotice = $state(false);
  let selectedDeviceId = $state<string | null>(null);
  let reducedMotion = $state(false);

  const deviceRefs = $derived(toHomeDeviceRefs(liveState.devices));
  const twinDevices = $derived(toTwinDevices(liveState.devices));
  const presence = $derived(toPresenceMap(liveState.devices));
  const bandwidth = $derived(toBandwidthMap(liveState.devices));
  const selectedName = $derived(
    selectedDeviceId === null
      ? null
      : liveState.devices[selectedDeviceId]?.owner_name ?? `Device ${selectedDeviceId.slice(0, 8)}`
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

  async function loadSnapshot() {
    const current = homeApi;
    if (!current) return;
    snapshotError = false;
    try {
      snapshot = await current.fetchHome(); // a 404 already degraded to an empty plan in the wrapper
    } catch {
      snapshot = null;
      snapshotError = true;
    }
  }

  onMount(() => {
    if (typeof window.matchMedia === 'function') {
      reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }
    homeApi = withEmptyPlanOn404(api ?? createHomeApi({ baseUrl: window.location.origin, serviceToken: '' }));
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

  {#if homeApi}
    <div id="home-panel-editor" role="tabpanel" aria-labelledby="home-tab-editor" hidden={tab !== 'editor'}>
      <HomeEditorView api={homeApi} devices={deviceRefs} />
    </div>
    {#if twinVisited}
      <div id="home-panel-twin" role="tabpanel" aria-labelledby="home-tab-twin" hidden={tab !== 'twin'}>
        <div class="view-heading">
          <p class="kicker">HOME / 3D VIEW</p>
        </div>
        {#if snapshotError}
          <div class="home-banner error" role="alert">
            The home plan could not be loaded for the 3D view.
            <button type="button" onclick={() => void loadSnapshot()}>Retry</button>
          </div>
        {/if}
        <HomeTwin3D
          plan={snapshot?.plan ?? null}
          placements={snapshot?.placements ?? []}
          devices={twinDevices}
          {presence}
          {bandwidth}
          {reducedMotion}
          onselect={onTwinSelect}
          onfallback={onTwinFallback}
        />
      </div>
    {/if}
  {:else}
    <p class="home-connecting muted">Connecting to the local collector…</p>
  {/if}
</section>

<style>
  .home-view { display: grid; gap: 14px; align-content: start; }
  .home-topbar { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; }
  .home-tabs { display: flex; gap: 8px; }
  .home-tabs button { min-height: 44px; padding: 9px 16px; border: 1px solid var(--line); border-radius: 999px; background: transparent; color: var(--ink-mute); font: 500 13px var(--font-body); cursor: pointer; }
  .home-tabs button[aria-selected='true'] { border-color: var(--ember); color: var(--ember); background: var(--surface); }
  .home-selection { margin: 0; color: var(--ink-mute); font: 11px var(--font-mono); }
  .home-selection strong { color: var(--ink); font-weight: 600; }
  .home-banner { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding: 12px 14px; border: 1px solid var(--ember); border-radius: var(--radius-card); background: var(--surface); color: var(--ink); font-size: 12.5px; }
  .home-banner.error { border-color: var(--alert); color: var(--alert-text); }
  .home-banner button { min-height: 38px; padding: 7px 12px; border: 1px solid var(--ember); border-radius: 8px; background: transparent; color: var(--ember); font: 500 12.5px var(--font-body); cursor: pointer; }
  .home-banner.error button { border-color: var(--alert); color: var(--alert-text); }
  .home-connecting { margin: 18px 0 0; }
  [role='tabpanel'][hidden] { display: none; }
</style>
