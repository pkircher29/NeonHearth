<script module lang="ts">
  export interface EstimatedRow { device_id: string; name: string; label: string; confidence: number }
</script>

<script lang="ts">
  import type { HomeDeviceRef } from '../stores/home';
  import { deviceLabel, filterDevices, sortDevices } from '../home/deviceLabel';

  let { unplaced, placing, estimated, onpick }: {
    unplaced: HomeDeviceRef[];
    placing: string | null;
    estimated: EstimatedRow[];
    onpick: (deviceId: string) => void;
  } = $props();

  let query = $state('');
  // Only worth a filter box once the list is long enough to need one.
  const FILTER_FROM = 6;
  const sorted = $derived(sortDevices(unplaced));
  const shown = $derived(filterDevices(sorted, query));
</script>

<aside class="device-tray" aria-label="Unplaced devices">
  <h2>Unplaced devices{unplaced.length > 0 ? ` · ${unplaced.length}` : ''}</h2>
  {#if unplaced.length >= FILTER_FROM}
    <div class="tray-search">
      <input type="search" aria-label="Filter devices" placeholder="Filter by name, vendor, MAC or IP" bind:value={query} />
      {#if query}<button type="button" class="tray-clear" aria-label="Clear filter" onclick={() => (query = '')}>×</button>{/if}
    </div>
  {/if}
  <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
  <div class="tray-body" role="region" aria-label="Device list" tabindex="0">
    {#if unplaced.length === 0}
      <p class="tray-muted">Every known device has an owner-confirmed spot.</p>
    {:else if shown.length === 0}
      <p class="tray-muted" role="status">No devices match “{query}”.</p>
    {:else}
      <ul class="tray-list">
        {#each shown as device (device.device_id)}
          <li>
            <button type="button" class="tray-device" class:arming={placing === device.device_id} aria-pressed={placing === device.device_id}
              draggable="true" ondragstart={(event) => event.dataTransfer?.setData('text/plain', device.device_id)}
              onclick={() => onpick(device.device_id)}>
              <span aria-hidden="true">◇</span>
              <span class="tray-label">{deviceLabel(device, 'Unnamed device')}</span>
              {#if device.ip}<small class="tray-ip">{device.ip}</small>{/if}
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  {#if estimated.length > 0}
    <h3>Estimated only — not confirmed</h3>
    <ul class="estimate-list">
      {#each estimated as row (row.device_id)}
        <li><strong>{row.name}</strong><span>{row.label}</span><em>estimated · {Math.round(row.confidence * 100)}% confidence</em></li>
      {/each}
    </ul>
  {/if}
  </div>
  {#if unplaced.length > 0}<p class="tray-muted">Drag a device onto the plan, or select it and click the plan to place it.</p>{/if}
</aside>

<style>
  .device-tray{display:flex;flex-direction:column;max-height:300px;padding:12px 14px;border:1px solid var(--line-mid);border-radius:10px;background:var(--surface)}
  .device-tray h2{margin:0 0 8px;font:600 14px var(--font-display);color:var(--ink)}
  .device-tray h3{margin:14px 0 8px;font:12px var(--font-display);color:var(--gold)}
  .tray-search{position:relative;margin:0 0 8px}
  .tray-search input{box-sizing:border-box;width:100%;min-height:34px;padding:5px 30px 5px 9px;border:1px solid var(--line-strong);border-radius:5px;background:#0e2430;color:var(--ink);font:12px var(--font-display)}
  .tray-clear{position:absolute;right:3px;top:3px;width:28px;height:28px;border:0;border-radius:4px;background:transparent;color:var(--muted-strong);font-size:16px;cursor:pointer}
  .tray-body{flex:1 1 auto;min-height:60px;overflow-y:auto;overscroll-behavior:contain;outline:none}
  .tray-body:focus-visible{box-shadow:0 0 0 2px var(--accent)}
  .tray-list{list-style:none;margin:0;padding:0;display:grid;gap:4px}
  .tray-device{display:flex;gap:8px;align-items:center;width:100%;min-height:36px;padding:5px 10px;border:1px solid var(--line-strong);border-radius:6px;background:#0e2430;color:var(--ink);font:12px var(--font-display);text-align:left;cursor:grab}
  .tray-device > span:first-child{color:var(--blue)}
  .tray-label{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .tray-ip{flex:none;color:var(--muted);font:10px var(--font-mono)}
  .tray-device.arming{border-color:var(--accent);color:var(--ink);box-shadow:inset 0 0 16px var(--accent)14}
  .tray-muted{margin:8px 0 0;color:var(--muted);font-size:11px;line-height:1.5}
  .estimate-list{list-style:none;margin:0;padding:0;display:grid;gap:9px}
  .estimate-list li{display:grid;gap:2px;padding:8px;border:1px dashed var(--line-strong);border-radius:6px}
  .estimate-list strong{font:600 12px var(--font-display);color:var(--ink)}
  .estimate-list span{color:var(--muted-strong);font-size:11px}
  .estimate-list em{color:var(--gold);font:12px var(--font-display);font-style:normal}
</style>
