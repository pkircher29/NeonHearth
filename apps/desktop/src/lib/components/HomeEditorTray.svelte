<script module lang="ts">
  export interface EstimatedRow { device_id: string; name: string; label: string; confidence: number }
</script>

<script lang="ts">
  import type { HomeDeviceRef } from '../stores/home';

  let { unplaced, placing, estimated, onpick }: {
    unplaced: HomeDeviceRef[];
    placing: string | null;
    estimated: EstimatedRow[];
    onpick: (deviceId: string) => void;
  } = $props();
</script>

<aside class="device-tray" aria-label="Unplaced devices">
  <h2>Unplaced devices</h2>
  {#if unplaced.length === 0}
    <p class="tray-muted">Every known device has an owner-confirmed spot.</p>
  {:else}
    <ul class="tray-list">
      {#each unplaced as device (device.device_id)}
        <li>
          <button type="button" class="tray-device" class:arming={placing === device.device_id} aria-pressed={placing === device.device_id}
            draggable="true" ondragstart={(event) => event.dataTransfer?.setData('text/plain', device.device_id)}
            onclick={() => onpick(device.device_id)}>
            <span aria-hidden="true">◇</span> {device.name ?? 'Unnamed device'}
          </button>
        </li>
      {/each}
    </ul>
    <p class="tray-muted">Drag a device onto the plan, or select it and click the plan to place it.</p>
  {/if}

  {#if estimated.length > 0}
    <h3>Estimated only — not confirmed</h3>
    <ul class="estimate-list">
      {#each estimated as row (row.device_id)}
        <li><strong>{row.name}</strong><span>{row.label}</span><em>estimated · {Math.round(row.confidence * 100)}% confidence</em></li>
      {/each}
    </ul>
  {/if}
</aside>

<style>
  .device-tray{padding:16px;border:1px solid var(--line);border-radius:var(--radius-card);background:var(--panel)}
  .device-tray h2{margin:0 0 10px;font:600 14px var(--font-body);color:var(--ink)}
  .device-tray h3{margin:18px 0 8px;font:500 10px var(--font-mono);text-transform:uppercase;letter-spacing:.12em;color:var(--ember)}
  .tray-list{list-style:none;margin:0;padding:0;display:grid;gap:7px}
  .tray-device{display:flex;gap:8px;align-items:center;width:100%;min-height:44px;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--surface-2);color:var(--ink);font:12.5px var(--font-body);text-align:left;cursor:grab}
  .tray-device span{color:var(--ink-mute)}
  .tray-device.arming{border-color:var(--ember);color:var(--ink)}
  .tray-device.arming span{color:var(--ember)}
  .tray-muted{margin:10px 0 0;color:var(--ink-mute);font-size:11.5px;line-height:1.5}
  .estimate-list{list-style:none;margin:0;padding:0;display:grid;gap:9px}
  .estimate-list li{display:grid;gap:2px;padding:8px;border:1px dashed var(--line);border-radius:8px}
  .estimate-list strong{font:600 12.5px var(--font-body);color:var(--ink)}
  .estimate-list span{color:var(--ink-mute);font-size:11.5px}
  .estimate-list em{color:var(--ember);font:500 10px var(--font-mono);font-style:normal;text-transform:uppercase;letter-spacing:.06em}
</style>
