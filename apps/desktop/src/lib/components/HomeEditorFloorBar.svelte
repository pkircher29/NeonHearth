<script lang="ts">
  import type { Floor } from '../stores/home';

  let { floors, active, onselect, onadd }: { floors: Floor[]; active: string | null; onselect: (floorId: string) => void; onadd: () => void } = $props();
</script>

<nav class="floor-bar" aria-label="Floors">
  {#each floors as floor (floor.floor_id)}
    <button type="button" class="floor-tab" class:active={floor.floor_id === active} aria-pressed={floor.floor_id === active} onclick={() => onselect(floor.floor_id)}>
      <strong>{floor.name}</strong><small>level {floor.level} · {floor.ceiling_height_m.toFixed(1)} m</small>
    </button>
  {/each}
  <button type="button" class="floor-add" onclick={onadd}>+ Add floor</button>
</nav>

<style>
  .floor-bar{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0 12px}
  .floor-tab{display:grid;gap:2px;min-height:44px;padding:8px 14px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink);text-align:left;cursor:pointer}
  .floor-tab.active{border-color:var(--ember);color:var(--ink)}
  .floor-tab strong{font:600 13px var(--font-body)}
  .floor-tab small{color:var(--ink-mute);font:400 10px var(--font-mono);text-transform:uppercase;letter-spacing:.06em}
  .floor-add{min-height:44px;padding:8px 14px;border:1px dashed var(--line);border-radius:8px;background:transparent;color:var(--ink-mute);font:500 12.5px var(--font-body);cursor:pointer}
  .floor-add:hover{border-color:var(--ember);color:var(--ember)}
</style>
