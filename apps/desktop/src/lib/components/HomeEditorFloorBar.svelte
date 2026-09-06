<script lang="ts">
  import type { Floor } from '../stores/home';
  import { formatLength, type HomeUnits } from '../homeUnits';

  let { floors, active, onselect, onadd, units = 'metric' }: { floors: Floor[]; active: string | null; onselect: (floorId: string) => void; onadd: () => void; units?: HomeUnits } = $props();
</script>

<nav class="floor-bar" aria-label="Floors">
  {#each floors as floor (floor.floor_id)}
    <button type="button" class="floor-tab" class:active={floor.floor_id === active} aria-pressed={floor.floor_id === active} onclick={() => onselect(floor.floor_id)}>
      <strong>{floor.name}</strong><small>level {floor.level} · {formatLength(floor.ceiling_height_m, units)}</small>
    </button>
  {/each}
  <button type="button" class="floor-add" onclick={onadd}>+ Add floor</button>
</nav>

<style>
  .floor-bar{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0 12px}
  .floor-tab{display:grid;gap:2px;min-height:44px;padding:8px 14px;border:1px solid var(--line-mid);border-radius:6px;background:var(--surface);color:var(--ink);text-align:left;cursor:pointer}
  .floor-tab.active{border-color:var(--accent);box-shadow:inset 0 0 18px var(--accent)14;color:var(--ink)}
  .floor-tab strong{font:600 13px var(--font-display)}
  .floor-tab small{color:var(--muted);font:10px var(--font-mono);text-transform:uppercase;letter-spacing:.06em}
  .floor-add{min-height:44px;padding:8px 14px;border:1px dashed var(--line-strong);border-radius:6px;background:transparent;color:var(--muted-strong);font:600 12px var(--font-display);cursor:pointer}
  .floor-add:hover{border-color:var(--accent);color:var(--accent)}
</style>
