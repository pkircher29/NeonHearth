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
  .floor-tab{display:grid;gap:2px;min-height:44px;padding:8px 14px;border:1px solid #20424b;border-radius:6px;background:#0b1c26;color:#cce4e7;text-align:left;cursor:pointer}
  .floor-tab.active{border-color:#63f3f0;box-shadow:inset 0 0 18px #63f3f014;color:#e9fbfc}
  .floor-tab strong{font:600 13px Arial}
  .floor-tab small{color:#77959d;font:10px monospace;text-transform:uppercase;letter-spacing:.06em}
  .floor-add{min-height:44px;padding:8px 14px;border:1px dashed #28505a;border-radius:6px;background:transparent;color:#9bb7bb;font:600 12px Arial;cursor:pointer}
  .floor-add:hover{border-color:#63f3f0;color:#63f3f0}
</style>
