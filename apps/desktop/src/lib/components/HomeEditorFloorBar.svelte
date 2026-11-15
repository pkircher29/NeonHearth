<script lang="ts">
  import type { Floor } from '../stores/home';
  import { formatArea, formatLength, type HomeUnits } from '../homeUnits';
  import { floorArea } from '../home/rooms';

  let { floors, active, onselect, onadd, onduplicate, units = 'metric' }: { floors: Floor[]; active: string | null; onselect: (floorId: string) => void; onadd: () => void; onduplicate?: () => void; units?: HomeUnits } = $props();
  const activeFloor = $derived(floors.find((floor) => floor.floor_id === active) ?? null);
  // Shown like a section through the house: the highest storey on top.
  const stacked = $derived([...floors].sort((a, b) => b.level - a.level));
</script>

<nav class="floor-bar" aria-label="Floors">
  <div class="storeys">
    {#each stacked as floor (floor.floor_id)}
      <button type="button" class="floor-tab" class:active={floor.floor_id === active} class:ground={floor.level === 0} aria-pressed={floor.floor_id === active} onclick={() => onselect(floor.floor_id)}>
        <span class="level" aria-hidden="true">{floor.level}</span>
        <span class="floor-text"><strong>{floor.name}</strong><small>level {floor.level} · {formatLength(floor.ceiling_height_m, units)}{#if floor.rooms.length > 0} · <span class="floor-area" title="Total room area">{formatArea(floorArea(floor.rooms), units)}</span>{/if}</small></span>
      </button>
    {/each}
  </div>
  <div class="floor-actions">
    <button type="button" class="floor-add" onclick={onadd}>+ Add floor</button>
    {#if onduplicate}
      <button type="button" class="floor-add" disabled={!activeFloor} onclick={onduplicate}
        title={activeFloor ? `Copies ${activeFloor.name} — walls, openings and rooms — to a new floor above. Devices stay where they are.` : 'Select a floor to duplicate'}>Duplicate floor</button>
    {/if}
  </div>
</nav>

<style>
  .floor-bar{display:grid;gap:10px}
  .storeys{display:grid;gap:3px}
  .floor-tab{display:grid;grid-template-columns:26px minmax(0,1fr);gap:10px;align-items:center;min-height:44px;padding:5px 10px 5px 6px;border:1px solid transparent;border-left:3px solid var(--line-strong);border-radius:0 6px 6px 0;background:transparent;color:var(--ink);text-align:left;cursor:pointer}
  .floor-tab:hover{background:var(--surface-raised)}
  .floor-tab.active{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 9%,transparent)}
  /* The ground line: level 0 sits on a heavier rule, as it would in a section drawing. */
  .floor-tab.ground{box-shadow:0 2px 0 -1px var(--line-strong)}
  .level{color:var(--muted-strong);font:600 13px var(--font-mono);text-align:center}
  .floor-tab.active .level{color:var(--accent)}
  .floor-text{display:grid;gap:1px;min-width:0}
  .floor-text strong{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font:600 13px var(--font-display)}
  .floor-text small{color:var(--muted);font:11px var(--font-display)}
  .floor-area{color:var(--accent);font-family:var(--font-mono)}
  .floor-actions{display:grid;grid-template-columns:1fr 1fr;gap:6px}
  .floor-add{min-height:36px;padding:5px 8px;border:1px dashed var(--line-strong);border-radius:6px;background:transparent;color:var(--muted-strong);font:600 12px var(--font-display);cursor:pointer}
  .floor-add:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}
  .floor-add:disabled{opacity:.4;cursor:not-allowed}
</style>
