<script lang="ts">
  // One wall on the plan canvas (home tools v2 · spec D): a band whose width is the real wall
  // thickness at the current zoom, with openings punched through it. Doors get a swing arc,
  // windows a sill line, stairs a dashed run.
  import { DEFAULT_THICKNESS_M, type PlanPoint, type Wall } from '../stores/home';

  let { wall, start, end, scale, selected, label, onclick, onkeydown, onpointerdown, tabindex = 0 }: {
    wall: Wall; start: PlanPoint; end: PlanPoint; scale: number; selected: boolean; label: string; tabindex?: number;
    onclick: (event: MouseEvent) => void; onkeydown: (event: KeyboardEvent) => void; onpointerdown: (event: PointerEvent) => void;
  } = $props();

  /** Never thinner than ~2 px so a thin wall stays visible when zoomed out. */
  const band = $derived(Math.max(2, (wall.thickness_m ?? DEFAULT_THICKNESS_M) * scale));
  const length = $derived(Math.hypot(end.x - start.x, end.y - start.y));
  const ux = $derived(length > 0 ? (end.x - start.x) / length : 0);
  const uy = $derived(length > 0 ? (end.y - start.y) / length : 0);
  const at = (offset: number) => ({ x: (start.x + ux * offset) * scale, y: (start.y + uy * offset) * scale });
</script>

<g class="wall-group" role="button" {tabindex} data-roving={`wall:${wall.wall_id}`} aria-label={label} {onclick} {onkeydown} {onpointerdown}>
  <line class="wall-hit" x1={start.x * scale} y1={start.y * scale} x2={end.x * scale} y2={end.y * scale} stroke-width={Math.max(band, 14)} />
  <line class="wall" class:selected data-wall-id={wall.wall_id}
    x1={start.x * scale} y1={start.y * scale} x2={end.x * scale} y2={end.y * scale} stroke-width={band} />
  {#each wall.openings as opening (opening.opening_id)}
    {@const a = at(opening.offset_m)}
    {@const b = at(opening.offset_m + opening.width_m)}
    <line class="opening-gap" x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke-width={band + 2} />
    {#if opening.kind === 'door'}
      {@const radius = opening.width_m * scale}
      {@const leaf = { x: a.x - uy * radius, y: a.y + ux * radius }}
      <path class="door-swing" d={`M ${b.x} ${b.y} A ${radius} ${radius} 0 0 1 ${leaf.x} ${leaf.y}`} fill="none" />
      <line class="wall-opening door" x1={a.x} y1={a.y} x2={leaf.x} y2={leaf.y} />
    {:else if opening.kind === 'window'}
      <line class="wall-opening window" x1={a.x} y1={a.y} x2={b.x} y2={b.y} />
    {:else}
      <line class="wall-opening stair" x1={a.x} y1={a.y} x2={b.x} y2={b.y} />
    {/if}
  {/each}
</g>

<style>
  .wall-group{cursor:pointer;outline:none}
  .wall-group:focus-visible .wall{stroke:var(--accent)}
  .wall-hit{stroke:transparent;stroke-linecap:round}
  .wall{stroke:var(--ink);stroke-linecap:square;pointer-events:none}
  .wall.selected{stroke:var(--accent)}
  .opening-gap{stroke:var(--plan-bg, #081722);stroke-linecap:butt;pointer-events:none}
  .wall-opening{stroke-width:2;stroke-linecap:butt;pointer-events:none}
  .wall-opening.door{stroke:var(--gold)}
  .wall-opening.window{stroke:var(--blue);stroke-width:2.5}
  .wall-opening.stair{stroke:var(--pink);stroke-width:4;stroke-dasharray:4 3}
  .door-swing{stroke:var(--gold);stroke-width:1;stroke-dasharray:3 2;opacity:.8;pointer-events:none}
</style>
