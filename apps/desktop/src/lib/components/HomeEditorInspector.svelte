<script module lang="ts">
  import type { EditorAction, Floor, HomeDeviceRef, Placement, Room, Wall } from '../stores/home';

  export type InspectorTarget =
    | { kind: 'floor'; floor: Floor; deletable: boolean }
    | { kind: 'wall'; floor_id: string; wall: Wall }
    | { kind: 'room'; floor_id: string; room: Room }
    | { kind: 'placement'; placement: Placement; device: HomeDeviceRef | null; ceiling_m: number };
</script>

<script lang="ts">
  import { MAX_CEILING_M, MIN_CEILING_M, snap, wallLength, type Mounting } from '../stores/home';
  import { formatLength, fromDisplayLength, gridStep, toDisplayLength, unitSymbol, type HomeUnits } from '../homeUnits';

  let { target, units = 'metric', onaction, onclose }: { target: InspectorTarget; units?: HomeUnits; onaction: (action: EditorAction) => void; onclose: () => void } = $props();
  const display = (meters: number) => Number(toDisplayLength(meters, units).toFixed(6));
  const length = (meters: number) => formatLength(meters, units);

  const mountings: Array<{ value: string; label: string }> = [
    { value: '', label: 'Not set' }, { value: 'wall', label: 'Wall' }, { value: 'ceiling', label: 'Ceiling' },
    { value: 'floor', label: 'Floor' }, { value: 'shelf', label: 'Shelf' }
  ];

  function numberFrom(event: Event): number {
    return fromDisplayLength((event.currentTarget as HTMLInputElement).valueAsNumber, units);
  }
  function splitWall(floor_id: string, wall: Wall) {
    const at = { x: snap((wall.start.x + wall.end.x) / 2, gridStep(units)), y: snap((wall.start.y + wall.end.y) / 2, gridStep(units)) };
    onaction({ type: 'split_wall', floor_id, wall_id: wall.wall_id, at, new_wall_id: crypto.randomUUID() });
  }
</script>

<aside class="inspector" aria-label="Inspector">
  <header>
    <p class="inspector-kicker">Inspector</p>
    <button type="button" class="inspector-close" onclick={onclose} aria-label="Close inspector">×</button>
  </header>

  {#if target.kind === 'floor'}
    <h2>{target.floor.name}</h2>
    <label>Floor name
      <input type="text" value={target.floor.name} maxlength="64" onchange={(event) => onaction({ type: 'rename_floor', floor_id: target.floor.floor_id, name: (event.currentTarget as HTMLInputElement).value })} />
    </label>
    <label>Ceiling height ({unitSymbol(units)})
      <input type="number" min={display(MIN_CEILING_M)} max={display(MAX_CEILING_M)} step="any" value={display(target.floor.ceiling_height_m)} onchange={(event) => onaction({ type: 'set_ceiling_height', floor_id: target.floor.floor_id, ceiling_height_m: numberFrom(event) })} />
    </label>
    <dl><div><dt>Level</dt><dd>{target.floor.level}</dd></div><div><dt>Walls</dt><dd>{target.floor.walls.length}</dd></div><div><dt>Rooms</dt><dd>{target.floor.rooms.length}</dd></div></dl>
    <button type="button" class="danger" disabled={!target.deletable} onclick={() => onaction({ type: 'delete_floor', floor_id: target.floor.floor_id })}>Delete floor</button>
    {#if !target.deletable}<p class="inspector-note">A floor with placed devices, or the last floor, cannot be deleted.</p>{/if}
  {:else if target.kind === 'wall'}
    <h2>Wall</h2>
    <dl>
      <div><dt>Length</dt><dd class="dimension-value">{length(wallLength(target.wall))}</dd></div>
      <div><dt>From</dt><dd>{length(target.wall.start.x)}, {length(target.wall.start.y)}</dd></div>
      <div><dt>To</dt><dd>{length(target.wall.end.x)}, {length(target.wall.end.y)}</dd></div>
    </dl>
    {#if target.wall.openings.length > 0}
      <p class="inspector-kicker">Openings</p>
      <ul class="opening-list">
        {#each target.wall.openings as opening (opening.opening_id)}
          <li>{opening.kind} · {length(opening.offset_m)} + {length(opening.width_m)}
            <button type="button" class="quiet" onclick={() => onaction({ type: 'delete_opening', floor_id: target.floor_id, wall_id: target.wall.wall_id, opening_id: opening.opening_id })}>Remove</button>
          </li>
        {/each}
      </ul>
    {/if}
    <button type="button" onclick={() => splitWall(target.floor_id, target.wall)}>Split wall</button>
    <button type="button" class="danger" onclick={() => onaction({ type: 'delete_wall', floor_id: target.floor_id, wall_id: target.wall.wall_id })}>Delete wall</button>
  {:else if target.kind === 'room'}
    <h2>{target.room.name}</h2>
    <label>Room name
      <input type="text" value={target.room.name} maxlength="64" onchange={(event) => onaction({ type: 'rename_room', floor_id: target.floor_id, room_id: target.room.room_id, name: (event.currentTarget as HTMLInputElement).value })} />
    </label>
    <dl><div><dt>Corners</dt><dd>{target.room.polygon.length}</dd></div></dl>
    <button type="button" class="danger" onclick={() => onaction({ type: 'delete_room', floor_id: target.floor_id, room_id: target.room.room_id })}>Delete room</button>
  {:else}
    <h2>{target.device?.name ?? 'Device'}</h2>
    <p class="confirmed-tag">Owner-confirmed placement</p>
    <dl>
      <div><dt>Position</dt><dd>{length(target.placement.x)}, {length(target.placement.y)}</dd></div>
    </dl>
    <label>Height ({unitSymbol(units)})
      <input type="number" min="0" max={display(target.ceiling_m)} step="any" value={display(target.placement.height_m)} onchange={(event) => onaction({ type: 'configure_placement', device_id: target.placement.device_id, height_m: numberFrom(event) })} />
    </label>
    <label>Mounting
      <select value={target.placement.mounting ?? ''} onchange={(event) => onaction({ type: 'configure_placement', device_id: target.placement.device_id, mounting: ((event.currentTarget as HTMLSelectElement).value || null) as Mounting })}>
        {#each mountings as option (option.value)}<option value={option.value}>{option.label}</option>{/each}
      </select>
    </label>
    <p class="inspector-note">Use the arrow keys on the plan to nudge by {units === 'imperial' ? '1 inch' : '0.1 m'}. Imperial inputs use decimal feet.</p>
    <button type="button" class="danger" onclick={() => onaction({ type: 'remove_placement', device_id: target.placement.device_id })}>Remove placement</button>
  {/if}
</aside>

<style>
  .inspector{display:grid;gap:11px;align-content:start;padding:16px;border:1px solid var(--line-mid);border-radius:10px;background:var(--surface)}
  .inspector header{display:flex;justify-content:space-between;align-items:center}
  .inspector-kicker{margin:0;color:var(--muted);font:10px var(--font-mono);text-transform:uppercase;letter-spacing:.08em}
  .inspector-close{width:28px;height:28px;border:1px solid var(--line-strong);border-radius:4px;background:transparent;color:var(--muted-strong);cursor:pointer}
  .inspector h2{margin:0;font:600 16px var(--font-display);color:var(--ink)}
  .inspector label{display:grid;gap:5px;color:var(--muted-strong);font:10px var(--font-mono);text-transform:uppercase;letter-spacing:.06em}
  .inspector input,.inspector select{min-height:38px;padding:7px 9px;border:1px solid var(--line-strong);border-radius:5px;background:#0e2430;color:var(--ink);font:13px var(--font-display)}
  .inspector dl{margin:0;display:grid;gap:8px}
  .inspector dl div{display:flex;justify-content:space-between;gap:8px;padding-top:8px;border-top:1px solid var(--line)}
  .inspector dt{color:var(--faint);font:10px var(--font-mono);text-transform:uppercase}
  .inspector dd{margin:0;color:var(--ink);font-size:12px}
  .dimension-value{color:var(--accent);font:700 13px var(--font-mono)}
  .opening-list{list-style:none;margin:0;padding:0;display:grid;gap:6px}
  .opening-list li{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:6px 8px;border:1px solid var(--line);border-radius:5px;color:var(--ink);font-size:11px;text-transform:capitalize}
  .inspector button:not(.inspector-close){min-height:40px;padding:9px 12px;border:1px solid var(--line-strong);border-radius:5px;background:transparent;color:var(--ink);font:600 12px var(--font-display);cursor:pointer}
  .inspector button.quiet{min-height:30px;padding:4px 8px;font-weight:400}
  .inspector button.danger{border-color:var(--pink);color:var(--pink)}
  .inspector button:disabled{opacity:.4;cursor:not-allowed}
  .confirmed-tag{margin:0;color:var(--accent);font:10px var(--font-mono);text-transform:uppercase;letter-spacing:.06em}
  .inspector-note{margin:0;color:var(--muted);font-size:11px;line-height:1.5}
</style>
