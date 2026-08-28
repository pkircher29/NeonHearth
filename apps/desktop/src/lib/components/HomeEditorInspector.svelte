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

  let { target, onaction, onclose }: { target: InspectorTarget; onaction: (action: EditorAction) => void; onclose: () => void } = $props();

  const mountings: Array<{ value: string; label: string }> = [
    { value: '', label: 'Not set' }, { value: 'wall', label: 'Wall' }, { value: 'ceiling', label: 'Ceiling' },
    { value: 'floor', label: 'Floor' }, { value: 'shelf', label: 'Shelf' }
  ];

  function numberFrom(event: Event): number {
    return Number((event.currentTarget as HTMLInputElement).value);
  }
  function splitWall(floor_id: string, wall: Wall) {
    const at = { x: snap((wall.start.x + wall.end.x) / 2), y: snap((wall.start.y + wall.end.y) / 2) };
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
    <label>Ceiling height (m)
      <input type="number" min={MIN_CEILING_M} max={MAX_CEILING_M} step="0.1" value={target.floor.ceiling_height_m} onchange={(event) => onaction({ type: 'set_ceiling_height', floor_id: target.floor.floor_id, ceiling_height_m: numberFrom(event) })} />
    </label>
    <dl><div><dt>Level</dt><dd>{target.floor.level}</dd></div><div><dt>Walls</dt><dd>{target.floor.walls.length}</dd></div><div><dt>Rooms</dt><dd>{target.floor.rooms.length}</dd></div></dl>
    <button type="button" class="danger" disabled={!target.deletable} onclick={() => onaction({ type: 'delete_floor', floor_id: target.floor.floor_id })}>Delete floor</button>
    {#if !target.deletable}<p class="inspector-note">A floor with placed devices, or the last floor, cannot be deleted.</p>{/if}
  {:else if target.kind === 'wall'}
    <h2>Wall</h2>
    <dl>
      <div><dt>Length</dt><dd class="dimension-value">{wallLength(target.wall).toFixed(2)} m</dd></div>
      <div><dt>From</dt><dd>{target.wall.start.x.toFixed(1)}, {target.wall.start.y.toFixed(1)}</dd></div>
      <div><dt>To</dt><dd>{target.wall.end.x.toFixed(1)}, {target.wall.end.y.toFixed(1)}</dd></div>
    </dl>
    {#if target.wall.openings.length > 0}
      <p class="inspector-kicker">Openings</p>
      <ul class="opening-list">
        {#each target.wall.openings as opening (opening.opening_id)}
          <li>{opening.kind} · {opening.offset_m.toFixed(1)} m + {opening.width_m.toFixed(1)} m
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
      <div><dt>Position</dt><dd>{target.placement.x.toFixed(1)}, {target.placement.y.toFixed(1)} m</dd></div>
    </dl>
    <label>Height (m)
      <input type="number" min="0" max={target.ceiling_m} step="0.1" value={target.placement.height_m} onchange={(event) => onaction({ type: 'configure_placement', device_id: target.placement.device_id, height_m: numberFrom(event) })} />
    </label>
    <label>Mounting
      <select value={target.placement.mounting ?? ''} onchange={(event) => onaction({ type: 'configure_placement', device_id: target.placement.device_id, mounting: ((event.currentTarget as HTMLSelectElement).value || null) as Mounting })}>
        {#each mountings as option (option.value)}<option value={option.value}>{option.label}</option>{/each}
      </select>
    </label>
    <p class="inspector-note">Use the arrow keys on the plan to nudge by 0.1 m.</p>
    <button type="button" class="danger" onclick={() => onaction({ type: 'remove_placement', device_id: target.placement.device_id })}>Remove placement</button>
  {/if}
</aside>

<style>
  .inspector{display:grid;gap:11px;align-content:start;padding:16px;border:1px solid var(--line);border-radius:var(--radius-card);background:var(--panel)}
  .inspector header{display:flex;justify-content:space-between;align-items:center}
  .inspector-kicker{margin:0;color:var(--ink-mute);font:500 10px var(--font-mono);text-transform:uppercase;letter-spacing:.12em}
  .inspector-close{width:28px;height:28px;border:1px solid var(--line);border-radius:6px;background:transparent;color:var(--ink-mute);cursor:pointer}
  .inspector h2{margin:0;font:600 16px var(--font-body);color:var(--ink)}
  .inspector label{display:grid;gap:5px;color:var(--ink-mute);font:500 10px var(--font-mono);text-transform:uppercase;letter-spacing:.06em}
  .inspector input,.inspector select{min-height:38px;padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--surface-2);color:var(--ink);font:13px var(--font-body)}
  .inspector dl{margin:0;display:grid;gap:8px}
  .inspector dl div{display:flex;justify-content:space-between;gap:8px;padding-top:8px;border-top:1px solid var(--line)}
  .inspector dt{color:var(--ink-mute);font:500 10px var(--font-mono);text-transform:uppercase}
  .inspector dd{margin:0;color:var(--ink);font:12px var(--font-mono)}
  .dimension-value{color:var(--ember);font:500 13px var(--font-mono)}
  .opening-list{list-style:none;margin:0;padding:0;display:grid;gap:6px}
  .opening-list li{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:6px 8px;border:1px solid var(--line);border-radius:6px;color:var(--ink);font-size:11.5px;text-transform:capitalize}
  .inspector button:not(.inspector-close){min-height:40px;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--ink);font:500 12.5px var(--font-body);cursor:pointer}
  .inspector button.quiet{min-height:30px;padding:4px 8px;font-weight:400}
  .inspector button.danger{border-color:var(--alert);color:var(--alert-text)}
  .inspector button:disabled{opacity:.4;cursor:not-allowed}
  .confirmed-tag{margin:0;color:var(--safe-text);font:500 10px var(--font-mono);text-transform:uppercase;letter-spacing:.06em}
  .inspector-note{margin:0;color:var(--ink-mute);font-size:11.5px;line-height:1.5}
</style>
