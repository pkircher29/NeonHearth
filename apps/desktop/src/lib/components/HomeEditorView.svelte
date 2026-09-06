<script lang="ts">
  import { onMount } from 'svelte';
  import {
    copyFloorFootprint, createEditorState, emptyHomePlan, reduceEditor, selectUncertain, selectUnplaced, snap, snapPoint, wallLength,
    type EditorAction, type EditorState, type Estimate, type HomeApi, type HomeDeviceRef, type HomeDraft, type HomeSnapshot, type OpeningKind, type Placement, type PlanPoint, type Room, type Wall
  } from '../stores/home';
  import HomeEditorFloorBar from './HomeEditorFloorBar.svelte';
  import HomeEditorInspector, { type InspectorTarget } from './HomeEditorInspector.svelte';
  import HomeEditorTray, { type EstimatedRow } from './HomeEditorTray.svelte';
  import { formatLength, gridStep, readHomeUnits, saveHomeUnits, type HomeUnits } from '../homeUnits';

  // `snapshot` is the already-loaded home when a parent owns it (HomeView
  // shares one fetch with the 3D twin, audit M-27); without it the editor
  // fetches on mount. `onsnapshot` reports every server-acknowledged change
  // (committed plan, placements, reloads) so the parent's twin stays current.
  let { api, devices = [], snapshot = undefined, onsnapshot }: { api: HomeApi; devices?: HomeDeviceRef[]; snapshot?: HomeSnapshot | null; onsnapshot?: (snapshot: HomeSnapshot) => void } = $props();

  const SCALE = 40; // pixels per meter
  const CANVAS_W_M = 18;
  const CANVAS_H_M = 12;
  const AUTOSAVE_DELAY_MS = 2000;
  const OPENING_WIDTHS: Record<OpeningKind, number> = { door: 0.9, window: 0.8, stair: 1.0 };

  type Tool = 'select' | 'wall' | 'room' | 'opening' | 'place';
  type Selection = { kind: 'wall' | 'room' | 'placement'; id: string } | { kind: 'floor' } | null;

  let editor = $state<EditorState>(createEditorState(emptyHomePlan(), []));
  let estimates = $state<Estimate[]>([]);
  let version = $state(0);
  let loading = $state(true);
  let loadError = $state<string | null>(null);
  let notice = $state<string | null>(null);
  let conflict = $state(false);
  let draftOffer = $state<HomeDraft | null>(null);
  let autosaveState = $state<'idle' | 'dirty' | 'saving' | 'saved' | 'error'>('idle');
  let committing = $state(false);
  let tool = $state<Tool>('select');
  let units = $state<HomeUnits>('metric');
  let copyTarget = $state('new');
  let openingKind = $state<OpeningKind>('door');
  let activeFloorId = $state<string | null>(null);
  let selection = $state<Selection>(null);
  let pendingWallStart = $state<PlanPoint | null>(null);
  let pendingRoom = $state<PlanPoint[]>([]);
  let placingDevice = $state<string | null>(null);
  let svgEl = $state<SVGSVGElement | null>(null);
  let autosaveTimer: ReturnType<typeof setTimeout> | undefined;

  const doc = $derived(editor.doc);
  const plan = $derived(doc.plan);
  const grid = $derived(gridStep(units));
  const majorGrid = $derived(units === 'imperial' ? 0.3048 : 1);
  const copyTargets = $derived(plan.floors.filter(floor => floor.floor_id !== activeFloorId && !floor.walls.length && !floor.rooms.length));
  const activeFloor = $derived(plan.floors.find((floor) => floor.floor_id === activeFloorId) ?? plan.floors[0] ?? null);
  const floorPlacements = $derived(activeFloor ? doc.placements.filter((placement) => placement.floor_id === activeFloor.floor_id) : []);
  const unplaced = $derived(selectUnplaced(devices, doc.placements));
  const uncertain = $derived(selectUncertain(devices, doc.placements, estimates));
  const canUndo = $derived(editor.past.length > 0);
  const canRedo = $derived(editor.future.length > 0);
  const selectedWall = $derived.by(() => {
    const current = selection;
    if (!current || current.kind !== 'wall' || !activeFloor) return null;
    return activeFloor.walls.find((wall) => wall.wall_id === current.id) ?? null;
  });
  const estimatedRows: EstimatedRow[] = $derived(estimates
    .filter((estimate) => !doc.placements.some((placement) => placement.device_id === estimate.device_id))
    .map((estimate) => ({ device_id: estimate.device_id, name: deviceName(estimate.device_id), label: estimateLabel(estimate), confidence: estimate.confidence })));
  const target: InspectorTarget | null = $derived.by(() => {
    const current = selection;
    if (!current) return null;
    if (current.kind === 'floor') {
      if (!activeFloor) return null;
      const floor = activeFloor;
      const deletable = plan.floors.length > 1 && !doc.placements.some((placement) => placement.floor_id === floor.floor_id);
      return { kind: 'floor', floor, deletable };
    }
    if (!activeFloor) return null;
    if (current.kind === 'wall') {
      const wall = activeFloor.walls.find((candidate) => candidate.wall_id === current.id);
      return wall ? { kind: 'wall', floor_id: activeFloor.floor_id, wall } : null;
    }
    if (current.kind === 'room') {
      const room = activeFloor.rooms.find((candidate) => candidate.room_id === current.id);
      return room ? { kind: 'room', floor_id: activeFloor.floor_id, room } : null;
    }
    const placement = doc.placements.find((candidate) => candidate.device_id === current.id);
    if (!placement) return null;
    const floor = plan.floors.find((candidate) => candidate.floor_id === placement.floor_id);
    return { kind: 'placement', placement, device: devices.find((device) => device.device_id === placement.device_id) ?? null, ceiling_m: floor?.ceiling_height_m ?? 2.4 };
  });
  const autosaveLabel = $derived(
    autosaveState === 'dirty' ? 'Unsaved changes'
      : autosaveState === 'saving' ? 'Saving draft…'
      : autosaveState === 'saved' ? 'Draft saved'
      : autosaveState === 'error' ? 'Draft save failed'
      : 'All changes committed');

  $effect(() => {
    if (plan.floors.length > 0 && !plan.floors.some((floor) => floor.floor_id === activeFloorId)) activeFloorId = plan.floors[0].floor_id;
  });

  const newId = () => crypto.randomUUID();
  function deviceName(deviceId: string): string {
    return devices.find((device) => device.device_id === deviceId)?.name ?? `Device ${deviceId.slice(0, 8)}`;
  }
  function estimateLabel(estimate: Estimate): string {
    const floor = estimate.floor_id ? plan.floors.find((candidate) => candidate.floor_id === estimate.floor_id) : null;
    const room = floor && estimate.room_id ? floor.rooms.find((candidate) => candidate.room_id === estimate.room_id) : null;
    if (room && floor) return `${room.name} · ${floor.name}`;
    if (floor) return floor.name;
    return 'Location unknown';
  }

  function markDirty() {
    autosaveState = 'dirty';
    clearTimeout(autosaveTimer);
    autosaveTimer = setTimeout(() => { void persistDraft(); }, AUTOSAVE_DELAY_MS);
  }

  // ---- Placement persistence (audit M-29) ----
  // One in-flight write per device with a latest-value slot: a burst of
  // nudges (key repeat, undo/redo) collapses to at most one queued write, and
  // the server always ends on the newest position. A failed write rolls the
  // device back to its last server-acknowledged placement.
  type PlacementWrite = { kind: 'put'; placement: Placement } | { kind: 'delete' };
  const confirmedPlacements = new Map<string, Placement>();
  const inFlight = new Map<string, Promise<void>>();
  const queued = new Map<string, PlacementWrite>();
  function rememberConfirmed(placements: Placement[]) {
    confirmedPlacements.clear();
    for (const placement of placements) confirmedPlacements.set(placement.device_id, placement);
  }
  function emitSnapshot() {
    onsnapshot?.({ plan: $state.snapshot(editor).doc.plan, placements: $state.snapshot(editor).doc.placements.map((placement) => ({ ...placement })), estimates: $state.snapshot(estimates) });
  }
  function rollbackPlacement(deviceId: string) {
    const confirmed = confirmedPlacements.get(deviceId);
    const placements = confirmed
      ? (editor.doc.placements.some((candidate) => candidate.device_id === deviceId)
        ? editor.doc.placements.map((candidate) => (candidate.device_id === deviceId ? { ...confirmed } : candidate))
        : [...editor.doc.placements, { ...confirmed }])
      : editor.doc.placements.filter((candidate) => candidate.device_id !== deviceId);
    editor = { ...editor, doc: { ...editor.doc, placements } };
    emitSnapshot();
  }
  function queuePlacementWrite(deviceId: string, write: PlacementWrite) {
    if (inFlight.has(deviceId)) { queued.set(deviceId, write); return; }
    const run = (async () => {
      try {
        if (write.kind === 'put') { await api.putPlacement({ ...write.placement }); confirmedPlacements.set(deviceId, write.placement); }
        else { await api.deletePlacement(deviceId); confirmedPlacements.delete(deviceId); }
      } catch {
        queued.delete(deviceId);
        notice = write.kind === 'put' ? 'The placement could not be saved to the service. It was put back where the service last saw it.' : 'The placement could not be removed from the service. It was restored.';
        rollbackPlacement(deviceId);
      } finally {
        inFlight.delete(deviceId);
        const next = queued.get(deviceId);
        if (next) { queued.delete(deviceId); queuePlacementWrite(deviceId, next); }
      }
    })();
    inFlight.set(deviceId, run);
  }

  function dispatch(action: EditorAction): boolean {
    const previous = editor;
    const next = reduceEditor(previous, { ...action, grid_m: grid });
    if (next === previous) return false;
    const previousPlacements = previous.doc.placements;
    const nextPlacements = next.doc.placements;
    const planChanged = next.doc.plan !== previous.doc.plan;
    editor = next;
    if (planChanged) markDirty();
    if (nextPlacements !== previousPlacements) {
      for (const placement of nextPlacements) {
        const before = previousPlacements.find((candidate) => candidate.device_id === placement.device_id);
        if (before !== placement) queuePlacementWrite(placement.device_id, { kind: 'put', placement: { ...placement } });
      }
      for (const before of previousPlacements) {
        if (!nextPlacements.some((candidate) => candidate.device_id === before.device_id)) queuePlacementWrite(before.device_id, { kind: 'delete' });
      }
      emitSnapshot();
    }
    return true;
  }
  function apply(action: EditorAction) {
    if (!dispatch(action)) notice = 'That change is not allowed.';
  }

  function planSnapshot() {
    return { ...$state.snapshot(editor).doc.plan, version };
  }
  async function persistDraft() {
    autosaveState = 'saving';
    try {
      await api.saveDraft({ plan: planSnapshot(), saved_at: new Date().toISOString() });
      autosaveState = 'saved';
    } catch { autosaveState = 'error'; }
  }
  async function saveCommitted() {
    committing = true;
    clearTimeout(autosaveTimer);
    try {
      const result = await api.savePlan(planSnapshot(), version);
      if (result.status === 'conflict') { conflict = true; return; }
      version = result.version;
      editor = { ...editor, doc: { ...editor.doc, plan: { ...editor.doc.plan, version: result.version } } };
      autosaveState = 'idle';
      notice = `Plan saved as version ${result.version}.`;
      emitSnapshot();
      void api.deleteDraft().catch(() => { /* A stale draft is harmless; the committed plan wins. */ });
    } catch { notice = 'The plan could not be saved. Try again shortly.'; }
    finally { committing = false; }
  }
  async function reloadLatest() {
    conflict = false;
    loading = true;
    await loadHome();
  }
  function adopt(loaded: HomeSnapshot) {
    editor = createEditorState(loaded.plan, loaded.placements);
    estimates = loaded.estimates;
    version = loaded.plan.version;
    activeFloorId = loaded.plan.floors[0]?.floor_id ?? null;
    selection = null;
    autosaveState = 'idle';
    rememberConfirmed(loaded.placements);
  }
  async function loadHome() {
    loadError = null;
    try {
      const loaded = await api.fetchHome();
      adopt(loaded);
      onsnapshot?.(loaded);
    } catch { loadError = 'The home plan is unavailable right now. Try again shortly.'; }
    finally { loading = false; }
  }
  function resumeDraft() {
    if (!draftOffer) return;
    editor = createEditorState(draftOffer.plan, editor.doc.placements.map((placement) => ({ ...placement })));
    autosaveState = 'saved';
    draftOffer = null;
    selection = null;
  }
  function discardDraft() {
    draftOffer = null;
    void api.deleteDraft().catch(() => { /* Discard is best-effort; the committed plan remains loaded. */ });
  }

  onMount(() => {
    units = readHomeUnits();
    void (async () => {
      if (snapshot) { adopt(snapshot); loading = false; }
      else await loadHome();
      if (loadError) return;
      try {
        const draft = await api.loadDraft();
        if (draft.status === 'draft') draftOffer = draft.draft;
        else if (draft.status === 'corrupt') notice = 'A saved draft could not be read and was discarded. The last committed plan is shown.';
      } catch { /* Draft recovery is optional; the committed plan is already loaded. */ }
    })();
    return () => clearTimeout(autosaveTimer);
  });

  // ---- Canvas interactions ----
  function canvasPoint(event: { clientX: number; clientY: number }): PlanPoint {
    const rect = svgEl?.getBoundingClientRect();
    return snapPoint({ x: (event.clientX - (rect?.left ?? 0)) / SCALE, y: (event.clientY - (rect?.top ?? 0)) / SCALE }, grid);
  }
  function onCanvasClick(event: MouseEvent) {
    if (!activeFloor) return;
    const point = canvasPoint(event);
    if (tool === 'wall') {
      if (!pendingWallStart) { pendingWallStart = point; return; }
      const wall_id = newId();
      if (dispatch({ type: 'add_wall', floor_id: activeFloor.floor_id, wall_id, start: pendingWallStart, end: point })) {
        selection = { kind: 'wall', id: wall_id };
      } else notice = 'Walls need two different grid points.';
      pendingWallStart = null;
      return;
    }
    if (tool === 'room') { pendingRoom = [...pendingRoom, point]; return; }
    if (tool === 'place' && placingDevice) { placeAt(placingDevice, point); return; }
    if (tool === 'select') selection = null;
  }
  function onWallClick(event: MouseEvent, wall: Wall) {
    if (!activeFloor) return;
    if (tool === 'select') { event.stopPropagation(); selection = { kind: 'wall', id: wall.wall_id }; return; }
    if (tool !== 'opening') return; // wall/room/place clicks fall through to the canvas
    event.stopPropagation();
    const point = canvasPoint(event);
    const length = wallLength(wall);
    const t = length === 0 ? 0 : ((point.x - wall.start.x) * (wall.end.x - wall.start.x) + (point.y - wall.start.y) * (wall.end.y - wall.start.y)) / (length * length);
    const width = units === 'imperial' ? (openingKind === 'window' ? 0.8128 : 0.9144) : OPENING_WIDTHS[openingKind];
    const offset = snap(Math.min(Math.max(t * length - width / 2, 0), Math.max(length - width, 0)), grid);
    if (!dispatch({ type: 'add_opening', floor_id: activeFloor.floor_id, wall_id: wall.wall_id, opening: { opening_id: newId(), kind: openingKind, offset_m: offset, width_m: width } })) {
      notice = `That wall is too short for a ${openingKind}.`;
    }
  }
  function onRoomClick(event: MouseEvent, room: Room) {
    if (tool !== 'select') return;
    event.stopPropagation();
    selection = { kind: 'room', id: room.room_id };
  }
  function selectPlacement(event: Event, placement: Placement) {
    event.stopPropagation();
    selection = { kind: 'placement', id: placement.device_id };
  }
  function keyActivate(event: KeyboardEvent, activate: () => void) {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); event.stopPropagation(); activate(); }
  }
  function finishRoom() {
    if (!activeFloor || pendingRoom.length < 3) return;
    apply({ type: 'add_room', floor_id: activeFloor.floor_id, room_id: newId(), name: `Room ${activeFloor.rooms.length + 1}`, polygon: pendingRoom });
    pendingRoom = [];
  }
  function cancelPending() {
    pendingWallStart = null;
    pendingRoom = [];
    placingDevice = null;
  }
  function placeAt(deviceId: string, point: PlanPoint) {
    if (!activeFloor) return;
    const existing = doc.placements.find((candidate) => candidate.device_id === deviceId);
    const placement: Placement = {
      placement_id: existing?.placement_id ?? newId(), device_id: deviceId, floor_id: activeFloor.floor_id,
      x: point.x, y: point.y, height_m: existing?.height_m ?? 1.0, mounting: existing?.mounting ?? null
    };
    if (dispatch({ type: 'place_device', placement })) {
      placingDevice = null;
      tool = 'select';
      selection = { kind: 'placement', id: deviceId };
    } else notice = 'That device cannot be placed there.';
  }
  function armPlacement(deviceId: string) {
    placingDevice = placingDevice === deviceId ? null : deviceId;
    if (placingDevice) tool = 'place';
  }
  function onCanvasDrop(event: DragEvent) {
    event.preventDefault();
    const deviceId = event.dataTransfer?.getData('text/plain');
    if (!deviceId || !devices.some((device) => device.device_id === deviceId)) return;
    placeAt(deviceId, canvasPoint(event));
  }
  function onCanvasKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') { cancelPending(); return; }
    if ((event.key === 'Delete' || event.key === 'Backspace') && selection && activeFloor) {
      event.preventDefault();
      if (selection.kind === 'wall') apply({ type: 'delete_wall', floor_id: activeFloor.floor_id, wall_id: selection.id });
      else if (selection.kind === 'room') apply({ type: 'delete_room', floor_id: activeFloor.floor_id, room_id: selection.id });
      else if (selection.kind === 'placement') apply({ type: 'remove_placement', device_id: selection.id });
      return;
    }
    const current = selection;
    if (current?.kind !== 'placement') return;
    const placement = doc.placements.find((candidate) => candidate.device_id === current.id);
    if (!placement) return;
    const step: Record<string, [number, number]> = { ArrowLeft: [-grid, 0], ArrowRight: [grid, 0], ArrowUp: [0, -grid], ArrowDown: [0, grid] };
    const nudge = step[event.key];
    if (!nudge) return;
    event.preventDefault();
    dispatch({ type: 'move_placement', device_id: placement.device_id, x: snap(placement.x + nudge[0], grid), y: snap(placement.y + nudge[1], grid) });
  }
  function onWindowKeydown(event: KeyboardEvent) {
    if (!(event.ctrlKey || event.metaKey)) return;
    const targetTag = (event.target as HTMLElement | null)?.tagName;
    if (targetTag === 'INPUT' || targetTag === 'TEXTAREA' || targetTag === 'SELECT') return;
    const key = event.key.toLowerCase();
    if (key === 'z' && !event.shiftKey) { event.preventDefault(); dispatch({ type: 'undo' }); }
    else if ((key === 'z' && event.shiftKey) || key === 'y') { event.preventDefault(); dispatch({ type: 'redo' }); }
  }
  function addFloor() {
    const level = plan.floors.length > 0 ? Math.max(...plan.floors.map((floor) => floor.level)) + 1 : 0;
    const floor_id = newId();
    if (dispatch({ type: 'add_floor', floor_id, level, name: `Floor ${level}`, ceiling_height_m: 2.4 })) activeFloorId = floor_id;
  }

  function copyFootprint() {
    if (!activeFloor) return;
    const level = Math.max(...plan.floors.map(floor => floor.level)) + 1;
    const destination = copyTarget === 'new'
      ? { floor_id: newId(), level, name: `Floor ${level}`, ceiling_height_m: activeFloor.ceiling_height_m, walls: [], rooms: [] }
      : copyTargets.find(floor => floor.floor_id === copyTarget);
    if (!destination) { notice = 'Choose a new or empty floor for the footprint.'; return; }
    const sourceName = activeFloor.name;
    const floor = copyFloorFootprint(activeFloor, destination, newId);
    if (dispatch({ type: 'copy_footprint', floor })) {
      activeFloorId = floor.floor_id;
      selection = { kind: 'floor' };
      copyTarget = 'new';
      cancelPending();
      notice = `Copied ${sourceName} to ${floor.name}. Edit each floor separately; Undo removes this copy.`;
    } else notice = 'The footprint could not be copied. Choose an empty floor within the plan limits.';
  }

  function openingSegment(wall: Wall, offset: number, width: number) {
    const length = wallLength(wall);
    if (length === 0) return { x1: 0, y1: 0, x2: 0, y2: 0 };
    const ux = (wall.end.x - wall.start.x) / length;
    const uy = (wall.end.y - wall.start.y) / length;
    return {
      x1: (wall.start.x + ux * offset) * SCALE, y1: (wall.start.y + uy * offset) * SCALE,
      x2: (wall.start.x + ux * (offset + width)) * SCALE, y2: (wall.start.y + uy * (offset + width)) * SCALE
    };
  }
  const polygonPoints = (points: PlanPoint[]) => points.map((point) => `${point.x * SCALE},${point.y * SCALE}`).join(' ');
  function centroid(points: PlanPoint[]): PlanPoint {
    const sum = points.reduce((acc, point) => ({ x: acc.x + point.x, y: acc.y + point.y }), { x: 0, y: 0 });
    return { x: sum.x / points.length, y: sum.y / points.length };
  }

  const tools: Array<{ id: Tool; label: string }> = [
    { id: 'select', label: 'Select' }, { id: 'wall', label: 'Wall' }, { id: 'room', label: 'Room' },
    { id: 'opening', label: 'Opening' }, { id: 'place', label: 'Place device' }
  ];
</script>

<svelte:window onkeydown={onWindowKeydown} />

<section class="home-editor" aria-labelledby="home-heading">
  <div class="view-heading">
    <div>
      <p class="kicker">HOME / PLAN EDITOR</p>
      <h1 id="home-heading">Draw the home you protect.</h1>
      <p class="muted">Owner-confirmed placement is the truth. Estimates stay advisory until you place them.</p>
    </div>
  </div>

  {#if loading}
    <div class="editor-state" role="status">Reading home plan…</div>
  {:else if loadError}
    <div class="editor-state error" role="alert">{loadError} <button type="button" onclick={() => { loading = true; void loadHome(); }}>Retry</button></div>
  {:else}
    {#if conflict}
      <div class="banner conflict" role="alert">
        <strong>Save conflict.</strong> This plan changed somewhere else since you loaded it. Reload the latest plan, then redo your edit.
        <button type="button" onclick={() => void reloadLatest()}>Reload latest plan</button>
      </div>
    {/if}
    {#if draftOffer}
      <div class="banner draft" role="region" aria-label="Draft found">
        <strong>Unsaved draft found</strong> from {new Date(draftOffer.saved_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}.
        <button type="button" onclick={resumeDraft}>Resume draft</button>
        <button type="button" class="quiet" onclick={discardDraft}>Discard draft</button>
      </div>
    {/if}
    {#if notice}
      <div class="banner notice" role="status">{notice} <button type="button" class="quiet" onclick={() => (notice = null)}>Dismiss</button></div>
    {/if}
    {#if uncertain.length > 0}
      <div class="banner uncertain" role="region" aria-label="Place these devices">
        <strong>Place these devices.</strong> Their location is only a low-confidence estimate:
        {#each uncertain as entry (entry.device.device_id)}
          <button type="button" onclick={() => armPlacement(entry.device.device_id)}>
            {entry.device.name ?? deviceName(entry.device.device_id)} · {Math.round(entry.estimate.confidence * 100)}%
          </button>
        {/each}
      </div>
    {/if}

    <div class="editor-toolbar">
      <div class="tool-palette" role="toolbar" aria-label="Editor tools">
        <label class="opening-kind">Units
          <select aria-label="Measurement units" value={units} onchange={event => { units = event.currentTarget.value as HomeUnits; saveHomeUnits(units); cancelPending(); }}>
            <option value="metric">Metric (meters)</option><option value="imperial">Imperial (feet / inches)</option>
          </select>
        </label>
        {#each tools as entry (entry.id)}
          <button type="button" class:active={tool === entry.id} aria-pressed={tool === entry.id} onclick={() => { tool = entry.id; if (entry.id !== 'place') placingDevice = null; }}>{entry.label}</button>
        {/each}
        {#if tool === 'opening'}
          <label class="opening-kind">Kind
            <select value={openingKind} onchange={(event) => (openingKind = (event.currentTarget as HTMLSelectElement).value as OpeningKind)}>
              <option value="door">Door</option><option value="window">Window</option><option value="stair">Stair</option>
            </select>
          </label>
        {/if}
        {#if tool === 'room' && pendingRoom.length > 0}
          <button type="button" class="finish" disabled={pendingRoom.length < 3} onclick={finishRoom}>Finish room ({pendingRoom.length})</button>
          <button type="button" class="quiet" onclick={cancelPending}>Cancel</button>
        {/if}
        {#if placingDevice}
          <span class="placing-hint" role="status">Placing {deviceName(placingDevice)} — click the plan.</span>
        {/if}
      </div>
      <div class="history-actions">
        <button type="button" disabled={!canUndo} onclick={() => dispatch({ type: 'undo' })} aria-keyshortcuts="Control+Z">Undo</button>
        <button type="button" disabled={!canRedo} onclick={() => dispatch({ type: 'redo' })} aria-keyshortcuts="Control+Shift+Z">Redo</button>
        <span class="autosave" role="status">{autosaveLabel}</span>
        <button type="button" class="save" disabled={committing} onclick={() => void saveCommitted()}>Save plan</button>
      </div>
    </div>

    <HomeEditorFloorBar {units} floors={plan.floors} active={activeFloor?.floor_id ?? null} onselect={(floorId) => { activeFloorId = floorId; selection = { kind: 'floor' }; cancelPending(); }} onadd={addFloor} />

    {#if activeFloor}
      <div class="footprint-controls tool-palette">
        <label class="opening-kind">Copy footprint to
          <select aria-label="Footprint destination" bind:value={copyTarget}>
            <option value="new">New floor above</option>
            {#each copyTargets as floor (floor.floor_id)}<option value={floor.floor_id}>{floor.name}</option>{/each}
          </select>
        </label>
        <button type="button" disabled={!activeFloor.walls.length && !activeFloor.rooms.length} onclick={copyFootprint}>Copy footprint</button>
        <span class="placing-hint">Copies walls, openings, and rooms. Devices keep their locations.</span>
      </div>
    {/if}

    <div class="editor-body">
      <div class="canvas-frame">
        {#if activeFloor}
          <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
          <!-- role=application is the ARIA drawing-canvas role; every tool is also reachable through real buttons. -->
          <svg class="plan-canvas" bind:this={svgEl} width={CANVAS_W_M * SCALE} height={CANVAS_H_M * SCALE}
            viewBox={`0 0 ${CANVAS_W_M * SCALE} ${CANVAS_H_M * SCALE}`} role="application" tabindex="0"
            aria-label={`Floor plan for ${activeFloor.name}. Grid squares are ${units === 'imperial' ? '6 inches' : '0.5 meters'}. Snap ${units === 'imperial' ? '1 inch' : '0.1 meter'}.`}
            onclick={onCanvasClick} onkeydown={onCanvasKeydown} ondragover={(event) => event.preventDefault()} ondrop={onCanvasDrop}>
            <defs>
              <pattern id="home-grid-minor" width={SCALE * majorGrid / 2} height={SCALE * majorGrid / 2} patternUnits="userSpaceOnUse">
                <path class="grid-minor" d={`M ${SCALE * majorGrid / 2} 0 L 0 0 0 ${SCALE * majorGrid / 2}`} fill="none" stroke-width="1" />
              </pattern>
              <pattern id="home-grid-major" width={SCALE * majorGrid} height={SCALE * majorGrid} patternUnits="userSpaceOnUse">
                <path class="grid-major" d={`M ${SCALE * majorGrid} 0 L 0 0 0 ${SCALE * majorGrid}`} fill="none" stroke-width="1" />
              </pattern>
            </defs>
            <rect class="grid" width="100%" height="100%" fill="url(#home-grid-minor)" />
            <rect class="grid" width="100%" height="100%" fill="url(#home-grid-major)" />
            {#each activeFloor.rooms as room (room.room_id)}
              <polygon class="room" class:selected={selection?.kind === 'room' && selection.id === room.room_id} data-room-id={room.room_id}
                points={polygonPoints(room.polygon)} role="button" tabindex="0" aria-label={`Room ${room.name}`}
                onclick={(event) => onRoomClick(event, room)} onkeydown={(event) => keyActivate(event, () => (selection = { kind: 'room', id: room.room_id }))} />
              <text class="room-label" x={centroid(room.polygon).x * SCALE} y={centroid(room.polygon).y * SCALE}>{room.name}</text>
            {/each}
            {#each activeFloor.walls as wall (wall.wall_id)}
              <line class="wall" class:selected={selection?.kind === 'wall' && selection.id === wall.wall_id} data-wall-id={wall.wall_id}
                x1={wall.start.x * SCALE} y1={wall.start.y * SCALE} x2={wall.end.x * SCALE} y2={wall.end.y * SCALE}
                role="button" tabindex="0" aria-label={`Wall, ${formatLength(wallLength(wall), units)}`}
                onclick={(event) => onWallClick(event, wall)} onkeydown={(event) => keyActivate(event, () => (selection = { kind: 'wall', id: wall.wall_id }))} />
              {#each wall.openings as opening (opening.opening_id)}
                {@const segment = openingSegment(wall, opening.offset_m, opening.width_m)}
                <line class={`wall-opening ${opening.kind}`} x1={segment.x1} y1={segment.y1} x2={segment.x2} y2={segment.y2} />
              {/each}
            {/each}
            {#if selectedWall}
              <text class="dimension" x={((selectedWall.start.x + selectedWall.end.x) / 2) * SCALE} y={((selectedWall.start.y + selectedWall.end.y) / 2) * SCALE - 10}>{formatLength(wallLength(selectedWall), units)}</text>
            {/if}
            {#each floorPlacements as placement (placement.device_id)}
              <g class="placement" class:selected={selection?.kind === 'placement' && selection.id === placement.device_id} data-device-id={placement.device_id}
                role="button" tabindex="0" aria-label={`${deviceName(placement.device_id)} — owner-placed`}
                onclick={(event) => selectPlacement(event, placement)} onkeydown={(event) => keyActivate(event, () => (selection = { kind: 'placement', id: placement.device_id }))}>
                <circle cx={placement.x * SCALE} cy={placement.y * SCALE} r="9" />
                <text x={placement.x * SCALE} y={placement.y * SCALE - 14}>{deviceName(placement.device_id)}</text>
              </g>
            {/each}
            {#if pendingWallStart}
              <circle class="pending-start" cx={pendingWallStart.x * SCALE} cy={pendingWallStart.y * SCALE} r="5" />
            {/if}
            {#if pendingRoom.length > 0}
              <polyline class="pending-room" points={polygonPoints(pendingRoom)} />
            {/if}
          </svg>
        {:else}
          <div class="editor-state">This home has no floors yet. Add a floor to start drawing.
            <button type="button" onclick={addFloor}>Add floor</button>
          </div>
        {/if}
      </div>
      <div class="side-panel">
        <HomeEditorTray {unplaced} placing={placingDevice} estimated={estimatedRows} onpick={armPlacement} />
        {#if target}
          <HomeEditorInspector {target} {units} onaction={apply} onclose={() => (selection = null)} />
        {/if}
      </div>
    </div>
  {/if}
</section>

<style>
  .footprint-controls{margin:0 0 14px;gap:10px}
  .grid-minor{stroke:var(--line)}
  .grid-major{stroke:var(--line-strong)}
  .editor-state{margin-top:28px;padding:18px;border:1px dashed var(--line-strong);color:var(--muted-strong);display:flex;gap:12px;align-items:center;flex-wrap:wrap}
  .editor-state.error{border-color:var(--pink);color:#ffb4cc}
  .editor-state button{min-height:40px;padding:8px 14px;border:1px solid var(--accent);border-radius:5px;background:transparent;color:var(--accent);font:600 12px var(--font-display);cursor:pointer}
  .banner{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:16px 0 0;padding:12px 14px;border-radius:8px;border:1px solid var(--line-strong);background:var(--surface);color:var(--ink);font-size:12px}
  .banner strong{color:var(--ink)}
  .banner button{min-height:38px;padding:7px 12px;border:1px solid var(--accent);border-radius:5px;background:transparent;color:var(--accent);font:600 12px var(--font-display);cursor:pointer}
  .banner button.quiet{border-color:var(--line-strong);color:var(--muted-strong)}
  .banner.conflict{border-color:var(--pink)}
  .banner.conflict strong{color:var(--pink)}
  .banner.conflict button{border-color:var(--pink);color:var(--pink)}
  .banner.draft{border-color:var(--gold)}
  .banner.draft strong{color:var(--gold)}
  .banner.uncertain{border-color:var(--gold);border-style:dashed}
  .banner.uncertain strong{color:var(--gold)}
  .banner.uncertain button{border-color:var(--gold);color:var(--gold)}
  .editor-toolbar{display:flex;flex-wrap:wrap;gap:12px;justify-content:space-between;align-items:center;margin:22px 0 0}
  .tool-palette{display:flex;flex-wrap:wrap;gap:7px;align-items:center}
  .tool-palette button{min-height:44px;padding:9px 13px;border:1px solid var(--line-strong);border-radius:5px;background:transparent;color:var(--ink);font:600 12px var(--font-display);cursor:pointer}
  .tool-palette button.active{border-color:var(--accent);color:var(--accent);box-shadow:inset 0 0 14px var(--accent)14}
  .tool-palette button.finish{border-color:var(--accent);color:var(--accent-ink);background:var(--accent)}
  .tool-palette button.quiet{border-color:var(--line-strong);color:var(--muted-strong)}
  .tool-palette button:disabled{opacity:.4;cursor:not-allowed}
  .opening-kind{display:flex;gap:7px;align-items:center;color:var(--muted-strong);font:10px var(--font-mono);text-transform:uppercase}
  .opening-kind select{min-height:38px;padding:6px 8px;border:1px solid var(--line-strong);border-radius:5px;background:#0e2430;color:var(--ink);font:12px var(--font-display)}
  .placing-hint{color:var(--accent);font:11px var(--font-mono)}
  .history-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  .history-actions button{min-height:44px;padding:9px 14px;border:1px solid var(--line-strong);border-radius:5px;background:transparent;color:var(--ink);font:600 12px var(--font-display);cursor:pointer}
  .history-actions button:disabled{opacity:.4;cursor:not-allowed}
  .history-actions button.save{border-color:var(--accent);background:var(--accent);color:var(--accent-ink)}
  .autosave{color:var(--muted-strong);font:10px var(--font-mono);text-transform:uppercase;letter-spacing:.07em}
  .editor-body{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:16px;align-items:start;margin-top:4px}
  .canvas-frame{overflow:auto;border:1px solid var(--line-mid);border-radius:10px;background:var(--bg)}
  .plan-canvas{display:block;background:#081722;outline:none}
  .plan-canvas:focus-visible{box-shadow:inset 0 0 0 2px var(--accent)}
  .grid{pointer-events:none}
  .room{fill:#123641;fill-opacity:.55;stroke:var(--line-strong);stroke-width:1.5;cursor:pointer}
  .room.selected{stroke:var(--accent);stroke-width:2;fill-opacity:.75}
  .room-label{fill:var(--muted-strong);font:11px var(--font-mono);text-anchor:middle;pointer-events:none}
  .wall{stroke:var(--ink);stroke-width:6;stroke-linecap:round;cursor:pointer}
  .wall.selected{stroke:var(--accent)}
  .wall-opening{stroke-width:6;stroke-linecap:butt;pointer-events:none}
  .wall-opening.door{stroke:var(--gold)}
  .wall-opening.window{stroke:var(--blue)}
  .wall-opening.stair{stroke:var(--pink);stroke-dasharray:4 3}
  .dimension{fill:var(--accent);font:700 12px var(--font-mono);text-anchor:middle;pointer-events:none}
  .placement{cursor:pointer}
  .placement circle{fill:#0e2430;stroke:var(--accent);stroke-width:2}
  .placement.selected circle{fill:var(--accent)}
  .placement text{fill:var(--ink);font:10px var(--font-mono);text-anchor:middle;pointer-events:none}
  .pending-start{fill:var(--accent)}
  .pending-room{fill:none;stroke:var(--accent);stroke-dasharray:5 4;stroke-width:1.5;pointer-events:none}
  .side-panel{display:grid;gap:14px;align-content:start}
  @media(max-width:1000px){.editor-body{grid-template-columns:1fr}.side-panel{grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}}
</style>
