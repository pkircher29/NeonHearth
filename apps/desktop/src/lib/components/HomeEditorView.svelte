<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import {
    DEFAULT_THICKNESS_M, PlanLimitError, copyFloorFootprint, createEditorState, emptyHomePlan, reduceEditor, rejectionReason, selectUncertain, selectUnplaced, snap, snapPoint, wallLength,
    type EditAction, type EditorAction, type EditorState, type Estimate, type HomeApi, type HomeDeviceRef, type HomeDraft, type HomeSnapshot, type OpeningKind, type Placement, type PlanPoint, type Room, type Wall
  } from '../stores/home';
  import HomeEditorFloorBar from './HomeEditorFloorBar.svelte';
  import HomeEditorInspector, { type InspectorTarget } from './HomeEditorInspector.svelte';
  import HomeEditorTray, { type EstimatedRow } from './HomeEditorTray.svelte';
  import HomePlanGrid from './HomePlanGrid.svelte';
  import HomePlanWall from './HomePlanWall.svelte';
  import { formatArea, formatLength, fromDisplayLength, gridStep, readHomeUnits, saveHomeUnits, unitSymbol, type HomeUnits } from '../homeUnits';
  import {
    DEFAULT_SCALE, boundsOf, defaultView, fitView, panBy, pinchView, scaleBar, toPlan, viewBox, zoomAt, zoomTo, type Size, type TouchPair, type ViewState
  } from '../home/view';
  import { SNAP_LABELS, angleDegrees, computeSnap, constrainAngle, pointAtLength, type SnapResult } from '../home/snap';
  import { dividedRooms, newRoomCandidates, polygonArea, polygonCentroid, type RoomCandidate } from '../home/rooms';
  import { deviceLabel } from '../home/deviceLabel';
  import { blockedOpening, blockedOpeningNotice, parseLengthEntry, planRectangleBatch, planWallBatch } from '../home/draft';
  import { DEFAULT_CANVAS_SIZE, floorPoints, initialFloorView, readFloorView, saveFloorView } from '../home/viewStore';
  import { readLetterShortcuts } from '../stores/preferences';

  // `snapshot` is the already-loaded home when a parent owns it (HomeView
  // shares one fetch with the 3D twin, audit M-27); without it the editor
  // fetches on mount. `onsnapshot` reports every server-acknowledged change
  // (committed plan, placements, reloads) so the parent's twin stays current.
  // `active` is false while the editor is mounted but hidden (the 3D tab is showing): the window-level keyboard
  // handler must then leave the keys alone.
  let { api, devices = [], snapshot = undefined, onsnapshot, active = true }: { api: HomeApi; devices?: HomeDeviceRef[]; snapshot?: HomeSnapshot | null; onsnapshot?: (snapshot: HomeSnapshot) => void; active?: boolean } = $props();

  const AUTOSAVE_DELAY_MS = 2000;
  const OPENING_WIDTHS: Record<OpeningKind, number> = { door: 0.9, window: 0.8, stair: 1.0 };
  const DRAG_THRESHOLD_PX = 4;

  type Tool = 'select' | 'pan' | 'wall' | 'room' | 'rect' | 'opening' | 'place';
  type Selection = { kind: 'wall' | 'room' | 'placement'; id: string } | { kind: 'floor' } | null;
  type Drag =
    | { kind: 'pan'; x: number; y: number; moved: boolean }
    | { kind: 'handle'; wall_id: string; end: 'start' | 'end'; point: PlanPoint; moved: boolean }
    | { kind: 'body'; wall_id: string; clientX: number; clientY: number; from: PlanPoint; delta: PlanPoint; moved: boolean };

  // Immutable documents replaced wholesale by the reducer: raw state avoids deep proxies over up to 200 history entries.
  let editor = $state.raw<EditorState>(createEditorState(emptyHomePlan(), []));
  let letterShortcuts = $state(true);
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
  let chainFirst = $state<PlanPoint | null>(null);
  let lengthEntry = $state('');
  let rectStart = $state<PlanPoint | null>(null);
  let pendingRoom = $state<PlanPoint[]>([]);
  let placingDevice = $state<string | null>(null);
  let svgEl = $state<SVGSVGElement | null>(null);
  let cursor = $state.raw<SnapResult | null>(null);
  let drag = $state.raw<Drag | null>(null);
  let spaceHeld = $state(false);
  let view = $state.raw<ViewState>(defaultView());
  let viewSize = $state.raw<Size>({ ...DEFAULT_CANVAS_SIZE });
  let roomOfferOpen = $state(false);
  let roomNameEdits = $state<Record<string, string>>({});
  let autosaveTimer: ReturnType<typeof setTimeout> | undefined;
  let suppressClick = false;
  // Active touch pointers (CSS px inside the canvas) and the finger pair of a running pinch.
  const touches = new Map<number, { x: number; y: number }>();
  let pinch: TouchPair | null = null;
  const viewsByFloor = new Map<string, ViewState>();

  const doc = $derived(editor.doc);
  const plan = $derived(doc.plan);
  const grid = $derived(gridStep(units));
  const copyTargets = $derived(plan.floors.filter(floor => floor.floor_id !== activeFloorId && !floor.walls.length && !floor.rooms.length));
  const activeFloor = $derived(plan.floors.find((floor) => floor.floor_id === activeFloorId) ?? plan.floors[0] ?? null);
  const activeFloorKey = $derived(activeFloor?.floor_id ?? null);
  const floorPlacements = $derived(activeFloor ? doc.placements.filter((placement) => placement.floor_id === activeFloor.floor_id) : []);
  const unplaced = $derived(selectUnplaced(devices, doc.placements));
  const uncertain = $derived(selectUncertain(devices, doc.placements, estimates));
  // One tab stop for the whole plan: the focused item, else the selected one, else the first. Arrow keys move between items.
  const rovingKeys = $derived(activeFloor ? [...activeFloor.rooms.map((room) => `room:${room.room_id}`), ...activeFloor.walls.map((wall) => `wall:${wall.wall_id}`), ...floorPlacements.map((placement) => `placement:${placement.device_id}`)] : []);
  let rovingFocus = $state<string | null>(null);
  const rovingKey = $derived.by(() => {
    if (rovingFocus && rovingKeys.includes(rovingFocus)) return rovingFocus;
    const current = selection;
    const selectedKey = current && current.kind !== 'floor' ? `${current.kind}:${current.id}` : null;
    return selectedKey && rovingKeys.includes(selectedKey) ? selectedKey : (rovingKeys[0] ?? null);
  });
  const canUndo = $derived(editor.past.length > 0);
  const canRedo = $derived(editor.future.length > 0);
  const segments = $derived(activeFloor ? activeFloor.walls.map((wall) => ({ wall_id: wall.wall_id, start: wall.start, end: wall.end })) : []);
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

  // ---- Viewport ----
  const scale = $derived(view.scale);
  const bar = $derived(scaleBar(scale));
  const originPx = $derived({ x: view.origin.x * scale, y: view.origin.y * scale });
  const panReady = $derived(tool === 'pan' || spaceHeld);
  const candidates = $derived<RoomCandidate[]>(roomOfferOpen && activeFloor ? newRoomCandidates(activeFloor.walls, activeFloor.rooms) : []);
  $effect(() => { if (roomOfferOpen && candidates.length === 0) roomOfferOpen = false; });

  function setView(next: ViewState) {
    view = next;
    if (!activeFloorKey) return;
    viewsByFloor.set(activeFloorKey, next);
    saveFloorView(activeFloorKey, next);
  }
  function measure() {
    const el = svgEl;
    if (!el) return;
    const width = el.clientWidth;
    const height = el.clientHeight;
    // jsdom (and a not-yet-laid-out frame) reports 0: keep the fallback size.
    const next = width > 0 && height > 0 ? { width, height } : { ...DEFAULT_CANVAS_SIZE };
    if (next.width !== viewSize.width || next.height !== viewSize.height) viewSize = next;
  }
  $effect(() => {
    const el = svgEl;
    if (!el) return;
    measure();
    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(() => measure());
    observer.observe(el);
    return () => observer.disconnect();
  });
  // Opening a floor restores its own view; the first time ever, a drawing that does not fit the
  // default view is framed instead.
  $effect(() => {
    const key = activeFloorKey;
    const el = svgEl;
    if (!key || !el) return;
    untrack(() => {
      const remembered = viewsByFloor.get(key) ?? readFloorView(key);
      const next = remembered ?? (activeFloor ? initialFloorView(activeFloor, viewSize) : defaultView());
      viewsByFloor.set(key, next);
      view = next;
    });
  });
  $effect(() => {
    const el = svgEl;
    if (!el) return;
    // Non-passive so a wheel over the plan zooms the plan instead of scrolling the page.
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      const o = offsetOf(event);
      const unit = event.deltaMode === 1 ? 0.05 : 0.0015;
      const factor = Math.min(2, Math.max(0.5, Math.exp(-event.deltaY * unit * (event.ctrlKey ? 3 : 1))));
      setView(zoomAt(view, factor, o.x, o.y));
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  });
  const zoomBy = (factor: number) => setView(zoomAt(view, factor, viewSize.width / 2, viewSize.height / 2));
  const fitPlan = () => setView(activeFloor ? fitView(boundsOf(floorPoints(activeFloor)), viewSize) : defaultView());
  const actualSize = () => setView(zoomTo(view, DEFAULT_SCALE, viewSize));

  $effect(() => {
    if (plan.floors.length > 0 && !plan.floors.some((floor) => floor.floor_id === activeFloorId)) activeFloorId = plan.floors[0].floor_id;
  });

  const newId = () => crypto.randomUUID();
  function deviceName(deviceId: string): string {
    const ref = devices.find((device) => device.device_id === deviceId);
    return ref ? deviceLabel(ref) : `Device ${deviceId.slice(0, 8)}`;
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
    onsnapshot?.({ plan: editor.doc.plan, placements: editor.doc.placements.map((placement) => ({ ...placement })), estimates: $state.snapshot(estimates) });
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
    if (action.type === 'undo' || action.type === 'redo') resetDrafting();
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
    if (!dispatch(action)) notice = rejectionReason(editor, { ...action, grid_m: grid }) ?? 'That change is not allowed.';
  }

  function planSnapshot() {
    return { ...editor.doc.plan, version };
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
    } catch (cause) { notice = cause instanceof PlanLimitError ? cause.message : 'The plan could not be saved. Try again shortly.'; }
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
    resetDrafting();
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
    resetDrafting();
  }
  function discardDraft() {
    draftOffer = null;
    void api.deleteDraft().catch(() => { /* Discard is best-effort; the committed plan remains loaded. */ });
  }

  onMount(() => {
    units = readHomeUnits();
    letterShortcuts = readLetterShortcuts();
    const onShortcuts = () => { letterShortcuts = readLetterShortcuts(); };
    window.addEventListener('neonhearth:shortcuts', onShortcuts);
    void (async () => {
      if (snapshot) { adopt(snapshot); loading = false; }
      else await loadHome();
      if (loadError) return;
      try {
        const draft = await api.loadDraft();
        if (draft.status === 'draft') { draftOffer = draft.draft; if (draft.overLimits) notice = 'The saved draft is over the plan size limits. Resume it, remove some items, then save.'; }
        else if (draft.status === 'corrupt') notice = 'A saved draft could not be read and was discarded. The last committed plan is shown.';
      } catch { /* Draft recovery is optional; the committed plan is already loaded. */ }
    })();
    return () => {
      window.removeEventListener('neonhearth:shortcuts', onShortcuts);
      clearTimeout(autosaveTimer);
      // Unsaved edits inside the autosave window must not vanish with the view: flush the draft now.
      if (autosaveState === 'dirty') void persistDraft();
    };
  });
  // A closing tab with unsaved edits asks first, and still tries to leave a draft behind.
  function onBeforeUnload(event: BeforeUnloadEvent) {
    if (autosaveState !== 'dirty' && autosaveState !== 'saving') return;
    void persistDraft();
    event.preventDefault();
    event.returnValue = '';
  }

  // ---- Canvas geometry ----
  function offsetOf(event: { clientX: number; clientY: number }): { x: number; y: number } {
    const rect = svgEl?.getBoundingClientRect();
    return { x: event.clientX - (rect?.left ?? 0), y: event.clientY - (rect?.top ?? 0) };
  }
  /** The pointer in plan meters, unsnapped. */
  function rawPoint(event: { clientX: number; clientY: number }): PlanPoint {
    const o = offsetOf(event);
    return toPlan(view, o.x, o.y);
  }
  /** The pointer snapped to the unit grid only (placement, openings, drops). */
  const gridPoint = (event: { clientX: number; clientY: number }): PlanPoint => snapPoint(rawPoint(event), grid);
  const samePoint = (a: PlanPoint, b: PlanPoint) => Math.abs(a.x - b.x) < 1e-6 && Math.abs(a.y - b.y) < 1e-6;

  /** The drafting snap for a raw cursor: the ladder first; Shift constrains to 0/45/90 from `anchor`. */
  function snapFor(raw: PlanPoint, shift: boolean, options: { anchor?: PlanPoint | null; extra?: PlanPoint[]; exclude?: string[] } = {}): SnapResult {
    const anchor = options.anchor ?? null;
    if (shift && anchor) {
      return { point: constrainAngle(anchor, raw, grid), kind: 'grid', label: SNAP_LABELS.grid, wall_id: null, guides: { x: null, y: null } };
    }
    return computeSnap(raw, { walls: segments, scale, excludeWallIds: options.exclude, extraPoints: options.extra, guidePoints: anchor ? [anchor] : [], grid });
  }
  function draftingSnap(raw: PlanPoint, shift: boolean): SnapResult | null {
    if (tool === 'wall') return snapFor(raw, shift, { anchor: pendingWallStart, extra: chainFirst ? [chainFirst] : [] });
    if (tool === 'rect') return snapFor(raw, false, { anchor: rectStart });
    if (tool === 'room') return snapFor(raw, shift, { anchor: pendingRoom.at(-1) ?? null, extra: pendingRoom.slice(0, 1) });
    return null;
  }

  // ---- Pointer interaction ----
  function capture(event: PointerEvent) {
    try { svgEl?.setPointerCapture?.(event.pointerId); } catch { /* Capture is an enhancement; some pointers cannot be captured. */ }
  }
  function touchPair(): TouchPair | null {
    if (touches.size !== 2) return null;
    const [a, b] = [...touches.values()];
    return { a, b };
  }
  function endTouch(event: PointerEvent) {
    touches.delete(event.pointerId);
    if (pinch && touches.size < 2) {
      pinch = null;
      suppressClick = true; // lifting the fingers must not click the plan
      setTimeout(() => { suppressClick = false; }, 0);
    }
  }
  function onPointerDownCapture(event: PointerEvent) {
    if (!activeFloor) return;
    if (event.pointerType === 'touch') {
      touches.set(event.pointerId, offsetOf(event));
      if (touches.size === 2) {
        // A second finger turns whatever the first started into a pinch/pan gesture.
        drag = null;
        pinch = touchPair();
        event.preventDefault();
        event.stopPropagation();
        capture(event);
        return;
      }
    }
    const wantsPan = event.button === 1 || (event.button === 0 && panReady);
    if (!wantsPan) return;
    event.preventDefault();
    event.stopPropagation();
    capture(event);
    drag = { kind: 'pan', x: event.clientX, y: event.clientY, moved: false };
  }
  function onPointerMove(event: PointerEvent) {
    if (touches.has(event.pointerId)) touches.set(event.pointerId, offsetOf(event));
    if (pinch) {
      const next = touchPair();
      if (next) { setView(pinchView(view, pinch, next)); pinch = next; }
      return;
    }
    const current = drag;
    if (current?.kind === 'pan') {
      const dx = event.clientX - current.x;
      const dy = event.clientY - current.y;
      if (!current.moved && Math.hypot(dx, dy) < 2) return;
      drag = { ...current, x: event.clientX, y: event.clientY, moved: true };
      setView(panBy(view, dx, dy));
      return;
    }
    const raw = rawPoint(event);
    if (current?.kind === 'handle' && activeFloor) {
      const wall = activeFloor.walls.find((candidate) => candidate.wall_id === current.wall_id);
      if (!wall) return;
      const fixed = current.end === 'start' ? wall.end : wall.start;
      const snapped = snapFor(raw, event.shiftKey, { anchor: fixed, exclude: [wall.wall_id] });
      cursor = snapped;
      drag = { ...current, point: snapped.point, moved: true };
      return;
    }
    if (current?.kind === 'body') {
      if (!current.moved && Math.hypot(event.clientX - current.clientX, event.clientY - current.clientY) < DRAG_THRESHOLD_PX) return;
      if (!current.moved) capture(event);
      drag = { ...current, moved: true, delta: { x: snap(raw.x - current.from.x, grid), y: snap(raw.y - current.from.y, grid) } };
      return;
    }
    cursor = draftingSnap(raw, event.shiftKey);
  }
  function onPointerUp(event: PointerEvent) {
    endTouch(event);
    const current = drag;
    if (!current) return;
    drag = null;
    try { svgEl?.releasePointerCapture?.(event.pointerId); } catch { /* Not captured. */ }
    if (current.moved) {
      suppressClick = true;
      setTimeout(() => { suppressClick = false; }, 0); // the click that follows a drag is swallowed; never let the flag go stale
    }
    if (!current.moved || !activeFloor) return;
    if (current.kind === 'handle') commitHandle(current);
    else if (current.kind === 'body') commitBody(current);
  }
  function onPointerLeave() {
    if (!drag) cursor = null;
  }
  function onClickCapture(event: MouseEvent) {
    if (!suppressClick) return;
    suppressClick = false;
    event.stopPropagation();
    event.preventDefault();
  }

  function commitHandle(current: Extract<Drag, { kind: 'handle' }>) {
    const wall = activeFloor?.walls.find((candidate) => candidate.wall_id === current.wall_id);
    if (wall) moveEndpoint(wall, current.end, current.point);
  }
  /** Move one wall endpoint, joining it to any wall body it lands on. */
  function moveEndpoint(wall: Wall, end: 'start' | 'end', point: PlanPoint) {
    const floor = activeFloor;
    if (!floor) return;
    const start = end === 'start' ? point : wall.start;
    const stop = end === 'end' ? point : wall.end;
    if (samePoint(start, stop)) { notice = 'A wall cannot shrink to a point.'; return; }
    if (samePoint(end === 'start' ? wall.start : wall.end, point)) return;
    const batch = planWallBatch({ floor, walls: [{ start, end: stop }], newId, moveWallId: wall.wall_id, ignoreWallIds: [wall.wall_id] });
    if (batch && dispatch({ type: 'batch', actions: batch })) return;
    if (dispatch({ type: 'move_wall', floor_id: floor.floor_id, wall_id: wall.wall_id, start, end: stop, exact: true })) {
      const blocked = blockedOpening(floor, [point], wall.wall_id);
      if (blocked) notice = blockedOpeningNotice(blocked);
    } else notice = 'That would overlap another wall.';
  }
  const HANDLE_NUDGES: Record<string, [number, number]> = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
  function onHandleKeydown(event: KeyboardEvent, wall: Wall, end: 'start' | 'end') {
    const nudge = HANDLE_NUDGES[event.key];
    if (!nudge || event.ctrlKey || event.metaKey || event.altKey) return;
    event.preventDefault();
    event.stopPropagation(); // the window handler would otherwise nudge the whole wall
    const steps = (event.shiftKey ? 10 : 1) * grid;
    const from = end === 'start' ? wall.start : wall.end;
    moveEndpoint(wall, end, snapPoint({ x: from.x + nudge[0] * steps, y: from.y + nudge[1] * steps }, grid));
  }
  function commitBody(current: Extract<Drag, { kind: 'body' }>) {
    const floor = activeFloor;
    const wall = floor?.walls.find((candidate) => candidate.wall_id === current.wall_id);
    if (!floor || !wall || (current.delta.x === 0 && current.delta.y === 0)) return;
    const shift = (point: PlanPoint) => ({ x: point.x + current.delta.x, y: point.y + current.delta.y });
    if (!dispatch({ type: 'move_wall', floor_id: floor.floor_id, wall_id: wall.wall_id, start: shift(wall.start), end: shift(wall.end), exact: true })) notice = 'That would overlap another wall.';
  }
  function onWallPointerDown(event: PointerEvent, wall: Wall) {
    if (tool !== 'select' || event.button !== 0 || drag) return;
    selection = { kind: 'wall', id: wall.wall_id };
    drag = { kind: 'body', wall_id: wall.wall_id, clientX: event.clientX, clientY: event.clientY, from: rawPoint(event), delta: { x: 0, y: 0 }, moved: false };
  }
  function onHandlePointerDown(event: PointerEvent, wall: Wall, end: 'start' | 'end') {
    if (event.button !== 0) return;
    event.stopPropagation();
    event.preventDefault();
    capture(event);
    drag = { kind: 'handle', wall_id: wall.wall_id, end, point: end === 'start' ? wall.start : wall.end, moved: false };
  }

  // ---- Drafting ----
  function resetDrafting() {
    pendingWallStart = null;
    chainFirst = null;
    lengthEntry = '';
    rectStart = null;
    pendingRoom = [];
    drag = null;
  }
  function cancelPending() {
    resetDrafting();
    placingDevice = null;
  }
  function setTool(next: Tool) {
    resetDrafting();
    tool = next;
    if (next !== 'place') placingDevice = null;
  }
  function endChain() {
    pendingWallStart = null;
    chainFirst = null;
    lengthEntry = '';
  }

  /** Commit one wall, joining it to whatever its endpoints touch. Returns the new wall's id. */
  function commitWall(start: PlanPoint, end: PlanPoint): string | null {
    const floor = activeFloor;
    if (!floor) return null;
    if (samePoint(start, end)) { notice = 'Walls need two different points.'; return null; }
    const batch = planWallBatch({ floor, walls: [{ start, end }], newId });
    const added = batch ? [...batch].reverse().find((action) => action.type === 'add_wall') : undefined;
    if (batch && added?.type === 'add_wall' && dispatch({ type: 'batch', actions: batch })) return added.wall_id;
    const duplicate = floor.walls.some((wall) => (samePoint(wall.start, start) && samePoint(wall.end, end)) || (samePoint(wall.start, end) && samePoint(wall.end, start)));
    if (duplicate) { notice = 'That wall already exists.'; return null; }
    // Splitting was refused (an opening is in the way): draw the wall without joining it.
    const wall_id = newId();
    if (dispatch({ type: 'add_wall', floor_id: floor.floor_id, wall_id, start, end, thickness_m: DEFAULT_THICKNESS_M, exact: true })) {
      const blocked = blockedOpening(floor, [start, end]);
      notice = blocked ? blockedOpeningNotice(blocked) : 'The wall was drawn, but it could not be joined to the wall it touches.';
      return wall_id;
    }
    notice = 'That wall is not allowed.';
    return null;
  }
  function clickWall(raw: PlanPoint, shift: boolean) {
    const snapped = snapFor(raw, shift, { anchor: pendingWallStart, extra: chainFirst ? [chainFirst] : [] });
    cursor = snapped;
    if (!pendingWallStart) {
      pendingWallStart = snapped.point;
      chainFirst = snapped.point;
      lengthEntry = '';
      return;
    }
    advanceChain(pendingWallStart, snapped.point);
  }
  function advanceChain(start: PlanPoint, end: PlanPoint) {
    const id = commitWall(start, end);
    if (!id) return;
    selection = { kind: 'wall', id };
    lengthEntry = '';
    if (chainFirst && samePoint(end, chainFirst)) {
      // Closed the loop: the chain ends and the rooms it made are offered.
      endChain();
      offerRooms(false);
    } else pendingWallStart = end;
  }
  function commitTypedLength() {
    const start = pendingWallStart;
    const typed = parseLengthEntry(lengthEntry);
    if (!start || typed === null) { lengthEntry = ''; return; }
    advanceChain(start, typedEnd(start, typed));
  }
  function typedEnd(start: PlanPoint, typed: number): PlanPoint {
    const towards = cursor?.point ?? { x: start.x + 1, y: start.y };
    return pointAtLength(start, towards, fromDisplayLength(typed, units), null);
  }
  function clickRect(raw: PlanPoint) {
    const floor = activeFloor;
    if (!floor) return;
    const snapped = snapFor(raw, false, { anchor: rectStart });
    cursor = snapped;
    if (!rectStart) { rectStart = snapped.point; return; }
    const batch = planRectangleBatch(floor, rectStart, snapped.point, `Room ${floor.rooms.length + 1}`, newId);
    if (!batch) { notice = 'Rectangles need two corners at least 0.05 m apart in both directions.'; return; }
    if (!dispatch({ type: 'batch', actions: batch })) { notice = 'That rectangle collides with existing walls or rooms.'; return; }
    const room = [...batch].reverse().find((action) => action.type === 'add_room');
    if (room?.type === 'add_room') selection = { kind: 'room', id: room.room_id };
    rectStart = null;
  }

  // ---- Rooms from walls ----
  const candidateKey = (candidate: RoomCandidate) => candidate.polygon.map((point) => `${Math.round(point.x * 10)}:${Math.round(point.y * 10)}`).sort().join('|');
  const defaultRoomName = (index: number) => `Room ${(activeFloor?.rooms.length ?? 0) + index + 1}`;
  const roomNameFor = (candidate: RoomCandidate, index: number) => roomNameEdits[candidateKey(candidate)] ?? defaultRoomName(index);
  function offerRooms(announceNone: boolean) {
    if (!activeFloor) return;
    if (newRoomCandidates(activeFloor.walls, activeFloor.rooms).length === 0) {
      roomOfferOpen = false;
      if (announceNone) notice = 'No new closed rooms found. Close a loop of walls first.';
      return;
    }
    roomNameEdits = {};
    roomOfferOpen = true;
  }
  // A wall drawn across an existing room leaves that room stale: once every
  // piece of it is a room, the old outline is removed in the same undo step.
  function addRooms(additions: Array<{ name: string; polygon: PlanPoint[] }>): { added: number; replaced: string[] } | null {
    if (!activeFloor || additions.length === 0) return null;
    const floor = activeFloor;
    const adds = additions.map((addition) => ({ type: 'add_room' as const, floor_id: floor.floor_id, room_id: newId(), name: addition.name, polygon: addition.polygon, exact: true }));
    const after = [...floor.rooms, ...adds.map((add) => ({ room_id: add.room_id, name: add.name, polygon: add.polygon }))];
    const stale = dividedRooms(floor.walls, after).filter((room) => floor.rooms.some((existing) => existing.room_id === room.room_id));
    const removals = stale.map((room) => ({ type: 'delete_room' as const, floor_id: floor.floor_id, room_id: room.room_id }));
    if (!dispatch({ type: 'batch', actions: [...adds, ...removals] })) return null;
    return { added: adds.length, replaced: stale.map((room) => room.name) };
  }
  const replacedNote = (replaced: string[]) => replaced.length ? ` ${replaced.join(', ')} was divided by a wall and has been replaced.` : '';
  function addCandidate(candidate: RoomCandidate, index: number) {
    const name = roomNameFor(candidate, index).trim() || defaultRoomName(index);
    const result = addRooms([{ name, polygon: candidate.polygon }]);
    notice = result ? `Added ${name}.${replacedNote(result.replaced)}` : 'That room could not be added.';
  }
  function addAllCandidates() {
    const result = addRooms(candidates.map((candidate, index) => ({ name: roomNameFor(candidate, index).trim() || defaultRoomName(index), polygon: candidate.polygon })));
    notice = result ? `Added ${result.added} ${result.added === 1 ? 'room' : 'rooms'}.${replacedNote(result.replaced)}` : 'Those rooms could not be added.';
  }

  // ---- Clicks ----
  function onCanvasClick(event: MouseEvent) {
    if (!activeFloor || tool === 'pan') return;
    const raw = rawPoint(event);
    if (tool === 'wall') { clickWall(raw, event.shiftKey); return; }
    if (tool === 'rect') { clickRect(raw); return; }
    if (tool === 'room') {
      const snapped = snapFor(raw, event.shiftKey, { anchor: pendingRoom.at(-1) ?? null, extra: pendingRoom.slice(0, 1) });
      pendingRoom = [...pendingRoom, snapped.point];
      cursor = snapped;
      return;
    }
    if (tool === 'place' && placingDevice) { placeAt(placingDevice, snapPoint(raw, grid)); return; }
    if (tool === 'select') selection = null;
  }
  function onWallClick(event: MouseEvent, wall: Wall) {
    if (!activeFloor) return;
    if (tool === 'select') { event.stopPropagation(); selection = { kind: 'wall', id: wall.wall_id }; return; }
    if (tool !== 'opening') return; // wall/room/place clicks fall through to the canvas
    event.stopPropagation();
    const point = gridPoint(event);
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
    apply({ type: 'add_room', floor_id: activeFloor.floor_id, room_id: newId(), name: `Room ${activeFloor.rooms.length + 1}`, polygon: pendingRoom, exact: true });
    pendingRoom = [];
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
    placeAt(deviceId, gridPoint(event));
  }

  // ---- Keyboard ----
  const TOOL_KEYS: Record<string, Tool> = { v: 'select', h: 'pan', w: 'wall', r: 'room', b: 'rect', o: 'opening', p: 'place' };
  const isTextEntry = (element: EventTarget | null) => {
    const el = element as HTMLElement | null;
    return !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable === true);
  };
  const inCanvas = (element: EventTarget | null) => !!svgEl && (element === svgEl || svgEl.contains(element as Node | null));
  const onBody = (element: EventTarget | null) => !element || element === document.body || element === document.documentElement;

  /** Ctrl+D: copy the selected wall or room one major grid step down-right, as one undo step. */
  function duplicateSelection() {
    const floor = activeFloor;
    const current = selection;
    if (!floor || !current) return;
    const step = units === 'imperial' ? 0.3048 : 1;
    const shift = (point: PlanPoint) => ({ x: point.x + step, y: point.y + step });
    if (current.kind === 'wall') {
      const wall = floor.walls.find((candidate) => candidate.wall_id === current.id);
      if (!wall) return;
      const wall_id = newId();
      const actions: EditAction[] = [
        { type: 'add_wall', floor_id: floor.floor_id, wall_id, start: shift(wall.start), end: shift(wall.end), thickness_m: wall.thickness_m ?? DEFAULT_THICKNESS_M, exact: true },
        ...wall.openings.map((opening): EditAction => ({ type: 'add_opening', floor_id: floor.floor_id, wall_id, opening: { ...opening, opening_id: newId() } }))
      ];
      if (dispatch({ type: 'batch', actions })) selection = { kind: 'wall', id: wall_id };
      else notice = 'That wall could not be duplicated.';
    } else if (current.kind === 'room') {
      const room = floor.rooms.find((candidate) => candidate.room_id === current.id);
      if (!room) return;
      const room_id = newId();
      const name = `${room.name.slice(0, 58)} copy`;
      if (dispatch({ type: 'add_room', floor_id: floor.floor_id, room_id, name, polygon: room.polygon.map(shift), exact: true })) selection = { kind: 'room', id: room_id };
      else notice = 'That room could not be duplicated.';
    }
  }
  function onWindowKeydown(event: KeyboardEvent) {
    if (!active) return;
    const textEntry = isTextEntry(event.target);
    if (event.ctrlKey || event.metaKey) {
      if (textEntry) return;
      const key = event.key.toLowerCase();
      if (key === 'd' && !event.shiftKey && !event.altKey) { event.preventDefault(); duplicateSelection(); return; }
      if (key === 'z' && !event.shiftKey) { event.preventDefault(); dispatch({ type: 'undo' }); }
      else if ((key === 'z' && event.shiftKey) || key === 'y') { event.preventDefault(); dispatch({ type: 'redo' }); }
      return;
    }
    // Single-letter shortcuts, digits and Space never fire while typing in a field.
    if (textEntry || event.altKey || loading) return;
    const key = event.key;
    const onPlan = inCanvas(event.target);
    const drafting = tool === 'wall' && pendingWallStart !== null;

    if (key === 'Escape') { cancelPending(); return; }
    if (drafting) {
      if (/^[0-9]$/.test(key) || key === '.') { event.preventDefault(); lengthEntry += key; return; }
      if (key === 'Backspace') { event.preventDefault(); lengthEntry = lengthEntry.slice(0, -1); return; }
      if (key === 'Enter' && (onPlan || onBody(event.target))) {
        event.preventDefault();
        if (lengthEntry) commitTypedLength(); else endChain();
        return;
      }
    }
    if (key === 'Enter' && tool === 'room' && pendingRoom.length >= 3 && (onPlan || onBody(event.target))) { event.preventDefault(); finishRoom(); return; }
    if (letterShortcuts && key === ' ' && !event.repeat && (onPlan || onBody(event.target)) && !(event.target as Element | null)?.closest?.('button, [role="button"], a, summary')) {
      event.preventDefault();
      spaceHeld = true;
      return;
    }
    const nextTool = letterShortcuts ? TOOL_KEYS[key.toLowerCase()] : undefined;
    if (nextTool && !event.repeat && !event.shiftKey) { setTool(nextTool); return; }

    if (!onPlan || !activeFloor) return;
    if ((key === 'Delete' || key === 'Backspace') && selection) {
      event.preventDefault();
      if (selection.kind === 'wall') apply({ type: 'delete_wall', floor_id: activeFloor.floor_id, wall_id: selection.id });
      else if (selection.kind === 'room') apply({ type: 'delete_room', floor_id: activeFloor.floor_id, room_id: selection.id });
      else if (selection.kind === 'placement') apply({ type: 'remove_placement', device_id: selection.id });
      return;
    }
    // Arrows on a plan item that is not the selection browse between items; on the selection they nudge it.
    const itemEl = (event.target as Element | null)?.closest?.('[data-roving]') ?? null;
    const order: Record<string, number> = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };
    if (itemEl && order[key] !== undefined && !event.shiftKey) {
      const here = itemEl.getAttribute('data-roving') ?? '';
      const sel = selection && selection.kind !== 'floor' ? `${selection.kind}:${selection.id}` : null;
      if (here !== sel && rovingKeys.length > 1) {
        event.preventDefault();
        const nextKey = rovingKeys[(rovingKeys.indexOf(here) + order[key]! + rovingKeys.length) % rovingKeys.length]!;
        rovingFocus = nextKey;
        queueMicrotask(() => svgEl?.querySelector<SVGElement>(`[data-roving="${CSS.escape(nextKey)}"]`)?.focus());
        return;
      }
    }
    const step: Record<string, [number, number]> = { ArrowLeft: [-grid, 0], ArrowRight: [grid, 0], ArrowUp: [0, -grid], ArrowDown: [0, grid] };
    const nudge = step[key];
    const current = selection;
    if (!nudge || !current) return;
    if (current.kind === 'placement') {
      const placement = doc.placements.find((candidate) => candidate.device_id === current.id);
      if (!placement) return;
      event.preventDefault();
      dispatch({ type: 'move_placement', device_id: placement.device_id, x: snap(placement.x + nudge[0], grid), y: snap(placement.y + nudge[1], grid) });
    } else if (current.kind === 'wall') {
      const wall = activeFloor.walls.find((candidate) => candidate.wall_id === current.id);
      if (!wall) return;
      event.preventDefault();
      dispatch({
        type: 'move_wall', floor_id: activeFloor.floor_id, wall_id: wall.wall_id, exact: true,
        start: { x: wall.start.x + nudge[0], y: wall.start.y + nudge[1] }, end: { x: wall.end.x + nudge[0], y: wall.end.y + nudge[1] }
      });
    }
  }
  function onWindowKeyup(event: KeyboardEvent) {
    if (event.key === ' ') spaceHeld = false;
  }

  function addFloor() {
    const level = plan.floors.length > 0 ? Math.max(...plan.floors.map((floor) => floor.level)) + 1 : 0;
    const floor_id = newId();
    if (dispatch({ type: 'add_floor', floor_id, level, name: `Floor ${level}`, ceiling_height_m: 2.4 })) activeFloorId = floor_id;
  }

  /** One click: the active floor's walls, openings and rooms on a new floor above, as one undo step. */
  function duplicateFloor() {
    if (!activeFloor) return;
    const source = activeFloor;
    const level = Math.max(...plan.floors.map((floor) => floor.level)) + 1;
    const taken = new Set(plan.floors.map((floor) => floor.name));
    const base = `Copy of ${source.name}`;
    let name = base.slice(0, 64);
    for (let n = 2; taken.has(name); n += 1) name = `${base.slice(0, 64 - ` ${n}`.length)} ${n}`;
    const blank = { floor_id: newId(), level, name, ceiling_height_m: source.ceiling_height_m, walls: [], rooms: [] };
    // An empty floor has no footprint to copy, so it duplicates as a new empty floor of the same height.
    const done = source.walls.length || source.rooms.length
      ? dispatch({ type: 'copy_footprint', floor: copyFloorFootprint(source, blank, newId) })
      : dispatch({ type: 'add_floor', floor_id: blank.floor_id, level, name, ceiling_height_m: blank.ceiling_height_m });
    if (!done) { notice = 'The floor could not be duplicated. A plan holds up to 64 floors.'; return; }
    activeFloorId = blank.floor_id;
    selection = { kind: 'floor' };
    cancelPending();
    roomOfferOpen = false;
    notice = `Duplicated ${source.name} as ${name} (level ${level}). Devices stay on their own floor; Undo removes the copy.`;
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

  // ---- Rendering helpers ----
  const px = (meters: number) => meters * scale;
  const polygonPoints = (points: PlanPoint[]) => points.map((point) => `${px(point.x)},${px(point.y)}`).join(' ');
  /** Walls as drawn: a wall being dragged shows where it will land. */
  function shownEnds(wall: Wall): { start: PlanPoint; end: PlanPoint } {
    const current = drag;
    if (current?.kind === 'handle' && current.wall_id === wall.wall_id) {
      return current.end === 'start' ? { start: current.point, end: wall.end } : { start: wall.start, end: current.point };
    }
    if (current?.kind === 'body' && current.wall_id === wall.wall_id && current.moved) {
      const move = (point: PlanPoint) => ({ x: point.x + current.delta.x, y: point.y + current.delta.y });
      return { start: move(wall.start), end: move(wall.end) };
    }
    return { start: wall.start, end: wall.end };
  }
  const shownSelected = $derived(selectedWall ? shownEnds(selectedWall) : null);
  const typedLength = $derived(parseLengthEntry(lengthEntry));
  const wallPreviewEnd = $derived.by(() => {
    if (tool !== 'wall' || !pendingWallStart) return null;
    if (typedLength !== null) return typedEnd(pendingWallStart, typedLength);
    return cursor?.point ?? null;
  });
  const rectPreviewEnd = $derived(tool === 'rect' && rectStart ? (cursor?.point ?? null) : null);
  const showMarker = $derived(cursor !== null && !panReady && (tool === 'wall' || tool === 'rect' || tool === 'room' || drag?.kind === 'handle') && typedLength === null);
  const readout = $derived.by(() => {
    if (wallPreviewEnd && pendingWallStart) {
      const length = Math.hypot(wallPreviewEnd.x - pendingWallStart.x, wallPreviewEnd.y - pendingWallStart.y);
      const lengthText = lengthEntry ? `${lengthEntry} ${unitSymbol(units)}▏` : formatLength(length, units);
      return { at: wallPreviewEnd, a: lengthText, b: `${angleDegrees(pendingWallStart, wallPreviewEnd)}°` };
    }
    if (rectPreviewEnd && rectStart) {
      const w = Math.abs(rectPreviewEnd.x - rectStart.x);
      const h = Math.abs(rectPreviewEnd.y - rectStart.y);
      return { at: rectPreviewEnd, a: `${formatLength(w, units)} × ${formatLength(h, units)}`, b: formatArea(w * h, units) };
    }
    return null;
  });
  const hint = $derived.by(() => {
    switch (tool) {
      case 'select': return 'Click a wall, room or device to select it, or Tab to the plan and use the arrow keys to move between items; Enter selects, then arrows nudge it. Drag a selected wall’s end handles to reshape it. Delete removes it.';
      case 'pan': return 'Drag to pan the plan. Scroll to zoom at the cursor. Space or the middle mouse button also pans in any tool.';
      case 'wall': return pendingWallStart
        ? 'Click for the next corner, or type a length and press Enter. Click the first point to close the loop. Shift keeps it straight. Esc or Enter finishes.'
        : 'Click to start a wall. It snaps to endpoints, midpoints and walls. Shift keeps it straight (0/45/90°).';
      case 'room': return pendingRoom.length > 0 ? 'Click each corner, then Finish room (or Enter). Esc cancels.' : 'Click the corners of an irregular room. For a plain rectangle use Rectangle.';
      case 'rect': return rectStart ? 'Click the opposite corner. Four walls and the room are added together. Esc cancels.' : 'Click one corner of the room, then the opposite corner. Makes four walls and a room.';
      case 'opening': return `Click a wall to put a ${openingKind} there. Change the kind with the selector.`;
      case 'place': return placingDevice ? `Click the plan to confirm where ${deviceName(placingDevice)} is. Esc cancels.` : 'Pick a device from the tray, then click the plan to place it.';
    }
  });

  const tools: Array<{ id: Tool; label: string; key: string }> = [
    { id: 'select', label: 'Select', key: 'V' }, { id: 'pan', label: 'Pan', key: 'H' }, { id: 'wall', label: 'Wall', key: 'W' },
    { id: 'opening', label: 'Opening', key: 'O' }, { id: 'place', label: 'Place device', key: 'P' },
    { id: 'room', label: 'Room', key: 'R' }, { id: 'rect', label: 'Rectangle', key: 'B' }
  ];
</script>

<svelte:window onkeydown={onWindowKeydown} onkeyup={onWindowKeyup} onbeforeunload={onBeforeUnload} onblur={() => { spaceHeld = false; }} />

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
      <div class="tool-row">
      <div class="tool-palette" role="toolbar" aria-label="Editor tools">
        <label class="opening-kind">Units
          <select aria-label="Measurement units" value={units} onchange={event => { units = event.currentTarget.value as HomeUnits; saveHomeUnits(units); cancelPending(); }}>
            <option value="metric">Metric (meters)</option><option value="imperial">Imperial (feet / inches)</option>
          </select>
        </label>
        {#each tools as entry (entry.id)}
          <button type="button" class:active={tool === entry.id} aria-pressed={tool === entry.id} aria-keyshortcuts={entry.key} title={`${entry.label} (${entry.key})`} onclick={() => setTool(entry.id)}>{entry.label}</button>
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
        <button type="button" class="detect" title="Find closed loops of walls that are not rooms yet" onclick={() => offerRooms(true)}>Detect rooms</button>
      </div>
      <div class="history-actions">
        <button type="button" disabled={!canUndo} onclick={() => dispatch({ type: 'undo' })} aria-keyshortcuts="Control+Z">Undo</button>
        <button type="button" disabled={!canRedo} onclick={() => dispatch({ type: 'redo' })} aria-keyshortcuts="Control+Shift+Z">Redo</button>
        <span class="autosave" role="status">{autosaveLabel}</span>
        <button type="button" class="save" disabled={committing} onclick={() => void saveCommitted()}>Save plan</button>
      </div>
    </div>
    <p class="tool-hint" aria-live="polite">{hint}</p>

    <div class="floor-row">
    <HomeEditorFloorBar {units} floors={plan.floors} active={activeFloor?.floor_id ?? null} onselect={(floorId) => { activeFloorId = floorId; selection = { kind: 'floor' }; cancelPending(); roomOfferOpen = false; }} onadd={addFloor} onduplicate={duplicateFloor} />
      {#if activeFloor}
        <div class="footprint-controls tool-palette" title="Copies walls (with thickness), openings, and rooms. Devices keep their locations.">
          <label class="opening-kind">Copy footprint to
            <select aria-label="Footprint destination" bind:value={copyTarget}>
              <option value="new">New floor above</option>
              {#each copyTargets as floor (floor.floor_id)}<option value={floor.floor_id}>{floor.name}</option>{/each}
            </select>
          </label>
          <button type="button" disabled={!activeFloor.walls.length && !activeFloor.rooms.length} onclick={copyFootprint}>Copy footprint</button>
        </div>
      {/if}
    </div>

    {#if roomOfferOpen && candidates.length > 0}
      <div class="banner offer" role="region" aria-label="Detected rooms">
        <strong>{candidates.length === 1 ? 'A closed room was found.' : `${candidates.length} closed rooms were found.`}</strong>
        <ul class="offer-list">
          {#each candidates as candidate, index (candidateKey(candidate))}
            <li>
              <span class="offer-index">{index + 1}</span>
              <input type="text" maxlength="64" aria-label={`Name for detected room ${index + 1}`} value={roomNameFor(candidate, index)}
                oninput={(event) => { roomNameEdits[candidateKey(candidate)] = event.currentTarget.value; }} />
              <span class="offer-area">{formatArea(candidate.area, units)}</span>
              <button type="button" onclick={() => addCandidate(candidate, index)}>Add</button>
            </li>
          {/each}
        </ul>
        {#if candidates.length > 1}<button type="button" onclick={addAllCandidates}>Add all</button>{/if}
        <button type="button" class="quiet" onclick={() => (roomOfferOpen = false)}>Dismiss</button>
      </div>
    {/if}

    <div class="editor-body">
      <div class="canvas-frame">
        {#if activeFloor}
          <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions, a11y_click_events_have_key_events -->
          <!-- role=application is the ARIA drawing-canvas role; every tool is also reachable through real buttons. -->
          <svg class="plan-canvas" class:pan-ready={panReady} class:panning={drag?.kind === 'pan'} bind:this={svgEl}
            viewBox={viewBox(view, viewSize)} role="application" tabindex="0"
            aria-label={`Floor plan for ${activeFloor.name}. Major grid lines are ${units === 'imperial' ? '1 foot' : '1 meter'} apart. Snap ${units === 'imperial' ? '1 inch' : '0.1 meter'}.`}
            onfocusin={(event) => { rovingFocus = (event.target as Element).closest?.('[data-roving]')?.getAttribute('data-roving') ?? rovingFocus; }} onclick={onCanvasClick} onclickcapture={onClickCapture} onpointerdowncapture={onPointerDownCapture}
            onpointermove={onPointerMove} onpointerup={onPointerUp} onpointercancel={onPointerUp} onpointerleave={onPointerLeave}
            ondragover={(event) => event.preventDefault()} ondrop={onCanvasDrop}>
            <HomePlanGrid {view} size={viewSize} {units} />
            {#each activeFloor.rooms as room (room.room_id)}
              {@const centre = polygonCentroid(room.polygon)}
              <polygon class="room" class:selected={selection?.kind === 'room' && selection.id === room.room_id} data-room-id={room.room_id}
                points={polygonPoints(room.polygon)} role="button" tabindex={rovingKey === `room:${room.room_id}` ? 0 : -1} data-roving={`room:${room.room_id}`} aria-label={`Room ${room.name}`}
                onclick={(event) => onRoomClick(event, room)} onkeydown={(event) => keyActivate(event, () => (selection = { kind: 'room', id: room.room_id }))} />
              <text class="room-label" x={px(centre.x)} y={px(centre.y)}>{room.name}</text>
              <text class="room-area" x={px(centre.x)} y={px(centre.y) + 14}>{formatArea(polygonArea(room.polygon), units)}</text>
            {/each}
            {#each candidates as candidate, index (candidateKey(candidate))}
              <polygon class="candidate" points={polygonPoints(candidate.polygon)} data-candidate={index + 1} />
              <text class="candidate-label" x={px(candidate.centroid.x)} y={px(candidate.centroid.y)}>{index + 1}</text>
            {/each}
            {#each activeFloor.walls as wall (wall.wall_id)}
              {@const ends = shownEnds(wall)}
              <HomePlanWall {wall} start={ends.start} end={ends.end} {scale} tabindex={rovingKey === `wall:${wall.wall_id}` ? 0 : -1} selected={selection?.kind === 'wall' && selection.id === wall.wall_id}
                label={`Wall, ${formatLength(wallLength(wall), units)}`}
                onclick={(event) => onWallClick(event, wall)} onkeydown={(event) => keyActivate(event, () => (selection = { kind: 'wall', id: wall.wall_id }))}
                onpointerdown={(event) => onWallPointerDown(event, wall)} />
            {/each}
            {#if selectedWall && shownSelected}
              <text class="dimension" x={px((shownSelected.start.x + shownSelected.end.x) / 2)} y={px((shownSelected.start.y + shownSelected.end.y) / 2) - 12}>{formatLength(Math.hypot(shownSelected.end.x - shownSelected.start.x, shownSelected.end.y - shownSelected.start.y), units)}</text>
              {#if tool === 'select'}
                <circle class="handle" role="button" tabindex="0" aria-label="Wall start handle" data-handle="start" cx={px(shownSelected.start.x)} cy={px(shownSelected.start.y)} r="6"
                  onpointerdown={(event) => onHandlePointerDown(event, selectedWall, 'start')} onkeydown={(event) => onHandleKeydown(event, selectedWall, 'start')} />
                <circle class="handle" role="button" tabindex="0" aria-label="Wall end handle" data-handle="end" cx={px(shownSelected.end.x)} cy={px(shownSelected.end.y)} r="6"
                  onpointerdown={(event) => onHandlePointerDown(event, selectedWall, 'end')} onkeydown={(event) => onHandleKeydown(event, selectedWall, 'end')} />
              {/if}
            {/if}
            {#each floorPlacements as placement (placement.device_id)}
              <g class="placement" class:selected={selection?.kind === 'placement' && selection.id === placement.device_id} data-device-id={placement.device_id}
                role="button" tabindex={rovingKey === `placement:${placement.device_id}` ? 0 : -1} data-roving={`placement:${placement.device_id}`} aria-label={`${deviceName(placement.device_id)} — owner-placed`}
                onclick={(event) => selectPlacement(event, placement)} onkeydown={(event) => keyActivate(event, () => (selection = { kind: 'placement', id: placement.device_id }))}>
                <circle cx={px(placement.x)} cy={px(placement.y)} r="9" />
                <text x={px(placement.x)} y={px(placement.y) - 14}>{deviceName(placement.device_id)}</text>
              </g>
            {/each}
            {#if pendingRoom.length > 0}
              <polyline class="pending-room" points={polygonPoints(cursor ? [...pendingRoom, cursor.point] : pendingRoom)} />
            {/if}
            {#if pendingWallStart}
              {#if wallPreviewEnd}
                <line class="preview-wall" x1={px(pendingWallStart.x)} y1={px(pendingWallStart.y)} x2={px(wallPreviewEnd.x)} y2={px(wallPreviewEnd.y)} stroke-width={Math.max(2, DEFAULT_THICKNESS_M * scale)} />
              {/if}
              <circle class="pending-start" cx={px(pendingWallStart.x)} cy={px(pendingWallStart.y)} r="5" />
            {/if}
            {#if rectStart}
              {#if rectPreviewEnd}
                <rect class="preview-rect" x={px(Math.min(rectStart.x, rectPreviewEnd.x))} y={px(Math.min(rectStart.y, rectPreviewEnd.y))}
                  width={px(Math.abs(rectPreviewEnd.x - rectStart.x))} height={px(Math.abs(rectPreviewEnd.y - rectStart.y))} />
              {/if}
              <circle class="pending-start" cx={px(rectStart.x)} cy={px(rectStart.y)} r="5" />
            {/if}
            {#if showMarker && cursor}
              {@const labelFlip = px(cursor.point.x) - originPx.x > viewSize.width - 100}
              {#if cursor.guides.x !== null}
                <line class="guide" x1={px(cursor.guides.x)} y1={originPx.y} x2={px(cursor.guides.x)} y2={originPx.y + viewSize.height} />
              {/if}
              {#if cursor.guides.y !== null}
                <line class="guide" x1={originPx.x} y1={px(cursor.guides.y)} x2={originPx.x + viewSize.width} y2={px(cursor.guides.y)} />
              {/if}
              <g class={`snap-marker snap-${cursor.kind}`} data-snap-kind={cursor.kind} transform={`translate(${px(cursor.point.x)} ${px(cursor.point.y)})`}>
                {#if cursor.kind === 'endpoint'}<rect x="-7" y="-7" width="14" height="14" />
                {:else if cursor.kind === 'midpoint'}<path d="M0 -8 L8 6 L-8 6 Z" />
                {:else if cursor.kind === 'on-wall'}<path d="M0 -8 L8 0 L0 8 L-8 0 Z" />
                {:else if cursor.kind === 'guide'}<path d="M-7 -7 L7 7 M7 -7 L-7 7" />
                {:else}<path d="M-6 0 H6 M0 -6 V6" />{/if}
                <text class="snap-label" x={labelFlip ? -11 : 11} y="19" text-anchor={labelFlip ? 'end' : 'start'}>{cursor.label}</text>
              </g>
            {/if}
            {#if readout}
              {@const flip = px(readout.at.x) - originPx.x > viewSize.width - 150}
              <text class="readout" x={px(readout.at.x) + (flip ? -14 : 14)} y={px(readout.at.y) - 14} text-anchor={flip ? 'end' : 'start'}>
                <tspan class="readout-length">{readout.a}</tspan><tspan class="readout-angle" dx="8">{readout.b}</tspan>
              </text>
            {/if}
            <g class="scale-bar" transform={`translate(${originPx.x + 16} ${originPx.y + viewSize.height - 22})`} aria-hidden="true">
              <path d={`M0 -5 V0 H${bar.px} V-5`} />
              <text x="0" y="-9">{bar.label}</text>
            </g>
          </svg>
          <div class="view-controls" role="toolbar" aria-label="Plan view">
            <button type="button" onclick={() => zoomBy(1 / 1.25)}>Zoom out</button>
            <span class="zoom-readout" aria-label="Current zoom">{Math.round(scale)} px/m</span>
            <button type="button" onclick={() => zoomBy(1.25)}>Zoom in</button>
            <button type="button" onclick={fitPlan}>Fit plan</button>
            <button type="button" onclick={actualSize}>100%</button>
          </div>
        {:else}
          <div class="editor-state">This home has no floors yet. Add a floor to start drawing.
            <button type="button" onclick={addFloor}>Add floor</button>
          </div>
        {/if}
      </div>
      <div class="side-panel">
        {#if target}
          <HomeEditorInspector {target} {units} onaction={apply} onclose={() => (selection = null)} />
        {/if}
        <HomeEditorTray {unplaced} placing={placingDevice} estimated={estimatedRows} onpick={armPlacement} />
      </div>
    </div>
  {/if}
</section>

<style>
  .view-heading h1{font-size:clamp(26px,2.6vw,36px);line-height:1.1;margin:2px 0 4px}
  .view-heading .muted{margin:0}
  .footprint-controls{gap:8px;margin-left:auto}
  .footprint-controls button{min-height:38px!important;padding:6px 12px!important}
  .floor-row{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;margin:10px 0}
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
  .banner.offer{border-color:var(--accent);margin:0 0 12px}
  .banner.offer strong{color:var(--accent)}
  .offer-list{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:8px}
  .offer-list li{display:flex;gap:8px;align-items:center;padding:4px 6px;border:1px solid var(--line-strong);border-radius:6px}
  .offer-index{display:grid;place-items:center;width:20px;height:20px;border-radius:50%;background:var(--accent);color:var(--accent-ink);font:700 11px var(--font-mono)}
  .offer-list input{min-height:34px;width:130px;padding:4px 8px;border:1px solid var(--line-strong);border-radius:5px;background:#0e2430;color:var(--ink);font:13px var(--font-display)}
  .offer-area{color:var(--muted-strong);font:11px var(--font-mono)}
  .editor-toolbar{display:flex;flex-wrap:wrap;gap:8px 14px;justify-content:space-between;align-items:center;margin:14px 0 0}
  .tool-row{display:flex;flex-wrap:wrap;gap:7px;align-items:center}
  .tool-row .detect{min-height:40px;padding:7px 12px;border:1px solid var(--accent);border-radius:5px;background:transparent;color:var(--accent);font:600 12px var(--font-display);cursor:pointer}
  .tool-hint{margin:8px 0 0;padding:8px 12px;border-left:2px solid var(--accent);background:var(--surface);color:var(--muted-strong);font:12px/1.5 var(--font-display)}
  .tool-palette{display:flex;flex-wrap:wrap;gap:7px;align-items:center}
  .tool-palette button{min-height:40px;padding:7px 12px;border:1px solid var(--line-strong);border-radius:5px;background:transparent;color:var(--ink);font:600 12px var(--font-display);cursor:pointer}
  .tool-palette button.active{border-color:var(--accent);color:var(--accent);box-shadow:inset 0 0 14px var(--accent)14}
  .tool-palette button.finish{border-color:var(--accent);color:var(--accent-ink);background:var(--accent)}
  .tool-palette button.quiet{border-color:var(--line-strong);color:var(--muted-strong)}
  .tool-palette button:disabled{opacity:.4;cursor:not-allowed}
  .opening-kind{display:flex;gap:7px;align-items:center;color:var(--muted-strong);font:10px var(--font-mono);text-transform:uppercase}
  .opening-kind select{min-height:38px;padding:6px 8px;border:1px solid var(--line-strong);border-radius:5px;background:#0e2430;color:var(--ink);font:12px var(--font-display)}
  .placing-hint{color:var(--accent);font:11px var(--font-mono)}
  .history-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  .history-actions button{min-height:40px;padding:7px 12px;border:1px solid var(--line-strong);border-radius:5px;background:transparent;color:var(--ink);font:600 12px var(--font-display);cursor:pointer}
  .history-actions button:disabled{opacity:.4;cursor:not-allowed}
  .history-actions button.save{border-color:var(--accent);background:var(--accent);color:var(--accent-ink)}
  .autosave{color:var(--muted-strong);font:10px var(--font-mono);text-transform:uppercase;letter-spacing:.07em}
  .view-controls{position:absolute;top:10px;right:10px;z-index:2;display:flex;flex-wrap:wrap;gap:6px;align-items:center;padding:6px;border:1px solid var(--line-strong);border-radius:10px;background:rgba(8,23,34,.72);backdrop-filter:blur(10px) saturate(1.2);box-shadow:0 6px 24px rgba(0,0,0,.35)}
  .view-controls button{min-height:34px;padding:4px 10px;border:1px solid var(--line-strong);border-radius:6px;background:transparent;color:var(--ink);font:600 12px var(--font-display);cursor:pointer}
  .view-controls button:hover{border-color:var(--accent);color:var(--accent)}
  .zoom-readout{min-width:64px;text-align:center;color:var(--muted-strong);font:11px var(--font-mono)}
  .editor-body{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:16px;align-items:start;margin-top:4px}
  .canvas-frame{position:relative;overflow:hidden;height:max(560px,min(72vh,720px));border:1px solid var(--line-mid);border-radius:10px;background:var(--bg)}
  .canvas-frame .editor-state{margin:0;height:100%}
  .plan-canvas{--plan-bg:#081722;display:block;width:100%;height:100%;background:var(--plan-bg);outline:none;touch-action:none;user-select:none}
  .plan-canvas:focus-visible{box-shadow:inset 0 0 0 2px var(--accent)}
  .plan-canvas.pan-ready{cursor:grab}
  .plan-canvas.panning{cursor:grabbing}
  .room{fill:#123641;fill-opacity:.55;stroke:var(--line-strong);stroke-width:1.5;cursor:pointer}
  .room.selected{stroke:var(--accent);stroke-width:2;fill-opacity:.75}
  .room-label{fill:var(--ink);font:600 11px var(--font-mono);text-anchor:middle;pointer-events:none}
  .room-area{fill:var(--muted-strong);font:10px var(--font-mono);text-anchor:middle;pointer-events:none}
  .candidate{fill:var(--accent);fill-opacity:.12;stroke:var(--accent);stroke-width:2;stroke-dasharray:6 4;pointer-events:none}
  .candidate-label{fill:var(--accent);font:700 14px var(--font-mono);text-anchor:middle;dominant-baseline:middle;pointer-events:none}
  .dimension{fill:var(--accent);font:700 12px var(--font-mono);text-anchor:middle;pointer-events:none;paint-order:stroke;stroke:var(--plan-bg);stroke-width:3px}
  .handle{fill:var(--plan-bg);stroke:var(--accent);stroke-width:2;cursor:grab}
  .handle:hover,.handle:focus-visible{fill:var(--accent);outline:none;stroke:var(--ink);stroke-width:3}
  .placement{cursor:pointer}
  .placement circle{fill:#0e2430;stroke:var(--accent);stroke-width:2}
  .placement.selected circle{fill:var(--accent)}
  .placement text{fill:var(--ink);font:10px var(--font-mono);text-anchor:middle;pointer-events:none}
  .pending-start{fill:var(--accent);pointer-events:none}
  .pending-room{fill:none;stroke:var(--accent);stroke-dasharray:5 4;stroke-width:1.5;pointer-events:none}
  .preview-wall{stroke:var(--accent);stroke-opacity:.6;stroke-linecap:square;pointer-events:none}
  .preview-rect{fill:var(--accent);fill-opacity:.08;stroke:var(--accent);stroke-width:1.5;stroke-dasharray:5 4;pointer-events:none}
  .guide{stroke:var(--gold);stroke-width:1;stroke-dasharray:4 4;opacity:.8;pointer-events:none}
  .snap-marker{fill:none;stroke:var(--gold);stroke-width:2;pointer-events:none}
  .snap-marker.snap-endpoint{stroke:var(--accent)}
  .snap-marker.snap-grid{stroke:var(--muted-strong);stroke-width:1.5}
  .snap-label{fill:var(--ink);stroke:var(--plan-bg);stroke-width:3px;paint-order:stroke;font:600 10px var(--font-mono);text-transform:uppercase;letter-spacing:.05em}
  .readout{fill:var(--ink);font:700 12px var(--font-mono);paint-order:stroke;stroke:var(--plan-bg);stroke-width:4px;pointer-events:none}
  .readout-angle{fill:var(--gold)}
  .scale-bar{pointer-events:none}
  .scale-bar path{fill:none;stroke:var(--muted-strong);stroke-width:1.5}
  .scale-bar text{fill:var(--muted-strong);font:10px var(--font-mono)}
  .side-panel{display:grid;grid-template-columns:minmax(0,1fr);gap:14px;align-content:start;min-width:0}
  @media(max-width:1000px){.editor-body{grid-template-columns:1fr}.side-panel{grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}}
</style>
