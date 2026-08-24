// Home Twin 2D plan editor store (M5 · H2, H3, H4, H11).
// Types mirror docs/architecture/m5-home-twin-contracts.md exactly (snake_case wire shape).

// ---- Contract types ----
export interface PlanPoint { x: number; y: number }
export type OpeningKind = 'door' | 'window' | 'stair';
export interface Opening { opening_id: string; kind: OpeningKind; offset_m: number; width_m: number }
export interface Wall { wall_id: string; start: PlanPoint; end: PlanPoint; openings: Opening[] }
export interface Room { room_id: string; name: string; polygon: PlanPoint[] }
export interface Floor { floor_id: string; level: number; name: string; ceiling_height_m: number; walls: Wall[]; rooms: Room[] }
export interface HomePlan { home_id: string; version: number; name: string; floors: Floor[] }
export type Mounting = 'wall' | 'ceiling' | 'floor' | 'shelf' | null;
export interface Placement { placement_id: string; device_id: string; floor_id: string; x: number; y: number; height_m: number; mounting: Mounting }
export interface Estimate { device_id: string; floor_id: string | null; room_id: string | null; confidence: number; evidence: string[]; estimated_at: string }
export interface HomeDeviceRef { device_id: string; name: string | null }
export interface HomeSnapshot { plan: HomePlan; placements: Placement[]; estimates: Estimate[] }

export const GRID_M = 0.1;
export const MIN_CEILING_M = 1.8;
export const MAX_CEILING_M = 6.0;
export const HISTORY_LIMIT = 200;
export const UNCERTAIN_BELOW = 0.6;
export const DRAFT_MAX_BYTES = 512 * 1024;
const MAX_COORDINATE_M = 10_000;
const EPSILON = 1e-6;

// ---- Geometry ----
export function snap(value: number): number { return Number((Math.round(value / GRID_M) * GRID_M).toFixed(1)); }
export function snapPoint(point: PlanPoint): PlanPoint { return { x: snap(point.x), y: snap(point.y) }; }
export function wallLength(wall: Pick<Wall, 'start' | 'end'>): number { return Math.hypot(wall.end.x - wall.start.x, wall.end.y - wall.start.y); }
const samePoint = (a: PlanPoint, b: PlanPoint) => Math.abs(a.x - b.x) < EPSILON && Math.abs(a.y - b.y) < EPSILON;

export function openingFits(wall: Pick<Wall, 'start' | 'end'>, opening: Pick<Opening, 'offset_m' | 'width_m'>): boolean {
  return opening.offset_m >= 0 && opening.width_m > 0 && opening.offset_m + opening.width_m <= wallLength(wall) + EPSILON;
}

// ---- Editor model (pure reducer; every rule unit-testable) ----
export interface EditorDoc { plan: HomePlan; placements: Placement[] }
export interface EditorState { doc: EditorDoc; past: EditorDoc[]; future: EditorDoc[] }

export function emptyHomePlan(): HomePlan { return { home_id: '00000000-0000-0000-0000-000000000000', version: 0, name: 'Home', floors: [] }; }
export function createEditorState(plan: HomePlan, placements: Placement[]): EditorState {
  return { doc: { plan, placements }, past: [], future: [] };
}

export type EditorAction =
  | { type: 'add_wall'; floor_id: string; wall_id: string; start: PlanPoint; end: PlanPoint }
  | { type: 'move_wall'; floor_id: string; wall_id: string; start: PlanPoint; end: PlanPoint }
  | { type: 'delete_wall'; floor_id: string; wall_id: string }
  | { type: 'split_wall'; floor_id: string; wall_id: string; at: PlanPoint; new_wall_id: string }
  | { type: 'add_opening'; floor_id: string; wall_id: string; opening: Opening }
  | { type: 'delete_opening'; floor_id: string; wall_id: string; opening_id: string }
  | { type: 'add_room'; floor_id: string; room_id: string; name: string; polygon: PlanPoint[] }
  | { type: 'rename_room'; floor_id: string; room_id: string; name: string }
  | { type: 'delete_room'; floor_id: string; room_id: string }
  | { type: 'add_floor'; floor_id: string; level: number; name: string; ceiling_height_m: number }
  | { type: 'rename_floor'; floor_id: string; name: string }
  | { type: 'set_ceiling_height'; floor_id: string; ceiling_height_m: number }
  | { type: 'delete_floor'; floor_id: string }
  | { type: 'place_device'; placement: Placement }
  | { type: 'move_placement'; device_id: string; x: number; y: number }
  | { type: 'configure_placement'; device_id: string; height_m?: number; mounting?: Mounting }
  | { type: 'remove_placement'; device_id: string }
  | { type: 'undo' }
  | { type: 'redo' };

const validName = (name: string) => name.trim().length > 0 && name.length <= 64;
const validCoordinate = (value: number) => Number.isFinite(value) && Math.abs(value) <= MAX_COORDINATE_M;
const validPoint = (point: PlanPoint) => validCoordinate(point.x) && validCoordinate(point.y);
const validCeiling = (value: number) => Number.isFinite(value) && value >= MIN_CEILING_M && value <= MAX_CEILING_M;

function withFloor(doc: EditorDoc, floorId: string, edit: (floor: Floor) => Floor | null): EditorDoc | null {
  const floor = doc.plan.floors.find((candidate) => candidate.floor_id === floorId);
  if (!floor) return null;
  const next = edit(floor);
  if (!next) return null;
  return { ...doc, plan: { ...doc.plan, floors: doc.plan.floors.map((candidate) => (candidate.floor_id === floorId ? next : candidate)) } };
}

function withWall(doc: EditorDoc, floorId: string, wallId: string, edit: (wall: Wall, floor: Floor) => Wall[] | null): EditorDoc | null {
  return withFloor(doc, floorId, (floor) => {
    const wall = floor.walls.find((candidate) => candidate.wall_id === wallId);
    if (!wall) return null;
    const replacement = edit(wall, floor);
    if (!replacement) return null;
    return { ...floor, walls: floor.walls.flatMap((candidate) => (candidate.wall_id === wallId ? replacement : [candidate])) };
  });
}

function applyEdit(doc: EditorDoc, action: Exclude<EditorAction, { type: 'undo' } | { type: 'redo' }>): EditorDoc | null {
  switch (action.type) {
    case 'add_wall': {
      if (!validPoint(action.start) || !validPoint(action.end)) return null;
      const start = snapPoint(action.start);
      const end = snapPoint(action.end);
      if (samePoint(start, end)) return null;
      return withFloor(doc, action.floor_id, (floor) => ({ ...floor, walls: [...floor.walls, { wall_id: action.wall_id, start, end, openings: [] }] }));
    }
    case 'move_wall': {
      if (!validPoint(action.start) || !validPoint(action.end)) return null;
      const start = snapPoint(action.start);
      const end = snapPoint(action.end);
      if (samePoint(start, end)) return null;
      // Openings that no longer fit the moved wall are removed with the move (undo restores them).
      return withWall(doc, action.floor_id, action.wall_id, (wall) => {
        const moved = { ...wall, start, end };
        return [{ ...moved, openings: wall.openings.filter((opening) => openingFits(moved, opening)) }];
      });
    }
    case 'delete_wall':
      return withWall(doc, action.floor_id, action.wall_id, () => []);
    case 'split_wall': {
      if (!validPoint(action.at)) return null;
      return withWall(doc, action.floor_id, action.wall_id, (wall) => {
        const length = wallLength(wall);
        if (length < EPSILON) return null;
        const t = ((action.at.x - wall.start.x) * (wall.end.x - wall.start.x) + (action.at.y - wall.start.y) * (wall.end.y - wall.start.y)) / (length * length);
        const split = snapPoint({ x: wall.start.x + t * (wall.end.x - wall.start.x), y: wall.start.y + t * (wall.end.y - wall.start.y) });
        if (samePoint(split, wall.start) || samePoint(split, wall.end)) return null;
        const distance = Math.hypot(split.x - wall.start.x, split.y - wall.start.y);
        // A split landing inside an opening is rejected rather than truncating it.
        if (wall.openings.some((opening) => opening.offset_m < distance - EPSILON && opening.offset_m + opening.width_m > distance + EPSILON)) return null;
        const first: Wall = { ...wall, end: split, openings: wall.openings.filter((opening) => opening.offset_m + opening.width_m <= distance + EPSILON) };
        const second: Wall = {
          wall_id: action.new_wall_id, start: split, end: wall.end,
          openings: wall.openings.filter((opening) => opening.offset_m >= distance - EPSILON).map((opening) => ({ ...opening, offset_m: snap(opening.offset_m - distance) }))
        };
        return [first, second];
      });
    }
    case 'add_opening': {
      const opening = { ...action.opening, offset_m: snap(action.opening.offset_m), width_m: snap(action.opening.width_m) };
      return withWall(doc, action.floor_id, action.wall_id, (wall) => (openingFits(wall, opening) ? [{ ...wall, openings: [...wall.openings, opening] }] : null));
    }
    case 'delete_opening':
      return withWall(doc, action.floor_id, action.wall_id, (wall) => {
        if (!wall.openings.some((opening) => opening.opening_id === action.opening_id)) return null;
        return [{ ...wall, openings: wall.openings.filter((opening) => opening.opening_id !== action.opening_id) }];
      });
    case 'add_room': {
      if (!validName(action.name) || action.polygon.length < 3 || !action.polygon.every(validPoint)) return null;
      const polygon = action.polygon.map(snapPoint);
      return withFloor(doc, action.floor_id, (floor) => ({ ...floor, rooms: [...floor.rooms, { room_id: action.room_id, name: action.name.trim(), polygon }] }));
    }
    case 'rename_room': {
      if (!validName(action.name)) return null;
      return withFloor(doc, action.floor_id, (floor) => {
        const room = floor.rooms.find((candidate) => candidate.room_id === action.room_id);
        if (!room || room.name === action.name.trim()) return null;
        return { ...floor, rooms: floor.rooms.map((candidate) => (candidate.room_id === action.room_id ? { ...candidate, name: action.name.trim() } : candidate)) };
      });
    }
    case 'delete_room':
      return withFloor(doc, action.floor_id, (floor) => {
        if (!floor.rooms.some((room) => room.room_id === action.room_id)) return null;
        return { ...floor, rooms: floor.rooms.filter((room) => room.room_id !== action.room_id) };
      });
    case 'add_floor': {
      if (!validName(action.name) || !validCeiling(action.ceiling_height_m) || !Number.isSafeInteger(action.level)) return null;
      if (doc.plan.floors.some((floor) => floor.level === action.level)) return null;
      const floor: Floor = { floor_id: action.floor_id, level: action.level, name: action.name.trim(), ceiling_height_m: action.ceiling_height_m, walls: [], rooms: [] };
      return { ...doc, plan: { ...doc.plan, floors: [...doc.plan.floors, floor].sort((a, b) => a.level - b.level) } };
    }
    case 'rename_floor':
      if (!validName(action.name)) return null;
      return withFloor(doc, action.floor_id, (floor) => (floor.name === action.name.trim() ? null : { ...floor, name: action.name.trim() }));
    case 'set_ceiling_height':
      if (!validCeiling(action.ceiling_height_m)) return null;
      return withFloor(doc, action.floor_id, (floor) => (floor.ceiling_height_m === action.ceiling_height_m ? null : { ...floor, ceiling_height_m: action.ceiling_height_m }));
    case 'delete_floor': {
      if (doc.plan.floors.length <= 1) return null;
      if (!doc.plan.floors.some((floor) => floor.floor_id === action.floor_id)) return null;
      // A floor with owner placements is kept; the owner removes or moves them first.
      if (doc.placements.some((placement) => placement.floor_id === action.floor_id)) return null;
      return { ...doc, plan: { ...doc.plan, floors: doc.plan.floors.filter((floor) => floor.floor_id !== action.floor_id) } };
    }
    case 'place_device': {
      const raw = action.placement;
      const floor = doc.plan.floors.find((candidate) => candidate.floor_id === raw.floor_id);
      if (!floor || !validPoint(raw) || !Number.isFinite(raw.height_m) || raw.height_m < 0 || raw.height_m > floor.ceiling_height_m) return null;
      const placement: Placement = { ...raw, x: snap(raw.x), y: snap(raw.y) };
      const existing = doc.placements.find((candidate) => candidate.device_id === placement.device_id);
      const placements = existing
        ? doc.placements.map((candidate) => (candidate.device_id === placement.device_id ? { ...placement, placement_id: existing.placement_id } : candidate))
        : [...doc.placements, placement];
      return { ...doc, placements };
    }
    case 'move_placement': {
      const placement = doc.placements.find((candidate) => candidate.device_id === action.device_id);
      if (!placement || !validCoordinate(action.x) || !validCoordinate(action.y)) return null;
      const x = snap(action.x);
      const y = snap(action.y);
      if (placement.x === x && placement.y === y) return null;
      return { ...doc, placements: doc.placements.map((candidate) => (candidate.device_id === action.device_id ? { ...candidate, x, y } : candidate)) };
    }
    case 'configure_placement': {
      const placement = doc.placements.find((candidate) => candidate.device_id === action.device_id);
      if (!placement) return null;
      const floor = doc.plan.floors.find((candidate) => candidate.floor_id === placement.floor_id);
      const height_m = action.height_m ?? placement.height_m;
      const mounting = action.mounting === undefined ? placement.mounting : action.mounting;
      if (!floor || !Number.isFinite(height_m) || height_m < 0 || height_m > floor.ceiling_height_m) return null;
      if (height_m === placement.height_m && mounting === placement.mounting) return null;
      return { ...doc, placements: doc.placements.map((candidate) => (candidate.device_id === action.device_id ? { ...candidate, height_m, mounting } : candidate)) };
    }
    case 'remove_placement': {
      if (!doc.placements.some((candidate) => candidate.device_id === action.device_id)) return null;
      return { ...doc, placements: doc.placements.filter((candidate) => candidate.device_id !== action.device_id) };
    }
  }
}

export function reduceEditor(state: EditorState, action: EditorAction): EditorState {
  if (action.type === 'undo') {
    const previous = state.past.at(-1);
    if (!previous) return state;
    return { doc: previous, past: state.past.slice(0, -1), future: [state.doc, ...state.future] };
  }
  if (action.type === 'redo') {
    const [next, ...future] = state.future;
    if (!next) return state;
    return { doc: next, past: [...state.past, state.doc], future };
  }
  const doc = applyEdit(state.doc, action);
  if (!doc) return state;
  const past = [...state.past, state.doc];
  while (past.length > HISTORY_LIMIT) past.shift();
  return { doc, past, future: [] };
}

// ---- Selectors (H4 tray, H11 uncertain prompt) ----
export function selectUnplaced(devices: HomeDeviceRef[], placements: Placement[]): HomeDeviceRef[] {
  const placed = new Set(placements.map((placement) => placement.device_id));
  return devices.filter((device) => !placed.has(device.device_id));
}

export function selectUncertain(devices: HomeDeviceRef[], placements: Placement[], estimates: Estimate[]): Array<{ device: HomeDeviceRef; estimate: Estimate }> {
  const placed = new Set(placements.map((placement) => placement.device_id));
  const byId = new Map(devices.map((device) => [device.device_id, device]));
  return estimates
    .filter((estimate) => !placed.has(estimate.device_id) && estimate.confidence < UNCERTAIN_BELOW)
    .map((estimate) => ({ device: byId.get(estimate.device_id) ?? { device_id: estimate.device_id, name: null }, estimate }));
}

// ---- Wire validation ----
function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null; }
const isOpaqueId = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
const utcRfc3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const isDate = (value: unknown): value is string => typeof value === 'string' && utcRfc3339.test(value) && !Number.isNaN(new Date(value).valueOf());
const isCoordinate = (value: unknown): value is number => typeof value === 'number' && validCoordinate(value);
const isConfidence = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;
const openingKinds = new Set(['door', 'window', 'stair']);
const mountings = new Set(['wall', 'ceiling', 'floor', 'shelf']);

function isPoint(value: unknown): value is PlanPoint { return isRecord(value) && isCoordinate(value.x) && isCoordinate(value.y); }
function isOpening(value: unknown): value is Opening {
  return isRecord(value) && isOpaqueId(value.opening_id) && typeof value.kind === 'string' && openingKinds.has(value.kind)
    && isCoordinate(value.offset_m) && value.offset_m >= 0 && isCoordinate(value.width_m) && value.width_m > 0;
}
function isWall(value: unknown): value is Wall {
  return isRecord(value) && isOpaqueId(value.wall_id) && isPoint(value.start) && isPoint(value.end)
    && Array.isArray(value.openings) && value.openings.length <= 64 && value.openings.every(isOpening)
    && value.openings.every((opening) => openingFits({ start: (value as unknown as Wall).start, end: (value as unknown as Wall).end }, opening as Opening));
}
function isRoom(value: unknown): value is Room {
  return isRecord(value) && isOpaqueId(value.room_id) && typeof value.name === 'string' && value.name.length > 0 && value.name.length <= 64
    && Array.isArray(value.polygon) && value.polygon.length >= 3 && value.polygon.length <= 256 && value.polygon.every(isPoint);
}
function isFloor(value: unknown): value is Floor {
  return isRecord(value) && isOpaqueId(value.floor_id) && Number.isSafeInteger(value.level) && Math.abs(value.level as number) <= 100
    && typeof value.name === 'string' && value.name.length > 0 && value.name.length <= 64
    && typeof value.ceiling_height_m === 'number' && validCeiling(value.ceiling_height_m)
    && Array.isArray(value.walls) && value.walls.length <= 2048 && value.walls.every(isWall)
    && Array.isArray(value.rooms) && value.rooms.length <= 256 && value.rooms.every(isRoom);
}
export function isHomePlan(value: unknown): value is HomePlan {
  return isRecord(value) && isOpaqueId(value.home_id) && Number.isSafeInteger(value.version) && (value.version as number) >= 0
    && typeof value.name === 'string' && value.name.length > 0 && value.name.length <= 64
    && Array.isArray(value.floors) && value.floors.length <= 64 && value.floors.every(isFloor);
}
export function isPlacement(value: unknown): value is Placement {
  return isRecord(value) && isOpaqueId(value.placement_id) && isOpaqueId(value.device_id) && isOpaqueId(value.floor_id)
    && isCoordinate(value.x) && isCoordinate(value.y)
    && typeof value.height_m === 'number' && Number.isFinite(value.height_m) && value.height_m >= 0 && value.height_m <= MAX_CEILING_M
    && (value.mounting === null || (typeof value.mounting === 'string' && mountings.has(value.mounting)));
}
export function isEstimate(value: unknown): value is Estimate {
  return isRecord(value) && isOpaqueId(value.device_id)
    && (value.floor_id === null || isOpaqueId(value.floor_id)) && (value.room_id === null || isOpaqueId(value.room_id))
    && isConfidence(value.confidence) && Array.isArray(value.evidence) && value.evidence.length <= 32
    && value.evidence.every((entry) => typeof entry === 'string' && entry.length > 0 && entry.length <= 128)
    && isDate(value.estimated_at);
}
function isHomeSnapshot(value: unknown): value is HomeSnapshot {
  return isRecord(value) && isHomePlan(value.plan)
    && Array.isArray(value.placements) && value.placements.length <= 4096 && value.placements.every(isPlacement)
    && Array.isArray(value.estimates) && value.estimates.length <= 4096 && value.estimates.every(isEstimate);
}

// ---- API glue (loopback service; bearer-authenticated like every other route) ----
export interface HomeDraft { plan: HomePlan; saved_at: string }
export type SavePlanResult = { status: 'saved'; version: number } | { status: 'conflict' };
export type DraftResult = { status: 'none' } | { status: 'draft'; draft: HomeDraft } | { status: 'corrupt' };

export interface HomeApi {
  fetchHome(): Promise<HomeSnapshot>;
  savePlan(plan: HomePlan, expectedVersion: number): Promise<SavePlanResult>;
  saveDraft(draft: HomeDraft): Promise<void>;
  loadDraft(): Promise<DraftResult>;
  deleteDraft(): Promise<void>;
  putPlacement(placement: Placement): Promise<void>;
  deletePlacement(deviceId: string): Promise<void>;
}

export interface HomeApiOptions { baseUrl: string; serviceToken: string; fetchImpl?: typeof fetch }

export function createHomeApi({ baseUrl, serviceToken, fetchImpl = fetch }: HomeApiOptions): HomeApi {
  const apiUrl = (path: string) => new URL(path, baseUrl).toString();
  const authorized = (method: string, body?: unknown): RequestInit => ({
    method,
    headers: body === undefined
      ? { Authorization: `Bearer ${serviceToken}` }
      : { Authorization: `Bearer ${serviceToken}`, 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });

  async function fetchHome(): Promise<HomeSnapshot> {
    const response = await fetchImpl(apiUrl('/api/v1/home'), authorized('GET'));
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
    const value: unknown = await response.json();
    if (!isHomeSnapshot(value)) throw new Error('Invalid home response');
    return value;
  }

  async function savePlan(plan: HomePlan, expectedVersion: number): Promise<SavePlanResult> {
    if (!isHomePlan(plan) || !Number.isSafeInteger(expectedVersion) || expectedVersion < 0) throw new Error('Invalid plan save');
    const response = await fetchImpl(apiUrl('/api/v1/home/plan'), authorized('PUT', { expected_version: expectedVersion, plan }));
    if (response.status === 409) return { status: 'conflict' };
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
    let version = expectedVersion + 1;
    try {
      const body: unknown = await response.json();
      if (isRecord(body) && Number.isSafeInteger(body.version) && (body.version as number) >= 0) version = body.version as number;
      else if (isRecord(body) && isHomePlan(body.plan)) version = body.plan.version;
    } catch { /* An empty save response keeps the locally computed next version. */ }
    return { status: 'saved', version };
  }

  async function saveDraft(draft: HomeDraft): Promise<void> {
    const body = JSON.stringify(draft);
    if (new TextEncoder().encode(body).length > DRAFT_MAX_BYTES) throw new Error('Draft exceeds safety bound');
    const response = await fetchImpl(apiUrl('/api/v1/home/draft'), { method: 'PUT', headers: { Authorization: `Bearer ${serviceToken}`, 'content-type': 'application/json' }, body });
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
  }

  async function deleteDraft(): Promise<void> {
    const response = await fetchImpl(apiUrl('/api/v1/home/draft'), authorized('DELETE'));
    if (!response.ok && response.status !== 404) throw new Error(`Request failed with status ${response.status}`);
  }

  async function loadDraft(): Promise<DraftResult> {
    const response = await fetchImpl(apiUrl('/api/v1/home/draft'), authorized('GET'));
    if (response.status === 404) return { status: 'none' };
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
    const text = await response.text();
    let draft: unknown = null;
    if (text.length <= DRAFT_MAX_BYTES) {
      try { draft = JSON.parse(text); } catch { draft = null; }
    }
    if (isRecord(draft) && isHomePlan(draft.plan) && isDate(draft.saved_at)) return { status: 'draft', draft: { plan: draft.plan, saved_at: draft.saved_at } };
    // H3: a draft that fails validation is reported corrupt and discarded — never silently merged.
    try { await deleteDraft(); } catch { /* Discard is best-effort; the committed plan remains the truth. */ }
    return { status: 'corrupt' };
  }

  async function putPlacement(placement: Placement): Promise<void> {
    if (!isPlacement(placement)) throw new Error('Invalid placement');
    const response = await fetchImpl(apiUrl(`/api/v1/home/placements/${placement.device_id}`), authorized('PUT', placement));
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
  }

  async function deletePlacement(deviceId: string): Promise<void> {
    if (!isOpaqueId(deviceId)) throw new Error('Invalid placement');
    const response = await fetchImpl(apiUrl(`/api/v1/home/placements/${deviceId}`), authorized('DELETE'));
    if (!response.ok && response.status !== 404) throw new Error(`Request failed with status ${response.status}`);
  }

  return { fetchHome, savePlan, saveDraft, loadDraft, deleteDraft, putPlacement, deletePlacement };
}
