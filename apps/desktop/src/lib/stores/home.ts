// Home Twin 2D plan editor store (M5 · H2, H3, H4, H11).
// Types mirror docs/architecture/m5-home-twin-contracts.md exactly (snake_case wire shape).

import type { AuthSource } from '../api/client';

// ---- Contract types ----
export interface PlanPoint { x: number; y: number }
export type OpeningKind = 'door' | 'window' | 'stair';
export interface Opening { opening_id: string; kind: OpeningKind; offset_m: number; width_m: number }
/** `thickness_m` is optional on read (older plans predate it) and always written back. */
export interface Wall { wall_id: string; start: PlanPoint; end: PlanPoint; thickness_m?: number; openings: Opening[] }
export interface Room { room_id: string; name: string; polygon: PlanPoint[] }
export interface Floor { floor_id: string; level: number; name: string; ceiling_height_m: number; walls: Wall[]; rooms: Room[] }
export interface HomePlan { home_id: string; version: number; name: string; floors: Floor[] }
export type Mounting = 'wall' | 'ceiling' | 'floor' | 'shelf' | null;
export interface Placement { placement_id: string; device_id: string; floor_id: string; x: number; y: number; height_m: number; mounting: Mounting }
export interface Estimate { device_id: string; floor_id: string | null; room_id: string | null; confidence: number; evidence: string[]; estimated_at: string }
/**
 * `name` is the owner's (or Home Assistant's) name only. The optional fields describe an unnamed
 * device (vendor from the MAC registry, a MAC, an IP) so the tray can label it usefully.
 */
export interface HomeDeviceRef { device_id: string; name: string | null; vendor?: string | null; mac?: string | null; ip?: string | null }
export interface HomeSnapshot { plan: HomePlan; placements: Placement[]; estimates: Estimate[] }

export const GRID_M = 0.1;
export const MIN_CEILING_M = 1.8;
export const MAX_CEILING_M = 6.0;
export const DEFAULT_THICKNESS_M = 0.1;
export const MIN_THICKNESS_M = 0.02;
export const MAX_THICKNESS_M = 1.0;
export const HISTORY_LIMIT = 200;
export const UNCERTAIN_BELOW = 0.6;
export const DRAFT_MAX_BYTES = 512 * 1024;
const MAX_COORDINATE_M = 10_000;

/** The wire contract's bounds. The reducer enforces the same numbers the validator checks, so an edit that would produce an unsavable plan is refused up front. */
export interface PlanLimits { floors: number; level: number; walls: number; rooms: number; roomPoints: number; openings: number }
export const PLAN_LIMITS: PlanLimits = { floors: 64, level: 100, walls: 2048, rooms: 256, roomPoints: 256, openings: 64 };
const UNBOUNDED: PlanLimits = { floors: Infinity, level: Infinity, walls: Infinity, rooms: Infinity, roomPoints: Infinity, openings: Infinity };
const EPSILON = 1e-6;

// ---- Geometry ----
export function snap(value: number, grid = GRID_M): number { return Number((Math.round(value / grid) * grid).toFixed(6)); }
export function snapPoint(point: PlanPoint, grid = GRID_M): PlanPoint { return { x: snap(point.x, grid), y: snap(point.y, grid) }; }
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

/** Edits that change the document (everything except history navigation and batching). */
export type EditAction =
  | { type: 'add_wall'; floor_id: string; wall_id: string; start: PlanPoint; end: PlanPoint; thickness_m?: number; /** Take the points as given (already snapped to a real feature) instead of re-snapping to the grid. */ exact?: boolean }
  | { type: 'move_wall'; floor_id: string; wall_id: string; start: PlanPoint; end: PlanPoint; exact?: boolean }
  | { type: 'delete_wall'; floor_id: string; wall_id: string }
  | { type: 'split_wall'; floor_id: string; wall_id: string; at: PlanPoint; new_wall_id: string; exact?: boolean }
  | { type: 'set_wall_thickness'; floor_id: string; wall_id: string; thickness_m: number }
  | { type: 'add_opening'; floor_id: string; wall_id: string; opening: Opening }
  | { type: 'delete_opening'; floor_id: string; wall_id: string; opening_id: string }
  | { type: 'add_room'; floor_id: string; room_id: string; name: string; polygon: PlanPoint[]; exact?: boolean }
  | { type: 'rename_room'; floor_id: string; room_id: string; name: string }
  | { type: 'delete_room'; floor_id: string; room_id: string }
  | { type: 'add_floor'; floor_id: string; level: number; name: string; ceiling_height_m: number }
  | { type: 'rename_floor'; floor_id: string; name: string }
  | { type: 'set_ceiling_height'; floor_id: string; ceiling_height_m: number }
  | { type: 'delete_floor'; floor_id: string }
  | { type: 'copy_footprint'; floor: Floor }
  | { type: 'place_device'; placement: Placement }
  | { type: 'move_placement'; device_id: string; x: number; y: number }
  | { type: 'configure_placement'; device_id: string; height_m?: number; mounting?: Mounting }
  | { type: 'remove_placement'; device_id: string };

export const BATCH_LIMIT = 64;

export type EditorAction = (
  | EditAction
  /** Several edits applied in order as ONE history entry; if any edit is rejected the whole batch is. */
  | { type: 'batch'; actions: EditAction[] }
  | { type: 'undo' }
  | { type: 'redo' }) & { grid_m?: number };

export function copyFloorFootprint(source: Floor, destination: Floor, newId: () => string): Floor {
  return { ...destination,
    walls: source.walls.map(wall => ({ ...wall, wall_id: newId(), start: { ...wall.start }, end: { ...wall.end },
      openings: wall.openings.map(opening => ({ ...opening, opening_id: newId() })) })),
    rooms: source.rooms.map(room => ({ ...room, room_id: newId(), polygon: room.polygon.map(point => ({ ...point })) }))
  };
}

/** Every id in the plan (floors, walls, openings, rooms): the reducer keeps them unique across the whole document. */
function allIds(plan: HomePlan): Set<string> {
  const ids = new Set<string>();
  for (const floor of plan.floors) { ids.add(floor.floor_id); for (const id of geometryIds(floor)) ids.add(id); }
  return ids;
}

const cross = (a: PlanPoint, b: PlanPoint, c: PlanPoint) => (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x);
function segmentsCross(a: PlanPoint, b: PlanPoint, c: PlanPoint, d: PlanPoint): boolean {
  const d1 = cross(a, b, c); const d2 = cross(a, b, d); const d3 = cross(c, d, a); const d4 = cross(c, d, b);
  return ((d1 > EPSILON && d2 < -EPSILON) || (d1 < -EPSILON && d2 > EPSILON)) && ((d3 > EPSILON && d4 < -EPSILON) || (d3 < -EPSILON && d4 > EPSILON));
}
/** Reasons a room outline cannot be a room: too few distinct corners, no area, or edges that cross each other. */
export function polygonProblem(polygon: PlanPoint[]): string | null {
  const points = polygon.length > 1 && samePoint(polygon[0]!, polygon[polygon.length - 1]!) ? polygon.slice(0, -1) : polygon;
  if (points.length < 3) return 'A room needs at least three corners.';
  for (let i = 0; i < points.length; i += 1) if (samePoint(points[i]!, points[(i + 1) % points.length]!)) return 'Two neighbouring corners are in the same place.';
  for (let i = 0; i < points.length; i += 1) {
    for (let j = i + 1; j < points.length; j += 1) {
      if (j === i + 1 || (i === 0 && j === points.length - 1)) continue;
      if (segmentsCross(points[i]!, points[(i + 1) % points.length]!, points[j]!, points[(j + 1) % points.length]!)) return 'The outline crosses itself.';
    }
  }
  let area2 = 0;
  for (let i = 0; i < points.length; i += 1) { const a = points[i]!; const b = points[(i + 1) % points.length]!; area2 += a.x * b.y - b.x * a.y; }
  if (Math.abs(area2) / 2 < 1e-4) return 'The corners enclose no area.';
  return null;
}

function geometryIds(floor: Floor): string[] {
  return [...floor.walls.flatMap(wall => [wall.wall_id, ...wall.openings.map(opening => opening.opening_id)]), ...floor.rooms.map(room => room.room_id)];
}

const validName = (name: string) => name.trim().length > 0 && name.length <= 64;
const validCoordinate = (value: number) => Number.isFinite(value) && Math.abs(value) <= MAX_COORDINATE_M;
const validPoint = (point: PlanPoint) => validCoordinate(point.x) && validCoordinate(point.y);
const validCeiling = (value: number) => Number.isFinite(value) && value >= MIN_CEILING_M && value <= MAX_CEILING_M;
const validThickness = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value) && value >= MIN_THICKNESS_M - EPSILON && value <= MAX_THICKNESS_M + EPSILON;
const round6 = (value: number) => Number(value.toFixed(6));
const sameSegment = (a: Pick<Wall, 'start' | 'end'>, start: PlanPoint, end: PlanPoint) =>
  (samePoint(a.start, start) && samePoint(a.end, end)) || (samePoint(a.start, end) && samePoint(a.end, start));

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

function applyEdit(doc: EditorDoc, action: EditAction, grid: number): EditorDoc | null {
  const place = (point: PlanPoint, exact?: boolean): PlanPoint => exact ? { x: round6(point.x), y: round6(point.y) } : snapPoint(point, grid);
  switch (action.type) {
    case 'add_wall': {
      if (!validPoint(action.start) || !validPoint(action.end)) return null;
      const start = place(action.start, action.exact);
      const end = place(action.end, action.exact);
      if (samePoint(start, end)) return null;
      const thickness_m = action.thickness_m === undefined ? DEFAULT_THICKNESS_M : round6(action.thickness_m);
      if (!validThickness(thickness_m)) return null;
      return withFloor(doc, action.floor_id, (floor) => {
        // The same two endpoints (either way round) are the same wall; a second copy would double-draw it.
        if (floor.walls.length >= PLAN_LIMITS.walls || allIds(doc.plan).has(action.wall_id) || floor.walls.some((wall) => sameSegment(wall, start, end))) return null;
        return { ...floor, walls: [...floor.walls, { wall_id: action.wall_id, start, end, thickness_m, openings: [] }] };
      });
    }
    case 'move_wall': {
      if (!validPoint(action.start) || !validPoint(action.end)) return null;
      const start = place(action.start, action.exact);
      const end = place(action.end, action.exact);
      if (samePoint(start, end)) return null;
      // Openings that no longer fit the moved wall are removed with the move (undo restores them).
      return withWall(doc, action.floor_id, action.wall_id, (wall, floor) => {
        if (floor.walls.some((other) => other.wall_id !== wall.wall_id && sameSegment(other, start, end))) return null;
        const moved = { ...wall, start, end };
        return [{ ...moved, openings: wall.openings.filter((opening) => openingFits(moved, opening)) }];
      });
    }
    case 'delete_wall':
      return withWall(doc, action.floor_id, action.wall_id, () => []);
    case 'split_wall': {
      if (!validPoint(action.at)) return null;
      return withWall(doc, action.floor_id, action.wall_id, (wall, floor) => {
        const length = wallLength(wall);
        if (length < EPSILON) return null;
        if (floor.walls.length >= PLAN_LIMITS.walls || allIds(doc.plan).has(action.new_wall_id)) return null;
        // Clamped: a point beyond an end projects onto that end (and is then refused as no split), never outside the wall.
        const t = Math.min(1, Math.max(0, ((action.at.x - wall.start.x) * (wall.end.x - wall.start.x) + (action.at.y - wall.start.y) * (wall.end.y - wall.start.y)) / (length * length)));
        const projected = { x: wall.start.x + t * (wall.end.x - wall.start.x), y: wall.start.y + t * (wall.end.y - wall.start.y) };
        // An exact split keeps a point that already lies on the wall (a snapped "on wall" click) where it is.
        const split = action.exact
          ? (Math.hypot(projected.x - action.at.x, projected.y - action.at.y) < 1e-4 ? place(action.at, true) : null)
          : snapPoint(projected, grid);
        if (!split) return null;
        if (samePoint(split, wall.start) || samePoint(split, wall.end)) return null;
        const distance = Math.hypot(split.x - wall.start.x, split.y - wall.start.y);
        // A split landing inside an opening is rejected rather than truncating it.
        if (wall.openings.some((opening) => opening.offset_m < distance - EPSILON && opening.offset_m + opening.width_m > distance + EPSILON)) return null;
        const first: Wall = { ...wall, end: split, openings: wall.openings.filter((opening) => opening.offset_m + opening.width_m <= distance + EPSILON) };
        const second: Wall = {
          wall_id: action.new_wall_id, start: split, end: wall.end, ...(wall.thickness_m === undefined ? {} : { thickness_m: wall.thickness_m }),
          openings: wall.openings.filter((opening) => opening.offset_m >= distance - EPSILON).map((opening) => ({ ...opening, offset_m: Number((opening.offset_m - distance).toFixed(6)) }))
        };
        return [first, second];
      });
    }
    case 'set_wall_thickness': {
      const thickness_m = typeof action.thickness_m === 'number' ? round6(action.thickness_m) : NaN;
      if (!validThickness(thickness_m)) return null;
      return withWall(doc, action.floor_id, action.wall_id, (wall) => (wall.thickness_m === thickness_m ? null : [{ ...wall, thickness_m }]));
    }
    case 'add_opening': {
      const opening = { ...action.opening, offset_m: snap(action.opening.offset_m, grid), width_m: snap(action.opening.width_m, grid) };
      if (!['door', 'window', 'stair'].includes(opening.kind)) return null;
      return withWall(doc, action.floor_id, action.wall_id, (wall) => (openingFits(wall, opening) && wall.openings.length < PLAN_LIMITS.openings && !allIds(doc.plan).has(opening.opening_id) ? [{ ...wall, openings: [...wall.openings, opening] }] : null));
    }
    case 'delete_opening':
      return withWall(doc, action.floor_id, action.wall_id, (wall) => {
        if (!wall.openings.some((opening) => opening.opening_id === action.opening_id)) return null;
        return [{ ...wall, openings: wall.openings.filter((opening) => opening.opening_id !== action.opening_id) }];
      });
    case 'add_room': {
      if (!validName(action.name) || action.polygon.length < 3 || action.polygon.length > PLAN_LIMITS.roomPoints || !action.polygon.every(validPoint)) return null;
      const polygon = action.polygon.map(point => place(point, action.exact));
      if (polygonProblem(polygon) !== null) return null;
      return withFloor(doc, action.floor_id, (floor) => (floor.rooms.length >= PLAN_LIMITS.rooms || allIds(doc.plan).has(action.room_id) ? null : { ...floor, rooms: [...floor.rooms, { room_id: action.room_id, name: action.name.trim(), polygon }] }));
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
      if (!validName(action.name) || !validCeiling(action.ceiling_height_m) || !Number.isSafeInteger(action.level) || Math.abs(action.level) > PLAN_LIMITS.level) return null;
      if (doc.plan.floors.length >= PLAN_LIMITS.floors || allIds(doc.plan).has(action.floor_id) || doc.plan.floors.some((floor) => floor.level === action.level)) return null;
      const floor: Floor = { floor_id: action.floor_id, level: action.level, name: action.name.trim(), ceiling_height_m: action.ceiling_height_m, walls: [], rooms: [] };
      return { ...doc, plan: { ...doc.plan, floors: [...doc.plan.floors, floor].sort((a, b) => a.level - b.level) } };
    }
    case 'rename_floor':
      if (!validName(action.name)) return null;
      return withFloor(doc, action.floor_id, (floor) => (floor.name === action.name.trim() ? null : { ...floor, name: action.name.trim() }));
    case 'copy_footprint': {
      const floor = action.floor;
      if (!isFloor(floor) || (!floor.walls.length && !floor.rooms.length)) return null;
      const existing = doc.plan.floors.find(item => item.floor_id === floor.floor_id);
      if (existing && (existing.walls.length || existing.rooms.length)) return null;
      if (existing && (existing.level !== floor.level || existing.name !== floor.name || existing.ceiling_height_m !== floor.ceiling_height_m)) return null;
      if (!existing && (doc.plan.floors.length >= PLAN_LIMITS.floors || doc.plan.floors.some(item => item.level === floor.level))) return null;
      const used = new Set(doc.plan.floors.flatMap(item => [item.floor_id, ...geometryIds(item)]));
      const ids = geometryIds(floor);
      if (ids.some(id => used.has(id) || id === floor.floor_id) || new Set(ids).size !== ids.length) return null;
      const floors = existing ? doc.plan.floors.map(item => item.floor_id === floor.floor_id ? floor : item) : [...doc.plan.floors, floor];
      return { ...doc, plan: { ...doc.plan, floors: floors.sort((a, b) => a.level - b.level) } };
    }
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
      const placement: Placement = { ...raw, x: snap(raw.x, grid), y: snap(raw.y, grid) };
      const existing = doc.placements.find((candidate) => candidate.device_id === placement.device_id);
      const placements = existing
        ? doc.placements.map((candidate) => (candidate.device_id === placement.device_id ? { ...placement, placement_id: existing.placement_id } : candidate))
        : [...doc.placements, placement];
      return { ...doc, placements };
    }
    case 'move_placement': {
      const placement = doc.placements.find((candidate) => candidate.device_id === action.device_id);
      if (!placement || !validCoordinate(action.x) || !validCoordinate(action.y)) return null;
      const x = snap(action.x, grid);
      const y = snap(action.y, grid);
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

/** The specific, owner-readable reason an edit was refused; null when it would be accepted (or there is no more specific reason). */
export function rejectionReason(state: EditorState, action: EditorAction): string | null {
  if (action.type === 'undo' || action.type === 'redo') return null;
  const grid = action.grid_m === 0.0254 ? 0.0254 : GRID_M;
  let doc: EditorDoc = state.doc;
  const edits = action.type === 'batch' ? action.actions : [action];
  for (const edit of edits) {
    const next = applyEdit(doc, edit, grid);
    if (next) { doc = next; continue; }
    const floor = 'floor_id' in edit ? doc.plan.floors.find((candidate) => candidate.floor_id === edit.floor_id) : undefined;
    const ids = allIds(doc.plan);
    switch (edit.type) {
      case 'add_wall': case 'split_wall':
        if (floor && floor.walls.length >= PLAN_LIMITS.walls) return `A floor holds at most ${PLAN_LIMITS.walls} walls.`;
        if (ids.has(edit.type === 'add_wall' ? edit.wall_id : edit.new_wall_id)) return 'That wall id is already used in this plan.';
        return null;
      case 'add_opening':
        if (floor?.walls.find((wall) => wall.wall_id === edit.wall_id)?.openings.length === PLAN_LIMITS.openings) return `A wall holds at most ${PLAN_LIMITS.openings} openings.`;
        if (ids.has(edit.opening.opening_id)) return 'That opening id is already used in this plan.';
        return null;
      case 'add_room': {
        if (edit.polygon.length > PLAN_LIMITS.roomPoints) return `A room outline has at most ${PLAN_LIMITS.roomPoints} corners.`;
        if (floor && floor.rooms.length >= PLAN_LIMITS.rooms) return `A floor holds at most ${PLAN_LIMITS.rooms} rooms.`;
        if (ids.has(edit.room_id)) return 'That room id is already used in this plan.';
        return polygonProblem(edit.polygon.map((point) => (edit.exact ? { x: round6(point.x), y: round6(point.y) } : snapPoint(point, grid))));
      }
      case 'add_floor':
        if (doc.plan.floors.length >= PLAN_LIMITS.floors) return `A plan holds at most ${PLAN_LIMITS.floors} floors.`;
        if (ids.has(edit.floor_id)) return 'That floor id is already used in this plan.';
        if (Math.abs(edit.level) > PLAN_LIMITS.level) return `Floor levels run from -${PLAN_LIMITS.level} to ${PLAN_LIMITS.level}.`;
        return null;
      default: return null;
    }
  }
  return null;
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
  const grid = action.grid_m === 0.0254 ? 0.0254 : GRID_M;
  let doc: EditorDoc | null = state.doc;
  if (action.type === 'batch') {
    if (action.actions.length === 0 || action.actions.length > BATCH_LIMIT) return state;
    for (const edit of action.actions) {
      doc = applyEdit(doc, edit, grid);
      if (!doc) return state; // one rejected edit rejects the whole batch
    }
  } else doc = applyEdit(doc, action, grid);
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
function isWall(value: unknown, limits: PlanLimits = PLAN_LIMITS): value is Wall {
  return isRecord(value) && isOpaqueId(value.wall_id) && isPoint(value.start) && isPoint(value.end)
    && (value.thickness_m === undefined || validThickness(value.thickness_m))
    && Array.isArray(value.openings) && value.openings.length <= limits.openings && value.openings.every(isOpening)
    && value.openings.every((opening) => openingFits({ start: (value as unknown as Wall).start, end: (value as unknown as Wall).end }, opening as Opening));
}
function isRoom(value: unknown, limits: PlanLimits = PLAN_LIMITS): value is Room {
  return isRecord(value) && isOpaqueId(value.room_id) && typeof value.name === 'string' && value.name.length > 0 && value.name.length <= 64
    && Array.isArray(value.polygon) && value.polygon.length >= 3 && value.polygon.length <= limits.roomPoints && value.polygon.every(isPoint);
}
function isFloor(value: unknown, limits: PlanLimits = PLAN_LIMITS): value is Floor {
  return isRecord(value) && isOpaqueId(value.floor_id) && Number.isSafeInteger(value.level) && Math.abs(value.level as number) <= limits.level
    && typeof value.name === 'string' && value.name.length > 0 && value.name.length <= 64
    && typeof value.ceiling_height_m === 'number' && validCeiling(value.ceiling_height_m)
    && Array.isArray(value.walls) && value.walls.length <= limits.walls && value.walls.every((wall) => isWall(wall, limits))
    && Array.isArray(value.rooms) && value.rooms.length <= limits.rooms && value.rooms.every((room) => isRoom(room, limits));
}
/** `limits` only widens the size bounds; every structural rule (ids, finite numbers, shapes) still applies. */
export function isHomePlan(value: unknown, limits: PlanLimits = PLAN_LIMITS): value is HomePlan {
  return isRecord(value) && isOpaqueId(value.home_id) && Number.isSafeInteger(value.version) && (value.version as number) >= 0
    && typeof value.name === 'string' && value.name.length > 0 && value.name.length <= 64
    && Array.isArray(value.floors) && value.floors.length <= limits.floors && value.floors.every((floor) => isFloor(floor, limits));
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

/** A save was refused locally because the plan is not storable; the message is owner-readable. */
export class PlanLimitError extends Error { constructor(message: string) { super(message); this.name = 'PlanLimitError'; } }
/** Which size bounds a structurally valid plan exceeds. */
export function overLimit(plan: HomePlan): string {
  const parts: string[] = [];
  if (plan.floors.length > PLAN_LIMITS.floors) parts.push(`${plan.floors.length} floors, max ${PLAN_LIMITS.floors}`);
  for (const floor of plan.floors) {
    if (floor.walls.length > PLAN_LIMITS.walls) parts.push(`${floor.name}: ${floor.walls.length} walls, max ${PLAN_LIMITS.walls}`);
    if (floor.rooms.length > PLAN_LIMITS.rooms) parts.push(`${floor.name}: ${floor.rooms.length} rooms, max ${PLAN_LIMITS.rooms}`);
    for (const room of floor.rooms) if (room.polygon.length > PLAN_LIMITS.roomPoints) parts.push(`${room.name}: ${room.polygon.length} corners, max ${PLAN_LIMITS.roomPoints}`);
    for (const wall of floor.walls) if (wall.openings.length > PLAN_LIMITS.openings) parts.push(`a wall on ${floor.name}: ${wall.openings.length} openings, max ${PLAN_LIMITS.openings}`);
  }
  return parts.join('; ') || 'size limits';
}

// ---- API glue (loopback service; bearer-authenticated like every other route) ----
export interface HomeDraft { plan: HomePlan; saved_at: string }
export type SavePlanResult = { status: 'saved'; version: number } | { status: 'conflict' };
export type DraftResult = { status: 'none' } | { status: 'draft'; draft: HomeDraft; /** True when the draft is intact but exceeds the size limits: it can be resumed and trimmed, not saved as is. */ overLimits?: boolean } | { status: 'corrupt' };

export interface HomeApi {
  fetchHome(): Promise<HomeSnapshot>;
  savePlan(plan: HomePlan, expectedVersion: number): Promise<SavePlanResult>;
  saveDraft(draft: HomeDraft): Promise<void>;
  loadDraft(): Promise<DraftResult>;
  deleteDraft(): Promise<void>;
  putPlacement(placement: Placement): Promise<void>;
  deletePlacement(deviceId: string): Promise<void>;
}

export interface HomeApiOptions { baseUrl: string; serviceToken?: string; auth?: AuthSource; fetchImpl?: typeof fetch; requestTimeoutMs?: number }

export function createHomeApi({ baseUrl, serviceToken, auth, fetchImpl = fetch, requestTimeoutMs = 15_000 }: HomeApiOptions): HomeApi {
  const apiUrl = (path: string) => new URL(path, baseUrl).toString();
  const credential = (): string | null => auth ? auth.header() : (serviceToken ? `Bearer ${serviceToken}` : null);
  const authorized = (method: string, body?: unknown): RequestInit => {
    const header = credential();
    const headers: Record<string, string> = header === null ? {} : { Authorization: header };
    if (body !== undefined) headers['content-type'] = 'application/json';
    return { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) };
  };
  // Same discipline as the API client: bounded fetches, auth refusals reported.
  async function send(path: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = requestTimeoutMs > 0 ? setTimeout(() => controller.abort(new Error('Request timed out')), requestTimeoutMs) : undefined;
    try {
      const response = await fetchImpl(apiUrl(path), { ...init, signal: controller.signal });
      if (response.status === 401) auth?.unauthorized?.();
      else if (response.status === 403 && credential()?.startsWith('PhoneSession ')) auth?.stepupRequired?.();
      return response;
    } finally { if (timer !== undefined) clearTimeout(timer); }
  }

  async function fetchHome(): Promise<HomeSnapshot> {
    const response = await send('/api/v1/home', authorized('GET'));
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
    const value: unknown = await response.json();
    if (!isHomeSnapshot(value)) throw new Error('Invalid home response');
    return value;
  }

  async function savePlan(plan: HomePlan, expectedVersion: number): Promise<SavePlanResult> {
    if (!isHomePlan(plan)) throw new PlanLimitError(isHomePlan(plan, UNBOUNDED) ? `This plan is over the size limits (${overLimit(plan)}). Remove some before saving.` : 'This plan has invalid values and cannot be saved.');
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) throw new Error('Invalid plan save');
    const response = await send('/api/v1/home/plan', authorized('PUT', { expected_version: expectedVersion, plan }));
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
    const response = await send('/api/v1/home/draft', { ...authorized('PUT', {}), body });
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
  }

  async function deleteDraft(): Promise<void> {
    const response = await send('/api/v1/home/draft', authorized('DELETE'));
    if (!response.ok && response.status !== 404) throw new Error(`Request failed with status ${response.status}`);
  }

  async function loadDraft(): Promise<DraftResult> {
    const response = await send('/api/v1/home/draft', authorized('GET'));
    if (response.status === 204 || response.status === 404) return { status: 'none' };
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
    const text = await response.text();
    let draft: unknown = null;
    if (text.length <= DRAFT_MAX_BYTES) {
      try { draft = JSON.parse(text); } catch { draft = null; }
    }
    if (isRecord(draft) && isDate(draft.saved_at)) {
      if (isHomePlan(draft.plan)) return { status: 'draft', draft: { plan: draft.plan, saved_at: draft.saved_at } };
      // Only the size bounds are exceeded: the owner's work is intact, so it is offered, never deleted.
      if (isHomePlan(draft.plan, UNBOUNDED)) return { status: 'draft', draft: { plan: draft.plan, saved_at: draft.saved_at }, overLimits: true };
    }
    // H3: a draft that is structurally invalid is reported corrupt and discarded — never silently merged.
    try { await deleteDraft(); } catch { /* Discard is best-effort; the committed plan remains the truth. */ }
    return { status: 'corrupt' };
  }

  async function putPlacement(placement: Placement): Promise<void> {
    if (!isPlacement(placement)) throw new Error('Invalid placement');
    const response = await send(`/api/v1/home/placements/${placement.device_id}`, authorized('PUT', placement));
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
  }

  async function deletePlacement(deviceId: string): Promise<void> {
    if (!isOpaqueId(deviceId)) throw new Error('Invalid placement');
    const response = await send(`/api/v1/home/placements/${deviceId}`, authorized('DELETE'));
    if (!response.ok && response.status !== 404) throw new Error(`Request failed with status ${response.status}`);
  }

  return { fetchHome, savePlan, saveDraft, loadDraft, deleteDraft, putPlacement, deletePlacement };
}
