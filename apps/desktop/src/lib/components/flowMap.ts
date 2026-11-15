// Pure layout and maths for the Flow Map (Pulse view).
//
// The Flow Map shows the network as a flow diagram in which every pixel of
// motion is data:
// - the gateway sits in the centre; a 60 second radial history ring around it
//   traces total download (outside the baseline) and upload (inside it), newest
//   sample at 12 o'clock, sweeping clockwise;
// - devices are nodes grouped into angular sectors by what they are, the
//   busiest nearest the core;
// - a curved stream joins the core to every active device, its width following
//   the device's share of measured traffic (log scaled), particles travelling
//   outward for download and inward for upload.
//
// Everything here is deterministic and canvas-free so it can be unit tested.
// Units: bytes per second in, as the service reports them. Angles are radians,
// 0 = 3 o'clock, positive = clockwise on screen (canvas convention).

import type { DeviceSnapshot, PresenceState } from '../api/types';

export const TAU = Math.PI * 2;
/** 12 o'clock in canvas angle space. */
export const TOP = -Math.PI / 2;

// --- Palette ---------------------------------------------------------------

/** Mirrors the design-system fire tokens (docs/architecture/ui-design-system.md). */
export const FIRE = {
  blue: '#3d5afe',
  violet: '#7c4dff',
  magenta: '#e040fb',
  orange: '#ff6d3b',
  gold: '#ffc53d',
  alert: '#ff4757',
  neutral: '#68808a'
} as const;

function hexChannel(hex: string, index: number): number {
  return parseInt(hex.slice(1 + index * 2, 3 + index * 2), 16);
}

export function mixHex(a: string, b: string, t: number): string {
  const k = Math.min(1, Math.max(0, t));
  const out = [0, 1, 2].map((index) => {
    const value = Math.round(hexChannel(a, index) + (hexChannel(b, index) - hexChannel(a, index)) * k);
    return Math.min(255, Math.max(0, value)).toString(16).padStart(2, '0');
  });
  return `#${out.join('')}`;
}

/** Ramp lookup table (inclusive of both ends) so the draw loop never builds colour strings. */
export function buildRamp(from: string, to: string, steps = 24): string[] {
  const n = Math.max(2, Math.floor(steps));
  return Array.from({ length: n }, (_, index) => mixHex(from, to, index / (n - 1)));
}

/** Download uses orange to gold; upload uses violet to magenta. */
export const DOWN_RAMP = { from: FIRE.orange, to: FIRE.gold } as const;
export const UP_RAMP = { from: FIRE.violet, to: FIRE.magenta } as const;

// --- Rates -----------------------------------------------------------------

/** Rates below this read as idle: no particles, hairline link. 10 kbit/s. */
export const STREAM_FLOOR_BPS = 1_250;
const SCALE_CEIL_BPS = 125_000_000; // 1 Gbit/s
/** Top-talker labels only appear for a rate worth reading: 500 kbit/s. */
export const TOP_TALKER_MIN_BPS = 62_500;
export const MAX_TOP_TALKERS = 4;
export const MAX_PARTICLES = 400;
export const HISTORY_WINDOW_MS = 60_000;
export const HISTORY_MAX_SAMPLES = 60;
export const HISTORY_MIN_GAP_MS = 1_000;
/** A gap longer than this between samples is drawn as a break, never interpolated. */
export const HISTORY_BREAK_MS = 5_000;

/** Log fraction 0..1: 10 kbit/s reads empty, 1 Gbit/s reads full. 1 Mbit/s = 0.4, 10 = 0.6, 100 = 0.8. */
export function rateFraction(bytesPerSecond: number | null | undefined): number {
  if (typeof bytesPerSecond !== 'number' || !Number.isFinite(bytesPerSecond) || bytesPerSecond <= STREAM_FLOOR_BPS) return 0;
  if (bytesPerSecond >= SCALE_CEIL_BPS) return 1;
  return Math.log10(bytesPerSecond / STREAM_FLOOR_BPS) / Math.log10(SCALE_CEIL_BPS / STREAM_FLOOR_BPS);
}

/** Width of a stream lane from a traffic share 0..1, log scaled so small devices stay visible. */
export function laneWidth(share: number, unit = 1): number {
  const s = Math.min(1, Math.max(0, Number.isFinite(share) ? share : 0));
  return (0.7 + 3.6 * (Math.log10(1 + 99 * s) / 2)) * unit;
}

export interface ParticleSpec { count: number; speed: number }
/** Particle density (1..7) and speed (cycles per second) follow the log of the rate. */
export function particleSpec(bytesPerSecond: number | null | undefined): ParticleSpec {
  const f = rateFraction(bytesPerSecond);
  if (f <= 0) return { count: 0, speed: 0 };
  return { count: 1 + Math.round(f * 6), speed: 0.1 + 0.4 * f };
}

/**
 * Trim a list of per-stream particle counts (given in priority order, busiest
 * first) so the total never exceeds `cap`. Each surviving stream keeps at least
 * one particle; the least busy streams lose theirs entirely before anyone is cut
 * below one. Returns a new array.
 */
export function capParticles(counts: readonly number[], cap = MAX_PARTICLES): number[] {
  const total = counts.reduce((sum, c) => sum + c, 0);
  if (total <= cap) return counts.slice();
  const scale = cap / total;
  const out = counts.map((c) => (c > 0 ? Math.max(1, Math.floor(c * scale)) : 0));
  let sum = out.reduce((s, c) => s + c, 0);
  for (let index = out.length - 1; index >= 0 && sum > cap; index -= 1) {
    sum -= out[index]!;
    out[index] = 0;
  }
  return out;
}

/** Position 0..1 along a stream of particle `i` of `n`; phase seed keeps streams out of step. */
export function particlePhase(index: number, count: number, seconds: number, speed: number, seed: number): number {
  const raw = index / Math.max(1, count) + seconds * speed + seed;
  return raw - Math.floor(raw);
}

/** FNV-1a 32-bit, used only to de-synchronise particle phases (never for position). */
export function hashId(id: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < id.length; index += 1) {
    hash ^= id.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

/** Frame-rate independent easing toward a target. */
export function easeToward(current: number, target: number, dtSeconds: number, tau = 0.22): number {
  if (!Number.isFinite(current)) return target;
  if (dtSeconds <= 0) return current;
  return target + (current - target) * Math.exp(-dtSeconds / tau);
}

// --- Grouping --------------------------------------------------------------

export type GroupId = 'computers' | 'phones' | 'media' | 'cameras' | 'iot' | 'network' | 'guests' | 'other' | 'unclassified';

/** Fixed order: sectors always appear in this order, clockwise from 12 o'clock. */
export const GROUPS: ReadonlyArray<{ id: GroupId; label: string; patterns: RegExp }> = [
  { id: 'computers', label: 'Computers', patterns: /laptop|desktop|computer|\bpc\b|mac|workstation|server|\bnas\b/ },
  { id: 'phones', label: 'Phones', patterns: /phone|mobile|tablet|ipad|watch|handset/ },
  { id: 'media', label: 'Media', patterns: /\btv\b|television|speaker|audio|stream|console|game|media|cast|soundbar|projector/ },
  { id: 'cameras', label: 'Cameras', patterns: /camera|doorbell|\bcam\b/ },
  { id: 'iot', label: 'Home & IoT', patterns: /iot|sensor|light|bulb|plug|thermostat|lock|hub|appliance|printer|vacuum|switchbot|smart/ },
  { id: 'network', label: 'Network', patterns: /router|gateway|switch|access.?point|\bap\b|mesh|modem|extender/ },
  { id: 'guests', label: 'Guests', patterns: /guest|visitor/ },
  { id: 'other', label: 'Other', patterns: /$^/ },
  { id: 'unclassified', label: 'Unclassified', patterns: /$^/ }
];

/**
 * Stable category for a device from fields that exist on DeviceSnapshot: the
 * owner-confirmed `owner_type` wins, then the inferred `identity.classification`.
 * The snapshot has no room or location, so none is invented.
 */
export function groupOf(device: DeviceSnapshot): GroupId {
  const raw = (device.owner_type?.trim() || device.identity?.classification?.trim() || '').toLowerCase();
  if (!raw) return 'unclassified';
  for (const group of GROUPS) if (group.id !== 'other' && group.id !== 'unclassified' && group.patterns.test(raw)) return group.id;
  return 'other';
}

export function groupLabel(id: GroupId): string {
  return GROUPS.find((group) => group.id === id)?.label ?? 'Other';
}

// --- Device status ---------------------------------------------------------

export type NodeStatus = 'active' | 'idle' | 'quiet' | 'offline' | 'blocked' | 'unknown' | 'unavailable';

export function deviceLabel(device: DeviceSnapshot): string {
  return device.owner_name ?? `Device ${device.device_id.slice(0, 6)}`;
}

/** Directional rates, or null when counters are unavailable (never a fake zero). */
export function deviceRates(device: DeviceSnapshot): { down: number; up: number; total: number } | null {
  const b = device.bandwidth;
  if (!b.available) return null;
  const down = b.download ?? 0;
  const up = b.upload ?? 0;
  if (!Number.isFinite(down) || !Number.isFinite(up) || down < 0 || up < 0) return null;
  return { down, up, total: down + up };
}

export function statusOf(device: DeviceSnapshot): NodeStatus {
  const state: PresenceState = device.presence.state;
  if (state === 'blocked') return 'blocked';
  if (state === 'offline') return 'offline';
  if (state === 'unknown') return 'unknown';
  const rates = deviceRates(device);
  if (rates === null) return 'unavailable';
  if (state === 'quiet') return 'quiet';
  return rates.total >= STREAM_FLOOR_BPS ? 'active' : 'idle';
}

function activityScore(status: NodeStatus, total: number | null): number {
  const bucket = total === null ? 0 : Math.floor(rateFraction(total) * 12);
  switch (status) {
    case 'active': return 100 + bucket;
    case 'quiet': return total !== null && total >= STREAM_FLOOR_BPS ? 70 + bucket : 30;
    case 'idle': return 50;
    case 'unavailable': return 40;
    case 'blocked': return 25;
    case 'unknown': return 20;
    default: return 10;
  }
}

// --- Geometry --------------------------------------------------------------

export interface FlowSize { width: number; height: number }
export interface FlowGeometry {
  width: number; height: number; cx: number; cy: number; unit: number;
  coreR: number; histBase: number; histOut: number; histIn: number;
  nodeMin: number; nodeMax: number; rimR: number;
  /** Narrow canvases put group labels on the rail instead of beside it. */
  compact: boolean;
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

/** Preferred canvas size for a container width: wide panels are landscape, phones near-square. */
export function flowCanvasSize(containerWidth: number): FlowSize {
  const width = Math.max(240, Math.round(containerWidth));
  const height = width < 520 ? Math.round(width * 1.06) : Math.round(clamp(width * 0.74, 380, 590));
  return { width, height };
}

export function flowGeometry(size: FlowSize): FlowGeometry {
  const width = Math.max(200, size.width);
  const height = Math.max(200, size.height);
  const unit = clamp(Math.min(width, height) / 560, 0.5, 1.2);
  const coreR = Math.max(32, 46 * unit);
  const histBase = coreR + 22 * unit;
  const histOut = 17 * unit;
  const histIn = 13 * unit;
  const compact = width < 520;
  const labelReserve = compact ? 44 : clamp(width * 0.14, 54, 100);
  const nodeMax = Math.max(histBase + histOut + 40, Math.min(height / 2 - 40, width / 2 - labelReserve));
  const nodeMin = histBase + histOut + 26 * unit;
  return { width, height, cx: width / 2, cy: height / 2, unit, coreR, histBase, histOut, histIn, nodeMin, nodeMax: Math.max(nodeMax, nodeMin + 20), rimR: Math.max(nodeMax, nodeMin + 20) + 14, compact };
}

// --- Layout ----------------------------------------------------------------

export interface FlowNode {
  deviceId: string;
  label: string;
  group: GroupId;
  presence: PresenceState;
  status: NodeStatus;
  /** Combined rate, or null when counters are unavailable. */
  rate: number | null;
  down: number;
  up: number;
  /** Share of total measured device traffic, 0..1. */
  share: number;
  rank: number;
  x: number;
  y: number;
  angle: number;
  radius: number;
  /** Visual radius of the node itself. */
  hasStream: boolean;
  downLane: number;
  upLane: number;
  downParticles: number;
  upParticles: number;
  downSpeed: number;
  upSpeed: number;
  seed: number;
}

export interface FlowGroup {
  id: GroupId;
  label: string;
  count: number;
  active: number;
  rate: number;
  start: number;
  end: number;
  mid: number;
  labelX: number;
  labelY: number;
  align: 'left' | 'right' | 'center';
}

export type FlowState = 'offline' | 'empty' | 'no-counters' | 'live';

export interface FlowLayout {
  geo: FlowGeometry;
  state: FlowState;
  nodes: FlowNode[];
  groups: FlowGroup[];
  /** Sum of measured device rates (null counters excluded). */
  measuredTotal: number;
}

const GROUP_GAP = 0.075;

interface RingPlan { radii: number[]; counts: number[]; step: number }

/** Fill rings from the core outward; capacity follows the arc length at each radius. */
export function planRings(count: number, sectorWidth: number, rMin: number, rMax: number, spacing: number, step0: number): RingPlan {
  let step = step0;
  let plan: RingPlan = { radii: [], counts: [], step };
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const radii: number[] = [];
    const counts: number[] = [];
    let remaining = count;
    let ring = 0;
    while (remaining > 0 && ring < 400) {
      const r = rMin + ring * step;
      const capacity = Math.max(1, Math.floor((sectorWidth * r) / spacing));
      radii.push(r);
      counts.push(Math.min(capacity, remaining));
      remaining -= capacity;
      ring += 1;
    }
    plan = { radii, counts, step };
    const last = radii[radii.length - 1] ?? rMin;
    if (last <= rMax + 0.5) {
      // Use the available depth: stretch rings apart (up to 2.4x) so position reads as activity, not clutter.
      const stretched = Math.min(step * 2.4, (rMax - rMin) / Math.max(1.35, radii.length));
      const finalStep = Math.max(step, stretched);
      return { radii: radii.map((_, i) => rMin + i * finalStep), counts, step: finalStep };
    }
    if (radii.length <= 1) break;
    step = Math.max(spacing * 0.55, (rMax - rMin) / (radii.length - 1));
  }
  // Out of room: clamp the overflow onto the outermost radius rather than leaving the canvas.
  return { radii: plan.radii.map((r) => Math.min(r, rMax)), counts: plan.counts, step: plan.step };
}

export function emptyFlowLayout(size: FlowSize, state: FlowState = 'empty'): FlowLayout {
  return { geo: flowGeometry(size), state, nodes: [], groups: [], measuredTotal: 0 };
}

/**
 * Deterministic layout: groups form sectors in fixed order; inside a sector the
 * busiest device takes the innermost ring. Ranking uses log-bucketed rates with
 * the device id as tie-break, so it only changes when activity changes by about
 * a third of a decade and never jitters between frames.
 */
export function layoutFlow(devices: readonly DeviceSnapshot[], size: FlowSize, connected = true): FlowLayout {
  const geo = flowGeometry(size);
  if (!connected) {
    const base = layoutFlow(devices, size, true);
    // Offline: keep the ghosts of known devices, but never any stream.
    for (const node of base.nodes) { node.hasStream = false; node.downParticles = 0; node.upParticles = 0; }
    return { ...base, state: 'offline' };
  }
  if (devices.length === 0) return emptyFlowLayout(size, 'empty');

  const rows = devices.map((device) => {
    const rates = deviceRates(device);
    const status = statusOf(device);
    return { device, rates, status, group: groupOf(device), score: activityScore(status, rates?.total ?? null) };
  });
  // The same set the service aggregate covers: every device that reports counters, whatever its presence.
  // Blocked and offline devices still get a share (and appear in tooltips) but never a stream.
  const measuredTotal = rows.reduce((sum, row) => sum + (row.rates ? row.rates.total : 0), 0);
  const anyCounters = rows.some((row) => row.rates !== null);

  const byGroup = new Map<GroupId, typeof rows>();
  for (const row of rows) {
    const list = byGroup.get(row.group);
    if (list) list.push(row); else byGroup.set(row.group, [row]);
  }
  const present = GROUPS.filter((group) => byGroup.has(group.id));
  const weights = present.map((group) => Math.max(1, Math.sqrt(byGroup.get(group.id)!.length)));
  const weightSum = weights.reduce((a, b) => a + b, 0);
  const usable = TAU - GROUP_GAP * present.length;
  const spacing = 19 * geo.unit;
  const step0 = 19 * geo.unit;

  const nodes: FlowNode[] = [];
  const groups: FlowGroup[] = [];
  let cursor = TOP + GROUP_GAP / 2;

  present.forEach((group, groupIndex) => {
    const list = byGroup.get(group.id)!.slice().sort((a, b) => (b.score - a.score) || (a.device.device_id < b.device.device_id ? -1 : a.device.device_id > b.device.device_id ? 1 : 0));
    const width = (weights[groupIndex]! / weightSum) * usable;
    const start = cursor;
    const end = cursor + width;
    cursor = end + GROUP_GAP;
    const plan = planRings(list.length, width, geo.nodeMin, geo.nodeMax, spacing, step0);
    const ringStep = plan.step;
    const room = Math.max(0, geo.nodeMax - geo.nodeMin - (plan.radii.length - 1) * ringStep);
    const offsetMax = plan.radii.length === 1 ? room : Math.min(room, ringStep * 1.4);
    let offset = 0;
    plan.counts.forEach((ringCount, ringIndex) => {
      const slice = list.slice(offset, offset + ringCount);
      // Angular order inside a ring follows the id, not the rate, so a rate change never swaps neighbours.
      const ordered = slice.map((row, i) => ({ row, rank: offset + i })).sort((a, b) => (a.row.device.device_id < b.row.device.device_id ? -1 : 1));
      ordered.forEach(({ row, rank }, j) => {
        const angle = start + ((j + 0.5) / ringCount) * width;
        const total = row.rates?.total ?? null;
        const activity = row.status === 'active' || row.status === 'quiet' ? rateFraction(total) : 0;
        const r = Math.min(geo.nodeMax, plan.radii[ringIndex]! + (1 - activity) * 0.95 * offsetMax);
        const share = total !== null && measuredTotal > 0 ? total / measuredTotal : 0;
        const streaming = (row.status === 'active' || row.status === 'quiet') && total !== null && total >= STREAM_FLOOR_BPS;
        const down = row.rates?.down ?? 0;
        const up = row.rates?.up ?? 0;
        const dSpec = streaming ? particleSpec(down) : { count: 0, speed: 0 };
        const uSpec = streaming ? particleSpec(up) : { count: 0, speed: 0 };
        nodes.push({
          deviceId: row.device.device_id,
          label: deviceLabel(row.device),
          group: group.id,
          presence: row.device.presence.state,
          status: row.status,
          rate: total,
          down, up, share,
          rank,
          x: geo.cx + Math.cos(angle) * r,
          y: geo.cy + Math.sin(angle) * r,
          angle,
          radius: geo.unit * (4.2 + 6.2 * (streaming ? rateFraction(total) : 0)),
          hasStream: streaming,
          downLane: streaming && down >= STREAM_FLOOR_BPS ? laneWidth(down / Math.max(measuredTotal, 1), geo.unit) : 0,
          upLane: streaming && up >= STREAM_FLOOR_BPS ? laneWidth(up / Math.max(measuredTotal, 1), geo.unit) : 0,
          downParticles: dSpec.count, upParticles: uSpec.count, downSpeed: dSpec.speed, upSpeed: uSpec.speed,
          seed: (hashId(row.device.device_id) & 0xffff) / 0x10000
        });
      });
      offset += ringCount;
    });
    const mid = (start + end) / 2;
    const cos = Math.cos(mid);
    groups.push({
      id: group.id,
      label: group.label,
      count: list.length,
      active: list.filter((row) => row.status === 'active').length,
      rate: list.reduce((sum, row) => sum + (row.rates ? row.rates.total : 0), 0),
      start, end, mid,
      labelX: geo.cx + cos * (geo.compact ? geo.rimR : geo.rimR + 12),
      labelY: geo.cy + Math.sin(mid) * (geo.compact ? geo.rimR : geo.rimR + 12),
      align: geo.compact ? 'center' : cos > 0.28 ? 'left' : cos < -0.28 ? 'right' : 'center'
    });
  });

  // Particle budget: busiest streams keep theirs first.
  const order = nodes.map((_, index) => index).filter((index) => nodes[index]!.hasStream).sort((a, b) => (nodes[b]!.rate ?? 0) - (nodes[a]!.rate ?? 0));
  const flat = order.flatMap((index) => [nodes[index]!.downParticles, nodes[index]!.upParticles]);
  const capped = capParticles(flat);
  order.forEach((index, i) => { nodes[index]!.downParticles = capped[i * 2]!; nodes[index]!.upParticles = capped[i * 2 + 1]!; });

  return { geo, state: anyCounters ? 'live' : 'no-counters', nodes, groups, measuredTotal };
}

// --- Streams ---------------------------------------------------------------

export interface StreamCurve { x0: number; y0: number; cx: number; cy: number; x1: number; y1: number }

/** Quadratic curve from the core rim to the node rim, bending with a fixed swirl. */
export function streamCurve(geo: FlowGeometry, x: number, y: number, nodeRadius: number): StreamCurve {
  const dx = x - geo.cx;
  const dy = y - geo.cy;
  const dist = Math.hypot(dx, dy) || 1;
  const ux = dx / dist;
  const uy = dy / dist;
  const x0 = geo.cx + ux * (geo.coreR * 0.92);
  const y0 = geo.cy + uy * (geo.coreR * 0.92);
  const x1 = x - ux * (nodeRadius + 1.5);
  const y1 = y - uy * (nodeRadius + 1.5);
  const vx = x1 - x0;
  const vy = y1 - y0;
  return { x0, y0, cx: (x0 + x1) / 2 - vy * 0.13, cy: (y0 + y1) / 2 + vx * 0.13, x1, y1 };
}

/** Point on a quadratic curve. */
export function curvePoint(c: StreamCurve, t: number): { x: number; y: number } {
  const k = 1 - t;
  return { x: k * k * c.x0 + 2 * k * t * c.cx + t * t * c.x1, y: k * k * c.y0 + 2 * k * t * c.cy + t * t * c.y1 };
}

/** Unit tangent (direction of increasing t). */
export function curveTangent(c: StreamCurve, t: number): { x: number; y: number } {
  const k = 1 - t;
  const tx = 2 * k * (c.cx - c.x0) + 2 * t * (c.x1 - c.cx);
  const ty = 2 * k * (c.cy - c.y0) + 2 * t * (c.y1 - c.cy);
  const len = Math.hypot(tx, ty) || 1;
  return { x: tx / len, y: ty / len };
}

// --- History ring ----------------------------------------------------------

export interface HistorySample { at: number; down: number; up: number }

/**
 * Append a sample no more than once per second, drop anything older than the
 * window and cap the count. Returns the same array when nothing was added so
 * callers can detect "no change". Never invents data: invalid input is ignored.
 */
export function pushHistory(buffer: readonly HistorySample[], sample: HistorySample, opts: { minGapMs?: number; windowMs?: number; max?: number } = {}): readonly HistorySample[] {
  const { minGapMs = HISTORY_MIN_GAP_MS, windowMs = HISTORY_WINDOW_MS, max = HISTORY_MAX_SAMPLES } = opts;
  if (![sample.at, sample.down, sample.up].every((v) => Number.isFinite(v)) || sample.down < 0 || sample.up < 0) return buffer;
  const last = buffer[buffer.length - 1];
  if (last && sample.at - last.at < minGapMs) return buffer;
  const kept = buffer.filter((s) => sample.at - s.at <= windowMs);
  kept.push(sample);
  return kept.length > max ? kept.slice(kept.length - max) : kept;
}

/** Angle of a sample of the given age (fraction of the window): newest at 12 o'clock, oldest just after it, clockwise. */
export function historyAngle(ageFraction: number): number {
  return TOP + (1 - clamp(ageFraction, 0, 1)) * TAU;
}

export function historyRadius(geo: FlowGeometry, side: 'down' | 'up', fraction: number): number {
  const f = clamp(fraction, 0, 1);
  return side === 'down' ? geo.histBase + geo.histOut * f : geo.histBase - geo.histIn * f;
}

export interface HistoryPoint { x: number; y: number; ageFraction: number }
/** Allocating helper for tests and non-hot paths; the draw loop uses historyAngle/historyRadius directly. */
export function historyPoints(samples: readonly HistorySample[], now: number, geo: FlowGeometry, side: 'down' | 'up'): HistoryPoint[] {
  const out: HistoryPoint[] = [];
  for (const s of samples) {
    const age = now - s.at;
    if (age < 0 || age > HISTORY_WINDOW_MS) continue;
    const ageFraction = age / HISTORY_WINDOW_MS;
    const angle = historyAngle(ageFraction);
    const r = historyRadius(geo, side, rateFraction(side === 'down' ? s.down : s.up));
    out.push({ x: geo.cx + Math.cos(angle) * r, y: geo.cy + Math.sin(angle) * r, ageFraction });
  }
  return out;
}

// --- Top talkers and labels ------------------------------------------------

export function topTalkers(nodes: readonly FlowNode[], limit = MAX_TOP_TALKERS, minRate = TOP_TALKER_MIN_BPS): FlowNode[] {
  return nodes
    .filter((node) => node.rate !== null && node.rate >= minRate && (node.status === 'active' || node.status === 'quiet'))
    .sort((a, b) => (b.rate! - a.rate!) || (a.deviceId < b.deviceId ? -1 : 1))
    .slice(0, limit);
}

export interface Rect { x: number; y: number; w: number; h: number }
export interface PlacedLabel { deviceId: string; dx: number; dy: number; w: number; h: number; align: 'left' | 'right' }

const overlaps = (a: Rect, b: Rect, pad = 2) => a.x < b.x + b.w + pad && a.x + a.w + pad > b.x && a.y < b.y + b.h + pad && a.y + a.h + pad > b.y;

/**
 * Place always-on labels beside their nodes without overlapping each other,
 * other nodes, group rim labels or the canvas edge. Candidates are tried
 * outward-first, then shifted vertically, then flipped to the other side. A
 * label with no free spot is dropped (the tooltip still covers it).
 * Offsets are relative to the node so labels follow eased positions.
 */
export function placeLabels(talkers: readonly FlowNode[], all: readonly FlowNode[], widths: ReadonlyMap<string, number>, geo: FlowGeometry, obstacles: readonly Rect[] = [], height = 26): PlacedLabel[] {
  const placed: Array<PlacedLabel & { rect: Rect }> = [];
  const core: Rect = { x: geo.cx - geo.histBase - geo.histOut - 4, y: geo.cy - geo.histBase - geo.histOut - 4, w: (geo.histBase + geo.histOut + 4) * 2, h: (geo.histBase + geo.histOut + 4) * 2 };
  for (const node of talkers) {
    const w = (widths.get(node.deviceId) ?? 60) + 2;
    const preferRight = Math.cos(node.angle) >= 0;
    const sides: Array<'left' | 'right'> = preferRight ? ['right', 'left'] : ['left', 'right'];
    const shifts = [0, -1, 1, -2, 2].map((m) => m * (height + 2));
    let chosen: (PlacedLabel & { rect: Rect }) | null = null;
    search: for (const side of sides) {
      for (const shift of shifts) {
        const gap = node.radius + 6;
        const x = side === 'right' ? node.x + gap : node.x - gap - w;
        const y = node.y - height / 2 + shift;
        const rect: Rect = { x, y, w, h: height };
        if (x < 2 || y < 2 || x + w > geo.width - 2 || y + height > geo.height - 2) continue;
        if (overlaps(rect, core, 0)) continue;
        if (obstacles.some((o) => overlaps(rect, o))) continue;
        if (placed.some((p) => overlaps(rect, p.rect))) continue;
        if (all.some((n) => n.deviceId !== node.deviceId && Math.hypot(Math.max(rect.x - n.x, 0, n.x - (rect.x + rect.w)), Math.max(rect.y - n.y, 0, n.y - (rect.y + rect.h))) < n.radius + 2)) continue;
        chosen = { deviceId: node.deviceId, dx: x - node.x, dy: y - node.y, w, h: height, align: side, rect };
        break search;
      }
    }
    if (chosen) placed.push(chosen);
  }
  return placed.map(({ rect: _rect, ...label }) => label);
}

/** Rim label rectangle for a group, used as an obstacle for talker labels. */
export function groupLabelRect(group: FlowGroup, textWidth: number, height = 14): Rect {
  const y = group.labelY - height / 2;
  const x = group.align === 'left' ? group.labelX : group.align === 'right' ? group.labelX - textWidth : group.labelX - textWidth / 2;
  return { x, y, w: textWidth, h: height };
}

// --- Hit testing -----------------------------------------------------------

/** Nearest node within its hit radius (min 12 px so small nodes stay hoverable). */
export function nodeAt<T extends { x: number; y: number; radius: number }>(nodes: readonly T[], x: number, y: number): T | null {
  let best: T | null = null;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (const node of nodes) {
    const hit = Math.max(12, node.radius + 5);
    const distance = Math.hypot(node.x - x, node.y - y);
    if (distance <= hit && distance < bestDistance) { best = node; bestDistance = distance; }
  }
  return best;
}

// --- Copy ------------------------------------------------------------------

export function flowStateCopy(state: FlowState): { title: string; detail: string } | null {
  switch (state) {
    case 'offline': return { title: 'Collector offline', detail: 'Waiting to reconnect. Last known devices are dimmed; no live flow is shown.' };
    case 'empty': return { title: 'No devices yet', detail: 'Devices appear here once the collector has seen them.' };
    case 'no-counters': return { title: 'No per-device counters', detail: 'Devices are listed, but flow stays dark until bandwidth counters arrive.' };
    default: return null;
  }
}

export function describeFlow(input: { connected: boolean; upload: number | null; download: number | null; nodes: readonly FlowNode[]; format: (bytesPerSecond: number | null) => string }): string {
  if (!input.connected) return 'Network flow map: collector connection unavailable; reconnect or sign in if requested.';
  const online = input.nodes.filter((node) => node.presence === 'online').length;
  const blocked = input.nodes.filter((node) => node.presence === 'blocked').length;
  const total = input.upload === null && input.download === null ? null : (input.upload ?? 0) + (input.download ?? 0);
  const parts = [
    `Network flow map: ${input.format(total)} total`,
    `${input.format(input.download)} down`,
    `${input.format(input.upload)} up`,
    `${online} of ${input.nodes.length} devices online`
  ];
  if (blocked) parts.push(`${blocked} blocked`);
  let text = parts.join(', ') + '.';
  if (input.nodes.length && input.nodes.every((node) => node.rate === null)) text += ' Per-device counters unavailable.';
  const talkers = topTalkers(input.nodes);
  if (talkers.length) text += ` Top talkers: ${talkers.map((node) => `${node.label} ${input.format(node.rate)}`).join(', ')}.`;
  return text;
}
