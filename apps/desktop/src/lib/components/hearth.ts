// Pure layout math for the Hearth visualization (Pulse view).
//
// The Hearth replaces the earlier anatomical "lung" panel with something that
// carries information: a central ember whose warmth follows total throughput,
// two arc gauges (download inner, upload outer) on a log scale, and one spark
// per known device placed on a ring by a stable hash of its id, sized by its
// share of traffic and lit by its presence state.
//
// Everything here is deterministic so the component can be unit-tested
// without a canvas. Units: bytes per second in, as the service reports them.

import type { DeviceSnapshot, PresenceState } from '../api/types';
import { HEAT_STOPS, HEAT_UNAVAILABLE_COLOR, heatTier, type HeatTier } from '../twin/heat';

export const HEARTH_WIDTH = 620;
export const HEARTH_HEIGHT = 330;
export const HEARTH_CENTER = { x: HEARTH_WIDTH / 2, y: HEARTH_HEIGHT / 2 + 4 } as const;

/** Ember radius at rest; the breathing animation moves it a few px. */
export const EMBER_RADIUS = 54;
/** Download gauge (inner) and upload gauge (outer) radii. */
export const GAUGE_RADII = { download: 82, upload: 96 } as const;
/** The gauges sweep 270 degrees, opening at the bottom like a dial. */
export const GAUGE_START = (3 * Math.PI) / 4;
export const GAUGE_SWEEP = (3 * Math.PI) / 2;
/** Sparks sit in an annulus outside the gauges. */
export const SPARK_RING = { inner: 118, outer: 146 } as const;
export const SPARK_RADIUS = { min: 2.4, max: 8.5 } as const;

/** Gauge scale: 100 kbit/s reads as empty, 1 Gbit/s reads as full (log10). */
const GAUGE_FLOOR_BPS = 100_000 / 8;
const GAUGE_CEIL_BPS = 1_000_000_000 / 8;

export const TIER_COLOR: Record<HeatTier | 'unavailable', string> = {
  blue: HEAT_STOPS[0]!.color,
  cyan: HEAT_STOPS[1]!.color,
  gold: HEAT_STOPS[2]!.color,
  pink: HEAT_STOPS[3]!.color,
  unavailable: HEAT_UNAVAILABLE_COLOR
};

export const PRESENCE_ALPHA: Record<PresenceState, number> = {
  online: 1,
  quiet: 0.55,
  offline: 0.28,
  blocked: 0.9,
  unknown: 0.35
};

export interface Spark {
  deviceId: string;
  label: string;
  x: number;
  y: number;
  angle: number;
  orbit: number;
  radius: number;
  color: string;
  alpha: number;
  blocked: boolean;
  share: number;
  bytesPerSecond: number | null;
  presence: PresenceState;
}

/** FNV-1a 32-bit; stable across sessions so a device keeps its place on the ring. */
export function hashId(id: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < id.length; index += 1) {
    hash ^= id.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

/** Fraction 0..1 of a gauge for a rate in bytes/s, on a log scale. */
export function gaugeFraction(bytesPerSecond: number | null | undefined): number {
  if (typeof bytesPerSecond !== 'number' || !Number.isFinite(bytesPerSecond) || bytesPerSecond <= GAUGE_FLOOR_BPS) return 0;
  if (bytesPerSecond >= GAUGE_CEIL_BPS) return 1;
  return Math.log10(bytesPerSecond / GAUGE_FLOOR_BPS) / Math.log10(GAUGE_CEIL_BPS / GAUGE_FLOOR_BPS);
}

/** Energy 0.2..1.8 drives glow size and breathing speed; never NaN. */
export function emberEnergy(totalBytesPerSecond: number | null | undefined): number {
  const fraction = gaugeFraction(totalBytesPerSecond);
  if (typeof totalBytesPerSecond !== 'number' || !Number.isFinite(totalBytesPerSecond)) return 0.2;
  return 0.35 + fraction * 1.45;
}

function deviceRate(device: DeviceSnapshot): number | null {
  if (!device.bandwidth.available) return null;
  const upload = device.bandwidth.upload ?? 0;
  const download = device.bandwidth.download ?? 0;
  return Number.isFinite(upload) && Number.isFinite(download) ? upload + download : null;
}

export function deviceLabel(device: DeviceSnapshot): string {
  return device.owner_name ?? `Device ${device.device_id.slice(0, 6)}`;
}

/**
 * Lay out one spark per device. `drift` (radians) is added to every angle so the
 * ring can rotate very slowly; `wobble` 0..1 nudges each spark radially so a
 * paused frame and an animated frame share the same code path.
 */
export function layoutSparks(devices: readonly DeviceSnapshot[], drift = 0, wobble = 0): Spark[] {
  const rates = devices.map(deviceRate);
  const total = rates.reduce<number>((sum, rate) => sum + (rate ?? 0), 0);
  return devices.map((device, index) => {
    const hash = hashId(device.device_id);
    const baseAngle = ((hash & 0xffff) / 0x10000) * Math.PI * 2;
    const orbitSeed = ((hash >>> 16) & 0xff) / 0xff;
    const phase = ((hash >>> 24) & 0xff) / 0xff;
    const orbit = SPARK_RING.inner + orbitSeed * (SPARK_RING.outer - SPARK_RING.inner)
      + Math.sin((wobble + phase) * Math.PI * 2) * 3;
    const angle = baseAngle + drift * (0.6 + orbitSeed * 0.8);
    const rate = rates[index] ?? null;
    const share = total > 0 && rate !== null ? rate / total : 0;
    const presence = device.presence.state;
    const blocked = presence === 'blocked';
    const tier = rate === null ? 'unavailable' : heatTier(rate);
    const color = blocked ? TIER_COLOR.pink : presence === 'online' ? TIER_COLOR[tier] : HEAT_UNAVAILABLE_COLOR;
    return {
      deviceId: device.device_id,
      label: deviceLabel(device),
      x: HEARTH_CENTER.x + Math.cos(angle) * orbit,
      y: HEARTH_CENTER.y + Math.sin(angle) * orbit,
      angle,
      orbit,
      radius: SPARK_RADIUS.min + Math.sqrt(share) * (SPARK_RADIUS.max - SPARK_RADIUS.min),
      color,
      alpha: PRESENCE_ALPHA[presence] ?? PRESENCE_ALPHA.unknown,
      blocked,
      share,
      bytesPerSecond: rate,
      presence
    };
  });
}

/** Nearest spark within its hit radius (min 12px so small sparks stay hoverable). */
export function sparkAt(sparks: readonly Spark[], x: number, y: number): Spark | null {
  let best: Spark | null = null;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (const spark of sparks) {
    const hit = Math.max(12, spark.radius + 5);
    const distance = Math.hypot(spark.x - x, spark.y - y);
    if (distance <= hit && distance < bestDistance) { best = spark; bestDistance = distance; }
  }
  return best;
}

/** Accessible summary read by screen readers in place of the canvas. */
export function describeHearth(input: { connected: boolean; upload: number | null; download: number | null; sparks: readonly Spark[]; format: (bytesPerSecond: number | null) => string }): string {
  if (!input.connected) return 'Network hearth: live readings unavailable until the collector is paired.';
  const online = input.sparks.filter((spark) => spark.presence === 'online').length;
  const blocked = input.sparks.filter((spark) => spark.blocked).length;
  const total = (input.upload ?? 0) + (input.download ?? 0);
  const parts = [
    `Network hearth: ${input.format(total)} total`,
    `${input.format(input.download)} down`,
    `${input.format(input.upload)} up`,
    `${online} of ${input.sparks.length} devices online`
  ];
  if (blocked) parts.push(`${blocked} blocked`);
  return parts.join(', ') + '.';
}
