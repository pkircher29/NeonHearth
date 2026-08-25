// Bandwidth heat and security risk for the 3D home twin.
//
// These are two SEPARATE visual channels (checklist H9):
// - heat: bandwidth-only color ramp blue -> cyan -> gold -> pink
// - risk: badge / outline descriptors, never colors on the heat ramp inputs
// Risk must never feed the heat ramp; `pinVisual` below is the one place both
// channels meet, and it keeps them in independent fields.

export type HeatTier = 'blue' | 'cyan' | 'gold' | 'pink';

/**
 * Documented thresholds, in BYTES per second (device up + down combined).
 * They mirror the Pulse lung tiers (1 / 10 / 30 megabits per second):
 * - blue:  quiet          —            bps <   125_000 (< 1 Mbps)
 * - cyan:  active         —  125_000 <= bps < 1_250_000 (1..10 Mbps)
 * - gold:  busy           — 1_250_000 <= bps < 3_750_000 (10..30 Mbps)
 * - pink:  saturating     —            bps >= 3_750_000 (> 30 Mbps)
 */
export const HEAT_STOPS: ReadonlyArray<{ bps: number; tier: HeatTier; color: string }> = [
  { bps: 0, tier: 'blue', color: '#548cff' },
  { bps: 125_000, tier: 'cyan', color: '#63f3f0' },
  { bps: 1_250_000, tier: 'gold', color: '#ffcd66' },
  { bps: 3_750_000, tier: 'pink', color: '#ff5c9b' }
];

/** Neutral pin color when no bandwidth reading exists — not part of the ramp. */
export const HEAT_UNAVAILABLE_COLOR = '#68808a';

export function heatTier(bytesPerSecond: number | null | undefined): HeatTier | 'unavailable' {
  if (typeof bytesPerSecond !== 'number' || !Number.isFinite(bytesPerSecond) || bytesPerSecond < 0) {
    return 'unavailable';
  }
  if (bytesPerSecond < HEAT_STOPS[1]!.bps) return 'blue';
  if (bytesPerSecond < HEAT_STOPS[2]!.bps) return 'cyan';
  if (bytesPerSecond < HEAT_STOPS[3]!.bps) return 'gold';
  return 'pink';
}

function hexChannel(hex: string, index: number): number {
  return parseInt(hex.slice(1 + index * 2, 3 + index * 2), 16);
}

function mixHex(a: string, b: string, t: number): string {
  const channels = [0, 1, 2].map((index) => {
    const value = Math.round(hexChannel(a, index) + (hexChannel(b, index) - hexChannel(a, index)) * t);
    return Math.min(255, Math.max(0, value)).toString(16).padStart(2, '0');
  });
  return `#${channels.join('')}`;
}

/**
 * Continuous heat color: piecewise-linear interpolation between the ramp
 * stops, clamped to pink above the top stop. Missing readings get the
 * neutral unavailable color, never a ramp color.
 */
export function heatColor(bytesPerSecond: number | null | undefined): string {
  if (typeof bytesPerSecond !== 'number' || !Number.isFinite(bytesPerSecond) || bytesPerSecond < 0) {
    return HEAT_UNAVAILABLE_COLOR;
  }
  const top = HEAT_STOPS[HEAT_STOPS.length - 1]!;
  if (bytesPerSecond >= top.bps) return top.color;
  for (let i = HEAT_STOPS.length - 2; i >= 0; i -= 1) {
    const lower = HEAT_STOPS[i]!;
    if (bytesPerSecond >= lower.bps) {
      const upper = HEAT_STOPS[i + 1]!;
      const t = (bytesPerSecond - lower.bps) / (upper.bps - lower.bps);
      return mixHex(lower.color, upper.color, t);
    }
  }
  return HEAT_STOPS[0]!.color;
}

// --- Risk channel (badges and outlines, never the heat ramp) ---------------

export type RiskLevel = 'secure' | 'watch' | 'risk';

export interface RiskBadge {
  level: RiskLevel;
  /** Short glyph matching the Pulse status cues. */
  symbol: string;
  label: string;
  /** Outline / badge color. Deliberately NOT read from HEAT_STOPS. */
  outline: string;
  /** Whether the pin gets a visible warning ring in the 3D view. */
  ring: boolean;
}

export const RISK_BADGES: Readonly<Record<RiskLevel, RiskBadge>> = {
  secure: { level: 'secure', symbol: '✓', label: 'no active concern', outline: '#63f3f0', ring: false },
  watch: { level: 'watch', symbol: '△', label: 'needs attention', outline: '#ffcd66', ring: true },
  risk: { level: 'risk', symbol: '!', label: 'blocked or high risk', outline: '#ff5c9b', ring: true }
};

export function riskBadge(level: RiskLevel): RiskBadge {
  return RISK_BADGES[level];
}

/**
 * Presence-derived risk for the twin: a verified block is a risk cue, an
 * unknown device is a watch cue, everything else (online / quiet / offline)
 * is not a security signal at all.
 */
export function riskFromPresence(state: string | null | undefined): RiskLevel {
  if (state === 'blocked') return 'risk';
  if (state === 'unknown') return 'watch';
  return 'secure';
}

/**
 * The single meeting point of both channels for a device pin. Heat depends
 * only on bandwidth; the badge depends only on risk (H9). Keeping this a pure
 * function lets tests prove the independence.
 */
export function pinVisual(
  bytesPerSecond: number | null | undefined,
  risk: RiskLevel
): { heat: string; tier: HeatTier | 'unavailable'; badge: RiskBadge } {
  return { heat: heatColor(bytesPerSecond), tier: heatTier(bytesPerSecond), badge: riskBadge(risk) };
}
