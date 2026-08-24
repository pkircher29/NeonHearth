import { describe, expect, it } from 'vitest';

import {
  HEAT_STOPS,
  HEAT_UNAVAILABLE_COLOR,
  heatColor,
  heatTier,
  pinVisual,
  RISK_BADGES,
  riskBadge,
  riskFromPresence,
  type RiskLevel
} from './heat';

describe('heatTier', () => {
  it('applies the documented byte-per-second thresholds', () => {
    expect(heatTier(0)).toBe('blue');
    expect(heatTier(124_999)).toBe('blue');
    expect(heatTier(125_000)).toBe('cyan');
    expect(heatTier(1_249_999)).toBe('cyan');
    expect(heatTier(1_250_000)).toBe('gold');
    expect(heatTier(3_749_999)).toBe('gold');
    expect(heatTier(3_750_000)).toBe('pink');
    expect(heatTier(500_000_000)).toBe('pink');
  });

  it('reports unavailable for missing or invalid readings', () => {
    expect(heatTier(null)).toBe('unavailable');
    expect(heatTier(undefined)).toBe('unavailable');
    expect(heatTier(Number.NaN)).toBe('unavailable');
    expect(heatTier(-1)).toBe('unavailable');
  });
});

describe('heatColor', () => {
  it('returns the exact ramp anchors at each stop', () => {
    for (const stop of HEAT_STOPS) {
      expect(heatColor(stop.bps)).toBe(stop.color);
    }
  });

  it('clamps above the top stop to pink', () => {
    expect(heatColor(10_000_000)).toBe(HEAT_STOPS[HEAT_STOPS.length - 1]!.color);
  });

  it('interpolates midway between adjacent stops', () => {
    const mid = (HEAT_STOPS[0]!.bps + HEAT_STOPS[1]!.bps) / 2;
    // #548cff -> #63f3f0 at t=0.5: componentwise rounded midpoint
    expect(heatColor(mid)).toBe('#5cc0f8');
  });

  it('is monotone within a segment (more bandwidth never jumps backwards)', () => {
    const colors = [0, 60_000, 125_000, 700_000, 1_250_000, 2_500_000, 3_750_000].map(heatColor);
    expect(new Set(colors).size).toBe(colors.length);
  });

  it('uses a neutral non-ramp color when the reading is unavailable', () => {
    expect(heatColor(null)).toBe(HEAT_UNAVAILABLE_COLOR);
    expect(HEAT_STOPS.map((stop) => stop.color)).not.toContain(HEAT_UNAVAILABLE_COLOR);
  });
});

describe('risk badges', () => {
  it('maps each level to a distinct badge with symbol, label, and outline', () => {
    expect(riskBadge('secure')).toMatchObject({ symbol: '✓', ring: false });
    expect(riskBadge('watch')).toMatchObject({ symbol: '△', ring: true });
    expect(riskBadge('risk')).toMatchObject({ symbol: '!', ring: true });
    const outlines = Object.values(RISK_BADGES).map((badge) => badge.outline);
    expect(new Set(outlines).size).toBe(outlines.length);
  });

  it('derives risk only from control-plane presence states', () => {
    expect(riskFromPresence('blocked')).toBe('risk');
    expect(riskFromPresence('unknown')).toBe('watch');
    expect(riskFromPresence('online')).toBe('secure');
    expect(riskFromPresence('quiet')).toBe('secure');
    expect(riskFromPresence('offline')).toBe('secure');
    expect(riskFromPresence(null)).toBe('secure');
  });
});

describe('risk and heat independence (H9)', () => {
  const levels: RiskLevel[] = ['secure', 'watch', 'risk'];
  const readings = [null, 0, 125_000, 900_000, 3_750_000, 50_000_000];

  it('risk never changes the heat color for any bandwidth', () => {
    for (const bps of readings) {
      const heats = levels.map((level) => pinVisual(bps, level).heat);
      expect(new Set(heats).size).toBe(1);
      expect(heats[0]).toBe(heatColor(bps));
    }
  });

  it('bandwidth never changes the risk badge for any level', () => {
    for (const level of levels) {
      const badges = readings.map((bps) => pinVisual(bps, level).badge);
      for (const badge of badges) expect(badge).toEqual(riskBadge(level));
    }
  });

  it('a blocked, saturating device shows pink heat AND a risk badge — separate channels', () => {
    const visual = pinVisual(50_000_000, 'risk');
    expect(visual.tier).toBe('pink');
    expect(visual.heat).toBe(HEAT_STOPS[HEAT_STOPS.length - 1]!.color);
    expect(visual.badge.level).toBe('risk');
    expect(visual.badge.ring).toBe(true);
  });
});
