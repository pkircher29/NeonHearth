import { describe, expect, it } from 'vitest';

import type { DeviceSnapshot } from '../api/types';
import { HEARTH_CENTER, SPARK_RADIUS, SPARK_RING, TIER_COLOR, describeHearth, emberEnergy, gaugeFraction, hashId, layoutSparks, sparkAt } from './hearth';
import { formatThroughput } from './networkFormat';

function device(overrides: Partial<DeviceSnapshot> & { device_id: string }): DeviceSnapshot {
  return {
    first_seen_at: '2026-08-23T00:00:00Z',
    last_seen_at: '2026-08-23T00:00:00Z',
    owner_name: null,
    owner_type: null,
    owner_confirmed: false,
    presence: { state: 'online', observed_at: null, source: null, kind: null },
    evidence: null,
    identity: { available: false, classification: null, confidence: null },
    bandwidth: { available: true, upload: 0, download: 0, coverage: 'complete', observed_at: null },
    policy: null,
    ...overrides
  };
}

describe('hearth layout', () => {
  it('hashes ids stably and spreads them around the ring', () => {
    expect(hashId('a')).toBe(hashId('a'));
    expect(hashId('a')).not.toBe(hashId('b'));
    const sparks = layoutSparks([device({ device_id: 'alpha' }), device({ device_id: 'beta' }), device({ device_id: 'gamma' })]);
    const angles = sparks.map((spark) => spark.angle);
    expect(new Set(angles.map((angle) => angle.toFixed(3))).size).toBe(3);
    for (const spark of sparks) {
      const distance = Math.hypot(spark.x - HEARTH_CENTER.x, spark.y - HEARTH_CENTER.y);
      expect(distance).toBeGreaterThanOrEqual(SPARK_RING.inner - 3);
      expect(distance).toBeLessThanOrEqual(SPARK_RING.outer + 3);
    }
  });

  it('gauges are empty below 100 kbps, full at 1 Gbps, and log-scaled between', () => {
    expect(gaugeFraction(null)).toBe(0);
    expect(gaugeFraction(Number.NaN)).toBe(0);
    expect(gaugeFraction(-5)).toBe(0);
    expect(gaugeFraction(1_000)).toBe(0);
    expect(gaugeFraction(125_000_000)).toBe(1);
    expect(gaugeFraction(10_000_000_000)).toBe(1);
    const oneMbps = gaugeFraction(125_000);
    const tenMbps = gaugeFraction(1_250_000);
    const hundredMbps = gaugeFraction(12_500_000);
    expect(oneMbps).toBeGreaterThan(0);
    expect(tenMbps - oneMbps).toBeCloseTo(hundredMbps - tenMbps, 6);
  });

  it('ember energy is bounded and never NaN', () => {
    expect(emberEnergy(null)).toBe(0.2);
    expect(emberEnergy(Number.POSITIVE_INFINITY)).toBe(0.2);
    expect(emberEnergy(0)).toBeCloseTo(0.35, 6);
    expect(emberEnergy(125_000_000)).toBeCloseTo(1.8, 6);
  });

  it('sizes sparks by share of traffic and lights them by presence', () => {
    const sparks = layoutSparks([
      device({ device_id: 'big', bandwidth: { available: true, upload: 3_000_000, download: 1_000_000, coverage: 'complete', observed_at: null } }),
      device({ device_id: 'small', bandwidth: { available: true, upload: 0, download: 10_000, coverage: 'complete', observed_at: null } }),
      device({ device_id: 'quiet', presence: { state: 'quiet', observed_at: null, source: null, kind: null } }),
      device({ device_id: 'banned', presence: { state: 'blocked', observed_at: null, source: 'policy', kind: 'enforcement_blocked' } }),
      device({ device_id: 'silent', bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null } })
    ]);
    const byId = Object.fromEntries(sparks.map((spark) => [spark.deviceId, spark]));
    expect(byId.big!.radius).toBeGreaterThan(byId.small!.radius);
    expect(byId.big!.radius).toBeLessThanOrEqual(SPARK_RADIUS.max);
    expect(byId.silent!.radius).toBe(SPARK_RADIUS.min);
    expect(byId.big!.color).toBe(TIER_COLOR.pink);
    expect(byId.small!.color).toBe(TIER_COLOR.blue);
    expect(byId.quiet!.alpha).toBeLessThan(byId.big!.alpha);
    expect(byId.banned!.blocked).toBe(true);
    expect(byId.banned!.color).toBe(TIER_COLOR.pink);
    expect(byId.silent!.bytesPerSecond).toBeNull();
    expect(byId.silent!.share).toBe(0);
  });

  it('drift rotates the ring without changing sizes', () => {
    const still = layoutSparks([device({ device_id: 'x' })]);
    const moved = layoutSparks([device({ device_id: 'x' })], 0.5);
    expect(moved[0]!.angle).not.toBeCloseTo(still[0]!.angle, 6);
    expect(moved[0]!.radius).toBe(still[0]!.radius);
  });

  it('hit-tests the nearest spark with a minimum 12px target', () => {
    const sparks = layoutSparks([device({ device_id: 'one' }), device({ device_id: 'two' })]);
    const target = sparks[0]!;
    expect(sparkAt(sparks, target.x + 10, target.y)?.deviceId).toBe('one');
    expect(sparkAt(sparks, HEARTH_CENTER.x, HEARTH_CENTER.y)).toBeNull();
  });

  it('describes the hearth for assistive technology', () => {
    const sparks = layoutSparks([
      device({ device_id: 'one' }),
      device({ device_id: 'two', presence: { state: 'blocked', observed_at: null, source: null, kind: null } })
    ]);
    expect(describeHearth({ connected: false, upload: null, download: null, sparks, format: formatThroughput }))
      .toMatch(/unavailable until the collector is paired/);
    const text = describeHearth({ connected: true, upload: 125_000, download: 1_250_000, sparks, format: formatThroughput });
    expect(text).toContain('1 of 2 devices online');
    expect(text).toContain('1 blocked');
    expect(text).toContain('11 Mbps total');
  });
});
