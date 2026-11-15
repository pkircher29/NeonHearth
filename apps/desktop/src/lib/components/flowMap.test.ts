import { describe, expect, it } from 'vitest';
import type { DeviceSnapshot, PresenceState } from '../api/types';
import {
  FIRE, HISTORY_MAX_SAMPLES, HISTORY_WINDOW_MS, MAX_PARTICLES, STREAM_FLOOR_BPS, TOP, TAU,
  buildRamp, capParticles, curvePoint, curveTangent, describeFlow, easeToward, flowCanvasSize, flowGeometry, flowStateCopy, groupOf,
  historyAngle, historyPoints, historyRadius, laneWidth, layoutFlow, mixHex, nodeAt, particlePhase, particleSpec, placeLabels, planRings,
  pushHistory, rateFraction, statusOf, streamCurve, topTalkers, type FlowNode
} from './flowMap';
import { formatThroughput } from './networkFormat';

function device(id: string, overrides: Partial<DeviceSnapshot> & { rate?: [number, number] | null; state?: PresenceState; type?: string | null; cls?: string | null } = {}): DeviceSnapshot {
  const { rate = [0, 0], state = 'online', type = null, cls = null, ...rest } = overrides;
  return {
    device_id: id, first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:00Z',
    owner_name: null, owner_type: type, owner_confirmed: false,
    presence: { state, observed_at: null, source: null, kind: null }, evidence: null,
    identity: { available: cls !== null, classification: cls, confidence: cls ? 0.8 : null },
    bandwidth: rate === null ? { available: false, upload: null, download: null, coverage: null, observed_at: null } : { available: true, download: rate[0], upload: rate[1], coverage: 'complete', observed_at: null },
    policy: null,
    ...rest
  };
}

const SIZE = { width: 760, height: 560 };

describe('rates', () => {
  it('maps rates onto a monotonic log fraction with sane anchors', () => {
    expect(rateFraction(null)).toBe(0);
    expect(rateFraction(NaN)).toBe(0);
    expect(rateFraction(STREAM_FLOOR_BPS)).toBe(0);
    expect(rateFraction(125_000)).toBeCloseTo(0.4, 2); // 1 Mbps
    expect(rateFraction(1_250_000)).toBeCloseTo(0.6, 2); // 10 Mbps
    expect(rateFraction(1e12)).toBe(1);
    let previous = -1;
    for (const bps of [2_000, 20_000, 200_000, 2_000_000, 20_000_000, 100_000_000]) { const f = rateFraction(bps); expect(f).toBeGreaterThan(previous); previous = f; }
  });
  it('keeps lane width bounded, log scaled and visible for tiny shares', () => {
    expect(laneWidth(0)).toBeCloseTo(0.7);
    expect(laneWidth(1)).toBeCloseTo(4.3);
    expect(laneWidth(0.01)).toBeGreaterThan(laneWidth(0));
    expect(laneWidth(0.1) - laneWidth(0.01)).toBeLessThan(laneWidth(0.01) + 3); // log, not linear
    expect(laneWidth(5)).toBeCloseTo(laneWidth(1));
    expect(laneWidth(NaN)).toBeCloseTo(0.7);
    expect(laneWidth(0.5, 2)).toBeCloseTo(laneWidth(0.5) * 2);
  });
  it('derives particle density and speed from the log of the rate', () => {
    expect(particleSpec(null)).toEqual({ count: 0, speed: 0 });
    expect(particleSpec(500)).toEqual({ count: 0, speed: 0 });
    const slow = particleSpec(20_000);
    const fast = particleSpec(20_000_000);
    expect(slow.count).toBeGreaterThanOrEqual(1);
    expect(fast.count).toBeGreaterThan(slow.count);
    expect(fast.speed).toBeGreaterThan(slow.speed);
    expect(fast.count).toBeLessThanOrEqual(7);
  });
  it('caps particles, keeping the busiest streams alive', () => {
    expect(capParticles([3, 2, 1], 400)).toEqual([3, 2, 1]);
    const many = Array.from({ length: 600 }, () => 7);
    const capped = capParticles(many, MAX_PARTICLES);
    expect(capped.reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(MAX_PARTICLES);
    expect(capped[0]).toBeGreaterThanOrEqual(1);
    expect(capped[capped.length - 1]).toBe(0); // least busy are dropped first
    expect(capped.length).toBe(many.length);
  });
  it('phases particles deterministically inside [0,1)', () => {
    for (let i = 0; i < 5; i += 1) { const t = particlePhase(i, 5, 123.456, 0.3, 0.77); expect(t).toBeGreaterThanOrEqual(0); expect(t).toBeLessThan(1); }
    expect(particlePhase(0, 4, 0, 0.5, 0)).toBe(0);
    expect(particlePhase(2, 4, 0, 0.5, 0)).toBeCloseTo(0.5);
    expect(particlePhase(0, 4, 1, 0.25, 0)).toBeCloseTo(0.25);
  });
  it('eases without overshoot and handles bad input', () => {
    expect(easeToward(0, 10, 0)).toBe(0);
    const step = easeToward(0, 10, 0.1);
    expect(step).toBeGreaterThan(0); expect(step).toBeLessThan(10);
    expect(easeToward(0, 10, 100)).toBeCloseTo(10);
    expect(easeToward(NaN, 5, 0.1)).toBe(5);
  });
  it('mixes colours and builds ramps with exact endpoints', () => {
    expect(mixHex('#000000', '#ffffff', 0.5)).toBe('#808080');
    const ramp = buildRamp(FIRE.orange, FIRE.gold, 10);
    expect(ramp).toHaveLength(10);
    expect(ramp[0]).toBe(FIRE.orange);
    expect(ramp[9]).toBe(FIRE.gold);
  });
});

describe('grouping', () => {
  it('prefers owner_type, then identity classification, then unclassified', () => {
    expect(groupOf(device('a', { type: 'Laptop' }))).toBe('computers');
    expect(groupOf(device('a', { type: 'laptop', cls: 'camera' }))).toBe('computers');
    expect(groupOf(device('a', { cls: 'camera' }))).toBe('cameras');
    expect(groupOf(device('a', { cls: 'Smart TV' }))).toBe('media');
    expect(groupOf(device('a', { type: 'iPhone' }))).toBe('phones');
    expect(groupOf(device('a', { cls: 'router' }))).toBe('network');
    expect(groupOf(device('a', { cls: 'guest' }))).toBe('guests');
    expect(groupOf(device('a', { type: 'smart bulb' }))).toBe('iot');
    expect(groupOf(device('a', { type: 'quantum toaster' }))).toBe('other');
    expect(groupOf(device('a'))).toBe('unclassified');
    expect(groupOf(device('a', { type: '  ' }))).toBe('unclassified');
  });
  it('maps presence and counters to a status without faking activity', () => {
    expect(statusOf(device('a', { rate: [100_000, 0] }))).toBe('active');
    expect(statusOf(device('a', { rate: [0, 0] }))).toBe('idle');
    expect(statusOf(device('a', { rate: null }))).toBe('unavailable');
    expect(statusOf(device('a', { state: 'quiet', rate: [0, 0] }))).toBe('quiet');
    expect(statusOf(device('a', { state: 'offline', rate: [9e6, 0] }))).toBe('offline');
    expect(statusOf(device('a', { state: 'blocked', rate: [9e6, 0] }))).toBe('blocked');
    expect(statusOf(device('a', { state: 'unknown', rate: null }))).toBe('unknown');
    expect(statusOf(device('a', { rate: [NaN, 0] }))).toBe('unavailable');
  });
});

function fleet(): DeviceSnapshot[] {
  return [
    device('lap-1', { type: 'laptop', rate: [5_000_000, 200_000] }),
    device('lap-2', { type: 'laptop', rate: [0, 0] }),
    device('lap-3', { type: 'laptop', rate: [900_000, 100_000] }),
    device('ph-1', { type: 'phone', rate: [50_000, 10_000] }),
    device('ph-2', { type: 'phone', state: 'offline', rate: [0, 0] }),
    device('tv-1', { cls: 'tv', rate: [8_000_000, 20_000] }),
    device('cam-1', { cls: 'camera', rate: [10_000, 600_000] }),
    device('cam-2', { cls: 'camera', state: 'blocked', rate: [1_000_000, 0] }),
    device('x-1', { rate: null }),
    device('x-2', { state: 'unknown', rate: null })
  ];
}

describe('layoutFlow', () => {
  it('is deterministic and independent of input order', () => {
    const a = layoutFlow(fleet(), SIZE);
    const b = layoutFlow(fleet().reverse(), SIZE);
    const pos = (l: typeof a) => Object.fromEntries(l.nodes.map((n) => [n.deviceId, [Math.round(n.x * 1000) / 1000, Math.round(n.y * 1000) / 1000]]));
    expect(pos(b)).toEqual(pos(a));
    expect(layoutFlow(fleet(), SIZE).nodes.map((n) => n.deviceId)).toEqual(a.nodes.map((n) => n.deviceId));
  });
  it('orders sectors clockwise from 12 o clock in fixed group order, no overlap', () => {
    const layout = layoutFlow(fleet(), SIZE);
    expect(layout.groups.map((g) => g.id)).toEqual(['computers', 'phones', 'media', 'cameras', 'unclassified']);
    expect(layout.groups[0]!.start).toBeGreaterThanOrEqual(TOP);
    for (let i = 1; i < layout.groups.length; i += 1) expect(layout.groups[i]!.start).toBeGreaterThan(layout.groups[i - 1]!.end);
    expect(layout.groups[layout.groups.length - 1]!.end).toBeLessThanOrEqual(TOP + TAU);
    // every node sits inside its own sector
    for (const node of layout.nodes) {
      const g = layout.groups.find((x) => x.id === node.group)!;
      expect(node.angle).toBeGreaterThan(g.start); expect(node.angle).toBeLessThan(g.end);
    }
  });
  it('puts the busiest device of a group nearest the core and idle ones further out', () => {
    const layout = layoutFlow(fleet(), SIZE);
    const dist = (id: string) => { const n = layout.nodes.find((x) => x.deviceId === id)!; return Math.hypot(n.x - layout.geo.cx, n.y - layout.geo.cy); };
    expect(dist('lap-1')).toBeLessThan(dist('lap-3'));
    expect(dist('lap-3')).toBeLessThan(dist('lap-2'));
    expect(dist('ph-1')).toBeLessThan(dist('ph-2'));
  });
  it('keeps every node inside the canvas and outside the history ring', () => {
    const many = Array.from({ length: 140 }, (_, i) => device(`dev-${String(i).padStart(3, '0')}`, { type: ['laptop', 'phone', 'tv', 'camera', 'bulb'][i % 5]!, rate: i % 7 === 0 ? [i * 40_000, i * 3_000] : [0, 0], state: i % 11 === 0 ? 'offline' : 'online' }));
    for (const size of [SIZE, { width: 390, height: 414 }, { width: 320, height: 340 }]) {
      const layout = layoutFlow(many, size);
      expect(layout.nodes).toHaveLength(140);
      for (const n of layout.nodes) {
        const r = Math.hypot(n.x - layout.geo.cx, n.y - layout.geo.cy);
        expect(r).toBeGreaterThanOrEqual(layout.geo.nodeMin - 0.01);
        expect(r).toBeLessThanOrEqual(layout.geo.nodeMax + 0.01);
        expect(n.x).toBeGreaterThan(0); expect(n.x).toBeLessThan(size.width);
        expect(n.y).toBeGreaterThan(0); expect(n.y).toBeLessThan(size.height);
      }
    }
  });
  it('does not stack nodes of one group on top of each other at normal density', () => {
    const layout = layoutFlow(fleet(), SIZE);
    for (let i = 0; i < layout.nodes.length; i += 1) for (let j = i + 1; j < layout.nodes.length; j += 1) {
      const a = layout.nodes[i]!; const b = layout.nodes[j]!;
      expect(Math.hypot(a.x - b.x, a.y - b.y)).toBeGreaterThan(a.radius + b.radius);
    }
  });
  it('stays stable across small rate changes within a bucket (no jitter) and re-ranks when activity changes', () => {
    const base = fleet();
    const a = layoutFlow(base, SIZE);
    const nudged = base.map((d) => d.device_id === 'lap-1' ? device('lap-1', { type: 'laptop', rate: [5_050_000, 205_000] }) : d);
    const b = layoutFlow(nudged, SIZE);
    for (const n of a.nodes) { const m = b.nodes.find((x) => x.deviceId === n.deviceId)!; expect(m.rank).toBe(n.rank); expect(Math.abs(m.x - n.x)).toBeLessThan(2.5); expect(Math.abs(m.y - n.y)).toBeLessThan(2.5); }
    const flipped = base.map((d) => d.device_id === 'lap-2' ? device('lap-2', { type: 'laptop', rate: [40_000_000, 0] }) : d);
    const c = layoutFlow(flipped, SIZE);
    expect(c.nodes.find((n) => n.deviceId === 'lap-2')!.rank).toBe(0);
  });
  it('gives only genuinely active, unblocked, online devices a stream', () => {
    const layout = layoutFlow(fleet(), SIZE);
    const get = (id: string) => layout.nodes.find((n) => n.deviceId === id)!;
    expect(get('lap-1').hasStream).toBe(true);
    expect(get('lap-1').downParticles).toBeGreaterThan(0);
    expect(get('lap-1').upParticles).toBeGreaterThan(0);
    expect(get('lap-2').hasStream).toBe(false);
    expect(get('cam-2').hasStream).toBe(false); // blocked never shows a stream
    expect(get('cam-2').share).toBeGreaterThan(0); // counted in the aggregate, so it keeps a share (but no stream)
    expect(get('ph-2').hasStream).toBe(false);
    expect(get('x-1').hasStream).toBe(false); // unavailable counters: neutral, no stream
    expect(get('x-1').rate).toBeNull();
    expect(get('x-1').share).toBe(0);
    expect(get('x-1').status).toBe('unavailable');
  });
  it('computes shares over every device the service aggregate covers, so they sum to one', () => {
    const layout = layoutFlow(fleet(), SIZE);
    const sum = layout.nodes.reduce((s, n) => s + n.share, 0);
    expect(sum).toBeCloseTo(1, 6);
    const tv = layout.nodes.find((n) => n.deviceId === 'tv-1')!;
    const lap3 = layout.nodes.find((n) => n.deviceId === 'lap-3')!;
    expect(tv.downLane).toBeGreaterThan(lap3.downLane);
    expect(tv.radius).toBeGreaterThan(lap3.radius);
  });
  it('separates upload and download lanes and respects the particle cap for 200 busy devices', () => {
    const busy = Array.from({ length: 200 }, (_, i) => device(`b-${i}`, { type: 'laptop', rate: [5_000_000 + i, 4_000_000] }));
    const layout = layoutFlow(busy, SIZE);
    const particles = layout.nodes.reduce((s, n) => s + n.downParticles + n.upParticles, 0);
    expect(particles).toBeLessThanOrEqual(MAX_PARTICLES);
    expect(particles).toBeGreaterThan(0);
  });
  it('shrinks nodes for dense networks but never below 60 percent', () => {
    const mk = (n: number) => Array.from({ length: n }, (_, i) => device(`d-${String(i).padStart(3, '0')}`, { type: 'laptop', rate: [5_000_000, 0] }));
    const small = layoutFlow(mk(20), SIZE).nodes[0]!.radius;
    const dense = layoutFlow(mk(150), SIZE).nodes[0]!.radius;
    expect(dense).toBeLessThan(small);
    expect(dense).toBeGreaterThanOrEqual(small * 0.6 - 0.01);
    expect(layoutFlow(mk(40), SIZE).nodes[0]!.radius).toBeCloseTo(small);
  });
  it('still labels top talkers among 150 crowded devices', () => {
    const many = Array.from({ length: 150 }, (_, i) => device(`m-${String(i).padStart(3, '0')}`, { type: 'laptop', rate: i < 4 ? [(10 - i) * 1_000_000, 0] : [i * 100, 0] }));
    const layout = layoutFlow(many, SIZE);
    const talkers = topTalkers(layout.nodes);
    const labels = placeLabels(talkers, layout.nodes, new Map(talkers.map((t) => [t.deviceId, 90])), layout.geo);
    expect(talkers).toHaveLength(4);
    expect(labels.length).toBeGreaterThanOrEqual(3);
  });
  it('reports honest states', () => {
    expect(layoutFlow([], SIZE).state).toBe('empty');
    expect(layoutFlow([device('a', { rate: null })], SIZE).state).toBe('no-counters');
    expect(layoutFlow([device('a')], SIZE).state).toBe('live');
    const off = layoutFlow(fleet(), SIZE, false);
    expect(off.state).toBe('offline');
    expect(off.nodes.length).toBe(10);
    expect(off.nodes.every((n) => !n.hasStream && n.downParticles === 0 && n.upParticles === 0)).toBe(true);
    expect(layoutFlow([], SIZE, false).state).toBe('offline');
    expect(flowStateCopy('live')).toBeNull();
    for (const s of ['offline', 'empty', 'no-counters'] as const) expect(flowStateCopy(s)!.title.length).toBeGreaterThan(3);
  });
  it('handles a single device and malformed rates without NaN', () => {
    const layout = layoutFlow([device('solo', { rate: [Infinity, -5] })], SIZE);
    const n = layout.nodes[0]!;
    expect(Number.isFinite(n.x) && Number.isFinite(n.y)).toBe(true);
    expect(n.status).toBe('unavailable');
  });
  it('plans rings from the core outward and clamps overflow to the rim', () => {
    const plan = planRings(10, 1, 100, 200, 20, 20);
    expect(plan.radii[0]).toBe(100);
    expect(plan.counts.reduce((a, b) => a + b, 0)).toBe(10);
    const tight = planRings(500, 0.3, 100, 130, 20, 20);
    expect(Math.max(...tight.radii)).toBeLessThanOrEqual(130 + 0.5);
  });
});

describe('geometry and streams', () => {
  it('scales the canvas for phones and keeps a sane unit', () => {
    expect(flowCanvasSize(390).height).toBeGreaterThan(390);
    expect(flowCanvasSize(900).height).toBeLessThanOrEqual(590);
    const small = flowGeometry({ width: 320, height: 340 });
    const big = flowGeometry({ width: 760, height: 560 });
    expect(small.unit).toBeLessThan(big.unit);
    expect(small.coreR).toBeGreaterThanOrEqual(32);
    expect(big.nodeMin).toBeGreaterThan(big.histBase + big.histOut);
    expect(big.nodeMax).toBeGreaterThan(big.nodeMin);
  });
  it('draws a curve from the core rim to the node rim, bending consistently', () => {
    const geo = flowGeometry(SIZE);
    const x = geo.cx + 200; const y = geo.cy;
    const c = streamCurve(geo, x, y, 6);
    expect(Math.hypot(c.x0 - geo.cx, c.y0 - geo.cy)).toBeLessThan(geo.coreR);
    expect(Math.hypot(c.x1 - x, c.y1 - y)).toBeCloseTo(7.5, 1);
    expect(c.cy).toBeGreaterThan(geo.cy); // swirl bends clockwise on screen
    const p0 = curvePoint(c, 0); const p1 = curvePoint(c, 1);
    expect(p0.x).toBeCloseTo(c.x0); expect(p1.y).toBeCloseTo(c.y1);
    const tan = curveTangent(c, 0.5);
    expect(Math.hypot(tan.x, tan.y)).toBeCloseTo(1);
    expect(tan.x).toBeGreaterThan(0); // heads outward
  });
});

describe('history ring', () => {
  const geo = flowGeometry(SIZE);
  it('places the newest sample at 12 o clock and sweeps clockwise to the oldest', () => {
    expect(historyAngle(0)).toBeCloseTo(TOP + TAU);
    expect(Math.cos(historyAngle(0))).toBeCloseTo(0);
    expect(Math.sin(historyAngle(0))).toBeCloseTo(-1);
    expect(historyAngle(1)).toBeCloseTo(TOP);
    expect(historyAngle(0.5)).toBeCloseTo(TOP + Math.PI); // 6 o'clock halfway through the window
    expect(historyAngle(0.75)).toBeGreaterThan(historyAngle(1)); // older = earlier in the clockwise sweep
    expect(historyAngle(-3)).toBeCloseTo(historyAngle(0));
  });
  it('puts download outside the baseline and upload inside it', () => {
    expect(historyRadius(geo, 'down', 0)).toBe(geo.histBase);
    expect(historyRadius(geo, 'up', 0)).toBe(geo.histBase);
    expect(historyRadius(geo, 'down', 1)).toBeCloseTo(geo.histBase + geo.histOut);
    expect(historyRadius(geo, 'up', 1)).toBeCloseTo(geo.histBase - geo.histIn);
    expect(historyRadius(geo, 'up', 5)).toBeCloseTo(geo.histBase - geo.histIn);
    expect(geo.histBase - geo.histIn).toBeGreaterThan(geo.coreR);
  });
  it('builds points only from real samples inside the window', () => {
    expect(historyPoints([], 1000, geo, 'down')).toEqual([]);
    const now = 100_000;
    const pts = historyPoints([{ at: now - 70_000, down: 1e6, up: 0 }, { at: now - 30_000, down: 1e6, up: 0 }, { at: now, down: 0, up: 1e6 }], now, geo, 'down');
    expect(pts).toHaveLength(2);
    expect(pts[1]!.ageFraction).toBe(0);
    expect(pts[1]!.x).toBeCloseTo(geo.cx); expect(pts[1]!.y).toBeLessThan(geo.cy);
  });
  it('samples at most once a second, caps at 60 and drops old data', () => {
    let buf: readonly ReturnType<typeof pushHistory>[number][] = [];
    buf = pushHistory(buf, { at: 0, down: 1, up: 1 });
    expect(buf).toHaveLength(1);
    expect(pushHistory(buf, { at: 400, down: 2, up: 2 })).toBe(buf);
    for (let i = 1; i <= 100; i += 1) buf = pushHistory(buf, { at: i * 1000, down: i, up: i });
    expect(buf.length).toBeLessThanOrEqual(HISTORY_MAX_SAMPLES);
    expect(buf[buf.length - 1]!.at).toBe(100_000);
    expect(buf[0]!.at).toBeGreaterThanOrEqual(100_000 - HISTORY_WINDOW_MS);
  });
  it('ignores invalid readings instead of drawing fake data', () => {
    const empty: readonly never[] = [];
    expect(pushHistory(empty, { at: 0, down: NaN, up: 1 })).toBe(empty);
    expect(pushHistory(empty, { at: 0, down: -1, up: 1 })).toBe(empty);
    expect(pushHistory(empty, { at: Infinity, down: 1, up: 1 })).toBe(empty);
  });
});

function node(id: string, x: number, y: number, rate: number, extra: Partial<FlowNode> = {}): FlowNode {
  return { deviceId: id, label: id, group: 'computers', presence: 'online', status: 'active', rate, down: rate, up: 0, share: 0, rank: 0, x, y, angle: Math.atan2(y - 280, x - 380), radius: 6, hasStream: true, downLane: 1, upLane: 0, downParticles: 1, upParticles: 0, downSpeed: 0.2, upSpeed: 0, seed: 0, ...extra };
}

describe('top talkers and labels', () => {
  it('picks the busiest few and ignores insignificant or non-live devices', () => {
    const nodes = [node('a', 100, 100, 5e6), node('b', 200, 100, 4e6), node('c', 300, 100, 3e6), node('d', 400, 100, 2e6), node('e', 500, 100, 1e6), node('tiny', 600, 100, 10_000), node('blocked', 50, 50, 9e9, { status: 'blocked' }), node('nocount', 60, 60, 0, { status: 'unavailable', rate: null })];
    expect(topTalkers(nodes).map((n) => n.deviceId)).toEqual(['a', 'b', 'c', 'd']);
    expect(topTalkers(nodes, 2).map((n) => n.deviceId)).toEqual(['a', 'b']);
    expect(topTalkers([node('tiny', 1, 1, 10_000)])).toEqual([]);
  });
  it('places labels without overlap, off the core and inside the canvas, dropping what cannot fit', () => {
    const geo = flowGeometry(SIZE);
    const talkers = [node('a', geo.cx + 150, geo.cy - 10, 5e6), node('b', geo.cx + 150, geo.cy + 6, 4e6), node('c', geo.cx + 152, geo.cy + 20, 3e6), node('d', 8, geo.cy, 2e6, { angle: Math.PI })];
    const widths = new Map(talkers.map((t) => [t.deviceId, 90]));
    const labels = placeLabels(talkers, talkers, widths, geo);
    const rects = labels.map((l) => { const t = talkers.find((x) => x.deviceId === l.deviceId)!; return { x: t.x + l.dx, y: t.y + l.dy, w: l.w, h: l.h }; });
    for (let i = 0; i < rects.length; i += 1) {
      const r = rects[i]!;
      expect(r.x).toBeGreaterThanOrEqual(0); expect(r.y).toBeGreaterThanOrEqual(0);
      expect(r.x + r.w).toBeLessThanOrEqual(geo.width); expect(r.y + r.h).toBeLessThanOrEqual(geo.height);
      for (let j = i + 1; j < rects.length; j += 1) {
        const s = rects[j]!;
        expect(r.x < s.x + s.w && r.x + r.w > s.x && r.y < s.y + s.h && r.y + r.h > s.y).toBe(false);
      }
    }
    expect(labels.length).toBeGreaterThanOrEqual(2);
    expect(labels.find((l) => l.deviceId === 'a')).toBeTruthy();
  });
  it('flips to the other side when the preferred side would leave the canvas', () => {
    const geo = flowGeometry(SIZE);
    const edge = node('edge', geo.width - 12, 40, 5e6, { angle: 0.2 });
    const [label] = placeLabels([edge], [edge], new Map([['edge', 100]]), geo);
    expect(label).toBeTruthy();
    expect(label!.align).toBe('left');
  });
  it('avoids obstacles such as rim labels', () => {
    const geo = flowGeometry(SIZE);
    const n = node('a', geo.cx + 150, 60, 5e6, { angle: 0.3 });
    const blocker = { x: n.x + 6, y: n.y - 160, w: 120, h: 320 };
    const [label] = placeLabels([n], [n], new Map([['a', 90]]), geo, [blocker]);
    expect(label?.align).toBe('left');
  });
});

describe('hit testing', () => {
  it('finds the nearest node with a minimum 12px target', () => {
    const nodes = [{ x: 50, y: 50, radius: 3 }, { x: 62, y: 50, radius: 3 }];
    expect(nodeAt(nodes, 51, 50)).toBe(nodes[0]);
    expect(nodeAt(nodes, 61, 50)).toBe(nodes[1]);
    expect(nodeAt(nodes, 50, 63)).toBeNull();
    expect(nodeAt([], 1, 1)).toBeNull();
    expect(nodeAt([{ x: 0, y: 0, radius: 20 }], 24, 0)).not.toBeNull(); // radius + 5 grows the target
  });
});

describe('describeFlow', () => {
  const fmt = formatThroughput;
  it('summarises the live network with top talkers', () => {
    const layout = layoutFlow(fleet(), SIZE);
    const text = describeFlow({ connected: true, upload: 125_000, download: 1_250_000, nodes: layout.nodes, format: fmt });
    expect(text).toContain('Network flow map: 11 Mbps total');
    expect(text).toContain('10 Mbps down');
    expect(text).toContain('1.0 Mbps up');
    expect(text).toContain('8 of 10 devices online'.replace('8', String(layout.nodes.filter((n) => n.presence === 'online').length)));
    expect(text).toContain('1 blocked');
    expect(text).toContain('Top talkers: Device tv-1');
  });
  it('names the missing collector and missing counters honestly', () => {
    expect(describeFlow({ connected: false, upload: null, download: null, nodes: [], format: fmt })).toBe('Network flow map: collector connection unavailable; reconnect or sign in if requested.');
    const layout = layoutFlow([device('a', { rate: null })], SIZE);
    const text = describeFlow({ connected: true, upload: null, download: null, nodes: layout.nodes, format: fmt });
    expect(text).toContain('unavailable total');
    expect(text).toContain('Per-device counters unavailable.');
    expect(text).not.toContain('Top talkers');
  });
});
