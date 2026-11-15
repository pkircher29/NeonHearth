<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import type { DeviceSnapshot } from '../api/types';
  import {
    FIRE, DOWN_RAMP, UP_RAMP, TAU, TOP, HISTORY_BREAK_MS, HISTORY_WINDOW_MS, buildRamp, curvePoint, curveTangent, describeFlow, easeToward, flowCanvasSize,
    flowStateCopy, groupLabel, groupLabelRect, historyAngle, historyRadius, layoutFlow, nodeAt, particlePhase, placeLabels, pushHistory, rateFraction,
    streamCurve, topTalkers, type FlowLayout, type HistorySample, type PlacedLabel, type Rect
  } from './flowMap';
  import { formatThroughput } from './networkFormat';
  import { MOTION_KEY, motionReduced } from '../stores/preferences';

  interface Props {
    devices?: readonly DeviceSnapshot[];
    upload?: number | null;
    download?: number | null;
    connected?: boolean;
    paused?: boolean;
    onselect?: (deviceId: string) => void;
  }
  let { devices = [], upload = null, download = null, connected = false, paused = false, onselect }: Props = $props();

  const FONT_UI = '"Instrument Sans Variable", "Instrument Sans", "Segoe UI", Helvetica, Arial, sans-serif';
  const FONT_MONO = '"IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace';
  const LUT = 24;

  let wrap = $state<HTMLDivElement | null>(null);
  let canvas = $state<HTMLCanvasElement | null>(null);
  let size = $state(flowCanvasSize(760));
  let hoveredId = $state<string | null>(null);
  let prefersReduced = $state(typeof window !== 'undefined' && motionReduced());
  let pageHidden = $state(false);
  let fontTick = $state(0);

  const animate = $derived(!paused && !prefersReduced && !pageHidden);
  const layout = $derived(layoutFlow(devices, size, connected));
  const total = $derived(connected && (upload !== null || download !== null) ? (upload ?? 0) + (download ?? 0) : null);
  const description = $derived(describeFlow({ connected, upload, download, nodes: layout.nodes, format: formatThroughput }));
  const stateCopy = $derived(flowStateCopy(layout.state));
  const hovered = $derived(hoveredId ? layout.nodes.find((node) => node.deviceId === hoveredId) ?? null : null);

  // ---- Non-reactive draw state (kept out of $state so the frame loop never allocates reactive proxies) ----
  let ctx: CanvasRenderingContext2D | null = null;
  let history: readonly HistorySample[] = [];
  let scene: { layout: FlowLayout; connected: boolean; total: number | null; upload: number | null; download: number | null; labels: PlacedLabel[]; labelText: Map<string, { name: string; rate: string; w: number }>; groupRects: Rect[]; hoverId: string | null } | null = null;
  const current = new Map<string, { x: number; y: number }>();
  let drawn: Array<{ deviceId: string; x: number; y: number; radius: number }> = [];
  let snap = true;
  let lastGeoKey = '';
  let down = buildRamp(DOWN_RAMP.from, DOWN_RAMP.to, LUT);
  let up = buildRamp(UP_RAMP.from, UP_RAMP.to, LUT);
  let ink = '#e9fbfc';
  let muted = '#77959d';
  let alert: string = FIRE.alert;

  // Existing app.css tokens first (--gold, --ink, --muted, --risk, --blue); the design-doc --fire-* tokens if a
  // theme defines them; hex fallbacks only where the app has no equivalent (orange, violet, magenta).
  let quiet: string = FIRE.violet;
  function readPalette() {
    if (typeof document === 'undefined' || typeof getComputedStyle !== 'function') return;
    const style = getComputedStyle(document.documentElement);
    const pick = (names: string[], fallback: string) => {
      for (const name of names) { const value = style.getPropertyValue(name).trim(); if (/^#[0-9a-f]{6}$/i.test(value)) return value; }
      return fallback;
    };
    down = buildRamp(pick(['--fire-orange'], DOWN_RAMP.from), pick(['--fire-gold', '--gold'], DOWN_RAMP.to), LUT);
    up = buildRamp(pick(['--fire-violet'], UP_RAMP.from), pick(['--fire-magenta'], UP_RAMP.to), LUT);
    quiet = pick(['--fire-violet'], FIRE.violet);
    ink = pick(['--ink'], ink);
    muted = pick(['--muted'], muted);
    alert = pick(['--alert', '--risk'], FIRE.alert);
  }

  function rgba(hex: string, alpha: number): string {
    const value = parseInt(hex.slice(1), 16);
    return `rgba(${(value >> 16) & 255}, ${(value >> 8) & 255}, ${value & 255}, ${alpha})`;
  }

  function measure(text: string, font: string): number {
    if (ctx) { ctx.font = font; const width = ctx.measureText(text).width; if (Number.isFinite(width) && width > 0) return width; }
    return text.length * 6.4;
  }

  function truncate(text: string, max: number): string { return text.length > max ? `${text.slice(0, max - 1)}…` : text; }

  // Rebuilt only when the layout (data or size) changes, never per frame.
  function buildScene() {
    const l = layout;
    const u = l.geo.unit;
    const nameFont = `600 ${Math.max(10.5, 11.5 * u)}px ${FONT_UI}`;
    const rateFont = `500 ${Math.max(9.5, 10 * u)}px ${FONT_MONO}`;
    const talkers = topTalkers(l.nodes);
    const labelText = new Map<string, { name: string; rate: string; w: number }>();
    for (const node of talkers) {
      const name = truncate(node.label, 20);
      const rate = formatThroughput(node.rate);
      labelText.set(node.deviceId, { name, rate, w: Math.max(measure(name, nameFont), measure(rate, rateFont)) + 12 });
    }
    const groupFont = `500 ${Math.max(9.5, 10 * u)}px ${FONT_MONO}`;
    const groupRects = l.groups.map((group) => groupLabelRect(group, measure(`${group.label.toUpperCase()} ${group.count}`, groupFont) + 4));
    const widths = new Map<string, number>([...labelText].map(([id, value]) => [id, value.w]));
    const labels = placeLabels(talkers, l.nodes, widths, l.geo, groupRects, Math.max(25, 26 * u));
    scene = { layout: l, connected, total, upload, download, labels, labelText, groupRects, hoverId: hoveredId };
    drawn = l.nodes.map((node) => ({ deviceId: node.deviceId, x: node.x, y: node.y, radius: node.radius }));
    const known = new Set(l.nodes.map((node) => node.deviceId));
    for (const id of [...current.keys()]) if (!known.has(id)) current.delete(id);
    const geoKey = `${l.geo.width}x${l.geo.height}`;
    if (geoKey !== lastGeoKey) { snap = true; lastGeoKey = geoKey; }
  }

  function paint(now: number, dt: number, moving: boolean) {
    const c = ctx;
    const s = scene;
    if (!c || !s) return;
    const L = s.layout;
    const g = L.geo;
    const u = g.unit;
    const seconds = now / 1000;
    const live = s.connected;
    const dim = live ? 1 : 0.32;
    const totalFraction = rateFraction(s.total);
    const emberIndex = Math.round(totalFraction * (LUT - 1));
    const wall = Date.now();

    c.clearRect(0, 0, g.width, g.height);
    c.globalAlpha = 1;
    c.globalCompositeOperation = 'source-over';

    // Backdrop: a warm bloom that follows total activity, plus faint guide rings.
    const bloom = c.createRadialGradient(g.cx, g.cy, g.coreR * 0.5, g.cx, g.cy, g.nodeMax + 30);
    bloom.addColorStop(0, rgba(down[emberIndex]!, live ? 0.07 + 0.13 * totalFraction : 0.04));
    bloom.addColorStop(0.55, rgba(FIRE.violet, live ? 0.035 : 0.015));
    bloom.addColorStop(1, 'rgba(0,0,0,0)');
    c.fillStyle = bloom;
    c.fillRect(0, 0, g.width, g.height);
    c.lineWidth = 1;
    c.strokeStyle = 'rgba(233,251,252,0.045)';
    c.setLineDash([2, 6]);
    c.beginPath(); c.arc(g.cx, g.cy, g.nodeMin - 8 * u, 0, TAU); c.stroke();
    c.beginPath(); c.arc(g.cx, g.cy, g.nodeMax + 8 * u, 0, TAU); c.stroke();
    c.setLineDash([]);

    // Group rails and rim labels.
    c.font = `500 ${Math.max(9.5, 10 * u)}px ${FONT_MONO}`;
    c.textBaseline = 'middle';
    if ('letterSpacing' in c) (c as unknown as { letterSpacing: string }).letterSpacing = '0.6px';
    for (const group of L.groups) {
      const f = rateFraction(group.rate);
      c.beginPath();
      c.lineCap = 'round';
      c.lineWidth = 2.2 * u + 0.8;
      c.strokeStyle = f > 0 && live ? rgba(down[Math.round(f * (LUT - 1))]!, 0.75) : 'rgba(233,251,252,0.16)';
      c.arc(g.cx, g.cy, g.rimR, group.start + 0.012, group.end - 0.012);
      c.stroke();
      const caption = `${group.label.toUpperCase()} ${group.count}`;
      c.globalAlpha = live ? 1 : 0.6;
      c.textAlign = group.align;
      if (g.compact) { const w = c.measureText(caption).width + 10; c.fillStyle = 'rgba(10,12,20,0.88)'; c.fillRect(group.labelX - w / 2, group.labelY - 8, w, 16); }
      c.fillStyle = muted;
      c.fillText(caption, group.labelX, group.labelY);
      c.globalAlpha = 1;
    }
    if ('letterSpacing' in c) (c as unknown as { letterSpacing: string }).letterSpacing = '0px';

    // 60 second history ring: download outside the baseline, upload inside; newest at 12 o'clock.
    c.lineCap = 'butt';
    c.lineWidth = 1;
    c.strokeStyle = 'rgba(233,251,252,0.14)';
    c.beginPath(); c.arc(g.cx, g.cy, g.histBase, 0, TAU); c.stroke();
    c.strokeStyle = 'rgba(233,251,252,0.05)';
    c.beginPath(); c.arc(g.cx, g.cy, g.histBase + g.histOut, 0, TAU); c.stroke();
    c.beginPath(); c.arc(g.cx, g.cy, g.histBase - g.histIn, 0, TAU); c.stroke();
    if (live && history.length) {
      for (const side of ['down', 'up'] as const) {
        const lut = side === 'down' ? down : up;
        let segStart = -1;
        for (let i = 0; i <= history.length; i += 1) {
          const gapBreak = i < history.length && i > 0 && history[i]!.at - history[i - 1]!.at > HISTORY_BREAK_MS;
          if (i < history.length && segStart < 0) segStart = i;
          if ((i === history.length || gapBreak) && segStart >= 0) {
            const end = i - 1;
            // Polygon between the baseline and the trace, then the trace itself.
            c.beginPath();
            let first = true;
            let firstAngle = 0;
            let lastAngle = 0;
            for (let k = segStart; k <= end; k += 1) {
              const sample = history[k]!;
              const age = wall - sample.at;
              if (age < 0 || age > HISTORY_WINDOW_MS) continue;
              const angle = historyAngle(age / HISTORY_WINDOW_MS);
              const r = historyRadius(g, side, rateFraction(side === 'down' ? sample.down : sample.up));
              if (first) { c.moveTo(g.cx + Math.cos(angle) * g.histBase, g.cy + Math.sin(angle) * g.histBase); firstAngle = angle; first = false; }
              c.lineTo(g.cx + Math.cos(angle) * r, g.cy + Math.sin(angle) * r);
              lastAngle = angle;
            }
            if (!first) {
              c.lineTo(g.cx + Math.cos(lastAngle) * g.histBase, g.cy + Math.sin(lastAngle) * g.histBase);
              c.arc(g.cx, g.cy, g.histBase, lastAngle, firstAngle, true);
              c.closePath();
              c.globalAlpha = 0.34;
              c.fillStyle = lut[Math.round(0.45 * (LUT - 1))]!;
              c.fill();
              c.globalAlpha = 1;
              // Re-trace the outer edge for the crisp line.
              c.beginPath();
              let started = false;
              for (let k = segStart; k <= end; k += 1) {
                const sample = history[k]!;
                const age = wall - sample.at;
                if (age < 0 || age > HISTORY_WINDOW_MS) continue;
                const angle = historyAngle(age / HISTORY_WINDOW_MS);
                const r = historyRadius(g, side, rateFraction(side === 'down' ? sample.down : sample.up));
                if (started) c.lineTo(g.cx + Math.cos(angle) * r, g.cy + Math.sin(angle) * r); else { c.moveTo(g.cx + Math.cos(angle) * r, g.cy + Math.sin(angle) * r); started = true; }
              }
              c.lineWidth = 1.5 * Math.max(0.8, u);
              c.lineJoin = 'round';
              c.strokeStyle = lut[Math.round(0.8 * (LUT - 1))]!;
              c.stroke();
            }
            segStart = gapBreak ? i : -1;
          }
        }
      }
    }
    // "Now" tick at 12 o'clock.
    c.lineWidth = 1.2;
    c.strokeStyle = 'rgba(233,251,252,0.55)';
    c.beginPath();
    c.moveTo(g.cx, g.cy - g.histBase + g.histIn + 2);
    c.lineTo(g.cx, g.cy - g.histBase - g.histOut - 5 * u);
    c.stroke();
    // Ease drawn positions toward the layout targets (snap when resting, resized or first seen).
    const easing = moving && !snap && dt > 0;
    for (let i = 0; i < L.nodes.length; i += 1) {
      const node = L.nodes[i]!;
      let pos = current.get(node.deviceId);
      if (!pos) { pos = { x: node.x, y: node.y }; current.set(node.deviceId, pos); }
      if (easing) { pos.x = easeToward(pos.x, node.x, dt); pos.y = easeToward(pos.y, node.y, dt); } else { pos.x = node.x; pos.y = node.y; }
      const d = drawn[i];
      if (d) { d.x = pos.x; d.y = pos.y; d.radius = node.radius; d.deviceId = node.deviceId; }
    }
    snap = false;

    // Streams.
    c.lineCap = 'round';
    c.globalAlpha = dim;
    for (let i = 0; i < L.nodes.length; i += 1) {
      const node = L.nodes[i]!;
      if (node.hasStream || !live) continue;
      if (node.status !== 'idle' && node.status !== 'quiet') continue;
      const p = current.get(node.deviceId)!;
      const curve = streamCurve(g, p.x, p.y, node.radius);
      c.beginPath(); c.moveTo(curve.x0, curve.y0); c.quadraticCurveTo(curve.cx, curve.cy, curve.x1, curve.y1);
      c.lineWidth = 0.8; c.strokeStyle = 'rgba(233,251,252,0.11)'; c.stroke();
    }
    if (live) {
      for (let i = L.nodes.length - 1; i >= 0; i -= 1) {
        const node = L.nodes[i]!;
        if (!node.hasStream) continue;
        const p = current.get(node.deviceId)!;
        const curve = streamCurve(g, p.x, p.y, node.radius);
        const vx = curve.x1 - curve.x0;
        const vy = curve.y1 - curve.y0;
        const len = Math.hypot(vx, vy) || 1;
        const nx = -vy / len;
        const ny = vx / len;
        const both = node.downLane > 0 && node.upLane > 0;
        const offD = both ? node.downLane / 2 + 0.6 : 0;
        const offU = both ? -(node.upLane / 2 + 0.6) : 0;
        for (const lane of [0, 1] as const) {
          const width = lane === 0 ? node.downLane : node.upLane;
          if (width <= 0) continue;
          const off = lane === 0 ? offD : offU;
          const lut = lane === 0 ? down : up;
          const ox = nx * off;
          const oy = ny * off;
          // Lane base: a faint band so the direction reads even between particles.
          c.beginPath();
          c.moveTo(curve.x0 + ox, curve.y0 + oy);
          c.quadraticCurveTo(curve.cx + ox, curve.cy + oy, curve.x1 + ox, curve.y1 + oy);
          c.lineWidth = width;
          c.strokeStyle = lut[Math.round(0.5 * (LUT - 1))]!;
          c.globalAlpha = (moving ? 0.17 : 0.28) * dim;
          c.stroke();
          if (!moving) {
            // Static frame: solid ramp toward the destination, plus a direction arrowhead.
            const segments = 12;
            c.globalAlpha = 0.92 * dim;
            c.lineWidth = Math.max(1, width * 0.7);
            for (let k = 0; k < segments; k += 1) {
              const t0 = k / segments;
              const t1 = (k + 1) / segments;
              const a = curvePoint(curve, t0);
              const b = curvePoint(curve, t1);
              const ramp = lane === 0 ? (t0 + t1) / 2 : 1 - (t0 + t1) / 2;
              c.beginPath(); c.moveTo(a.x + ox, a.y + oy); c.lineTo(b.x + ox, b.y + oy);
              c.strokeStyle = lut[Math.round(ramp * (LUT - 1))]!; c.stroke();
            }
            const at = lane === 0 ? 0.64 : 0.4;
            const pt = curvePoint(curve, at);
            const tan = curveTangent(curve, at);
            const dirX = lane === 0 ? tan.x : -tan.x;
            const dirY = lane === 0 ? tan.y : -tan.y;
            const sz = 3.6 * u + width * 0.9;
            const bx = pt.x + ox - dirX * sz * 0.6;
            const by = pt.y + oy - dirY * sz * 0.6;
            c.beginPath();
            c.moveTo(pt.x + ox + dirX * sz, pt.y + oy + dirY * sz);
            c.lineTo(bx - dirY * sz * 0.62, by + dirX * sz * 0.62);
            c.lineTo(bx + dirY * sz * 0.62, by - dirX * sz * 0.62);
            c.closePath();
            c.fillStyle = lut[lane === 0 ? LUT - 1 : LUT - 1]!;
            c.globalAlpha = dim;
            c.fill();
          }
        }
        if (moving) {
          c.globalCompositeOperation = 'lighter';
          for (const lane of [0, 1] as const) {
            const count = lane === 0 ? node.downParticles : node.upParticles;
            const width = lane === 0 ? node.downLane : node.upLane;
            if (count <= 0 || width <= 0) continue;
            const speed = lane === 0 ? node.downSpeed : node.upSpeed;
            const off = lane === 0 ? offD : offU;
            const lut = lane === 0 ? down : up;
            const pr = Math.max(1.05 * u, width * 0.46 + 0.5);
            for (let k = 0; k < count; k += 1) {
              const t = particlePhase(k, count, seconds, speed, node.seed + lane * 0.37);
              const tt = lane === 0 ? t : 1 - t;
              const kk = 1 - tt;
              const px = kk * kk * curve.x0 + 2 * kk * tt * curve.cx + tt * tt * curve.x1 + nx * off;
              const py = kk * kk * curve.y0 + 2 * kk * tt * curve.cy + tt * tt * curve.y1 + ny * off;
              const fade = Math.sin(Math.PI * t);
              c.fillStyle = lut[Math.round((lane === 0 ? t : 1 - t) * (LUT - 1))]!;
              c.globalAlpha = 0.2 * fade * dim;
              c.beginPath(); c.arc(px, py, pr * 2.4, 0, TAU); c.fill();
              c.globalAlpha = Math.min(1, 0.35 + fade) * dim;
              c.beginPath(); c.arc(px, py, pr, 0, TAU); c.fill();
            }
          }
          c.globalCompositeOperation = 'source-over';
        }
        c.globalAlpha = dim;
      }
    }

    // Nodes.
    c.setLineDash([]);
    for (let i = 0; i < L.nodes.length; i += 1) {
      const node = L.nodes[i]!;
      const p = current.get(node.deviceId)!;
      const r = node.radius;
      c.globalAlpha = dim;
      switch (node.status) {
        case 'offline':
          c.beginPath(); c.lineWidth = 1.3; c.strokeStyle = rgba(ink, 0.38); c.arc(p.x, p.y, r, 0, TAU); c.stroke();
          break;
        case 'blocked':
          c.beginPath(); c.fillStyle = rgba(alert, 0.14); c.arc(p.x, p.y, r + 1, 0, TAU); c.fill();
          c.beginPath(); c.lineWidth = 2.2; c.strokeStyle = alert; c.arc(p.x, p.y, r + 1, 0, TAU); c.stroke();
          break;
        case 'unknown':
          c.beginPath(); c.lineWidth = 1.3; c.strokeStyle = rgba(ink, 0.5); c.setLineDash([2.4, 2.6]); c.arc(p.x, p.y, r, 0, TAU); c.stroke(); c.setLineDash([]);
          break;
        case 'unavailable':
          c.beginPath(); c.fillStyle = rgba(FIRE.neutral, 0.85); c.arc(p.x, p.y, r, 0, TAU); c.fill();
          break;
        case 'quiet': {
          c.beginPath(); c.fillStyle = rgba(quiet, 0.16); c.arc(p.x, p.y, r * 2, 0, TAU); c.fill();
          c.beginPath(); c.fillStyle = rgba(quiet, 0.8); c.arc(p.x, p.y, r, 0, TAU); c.fill();
          break;
        }
        default: {
          const f = node.status === 'active' ? rateFraction(node.rate) : 0;
          const color = down[Math.round(f * (LUT - 1))]!;
          if (live && f > 0) { c.beginPath(); c.fillStyle = rgba(color, 0.12 + 0.2 * f); c.arc(p.x, p.y, r * (1.9 + f), 0, TAU); c.fill(); }
          c.beginPath(); c.fillStyle = color; c.globalAlpha = (node.status === 'idle' ? 0.78 : 1) * dim; c.arc(p.x, p.y, r, 0, TAU); c.fill();
          if (node.status === 'active') { c.beginPath(); c.fillStyle = 'rgba(255,255,255,0.55)'; c.arc(p.x - r * 0.28, p.y - r * 0.3, r * 0.34, 0, TAU); c.fill(); }
        }
      }
      if (s.hoverId === node.deviceId) {
        c.globalAlpha = 1; c.beginPath(); c.lineWidth = 1.5; c.strokeStyle = 'rgba(233,251,252,0.95)'; c.arc(p.x, p.y, r + 5, 0, TAU); c.stroke();
      }
    }
    c.globalAlpha = 1;

    // Ring captions sit above nodes so a nearby device never hides them.
    c.font = `500 ${Math.max(10, 10 * u)}px ${FONT_MONO}`;
    c.fillStyle = muted;
    c.textBaseline = 'middle';
    const tickTop = g.cy - g.histBase - g.histOut - 5 * u;
    c.textAlign = 'right';
    c.fillText('NOW', g.cx - 4, tickTop - 7);
    c.textAlign = 'left';
    c.fillText('60 s', g.cx + 4, tickTop - 7);

    // Gateway core, drawn over the stream roots.
    const pulse = !live || L.state === 'empty' ? (moving ? 0.5 + 0.5 * Math.sin(seconds * 1.1) : 0.5) : 0;
    const glowR = g.coreR * (1.7 + totalFraction * 0.9);
    const glow = c.createRadialGradient(g.cx, g.cy, g.coreR * 0.6, g.cx, g.cy, glowR);
    glow.addColorStop(0, rgba(down[emberIndex]!, live ? 0.28 + 0.22 * totalFraction : 0.1 + 0.07 * pulse));
    glow.addColorStop(1, rgba(down[emberIndex]!, 0));
    c.fillStyle = glow;
    c.beginPath(); c.arc(g.cx, g.cy, glowR, 0, TAU); c.fill();
    const disk = c.createRadialGradient(g.cx - g.coreR * 0.3, g.cy - g.coreR * 0.4, 2, g.cx, g.cy, g.coreR);
    disk.addColorStop(0, 'rgba(34,28,46,0.97)');
    disk.addColorStop(1, 'rgba(9,11,19,0.98)');
    c.fillStyle = disk;
    c.beginPath(); c.arc(g.cx, g.cy, g.coreR, 0, TAU); c.fill();
    c.lineWidth = 2;
    c.strokeStyle = live ? down[Math.max(3, emberIndex)]! : rgba(FIRE.violet, 0.35 + 0.15 * pulse);
    c.beginPath(); c.arc(g.cx, g.cy, g.coreR, 0, TAU); c.stroke();
    c.lineWidth = 1; c.strokeStyle = 'rgba(233,251,252,0.12)';
    c.beginPath(); c.arc(g.cx, g.cy, g.coreR - 4 * u, 0, TAU); c.stroke();

    c.textAlign = 'center';
    c.textBaseline = 'middle';
    if (live && s.total !== null) {
      const lh = Math.max(11, 12.5 * u);
      c.font = `700 ${Math.max(13, 19 * u)}px ${FONT_UI}`;
      c.fillStyle = ink;
      c.fillText(formatThroughput(s.total), g.cx, g.cy - lh * 0.62);
      c.font = `500 ${Math.max(9, 10.5 * u)}px ${FONT_MONO}`;
      const rows: Array<[number | null, string, number]> = [[s.download, down[LUT - 1]!, 1], [s.upload, up[LUT - 1]!, -1]];
      rows.forEach(([value, color, dir], index) => {
        const text = formatThroughput(value);
        const w = c.measureText(text).width;
        const y = g.cy + lh * (0.62 + index * 1.0);
        const a = 3.4 * Math.max(0.8, u);
        const x0 = g.cx - (w + a * 2 + 4) / 2 + a;
        c.fillStyle = color;
        c.beginPath();
        if (dir > 0) { c.moveTo(x0 - a, y - a * 0.7); c.lineTo(x0 + a, y - a * 0.7); c.lineTo(x0, y + a * 0.8); } else { c.moveTo(x0 - a, y + a * 0.7); c.lineTo(x0 + a, y + a * 0.7); c.lineTo(x0, y - a * 0.8); }
        c.closePath(); c.fill();
        c.textAlign = 'left'; c.fillStyle = ink; c.fillText(text, x0 + a + 4, y); c.textAlign = 'center';
      });
    } else {
      c.font = `600 ${Math.max(10, 11 * u)}px ${FONT_MONO}`;
      c.fillStyle = muted;
      const word = !live ? 'OFFLINE' : L.state === 'empty' ? 'IDLE' : 'NO COUNTERS';
      c.fillText(word === 'NO COUNTERS' ? '—' : word, g.cx, g.cy - (word === 'NO COUNTERS' ? 6 : 0));
      if (word === 'NO COUNTERS') { c.font = `500 ${Math.max(8.5, 9 * u)}px ${FONT_MONO}`; c.fillText('no counters', g.cx, g.cy + 10 * Math.max(0.8, u)); }
    }

    // Always-on labels for the top talkers.
    if (live) {
      const nameFont = `600 ${Math.max(10.5, 11.5 * u)}px ${FONT_UI}`;
      const rateFont = `500 ${Math.max(9.5, 10 * u)}px ${FONT_MONO}`;
      for (const label of s.labels) {
        const p = current.get(label.deviceId);
        const text = s.labelText.get(label.deviceId);
        if (!p || !text) continue;
        const x = p.x + label.dx;
        const y = p.y + label.dy;
        c.fillStyle = 'rgba(8,9,16,0.62)';
        c.beginPath();
        if (typeof c.roundRect === 'function') c.roundRect(x, y, label.w, label.h, 5); else c.rect(x, y, label.w, label.h);
        c.fill();
        c.textAlign = 'left';
        c.font = nameFont; c.fillStyle = ink; c.fillText(text.name, x + 6, y + label.h * 0.34);
        c.font = rateFont; c.fillStyle = down[LUT - 5]!; c.fillText(text.rate, x + 6, y + label.h * 0.74);
      }
    }
  }

  function repaintStatic() {
    if (!animate && ctx) paint(typeof performance !== 'undefined' ? performance.now() : 0, 0, false);
  }

  // Layout/data changed: rebuild the scene; repaint now if nothing is animating.
  $effect(() => {
    void layout; void total; void upload; void download; void connected; void hoveredId; void fontTick;
    untrack(() => { buildScene(); repaintStatic(); });
  });

  // Rolling 60 s history, one sample per second at most, only from real readings.
  $effect(() => {
    const u = upload; const d = download; const ok = connected;
    untrack(() => {
      if (!ok || (u === null && d === null)) return;
      const next = pushHistory(history, { at: Date.now(), down: d ?? 0, up: u ?? 0 });
      if (next !== history) { history = next; repaintStatic(); }
    });
  });

  // Canvas backing store and the frame loop.
  $effect(() => {
    const element = canvas;
    const s = size;
    const moving = animate;
    if (!element) return;
    const context = element.getContext('2d');
    ctx = context;
    if (!context) return;
    const dpr = typeof window !== 'undefined' && window.devicePixelRatio ? Math.min(2, window.devicePixelRatio) : 1;
    const w = Math.round(s.width * dpr);
    const h = Math.round(s.height * dpr);
    if (element.width !== w || element.height !== h) { element.width = w; element.height = h; }
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
    let raf = 0;
    let last = 0;
    const frame = (now: number) => {
      const dt = last ? Math.min(0.1, (now - last) / 1000) : 0;
      last = now;
      paint(now, dt, true);
      raf = requestAnimationFrame(frame);
    };
    untrack(() => {
      if (moving && typeof requestAnimationFrame === 'function') raf = requestAnimationFrame(frame);
      else paint(typeof performance !== 'undefined' ? performance.now() : 0, 0, false);
    });
    return () => { if (raf && typeof cancelAnimationFrame === 'function') cancelAnimationFrame(raf); };
  });

  function point(event: PointerEvent | MouseEvent): { x: number; y: number } | null {
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return null;
    return { x: ((event.clientX - rect.left) / rect.width) * size.width, y: ((event.clientY - rect.top) / rect.height) * size.height };
  }
  function onPointerMove(event: PointerEvent) {
    const p = point(event);
    const hit = p ? nodeAt(drawn, p.x, p.y) : null;
    hoveredId = hit?.deviceId ?? null;
  }
  function onPointerLeave() { hoveredId = null; }
  function onClick(event: MouseEvent) {
    const p = point(event);
    const hit = p ? nodeAt(drawn, p.x, p.y) : null;
    if (hit && onselect) onselect(hit.deviceId);
  }

  onMount(() => {
    readPalette();
    fontTick += 1;
    const media = typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
    prefersReduced = motionReduced();
    const onMedia = () => { prefersReduced = motionReduced(); };
    media?.addEventListener?.('change', onMedia);
    const onStorage = (event: StorageEvent) => { if (event.key === null || event.key === MOTION_KEY) prefersReduced = motionReduced(); };
    window.addEventListener('storage', onStorage);
    window.addEventListener('neonhearth:motion', onMedia);
    const onVisibility = () => { pageHidden = document.hidden; };
    document.addEventListener('visibilitychange', onVisibility);
    let observer: ResizeObserver | null = null;
    const apply = (width: number) => { if (width > 0) { const next = flowCanvasSize(width); if (next.width !== size.width || next.height !== size.height) size = next; } };
    if (wrap) apply(wrap.getBoundingClientRect().width);
    if (wrap && typeof ResizeObserver === 'function') {
      observer = new ResizeObserver((entries) => apply(entries[0]?.contentRect.width ?? 0));
      observer.observe(wrap);
    }
    // Canvas text needs the bundled faces; repaint once they are ready.
    try { void document.fonts?.ready.then(() => { fontTick += 1; }); } catch { /* fonts API unavailable */ }
    return () => { media?.removeEventListener?.('change', onMedia); window.removeEventListener('storage', onStorage); window.removeEventListener('neonhearth:motion', onMedia); document.removeEventListener('visibilitychange', onVisibility); observer?.disconnect(); };
  });
</script>

<div class="flow" class:unavailable={!connected} bind:this={wrap}>
  <div class="stage" class:with-note={stateCopy !== null && layout.state !== 'empty'} role="img" aria-label={description}>
    <canvas
      bind:this={canvas}
      style={`height:${size.height}px`}
      onpointermove={onPointerMove}
      onpointerleave={onPointerLeave}
      onclick={onClick}
      class:pointer={hovered !== null}
    ></canvas>
    {#if stateCopy}
      <div class="note" class:centered={layout.state === 'empty'} style={layout.state === 'empty' ? `top:${layout.geo.cy + layout.geo.histBase + layout.geo.histOut + 26}px` : ''}>
        <strong>{stateCopy.title}</strong><span>{stateCopy.detail}</span>
      </div>
    {/if}
  </div>

  {#if hovered}
    <div class="tip" role="tooltip" style={`left:${Math.min(Math.max(hovered.x, 90), size.width - 90)}px; top:${hovered.y}px`}>
      <strong>{hovered.label}</strong>
      <span>{groupLabel(hovered.group)} · {hovered.presence}</span>
      {#if hovered.rate === null}
        <span>counters unavailable</span>
      {:else}
        <span class="rates"><b class="d">↓ {formatThroughput(hovered.down)}</b><b class="u">↑ {formatThroughput(hovered.up)}</b></span>
      {/if}
    </div>
  {/if}

  {#if onselect && layout.nodes.length}
    <ul class="sr-only">
      {#each layout.nodes as node (node.deviceId)}
        <li><button type="button" onclick={() => onselect?.(node.deviceId)} onfocus={() => (hoveredId = node.deviceId)} onblur={() => { if (hoveredId === node.deviceId) hoveredId = null; }}>{node.label}, {groupLabel(node.group)}, {node.presence}{node.rate === null ? ', counters unavailable' : `, ${formatThroughput(node.rate)}`}</button></li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .flow { position: relative; width: 100%; container-type: inline-size; }
  .stage { position: relative; }
  .stage.with-note { padding-bottom: 84px; }
  canvas { display: block; width: 100%; touch-action: pan-y; }
  canvas.pointer { cursor: pointer; }
  .note { position: absolute; left: 50%; bottom: 12px; transform: translateX(-50%); width: min(86%, 360px); display: grid; gap: 3px; text-align: center; padding: 9px 14px; border: 1px solid var(--line-mid, #20424b); border-radius: 10px; background: rgba(10, 12, 20, 0.66); backdrop-filter: blur(6px); pointer-events: none; }
  .note.centered { bottom: auto; }
  .note strong { font-size: 13px; color: var(--ink, #e9fbfc); }
  .note span { font-size: 12px; line-height: 1.4; color: var(--muted, #77959d); }
  .tip { position: absolute; transform: translate(-50%, calc(-100% - 16px)); background: var(--surface-raised, #102a35); border: 1px solid var(--line-strong, #28505a); border-radius: 8px; padding: 7px 10px; display: grid; gap: 2px; pointer-events: none; white-space: nowrap; font-size: 12px; box-shadow: 0 8px 28px rgba(0, 0, 0, 0.5); }
  .tip strong { color: var(--ink, #e9fbfc); }
  .tip span { color: var(--muted, #77959d); font: 11px var(--font-mono, monospace); text-transform: capitalize; }
  .tip .rates { display: flex; gap: 10px; text-transform: none; }
  .tip .rates b { font-weight: 500; }
  .tip .d { color: #ffb347; }
  .tip .u { color: #c78bff; }
  .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; list-style: none; }
  .sr-only button:focus-visible { position: fixed; left: 12px; bottom: 12px; width: auto; height: auto; clip: auto; padding: 8px 12px; background: var(--surface-raised, #102a35); color: var(--ink, #e9fbfc); border: 1px solid var(--accent, #63f3f0); border-radius: 6px; z-index: 10; }
</style>
