<script lang="ts">
  import { onMount } from 'svelte';
  import type { DeviceSnapshot } from '../api/types';
  import { heatTier } from '../twin/heat';
  import { EMBER_RADIUS, GAUGE_RADII, GAUGE_START, GAUGE_SWEEP, HEARTH_CENTER, HEARTH_HEIGHT, HEARTH_WIDTH, TIER_COLOR, describeHearth, emberEnergy, gaugeFraction, layoutSparks, sparkAt, type Spark } from './hearth';
  import { formatThroughput } from './networkFormat';

  interface Props {
    devices?: readonly DeviceSnapshot[];
    upload?: number | null;
    download?: number | null;
    connected?: boolean;
    paused?: boolean;
    onselect?: (deviceId: string) => void;
  }
  let { devices = [], upload = null, download = null, connected = false, paused = false, onselect }: Props = $props();

  let canvas = $state<HTMLCanvasElement | null>(null);
  let hovered = $state<Spark | null>(null);
  let prefersReduced = $state(false);
  let pageHidden = $state(false);
  let cssScale = $state(1);

  const total = $derived(connected && (upload !== null || download !== null) ? (upload ?? 0) + (download ?? 0) : null);
  const tier = $derived(total === null ? 'unavailable' : heatTier(total));
  const energy = $derived(emberEnergy(total));
  const animate = $derived(!paused && !prefersReduced && !pageHidden);
  const restingSparks = $derived(layoutSparks(devices));
  const description = $derived(describeHearth({ connected, upload, download, sparks: restingSparks, format: formatThroughput }));

  // Sparks as drawn in the most recent frame; hit-testing uses these so the
  // tooltip follows the slow drift instead of the resting layout.
  let drawnSparks: Spark[] = [];

  const GAUGE_TICKS = [125_000, 1_250_000, 12_500_000] as const; // 1, 10, 100 Mbps in bytes/s
  const TICK_LABELS = ['1', '10', '100'];

  function withAlpha(hex: string, alpha: number): string {
    const value = parseInt(hex.slice(1), 16);
    return `rgba(${(value >> 16) & 255}, ${(value >> 8) & 255}, ${value & 255}, ${alpha})`;
  }

  function arc(ctx: CanvasRenderingContext2D, radius: number, fraction: number, color: string, width: number) {
    if (fraction <= 0) return;
    ctx.beginPath();
    ctx.lineWidth = width;
    ctx.lineCap = 'round';
    ctx.strokeStyle = color;
    ctx.arc(HEARTH_CENTER.x, HEARTH_CENTER.y, radius, GAUGE_START, GAUGE_START + GAUGE_SWEEP * Math.min(1, fraction));
    ctx.stroke();
  }

  function draw(ctx: CanvasRenderingContext2D, now: number, live: { devices: readonly DeviceSnapshot[]; upload: number | null; download: number | null; connected: boolean; tier: keyof typeof TIER_COLOR; energy: number; moving: boolean }) {
    const t = now / 1000;
    const drift = live.moving ? t * 0.02 : 0;
    const wobble = live.moving ? (t / 6) % 1 : 0;
    const breath = live.moving ? Math.sin(t * (0.9 + live.energy * 0.9)) : 0;
    const accent = TIER_COLOR[live.tier];
    const online = live.connected;

    ctx.clearRect(0, 0, HEARTH_WIDTH, HEARTH_HEIGHT);

    // Warm backdrop that follows the tier.
    const halo = ctx.createRadialGradient(HEARTH_CENTER.x, HEARTH_CENTER.y, 20, HEARTH_CENTER.x, HEARTH_CENTER.y, 210);
    halo.addColorStop(0, withAlpha(accent, online ? 0.14 * live.energy : 0.04));
    halo.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = halo;
    ctx.fillRect(0, 0, HEARTH_WIDTH, HEARTH_HEIGHT);

    // Gauge tracks.
    ctx.beginPath();
    ctx.lineWidth = 6; ctx.lineCap = 'round'; ctx.strokeStyle = 'rgba(233,251,252,0.07)';
    ctx.arc(HEARTH_CENTER.x, HEARTH_CENTER.y, GAUGE_RADII.download, GAUGE_START, GAUGE_START + GAUGE_SWEEP); ctx.stroke();
    ctx.beginPath();
    ctx.arc(HEARTH_CENTER.x, HEARTH_CENTER.y, GAUGE_RADII.upload, GAUGE_START, GAUGE_START + GAUGE_SWEEP); ctx.stroke();

    // Scale ticks at 1 / 10 / 100 Mbps on the outer track.
    ctx.font = '500 9px "IBM Plex Mono", ui-monospace, monospace';
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    GAUGE_TICKS.forEach((bytesPerSecond, index) => {
      const angle = GAUGE_START + GAUGE_SWEEP * gaugeFraction(bytesPerSecond);
      const inner = GAUGE_RADII.upload + 6, outer = GAUGE_RADII.upload + 11, label = GAUGE_RADII.upload + 20;
      ctx.beginPath(); ctx.lineWidth = 1; ctx.strokeStyle = 'rgba(233,251,252,0.28)';
      ctx.moveTo(HEARTH_CENTER.x + Math.cos(angle) * inner, HEARTH_CENTER.y + Math.sin(angle) * inner);
      ctx.lineTo(HEARTH_CENTER.x + Math.cos(angle) * outer, HEARTH_CENTER.y + Math.sin(angle) * outer);
      ctx.stroke();
      ctx.fillStyle = 'rgba(233,251,252,0.45)';
      ctx.fillText(TICK_LABELS[index]!, HEARTH_CENTER.x + Math.cos(angle) * label, HEARTH_CENTER.y + Math.sin(angle) * label);
    });

    if (online) {
      arc(ctx, GAUGE_RADII.download, gaugeFraction(live.download), TIER_COLOR.cyan, 6);
      arc(ctx, GAUGE_RADII.upload, gaugeFraction(live.upload), TIER_COLOR.gold, 6);
    }

    // Sparks: one per device, outside the gauges.
    drawnSparks = layoutSparks(live.devices, drift, wobble);
    for (const spark of drawnSparks) {
      const isHovered = hovered?.deviceId === spark.deviceId;
      if (spark.presence === 'online' && online) {
        const glow = ctx.createRadialGradient(spark.x, spark.y, 0, spark.x, spark.y, spark.radius * 2.6);
        glow.addColorStop(0, withAlpha(spark.color, 0.35));
        glow.addColorStop(1, withAlpha(spark.color, 0));
        ctx.fillStyle = glow;
        ctx.beginPath(); ctx.arc(spark.x, spark.y, spark.radius * 2.6, 0, Math.PI * 2); ctx.fill();
      }
      ctx.beginPath();
      ctx.fillStyle = withAlpha(spark.color, online ? spark.alpha : 0.25);
      ctx.arc(spark.x, spark.y, spark.radius, 0, Math.PI * 2); ctx.fill();
      if (spark.blocked) {
        ctx.beginPath(); ctx.lineWidth = 1.5; ctx.setLineDash([3, 3]); ctx.strokeStyle = withAlpha(TIER_COLOR.pink, 0.9);
        ctx.arc(spark.x, spark.y, spark.radius + 4, 0, Math.PI * 2); ctx.stroke(); ctx.setLineDash([]);
      }
      if (isHovered) {
        ctx.beginPath(); ctx.lineWidth = 1.5; ctx.strokeStyle = 'rgba(233,251,252,0.95)';
        ctx.arc(spark.x, spark.y, spark.radius + 5, 0, Math.PI * 2); ctx.stroke();
      }
    }

    // The ember. Core stays bright; the glow breathes with energy.
    const emberRadius = EMBER_RADIUS * (1 + 0.035 * breath * live.energy);
    const glowRadius = emberRadius * (1.35 + live.energy * 0.5);
    const glow = ctx.createRadialGradient(HEARTH_CENTER.x, HEARTH_CENTER.y, emberRadius * 0.5, HEARTH_CENTER.x, HEARTH_CENTER.y, glowRadius);
    glow.addColorStop(0, withAlpha(accent, online ? 0.55 : 0.18));
    glow.addColorStop(1, withAlpha(accent, 0));
    ctx.fillStyle = glow;
    ctx.beginPath(); ctx.arc(HEARTH_CENTER.x, HEARTH_CENTER.y, glowRadius, 0, Math.PI * 2); ctx.fill();

    const core = ctx.createRadialGradient(HEARTH_CENTER.x - emberRadius * 0.2, HEARTH_CENTER.y - emberRadius * 0.25, 2, HEARTH_CENTER.x, HEARTH_CENTER.y, emberRadius);
    core.addColorStop(0, online ? 'rgba(255,255,255,0.92)' : 'rgba(233,251,252,0.35)');
    core.addColorStop(0.45, withAlpha(accent, online ? 0.85 : 0.3));
    core.addColorStop(1, withAlpha(accent, online ? 0.35 : 0.12));
    ctx.fillStyle = core;
    ctx.beginPath(); ctx.arc(HEARTH_CENTER.x, HEARTH_CENTER.y, emberRadius, 0, Math.PI * 2); ctx.fill();
    ctx.beginPath(); ctx.lineWidth = 1; ctx.strokeStyle = withAlpha(accent, online ? 0.9 : 0.35);
    ctx.arc(HEARTH_CENTER.x, HEARTH_CENTER.y, emberRadius, 0, Math.PI * 2); ctx.stroke();
  }

  function scaleFromEvent(event: PointerEvent): { x: number; y: number } | null {
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return null;
    return { x: ((event.clientX - rect.left) / rect.width) * HEARTH_WIDTH, y: ((event.clientY - rect.top) / rect.height) * HEARTH_HEIGHT };
  }
  function onPointerMove(event: PointerEvent) {
    const point = scaleFromEvent(event);
    hovered = point ? sparkAt(drawnSparks, point.x, point.y) : null;
  }
  function onPointerLeave() { hovered = null; }
  function onClick() { if (hovered && onselect) onselect(hovered.deviceId); }

  onMount(() => {
    const media = typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
    prefersReduced = media?.matches ?? false;
    const onMedia = (event: MediaQueryListEvent) => { prefersReduced = event.matches; };
    media?.addEventListener?.('change', onMedia);
    const onVisibility = () => { pageHidden = document.hidden; };
    document.addEventListener('visibilitychange', onVisibility);
    let observer: ResizeObserver | null = null;
    if (canvas && typeof ResizeObserver === 'function') {
      observer = new ResizeObserver((entries) => { const width = entries[0]?.contentRect.width; if (width) cssScale = width / HEARTH_WIDTH; });
      observer.observe(canvas);
    }
    return () => { media?.removeEventListener?.('change', onMedia); document.removeEventListener('visibilitychange', onVisibility); observer?.disconnect(); };
  });

  $effect(() => {
    const element = canvas;
    if (!element) return;
    const live = { devices, upload, download, connected, tier, energy, moving: animate };
    // Hover is read so the highlight ring redraws when not animating.
    void hovered;
    const ctx = element.getContext('2d');
    if (!ctx) return;
    const dpr = typeof window !== 'undefined' && window.devicePixelRatio ? Math.min(2, window.devicePixelRatio) : 1;
    if (element.width !== HEARTH_WIDTH * dpr || element.height !== HEARTH_HEIGHT * dpr) { element.width = HEARTH_WIDTH * dpr; element.height = HEARTH_HEIGHT * dpr; }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    let raf = 0;
    const frame = (now: number) => { draw(ctx, now, live); if (live.moving) raf = requestAnimationFrame(frame); };
    if (live.moving && typeof requestAnimationFrame === 'function') raf = requestAnimationFrame(frame);
    else draw(ctx, typeof performance !== 'undefined' ? performance.now() : 0, live);
    return () => { if (raf) cancelAnimationFrame(raf); };
  });
</script>

<div class="hearth" class:unavailable={!connected}>
  <div class="stage" role="img" aria-label={description}>
    <canvas
      bind:this={canvas}
      onpointermove={onPointerMove}
      onpointerleave={onPointerLeave}
      onclick={onClick}
      class:pointer={hovered !== null}
    ></canvas>
    <div class="readout">
      <span class="total">{formatThroughput(total)}</span>
      <span class="split"><b class="down">↓ {formatThroughput(connected ? download : null)}</b><b class="up">↑ {formatThroughput(connected ? upload : null)}</b></span>
    </div>
  </div>

  {#if hovered}
    <div class="tip" role="tooltip" style={`left:${hovered.x * cssScale}px; top:${hovered.y * cssScale}px`}>
      <strong>{hovered.label}</strong>
      <span>{hovered.presence}{hovered.bytesPerSecond === null ? '' : ` · ${formatThroughput(hovered.bytesPerSecond)}`}</span>
    </div>
  {/if}

  {#if onselect && restingSparks.length}
    <ul class="sr-only">
      {#each restingSparks as spark (spark.deviceId)}
        <li><button type="button" onclick={() => onselect?.(spark.deviceId)}>{spark.label}, {spark.presence}{spark.bytesPerSecond === null ? '' : `, ${formatThroughput(spark.bytesPerSecond)}`}</button></li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .hearth { position: relative; width: 100%; container-type: inline-size; }
  .stage { position: relative; }
  canvas { display: block; width: 100%; aspect-ratio: 620 / 330; touch-action: pan-y; }
  canvas.pointer { cursor: pointer; }
  .readout { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); text-align: center; display: grid; gap: 2px; pointer-events: none; padding-top: 2px; }
  .readout .total { font: 700 clamp(18px, 3.6cqw, 26px) / 1 var(--font-display, Arial, sans-serif); letter-spacing: -0.02em; color: var(--ink, #e9fbfc); text-shadow: 0 1px 12px rgba(6, 16, 24, 0.7); }
  .readout .split { display: flex; gap: 12px; justify-content: center; margin-top: 84px; font: 500 11px var(--font-mono, monospace); letter-spacing: 0.04em; }
  .readout .down { color: var(--tier-cyan, #63f3f0); }
  .readout .up { color: var(--tier-gold, #ffcd66); }
  .hearth.unavailable .readout .total { color: var(--muted, #77959d); }
  .tip { position: absolute; transform: translate(-50%, calc(-100% - 14px)); background: var(--surface-raised, #102a35); border: 1px solid var(--line-strong, #28505a); border-radius: 6px; padding: 6px 9px; display: grid; gap: 2px; pointer-events: none; white-space: nowrap; font-size: 12px; box-shadow: 0 6px 24px rgba(0, 0, 0, 0.45); }
  .tip strong { color: var(--ink, #e9fbfc); }
  .tip span { color: var(--muted, #77959d); font: 11px var(--font-mono, monospace); text-transform: capitalize; }
  .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; list-style: none; }
  .sr-only button:focus-visible { position: fixed; left: 12px; bottom: 12px; width: auto; height: auto; clip: auto; padding: 8px 12px; background: var(--surface-raised, #102a35); color: var(--ink, #e9fbfc); border: 1px solid var(--accent, #63f3f0); border-radius: 6px; z-index: 10; }
  @container (max-width: 480px) { .readout .split { margin-top: 70px; } }
</style>
