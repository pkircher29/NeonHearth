<script lang="ts">
  // Grid for the plan canvas (home tools v2 · spec A): 1 m major lines always, a fine minor
  // grid that fades with zoom. The rects always cover the current viewBox, wherever it is panned.
  import { METERS_PER_FOOT, type HomeUnits } from '../homeUnits';
  import { minorGridOpacity, type Size, type ViewState } from '../home/view';

  let { view, size, units }: { view: ViewState; size: Size; units: HomeUnits } = $props();

  const imperial = $derived(units === 'imperial');
  const majorStep = $derived(imperial ? (METERS_PER_FOOT * view.scale >= 10 ? METERS_PER_FOOT : METERS_PER_FOOT * 10) : 1);
  const minorStep = $derived(imperial ? 0.0254 : 0.1);
  const majorPx = $derived(majorStep * view.scale);
  const minorPx = $derived(minorStep * view.scale);
  // The 0.1 m fade curve, rescaled so an inch grid appears only when an inch is as legible as 0.1 m.
  const minorOpacity = $derived(minorGridOpacity((view.scale * minorStep) / 0.1));
  // Same rounding as the viewBox, so the rects line up with it exactly.
  const x = $derived(Number((view.origin.x * view.scale).toFixed(3)));
  const y = $derived(Number((view.origin.y * view.scale).toFixed(3)));
</script>

<defs>
  <pattern id="home-grid-minor" width={minorPx} height={minorPx} patternUnits="userSpaceOnUse">
    <path class="grid-minor" d={`M ${minorPx} 0 L 0 0 0 ${minorPx}`} fill="none" stroke-width="1" />
  </pattern>
  <pattern id="home-grid-major" width={majorPx} height={majorPx} patternUnits="userSpaceOnUse">
    <path class="grid-major" d={`M ${majorPx} 0 L 0 0 0 ${majorPx}`} fill="none" stroke-width="1" />
  </pattern>
</defs>
{#if minorOpacity > 0}
  <rect class="grid grid-minor-fill" {x} {y} width={size.width} height={size.height} fill="url(#home-grid-minor)" opacity={minorOpacity} />
{/if}
<rect class="grid grid-major-fill" {x} {y} width={size.width} height={size.height} fill="url(#home-grid-major)" />

<style>
  .grid-minor{stroke:var(--line)}
  .grid-major{stroke:var(--line-strong)}
  .grid{pointer-events:none}
</style>
