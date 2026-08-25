<script lang="ts">
  export type ThroughputTier = 'unavailable' | 'blue' | 'cyan' | 'gold' | 'pink';
  interface Props { throughput?: number | null; tier?: ThroughputTier; paused?: boolean; }
  let { throughput = null, tier = 'unavailable', paused = false }: Props = $props();
  import { formatThroughput } from './networkFormat';
</script>

<div class="lung-wrap {tier}" class:paused role="img" aria-label={`Network throughput ${formatThroughput(throughput)}, ${tier} tier`}>
  <div class="hearth" aria-hidden="true">
    <span class="hearth-halo"></span>
    <span class="hearth-bed"></span>
    <span class="hearth-core"></span>
  </div>
  <div class="lung-readout"><span>{formatThroughput(throughput)}</span><small>current throughput</small></div>
</div>
<style>
  /* Daylight fire: a soft amber/rose area that breathes with activity.
     Tiers set how much air is on the coals — never a different color family. */
  .lung-wrap { --hearth-energy: 0.5; --hearth-breathe: 5.2s; --hearth-size: 340px; }
  .lung-wrap.unavailable { --hearth-energy: 0.16; --hearth-breathe: 8s; }
  .lung-wrap.blue { --hearth-energy: 0.35; --hearth-breathe: 5.6s; }
  .lung-wrap.cyan { --hearth-energy: 0.55; --hearth-breathe: 4.2s; }
  .lung-wrap.gold { --hearth-energy: 0.75; --hearth-breathe: 3s; }
  .lung-wrap.pink { --hearth-energy: 0.95; --hearth-breathe: 2.1s; }

  .hearth { position: absolute; inset: 0; display: grid; place-items: center; overflow: hidden; }
  .hearth span { grid-area: 1 / 1; border-radius: 50%; }
  .hearth-halo {
    width: var(--hearth-size); height: var(--hearth-size);
    background: radial-gradient(closest-side, color-mix(in srgb, var(--down) 55%, transparent), color-mix(in srgb, var(--down) 20%, transparent) 55%, transparent 100%);
    opacity: var(--hearth-energy);
    animation: hearth-breathe var(--hearth-breathe) ease-in-out infinite;
  }
  .hearth-bed {
    width: calc(var(--hearth-size) * 0.55); height: calc(var(--hearth-size) * 0.55);
    background: radial-gradient(closest-side, color-mix(in srgb, var(--up) 45%, transparent), color-mix(in srgb, var(--up) 18%, transparent) 60%, transparent 100%);
    opacity: calc(var(--hearth-energy) * 0.9);
    animation: hearth-breathe var(--hearth-breathe) ease-in-out infinite;
    animation-delay: calc(var(--hearth-breathe) / -6);
  }
  .hearth-core {
    width: calc(var(--hearth-size) * 0.22); height: calc(var(--hearth-size) * 0.22);
    background: radial-gradient(closest-side, color-mix(in srgb, var(--down) 65%, var(--surface)), color-mix(in srgb, var(--down) 30%, transparent) 60%, transparent 100%);
    opacity: calc(var(--hearth-energy) * 0.95);
    animation: hearth-breathe var(--hearth-breathe) ease-in-out infinite;
    animation-delay: calc(var(--hearth-breathe) / -3);
  }
  .lung-wrap.paused .hearth span { animation-play-state: paused; }

  @keyframes hearth-breathe {
    0%, 100% { transform: scale(1); opacity: calc(var(--hearth-energy) * 0.7); }
    50% { transform: scale(1.06); opacity: var(--hearth-energy); }
  }

  /* Reduced motion: static two-state brightness, never a pulse. */
  @media (prefers-reduced-motion: reduce) {
    .hearth span { animation: none !important; transform: none; opacity: var(--hearth-energy); }
    .lung-wrap.unavailable .hearth span { opacity: 0.16; }
  }
</style>
