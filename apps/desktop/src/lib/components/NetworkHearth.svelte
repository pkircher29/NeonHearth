<script lang="ts">
  export type ThroughputTier = 'unavailable' | 'blue' | 'cyan' | 'gold' | 'pink';
  interface Props { throughput?: number | null; tier?: ThroughputTier; paused?: boolean; }
  let { throughput = null, tier = 'unavailable', paused = false }: Props = $props();
  import { formatThroughput } from './networkFormat';
</script>

<div class="hearth-wrap {tier}" class:paused role="img" aria-label={`Network throughput ${formatThroughput(throughput)}, ${tier} tier`}>
  <svg viewBox="0 0 620 280" aria-hidden="true">
    <defs>
      <linearGradient id="hearth-grad-cyan" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="#63F3F0" />
        <stop offset="100%" stop-color="#548CFF" />
      </linearGradient>
      <linearGradient id="hearth-grad-gold" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="#FFCD66" />
        <stop offset="100%" stop-color="#FF5C9B" />
      </linearGradient>
      <radialGradient id="hearth-glow" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stop-color="var(--hearth-glow)" stop-opacity="0.8" />
        <stop offset="100%" stop-color="var(--hearth-glow)" stop-opacity="0" />
      </radialGradient>
    </defs>

    <!-- Background radial aura -->
    <circle class="aura" cx="310" cy="140" r="120" fill="url(#hearth-glow)" />

    <!-- Outer resonance ring -->
    <circle class="ring ring-outer" cx="310" cy="140" r="110" />

    <!-- Middle radar dashed ring -->
    <circle class="ring ring-mid" cx="310" cy="140" r="82" />

    <!-- Core hexagon boundary -->
    <polygon class="core-hex" points="310,80 362,110 362,170 310,200 258,170 258,110" />

    <!-- Inner pulsing ring -->
    <circle class="ring ring-inner" cx="310" cy="140" r="42" />

    <!-- Crosshair guides -->
    <line class="crosshair" x1="160" y1="140" x2="250" y2="140" />
    <line class="crosshair" x1="370" y1="140" x2="460" y2="140" />
    <line class="crosshair" x1="310" y1="20" x2="310" y2="70" />
    <line class="crosshair" x1="310" y1="210" x2="310" y2="260" />

    <!-- Orbital satellite packets -->
    <g class="orbit orbit-1">
      <circle class="packet" cx="310" cy="58" r="4" />
    </g>
    <g class="orbit orbit-2">
      <circle class="packet" cx="310" cy="222" r="3" />
    </g>
    <g class="orbit orbit-3">
      <circle class="packet packet-secondary" cx="228" cy="140" r="3.5" />
      <circle class="packet packet-secondary" cx="392" cy="140" r="3.5" />
    </g>

    <!-- Center Nexus -->
    <circle class="center-nexus" cx="310" cy="140" r="10" />
    <circle class="center-pip" cx="310" cy="140" r="4" />
  </svg>
  <div class="hearth-readout">
    <span class="readout-val">{formatThroughput(throughput)}</span>
    <small class="readout-label">HEARTH THROUGHPUT</small>
  </div>
</div>

<style>
  .hearth-wrap {
    --hearth-a: #548cff;
    --hearth-b: #63f3f0;
    --hearth-glow: rgba(84, 140, 255, 0.25);
    --hearth-speed: 6s;
    --hearth-pulse-speed: 2.8s;
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    width: 100%;
    margin: 8px 0;
  }

  .hearth-wrap.unavailable {
    --hearth-a: #4d6069;
    --hearth-b: #6e828a;
    --hearth-glow: rgba(100, 120, 130, 0.1);
    --hearth-speed: 12s;
    --hearth-pulse-speed: 5s;
    opacity: 0.75;
  }

  .hearth-wrap.cyan {
    --hearth-a: #63f3f0;
    --hearth-b: #548cff;
    --hearth-glow: rgba(99, 243, 240, 0.35);
    --hearth-speed: 4.5s;
    --hearth-pulse-speed: 2.2s;
  }

  .hearth-wrap.gold {
    --hearth-a: #ffcd66;
    --hearth-b: #ff8a70;
    --hearth-glow: rgba(255, 205, 102, 0.4);
    --hearth-speed: 3.2s;
    --hearth-pulse-speed: 1.7s;
  }

  .hearth-wrap.pink {
    --hearth-a: #ff5c9b;
    --hearth-b: #c978ff;
    --hearth-glow: rgba(255, 92, 155, 0.45);
    --hearth-speed: 2.2s;
    --hearth-pulse-speed: 1.2s;
  }

  .hearth-wrap svg {
    width: 100%;
    max-width: 580px;
    height: auto;
    filter: drop-shadow(0 2px 16px var(--hearth-glow));
  }

  .ring {
    fill: none;
    stroke-linecap: round;
    transform-origin: 310px 140px;
  }

  .ring-outer {
    stroke: var(--hearth-a);
    stroke-width: 1.5px;
    stroke-dasharray: 8 16 32 16;
    animation: spin var(--hearth-speed) linear infinite;
  }

  .ring-mid {
    stroke: var(--hearth-b);
    stroke-width: 1px;
    stroke-dasharray: 4 8;
    opacity: 0.6;
    animation: spin-rev calc(var(--hearth-speed) * 1.3) linear infinite;
  }

  .ring-inner {
    stroke: var(--hearth-a);
    stroke-width: 2px;
    animation: pulse-ring var(--hearth-pulse-speed) ease-in-out infinite;
  }

  .core-hex {
    fill: color-mix(in srgb, var(--hearth-a) 8%, transparent);
    stroke: var(--hearth-a);
    stroke-width: 1.5px;
    transform-origin: 310px 140px;
    animation: spin calc(var(--hearth-speed) * 2.5) ease-in-out infinite alternate;
  }

  .crosshair {
    stroke: var(--hearth-b);
    stroke-width: 1px;
    opacity: 0.4;
    stroke-dasharray: 3 6;
  }

  .orbit {
    transform-origin: 310px 140px;
  }

  .orbit-1 { animation: spin var(--hearth-speed) linear infinite; }
  .orbit-2 { animation: spin-rev calc(var(--hearth-speed) * 0.8) linear infinite; }
  .orbit-3 { animation: spin calc(var(--hearth-speed) * 1.5) linear infinite; }

  .packet {
    fill: var(--hearth-b);
    filter: drop-shadow(0 0 6px var(--hearth-b));
  }

  .packet-secondary {
    fill: var(--hearth-a);
    filter: drop-shadow(0 0 4px var(--hearth-a));
  }

  .center-nexus {
    fill: color-mix(in srgb, var(--hearth-b) 20%, transparent);
    stroke: var(--hearth-b);
    stroke-width: 1.5px;
    animation: pulse-core var(--hearth-pulse-speed) ease-in-out infinite;
    transform-origin: 310px 140px;
  }

  .center-pip {
    fill: var(--hearth-b);
    filter: drop-shadow(0 0 8px var(--hearth-b));
  }

  .hearth-wrap.paused .ring-outer,
  .hearth-wrap.paused .ring-mid,
  .hearth-wrap.paused .ring-inner,
  .hearth-wrap.paused .core-hex,
  .hearth-wrap.paused .orbit,
  .hearth-wrap.paused .center-nexus {
    animation-play-state: paused;
  }

  .hearth-readout {
    position: absolute;
    bottom: 12px;
    display: flex;
    flex-direction: column;
    align-items: center;
    pointer-events: none;
  }

  .readout-val {
    font-size: 20px;
    font-weight: 700;
    color: #e9fbfc;
    letter-spacing: 0.5px;
    font-family: monospace;
  }

  .readout-label {
    font-size: 10px;
    color: #77959d;
    letter-spacing: 1.5px;
    font-weight: 600;
    margin-top: 2px;
  }

  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }

  @keyframes spin-rev {
    from { transform: rotate(360deg); }
    to { transform: rotate(0deg); }
  }

  @keyframes pulse-ring {
    0%, 100% { transform: scale(0.96); opacity: 0.7; }
    50% { transform: scale(1.06); opacity: 1; }
  }

  @keyframes pulse-core {
    0%, 100% { transform: scale(0.85); opacity: 0.6; }
    50% { transform: scale(1.15); opacity: 1; }
  }

  @media (prefers-reduced-motion: reduce) {
    .hearth-wrap :global(*) {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
    }
  }
</style>
