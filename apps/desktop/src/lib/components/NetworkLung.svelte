<script lang="ts">
  export type ThroughputTier = 'blue' | 'cyan' | 'gold' | 'pink';
  interface Props { throughput?: number | null; tier?: ThroughputTier; paused?: boolean; }
  let { throughput = null, tier = 'blue', paused = false }: Props = $props();
  import { formatThroughput } from './networkFormat';
</script>

<div class="lung-wrap {tier}" class:paused role="img" aria-label={`Network throughput ${formatThroughput(throughput)}, ${tier} tier`}>
  <svg viewBox="0 0 620 330" aria-hidden="true">
    <defs><linearGradient id="lung-cyan" x1="0" x2="1"><stop stop-color="#63F3F0"/><stop offset="1" stop-color="#548CFF"/></linearGradient><linearGradient id="lung-gold"><stop stop-color="#FFCD66"/><stop offset="1" stop-color="#FF5C9B"/></linearGradient></defs>
    <path class="lung-guide" d="M310 38v230M310 84C235 70 128 82 66 160M310 84c75-14 182-2 244 76"/>
    <path class="lobe left" d="M306 83C230 64 113 89 73 159c-31 53 16 113 87 105 63-7 102-57 146-103"/>
    <path class="lobe right" d="M314 83c76-19 193 6 233 76 31 53-16 113-87 105-63-7-102-57-146-103"/>
    <path class="breath" d="M79 161c61-19 98 39 151 3s86 2 112-32M541 161c-61-19-98 39-151 3s-86 2-112-32"/>
    <path class="ripple" d="M245 80c26-21 104-21 130 0M258 67c22-17 82-17 104 0"/>
    <circle class="core" cx="310" cy="84" r="8"/><g class="particles"><circle cx="105" cy="120" r="3"/><circle cx="182" cy="217" r="3"/><circle cx="516" cy="120" r="3"/><circle cx="438" cy="217" r="3"/></g>
  </svg>
  <div class="lung-readout"><span>{formatThroughput(throughput)}</span><small>current throughput</small></div>
</div>
<style>
  .lung-wrap.paused :global(.breath), .lung-wrap.paused :global(.ripple), .lung-wrap.paused :global(.particles circle) { animation-play-state: paused; }
  .lung-wrap :global(.breath) { animation: lung-breathe 3.6s ease-in-out infinite; transform-origin: center; }
  .lung-wrap :global(.ripple) { fill: none; stroke: #63f3f0; stroke-width: 1; stroke-dasharray: 4 8; animation: lung-ripple 2.6s ease-out infinite; transform-origin: center; }
  .lung-wrap :global(.particles circle) { animation: lung-drift 2.8s ease-in-out infinite alternate; }
  .lung-wrap :global(.particles circle:nth-child(even)) { animation-delay: 1s; }
  @keyframes lung-breathe { 50% { transform: translateY(-4px) scaleY(1.04); opacity: .6; } }
  @keyframes lung-ripple { 0% { opacity: .8; transform: scale(.86); } 100% { opacity: 0; transform: scale(1.12); } }
  @keyframes lung-drift { to { transform: translate(8px, -7px); opacity: .35; } }
  @media (prefers-reduced-motion: reduce) { .lung-wrap :global(*) { animation-duration: .01ms !important; animation-iteration-count: 1 !important; } }
</style>
