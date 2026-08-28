<script lang="ts">
  export type ThroughputTier = 'unavailable' | 'blue' | 'cyan' | 'gold' | 'pink';
  interface Props { throughput?: number | null; tier?: ThroughputTier; paused?: boolean; }
  let { throughput = null, tier = 'unavailable', paused = false }: Props = $props();
  import { formatThroughput } from './networkFormat';
</script>

<div class="lung-wrap {tier}" class:paused role="img" aria-label={`Network throughput ${formatThroughput(throughput)}, ${tier} tier`}>
  <div class="hearth" aria-hidden="true">
    <span class="bed"></span>
    <span class="sway">
      <span class="flame flame-blue"></span>
      <span class="flame flame-indigo"></span>
      <span class="flame flame-violet"></span>
      <span class="flame flame-magenta"></span>
      <span class="flame flame-orange"></span>
      <span class="flame flame-gold"></span>
      <span class="flame flame-core"></span>
      <span class="tongue tongue-a"></span>
      <span class="tongue tongue-b"></span>
    </span>
    <span class="spark spark-1"></span>
    <span class="spark spark-2"></span>
    <span class="spark spark-3"></span>
    <span class="spark spark-4"></span>
  </div>
  <div class="lung-readout"><span>{formatThroughput(throughput)}</span><small>current throughput</small></div>
</div>
<style>
  /* THE SHOWPIECE. A layered multicolour flame seen through frosted glass:
     a wide blue-indigo bed at the floor, violet and magenta through the body,
     orange and gold at the tip, plus a white-hot core. Each layer breathes on
     its own clock so the fire never pulses as one blob; the whole column sways
     and sheds sparks. Everything animates with transform/opacity only.

     Tier turns the air up: --fe = intensity, --fb = breath period,
     --fs = the flame's height. Unavailable idles low and slow but still burns. */
  /* --fs is viewport-relative so the same fire fits a 390px phone and a
     wide desktop without ever swamping the copy floating over it. */
  .lung-wrap { --fe: 1; --fb: 4.6s; --fs: clamp(358px, 38vw, 545px); --sway: 3deg; }
  .lung-wrap.unavailable { --fe: 1; --fb: 9s; --fs: clamp(340px, 32vw, 460px); --sway: 1.8deg; }
  .lung-wrap.blue { --fe: 0.9; --fb: 5.6s; --fs: clamp(340px, 34vw, 490px); }
  .lung-wrap.cyan { --fe: 1; --fb: 4.4s; --fs: clamp(352px, 37vw, 535px); }
  .lung-wrap.gold { --fe: 1.12; --fb: 3.2s; --fs: clamp(372px, 41vw, 585px); --sway: 4deg; }
  .lung-wrap.pink { --fe: 1.25; --fb: 2.3s; --fs: clamp(392px, 44vw, 635px); --sway: 5deg; }

  /* isolation keeps the additive screen blend inside the hearth, so the fire
     stays saturated instead of washing the panels behind it. */
  .hearth {
    position: absolute; inset: 0; overflow: hidden; isolation: isolate;
    contain: paint;
  }
  /* Ambient spill: the light the hearth throws across the whole hero, so the
     void around the fire is lit rather than dead black. */
  .hearth::before {
    content: ''; position: absolute; inset: 0; mix-blend-mode: screen;
    background:
      radial-gradient(70% 90% at 50% 92%, rgb(72 46 190 / 0.5), transparent 72%),
      radial-gradient(120% 70% at 50% 108%, rgb(120 40 190 / 0.34), transparent 76%);
    opacity: calc(var(--fe) * 0.9);
  }
  .sway {
    position: absolute; inset: 0; transform-origin: 50% 100%;
    animation: hearth-sway calc(var(--fb) * 3.7) ease-in-out infinite alternate;
  }
  .flame {
    position: absolute; left: 50%; border-radius: 50%;
    mix-blend-mode: screen; will-change: transform, opacity;
    animation: flame-breathe var(--fb) ease-in-out infinite;
  }

  /* The bed: a wide, low blue-white pool where the fire meets the floor, plus
     the ambient spill it throws sideways so the hero is never dead black. */
  .bed {
    position: absolute; left: 50%; bottom: calc(var(--fs) * -0.16);
    width: calc(var(--fs) * 1.55); height: calc(var(--fs) * 0.34);
    translate: -50% 0; border-radius: 50%; mix-blend-mode: screen;
    background: radial-gradient(closest-side, rgb(150 180 255 / 0.55), rgb(61 90 254 / 0.32) 42%, rgb(70 40 180 / 0.14) 70%, transparent 100%);
    opacity: calc(var(--fe) * 0.8); filter: blur(30px);
    animation: bed-breathe calc(var(--fb) * 1.6) ease-in-out infinite;
  }

  /* Body layers. Each layer's band climbs the column, so the spectrum reads
     bottom-to-top: blue, indigo, violet, magenta, orange, gold, white core.
     Every offset is in --fs so the whole flame scales as one with the tier. */
  .flame-blue {
    width: calc(var(--fs) * 0.92); height: calc(var(--fs) * 0.42); bottom: calc(var(--fs) * -0.08);
    translate: -50% 0;
    background: radial-gradient(closest-side, rgb(96 130 255 / 0.95), rgb(61 90 254 / 0.48) 46%, transparent 100%);
    opacity: calc(var(--fe) * 0.8); filter: blur(26px);
    animation-duration: calc(var(--fb) * 1.35);
  }
  .flame-indigo {
    width: calc(var(--fs) * 0.74); height: calc(var(--fs) * 0.4); bottom: calc(var(--fs) * 0.08);
    translate: -50% 0;
    background: radial-gradient(closest-side, rgb(112 82 255 / 0.98), rgb(94 68 255 / 0.46) 48%, transparent 100%);
    opacity: calc(var(--fe) * 0.86); filter: blur(23px);
    animation-duration: calc(var(--fb) * 1.12); animation-delay: calc(var(--fb) / -6);
  }
  .flame-violet {
    width: calc(var(--fs) * 0.6); height: calc(var(--fs) * 0.38); bottom: calc(var(--fs) * 0.22);
    translate: -53% 0;
    background: radial-gradient(closest-side, rgb(152 106 255 / 1), rgb(124 77 255 / 0.46) 50%, transparent 100%);
    opacity: calc(var(--fe) * 0.9); filter: blur(20px);
    animation-duration: calc(var(--fb) * 0.93); animation-delay: calc(var(--fb) / -3.1);
  }
  .flame-magenta {
    width: calc(var(--fs) * 0.46); height: calc(var(--fs) * 0.34); bottom: calc(var(--fs) * 0.36);
    translate: -46% 0;
    background: radial-gradient(closest-side, rgb(238 100 255 / 1), rgb(224 64 251 / 0.46) 52%, transparent 100%);
    opacity: calc(var(--fe) * 0.92); filter: blur(17px);
    animation-duration: calc(var(--fb) * 0.79); animation-delay: calc(var(--fb) / -2.2);
  }
  .flame-orange {
    width: calc(var(--fs) * 0.34); height: calc(var(--fs) * 0.3); bottom: calc(var(--fs) * 0.5);
    translate: -51% 0;
    background: radial-gradient(closest-side, rgb(255 132 72 / 1), rgb(255 109 59 / 0.5) 52%, transparent 100%);
    opacity: calc(var(--fe) * 0.96); filter: blur(14px);
    animation-duration: calc(var(--fb) * 0.66); animation-delay: calc(var(--fb) / -1.6);
  }
  .flame-gold {
    width: calc(var(--fs) * 0.19); height: calc(var(--fs) * 0.26); bottom: calc(var(--fs) * 0.66);
    translate: -50% 0;
    background: radial-gradient(closest-side, rgb(255 222 130 / 1), rgb(255 170 45 / 0.6) 52%, transparent 100%);
    opacity: var(--fe); filter: blur(10px);
    animation-duration: calc(var(--fb) * 0.52); animation-delay: calc(var(--fb) / -1.25);
  }
  /* The white-hot heart — small, quick, and low in the column, where a real
     flame is hottest. Kept tight so it never washes the spectrum out. */
  .flame-core {
    width: calc(var(--fs) * 0.12); height: calc(var(--fs) * 0.3); bottom: calc(var(--fs) * 0.2);
    translate: -50% 0;
    background: radial-gradient(closest-side, rgb(255 244 205 / 0.85), rgb(255 180 60 / 0.4) 52%, transparent 100%);
    opacity: calc(var(--fe) * 0.75); filter: blur(12px);
    animation-name: flame-flicker; animation-duration: calc(var(--fb) * 0.31);
  }

  /* Two tongues licking off the column. Teardrop radii plus their own flicker
     clocks break the symmetry — this is what turns a plume into fire. */
  .tongue {
    position: absolute; left: 50%; mix-blend-mode: screen;
    border-radius: 50% 50% 46% 46% / 68% 68% 32% 32%;
    transform-origin: 50% 100%; will-change: transform, opacity;
    animation: tongue-lick var(--fb) ease-in-out infinite;
  }
  .tongue-a {
    width: calc(var(--fs) * 0.13); height: calc(var(--fs) * 0.54);
    bottom: calc(var(--fs) * 0.42); translate: -92% 0;
    background: linear-gradient(to top, rgb(224 64 251 / 0.75), rgb(255 109 59 / 0.9) 46%, rgb(255 205 90 / 0.95) 82%, transparent 100%);
    opacity: calc(var(--fe) * 0.7); filter: blur(13px);
    animation-duration: calc(var(--fb) * 0.71); animation-delay: calc(var(--fb) / -2.9);
  }
  .tongue-b {
    width: calc(var(--fs) * 0.11); height: calc(var(--fs) * 0.46);
    bottom: calc(var(--fs) * 0.48); translate: 4% 0;
    background: linear-gradient(to top, rgb(124 77 255 / 0.7), rgb(236 100 255 / 0.85) 40%, rgb(255 150 70 / 0.95) 84%, transparent 100%);
    opacity: calc(var(--fe) * 0.66); filter: blur(12px);
    animation-duration: calc(var(--fb) * 0.58); animation-delay: calc(var(--fb) / -1.4);
  }
  @keyframes tongue-lick {
    0%, 100% { transform: rotate(-5deg) scale(0.8, 0.72); opacity: calc(var(--fe) * 0.28); }
    38% { transform: rotate(4deg) scale(1.06, 1.18); opacity: calc(var(--fe) * 0.78); }
    64% { transform: rotate(-2deg) scale(0.9, 0.94); opacity: calc(var(--fe) * 0.5); }
  }

  /* Embers lifting off the tip. Transform + opacity only. */
  .spark {
    position: absolute; left: 50%; bottom: calc(var(--fs) * 0.6); width: 5px; height: 5px;
    border-radius: 50%; mix-blend-mode: screen; filter: blur(1.5px);
    background: radial-gradient(circle, rgb(255 240 200 / 0.95), rgb(255 160 40 / 0.55) 55%, transparent 100%);
    opacity: 0; animation: spark-rise 6.5s ease-out infinite;
  }
  .spark-1 { margin-left: -46px; animation-duration: 5.4s; animation-delay: 0s; }
  .spark-2 { margin-left: 28px; animation-duration: 7.1s; animation-delay: -2.2s; }
  .spark-3 { margin-left: -8px; animation-duration: 6.2s; animation-delay: -4.1s; }
  .spark-4 { margin-left: 62px; animation-duration: 8s; animation-delay: -5.6s; }

  .lung-wrap.paused .hearth *, .lung-wrap.paused .bed { animation-play-state: paused; }

  @keyframes flame-breathe {
    0%, 100% { transform: translate3d(0, 3%, 0) scale(0.94, 0.9); opacity: calc(var(--fe) * 0.6); }
    45% { transform: translate3d(1.5%, -2%, 0) scale(1.04, 1.1); }
    70% { transform: translate3d(-1.5%, 0, 0) scale(0.99, 1.02); opacity: calc(var(--fe) * 0.95); }
  }
  @keyframes flame-flicker {
    0%, 100% { transform: translate3d(0, 4%, 0) scale(0.82, 0.86); opacity: calc(var(--fe) * 0.5); }
    30% { transform: translate3d(-4%, -6%, 0) scale(1.12, 1.24); opacity: calc(var(--fe) * 1); }
    60% { transform: translate3d(4%, -2%, 0) scale(0.94, 1.06); opacity: calc(var(--fe) * 0.72); }
  }
  @keyframes bed-breathe {
    0%, 100% { transform: scale(0.96, 0.9); opacity: calc(var(--fe) * 0.62); }
    50% { transform: scale(1.06, 1.06); opacity: calc(var(--fe) * 0.95); }
  }
  @keyframes hearth-sway {
    0% { transform: rotate(calc(var(--sway) * -1)) translate3d(-1%, 0, 0); }
    100% { transform: rotate(var(--sway)) translate3d(1%, 0, 0); }
  }
  @keyframes spark-rise {
    0% { transform: translate3d(0, 0, 0) scale(0.6); opacity: 0; }
    12% { opacity: 0.9; }
    100% { transform: translate3d(24px, -300px, 0) scale(0.25); opacity: 0; }
  }

  /* Reduced motion: the same fire, held still at the current tier. */
  @media (prefers-reduced-motion: reduce) {
    .hearth *, .bed { animation: none !important; transform: none; }
    .flame { opacity: calc(var(--fe) * 0.9); }
    .spark { opacity: 0.7; }
  }
</style>
