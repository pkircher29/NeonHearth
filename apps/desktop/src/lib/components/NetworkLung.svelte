<script lang="ts">
  interface Props { throughput?: number; paused?: boolean; }
  let { throughput = 0, paused = false }: Props = $props();
  const tier = throughput > 70 ? 'surge' : throughput > 30 ? 'active' : 'quiet';
</script>

<div class="lung-wrap" class:paused aria-label={`Network throughput ${throughput} percent, ${tier}`} role="img">
  <svg viewBox="0 0 620 330" aria-hidden="true">
    <defs><linearGradient id="lung-cyan" x1="0" x2="1"><stop stop-color="#63F3F0"/><stop offset="1" stop-color="#548CFF"/></linearGradient><linearGradient id="lung-gold"><stop stop-color="#FFCD66"/><stop offset="1" stop-color="#FF5C9B"/></linearGradient></defs>
    <path class="lung-guide" d="M310 38v230M310 84C235 70 128 82 66 160M310 84c75-14 182-2 244 76"/>
    <path class="lobe left" d="M306 83C230 64 113 89 73 159c-31 53 16 113 87 105 63-7 102-57 146-103"/>
    <path class="lobe right" d="M314 83c76-19 193 6 233 76 31 53-16 113-87 105-63-7-102-57-146-103"/>
    <path class="breath" d="M79 161c61-19 98 39 151 3s86 2 112-32M541 161c-61-19-98 39-151 3s-86 2-112-32"/>
    <circle class="core" cx="310" cy="84" r="8"/><g class="particles"><circle cx="105" cy="120" r="3"/><circle cx="182" cy="217" r="3"/><circle cx="516" cy="120" r="3"/><circle cx="438" cy="217" r="3"/></g>
  </svg>
  <div class="lung-readout"><span>{throughput}%</span><small>current load</small></div>
</div>
