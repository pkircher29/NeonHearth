<script lang="ts">
  import type { ThroughputPoint } from '../stores/live';
  import { formatThroughput } from './networkFormat';
  let { points = [], connected = false }: { points?: ThroughputPoint[]; connected?: boolean } = $props();
  const samples = $derived(connected ? points.slice(-60).filter(p => Number.isFinite(p.download) && Number.isFinite(p.upload) && p.download >= 0 && p.upload >= 0 && Number.isFinite(Date.parse(p.at))) : []);
  const latest = $derived(samples.at(-1));
  const ceiling = $derived(Math.max(125_000, ...samples.flatMap(p => [p.download, p.upload])));
  const firstTime = $derived(Date.parse(samples[0]?.at ?? ''));
  const duration = $derived(latest ? Date.parse(latest.at) - firstTime : 0);
  function trace(direction: 'download' | 'upload') {
    return samples.map((p, i) => {
      const x = duration > 0 ? 20 + (Date.parse(p.at) - firstTime) / duration * 880 : 900;
      const previous = samples[i - 1];
      const gap = previous ? Date.parse(p.at) - Date.parse(previous.at) : 0;
      const y = direction === 'download' ? 150 - p.download / ceiling * 110 : 190 + p.upload / ceiling * 110;
      return `${i && gap > 0 && gap <= 5000 ? 'L' : 'M'}${x.toFixed(2)},${y.toFixed(2)}`;
    }).join(' ');
  }
  function timeLabel(at?: string) {
    const date = new Date(at ?? '');
    return Number.isNaN(date.valueOf()) ? 'Sample time unavailable' : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
</script>

<section class="traffic-scope" aria-label="Traffic scope">
  <header><div><p class="scope-kicker">PULSE / SIGNAL</p><h2>Traffic scope</h2></div><span class="scope-state">{latest ? 'MEASURED DEVICES' : connected ? 'AWAITING COUNTERS' : 'OFFLINE'}</span></header>
  <div class="scope-readings">
    <div class="download"><span>↓ DOWNLOAD</span><strong>{formatThroughput(latest?.download)}</strong></div>
    <div class="upload"><span>↑ UPLOAD</span><strong>{formatThroughput(latest?.upload)}</strong></div>
    <div class="scope-scale"><span>SHARED SCALE</span><strong>{latest ? formatThroughput(ceiling) : '—'}</strong><small>per direction</small></div>
  </div>
  <div class="scope-plot">
    <svg viewBox="0 0 920 340" role="img" aria-label={latest ? `Measured device traffic. Download ${formatThroughput(latest.download)}; upload ${formatThroughput(latest.upload)}. ${samples.length} samples, shared scale ${formatThroughput(ceiling)}.` : 'Traffic measurements unavailable. No trace is plotted.'}>
      <path class="grid" d="M20 40H900M20 95H900M20 245H900M20 300H900M20 20V320M130 20V320M240 20V320M350 20V320M460 20V320M570 20V320M680 20V320M790 20V320M900 20V320"/>
      <path class="baseline" d="M20 150H900M20 190H900"/>
      <text x="28" y="173">DOWNLOAD ↑</text><text x="790" y="173">UPLOAD ↓</text>
      {#if samples.length > 1}<path class="trace down" d={trace('download')}/><path class="trace up" d={trace('upload')}/>{/if}
      {#if latest}<rect class="down" x="896" y={146 - latest.download / ceiling * 110} width="8" height="8"/><rect class="up" x="896" y={186 + latest.upload / ceiling * 110} width="8" height="8"/>{/if}
    </svg>
    {#if !latest}<div class="scope-empty"><strong>{connected ? 'Waiting for device counters' : 'Signal unavailable'}</strong><p>{connected ? 'The collector is connected. Measured device traffic will appear here when available.' : 'Reconnect the collector to see download and upload activity.'}</p></div>{/if}
  </div>
  <footer><span>{latest ? timeLabel(samples[0]?.at) : 'NO CURRENT MEASUREMENTS'}</span><span>{latest ? `${samples.length} samples · ${timeLabel(latest.at)}` : 'Download and upload stay separate'}</span></footer>
  <p class="scope-note">Measured devices only · household router totals are shown separately. Spacing represents elapsed time; gaps over five seconds break the trace.</p>
</section>
<style>
  .traffic-scope { margin:28px 0 0; border:1px solid #526269; border-top:3px solid #ff865f; background:#10191c; min-width:0; }
  header { display:flex;justify-content:space-between;align-items:center;gap:12px;padding:20px 22px;border-bottom:1px solid #354348; background:linear-gradient(135deg,transparent calc(100% - 24px),#ff865f calc(100% - 23px)); }
  .scope-kicker { margin:0 0 6px;color:#ff966f;font:11px var(--font-mono);letter-spacing:.15em; }
  h2 { margin:0;font:700 25px var(--font-display);text-transform:uppercase;letter-spacing:-.02em; }
  .scope-state { color:#b8c9c7;font:10px var(--font-mono);letter-spacing:.08em; padding-right:10px; }
  .scope-readings { display:grid;grid-template-columns:1fr 1fr auto;padding:20px 22px;gap:22px; }
  .scope-readings span { font:11px var(--font-mono);letter-spacing:.09em; }
  .scope-readings strong { display:block;font:600 clamp(18px,2.5vw,30px) var(--font-display);margin-top:6px; }
  .download { color:#ff966f; }.upload { color:#7ee6e0; }.scope-scale { color:#b8c9c7;text-align:right; }.scope-scale strong { font-size:17px; }.scope-scale small { font-size:11px; }
  .scope-plot { position:relative; }.scope-plot svg { display:block;width:100%;height:auto;min-height:210px; }
  .grid { fill:none;stroke:#2a3b40;stroke-width:1; }.baseline { fill:none;stroke:#617178;stroke-width:1; }
  text { fill:#b8c9c7;font:10px var(--font-mono);letter-spacing:1px; }
  .trace { fill:none;stroke-width:2.5;stroke-linejoin:miter;stroke-linecap:square;vector-effect:non-scaling-stroke; }
  .down { stroke:#ff865f; }.up { stroke:#7ee6e0; }rect.down{fill:#ff865f}rect.up{fill:#7ee6e0}
  .scope-empty { position:absolute;left:22px;top:20%;max-width:320px;padding:14px 18px;background:#10191c;border-left:3px solid #ff865f; }.scope-empty strong{font-size:17px}.scope-empty p{color:#b8c9c7;font-size:13px;line-height:1.5;margin-bottom:0}
  footer { display:flex;justify-content:space-between;gap:12px;padding:12px 22px;border-top:1px solid #354348;color:#b8c9c7;font:10px var(--font-mono); }
  .scope-note { margin:0;padding:12px 22px;color:#a8b8b7;font-size:11px;line-height:1.5; }
  @media(max-width:650px) { header { padding:16px;align-items:flex-start; }.scope-state{max-width:100px;line-height:1.6;text-align:right}.scope-readings{padding:16px;gap:14px;grid-template-columns:1fr 1fr}.scope-scale{grid-column:1/-1;text-align:left;display:flex;gap:8px;align-items:center}.scope-scale strong{margin:0;font-size:13px}.scope-empty{left:12px;right:12px;top:15%;padding:12px;max-width:none}footer{padding:12px;flex-wrap:wrap}.scope-note{padding:12px} }
</style>
