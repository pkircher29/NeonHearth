<script lang="ts">
  import type { ScanFinding } from '../api/networkScan';
  import { webServices } from '../deviceRecognition';
  let {findings}: {findings: ScanFinding[]} = $props();
  const services = $derived(webServices(findings));
</script>
{#if services.length}
  <div class="web-links" aria-label="Device web pages">
    {#each services as service (service.url)}
      <a href={service.url} target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" title="{service.address} · Opens separately{service.unverified ? ' · Verify the device and certificate in your browser' : ''}">{service.label}<span aria-hidden="true">↗</span></a>
    {/each}
  </div>
  <small>Opens the address observed in the last scan in a new window or tab.</small>
{/if}
<style>
  .web-links{display:flex;flex-wrap:wrap;gap:8px}.web-links a{display:inline-flex;align-items:center;gap:10px;min-height:38px;padding:0 12px;border:1px solid var(--line-strong);border-radius:6px;color:var(--accent);text-decoration:none;font-size:12px}.web-links a:hover{border-color:var(--accent)}small{display:block;color:var(--muted-strong);font-size:11px;line-height:1.5;margin:7px 0 12px}
</style>
