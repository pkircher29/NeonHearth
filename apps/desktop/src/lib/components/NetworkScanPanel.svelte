<script lang="ts">
  import { onMount } from 'svelte';
  import type { CaptureReport, ScanApi, ScanInput, ScanStatus } from '../api/networkScan';
  let { api, onchange }: { api: ScanApi; onchange: (scan: ScanStatus) => void } = $props();
  let scan = $state<ScanStatus | null>(null);
  let mode = $state<ScanInput['port_mode']>('common');
  let protocols = $state(['icmp','mdns','smb','netbios']);
  let customPorts = $state('');
  let webIdentification = $state(true);
  let error = $state('');
  let statusError = $state('');
  let busy = $state(false);
  let capabilities = $state<Record<string,string>>({});
  let capture = $state<CaptureReport | null>(null);
  let importBusy = $state(false);
  let snmpVersion = $state('v3'); let community = $state(''); let username = $state(''); let authPassword = $state(''); let privacyPassword = $state('');
  const running = $derived(scan?.state === 'running' || scan?.state === 'cancelling');
  const choices = [['icmp','ICMP ping'],['mdns','Multicast DNS / Bonjour'],['smb','SMB 2/3'],['netbios','NetBIOS'],['snmp','SNMP inventory']];
  function update(value: ScanStatus) { scan = value; onchange(value); }
  function toggle(protocol: string) { protocols = protocols.includes(protocol) ? protocols.filter(p => p !== protocol) : [...protocols,protocol]; }
  async function start() {
    busy = true; error = '';
    try {
      const ports = mode === 'custom' ? customPorts.split(',').map(p => Number(p.trim())) : [];
      if (mode === 'custom' && (!ports.length || ports.some(p => !Number.isInteger(p) || p < 1 || p > 65535))) throw new Error('Enter port numbers from 1 to 65535, separated by commas.');
      const input: ScanInput = { port_mode: mode, protocols, ports, web_identification: webIdentification };
      if (protocols.includes('snmp')) input.snmp = { version: snmpVersion, community, username, authentication_password: authPassword, privacy_password: privacyPassword };
      const pending = api.start(input);
      community = ''; authPassword = ''; privacyPassword = '';
      update(await pending);
    } catch (e) { error = e instanceof Error ? e.message : 'The scan could not start.'; }
    finally { busy = false; }
  }
  async function cancel() { try { await api.cancel(); update(await api.status()); } catch { error = 'The cancellation could not be confirmed. Refresh the scan status.'; } }
  async function importCapture(event: Event) {
    const input = event.currentTarget as HTMLInputElement; const file = input.files?.[0]; if (!file) return;
    importBusy = true; error = '';
    try { capture = await api.capture(file); } catch (e) { error = e instanceof Error ? e.message : 'Capture import failed.'; }
    finally { importBusy = false; input.value = ''; }
  }
  onMount(() => {
    let active = true; let timer: ReturnType<typeof setTimeout>;
    void Promise.allSettled([api.capabilities(),api.capture()]).then(results => { if (!active) return; if (results[0].status === 'fulfilled') capabilities = results[0].value; if (results[1].status === 'fulfilled') capture = results[1].value; });
    async function poll() { try { const result = await api.status(); if (active) { update(result); statusError = ''; } } catch { if (active) statusError = 'Scan status is unavailable.'; } finally { if (active) timer = setTimeout(() => void poll(), 1500); } }
    void poll(); return () => { active = false; clearTimeout(timer); };
  });
</script>
<details class="scan-panel">
  <summary>Identify devices with a network scan {#if running}<span>· Scanning {scan?.completed} / {scan?.total}</span>{/if}</summary>
  <p>Scan all observed devices on the local network. Open ports and reported names help identify devices. Scans send connection checks and read-only discovery requests.</p>
  <fieldset disabled={running || busy}>
    <label>TCP ports <select aria-label="TCP scan ports" bind:value={mode}><option value="common">Common device and automation ports</option><option value="all">All TCP ports (1–65535)</option><option value="custom">Specific TCP ports</option><option value="none">Protocol discovery only</option></select></label>
    {#if mode === 'custom'}<label>Port numbers <input bind:value={customPorts} placeholder="22, 80, 443, 445, 8123" maxlength="24000" /></label>{/if}
    {#if mode === 'all'}<p>All-port scans can take many hours. One connection per device runs at a time; you can cancel and keep partial results.</p>{/if}
    {#if mode !== 'none'}
      <label><input type="checkbox" bind:checked={webIdentification} />Identify open web ports with HTTP / HTTPS</label>
      <p>Reads the home page on common web ports for a title, server name, and product clues. No sign-in or redirects. Web checks are added to progress as open ports are found.</p>
    {/if}
    <div class="protocols">{#each choices as [value,label]}<label><input type="checkbox" checked={protocols.includes(value)} onchange={() => toggle(value)} />{label}</label>{/each}</div>
    {#if protocols.includes('snmp')}
      <div class="credentials">
        <label>SNMP version <select bind:value={snmpVersion}><option value="v3">v3 · SHA-256 / AES-128</option><option value="v2c">v2c · community sent unencrypted</option></select></label>
        {#if snmpVersion === 'v3'}<label>SNMP username<input bind:value={username} maxlength="128" autocomplete="off" /></label><label>Authentication password<input type="password" bind:value={authPassword} maxlength="128" autocomplete="new-password" /></label><label>Privacy password<input type="password" bind:value={privacyPassword} maxlength="128" autocomplete="new-password" /></label>
        {:else}<label>SNMP community<input type="password" bind:value={community} maxlength="128" autocomplete="new-password" /></label>{/if}
      </div><p>Supply the credentials configured on your devices. Credentials are kept only for this scan.</p>
    {/if}
    <button type="button" onclick={() => void start()}>Scan all devices</button>
  </fieldset>
  {#if running}<button type="button" disabled={scan?.state === 'cancelling'} onclick={() => void cancel()}>Cancel scan</button>{/if}
  {#if error}<p role="alert">{error}</p>{/if}
  {#if statusError}<p role="alert">{statusError}</p>{/if}
  <details><summary>Discovery support and CDP / LLDP</summary>
    <dl>{#each Object.entries(capabilities) as [name,detail]}<dt>{name.toUpperCase().replaceAll('_',' / ')}</dt><dd>{detail}</dd>{/each}</dl>
    <label>Import CDP / LLDP capture<input type="file" accept=".pcap,.cap,application/vnd.tcpdump.pcap" disabled={importBusy} onchange={event => void importCapture(event)}/></label>
    <p>Use an Ethernet PCAP up to 4 MiB captured on the link you want to inspect.</p>
    {#if capture}<p>{capture.detail}</p>{#each capture.findings as item}<p><b>{item.protocol.toUpperCase()} · {item.address} · {item.status.replaceAll('_',' ')}</b><br/>{Object.entries(item.facts).map(([key,value]) => `${key}: ${value}`).join(' · ')}<br/>Captured {new Date(item.observed_at).toLocaleString()}</p>{/each}{#if capture.imported_at && !capture.findings.length}<p>No valid CDP or LLDP advertisements were found in this capture.</p>{/if}{/if}
  </details>
  {#if scan?.job_id}
    <div role="status"><strong>{scan.state.replaceAll('_',' ')} · {scan.completed.toLocaleString()} / {scan.total.toLocaleString()} checks</strong><p>{scan.devices} devices · {scan.open_ports} open TCP ports · {scan.skipped_devices} without an eligible local address</p></div>
    <progress value={scan.completed} max={Math.max(1,scan.total)} aria-label="Scan progress"></progress>
    <p>{scan.detail}</p><p>{scan.no_response} no response · {scan.refused} refused · {scan.errors} unavailable or failed checks</p>
    {#if scan.started_at}<p>Started {new Date(scan.started_at).toLocaleString()}{scan.finished_at ? ` · Finished ${new Date(scan.finished_at).toLocaleString()}` : ''}</p>{/if}
    {#if scan.results_truncated}<p role="alert">The display limit was reached. Narrow the next scan to inspect more results.</p>{/if}
  {/if}
</details>
<style>
  .scan-panel{margin:18px 0;padding:16px;border:1px solid var(--line);border-radius:12px;background:var(--surface)}
  summary{cursor:pointer;font-weight:600;min-height:32px}p{font-size:13px;color:var(--muted-strong,var(--ink-mute));line-height:1.5}
  fieldset{border:0;padding:0;display:grid;gap:14px;min-width:0}label{display:flex;align-items:center;flex-wrap:wrap;gap:8px;font-size:13px}
  .protocols{display:flex;gap:16px;flex-wrap:wrap}.credentials{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}.credentials label{display:grid}
  select,input:not([type=checkbox]){min-height:40px;max-width:100%;padding:8px;background:var(--surface-2,var(--surface));color:var(--ink);border:1px solid var(--line);border-radius:6px}
  button{min-height:42px;justify-self:start;padding:10px 16px;border:1px solid var(--accent,var(--ember));border-radius:6px;background:var(--surface);color:var(--ink);cursor:pointer}button:disabled{opacity:.5}progress{width:100%;height:12px}
</style>
