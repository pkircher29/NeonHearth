<script lang="ts">
  import {onMount} from 'svelte';
  import type {HostApi,HostSnapshot,HostHistory,UsageApplication,ConnectionHistory,FirewallRule,HostSettings,TrafficPoint} from '../api/hostMonitor';
  import {formatBytes,trafficPath,trafficCsv} from '../trafficFormat';
  import {formatThroughput} from './networkFormat';
  import FirewallReview from './FirewallReview.svelte';
  import Icon from './Icon.svelte';
  let {api}: {api:HostApi}=$props();
  let snapshot=$state<HostSnapshot|null>(null);let history=$state<HostHistory|null>(null);let frozen=$state<HostHistory|null>(null);
  let tab=$state<'graph'|'apps'|'connections'|'alerts'|'settings'>('graph');let minutes=$state(5);let appId=$state('');let query=$state('');
  let error=$state('');let rulesError=$state('');let rules=$state<FirewallRule[]|null>(null);let busy=$state(false);let notice=$state('');
  let paused=$state(false);let selected=$state<TrafficPoint|null>(null);let mini=$state(false);
  let decision=$state<{app:UsageApplication;direction:'inbound'|'outbound';blocked:boolean;expected:boolean}|null>(null);
  let retention=$state(30);let budgetGiB=$state('');
  const displayed=$derived(paused&&frozen?frozen:history);
  let livePoints=$state<TrafficPoint[]>([]);let pausedPoints=$state<TrafficPoint[]>([]);
  const points=$derived(displayed?.points??[]);
  const chartPoints=$derived(paused?pausedPoints:!appId&&livePoints.length?[...points.filter(p=>p.at<Math.floor(livePoints[0]!.at/60)*60),...livePoints.filter(p=>p.at>=Date.now()/1000-minutes*60)]:points);
  const graphStart=$derived(displayed?Date.parse(displayed.since)/1000:0);
  const graphEnd=$derived(Math.max(displayed?Date.parse(displayed.until)/1000:1,chartPoints.at(-1)?.at??0));
  const graphMax=$derived(Math.max(1,...chartPoints.flatMap(p=>[p.sent_bytes,p.received_bytes].map(v=>v*1000/Math.max(1,p.measured_ms)))));
  const totals=$derived(points.reduce((sum,p)=>({sent:sum.sent+p.sent_bytes,received:sum.received+p.received_bytes}),{sent:0,received:0}));
  const available=$derived(snapshot?.status==='ready'||snapshot?.status==='history_unavailable');
  const currentApps=$derived.by(()=>{
    const grouped=new Map<string,{name:string;memory_bytes:number|null}>();
    for(const app of snapshot?.applications??[]){
      const old=grouped.get(app.app_id);
      grouped.set(app.app_id,{name:app.name,memory_bytes:old?old.memory_bytes===null||app.memory_bytes===null?null:old.memory_bytes+app.memory_bytes:app.memory_bytes});
    }
    return grouped;
  });
  const appOptions=$derived.by(()=>{
    const values=new Map((history?.applications??[]).map(a=>[a.app_id,a]));
    for(const app of snapshot?.applications??[])if(!values.has(app.app_id))values.set(app.app_id,{app_id:app.app_id,name:app.name,executable:app.executable,first_seen_at:'',last_seen_at:snapshot!.observed_at,sent_bytes:0,received_bytes:0,samples:0});
    return [...values.values()];
  });
  const apps=$derived(appOptions.filter(a=>(!appId||a.app_id===appId)&&`${a.name} ${a.executable??''}`.toLowerCase().includes(query.toLowerCase())));
  const connections=$derived.by(()=>{
    const values=new Map<string,ConnectionHistory>((history?.connections??[]).filter(c=>!appId||c.app_id===appId).map(c=>[c.connection_id,c]));
    for(const connection of snapshot?.connections??[]){
      if(appId&&connection.app_id!==appId)continue;
      const saved=values.get(connection.connection_id);
      values.set(connection.connection_id,{...connection,name:currentApps.get(connection.app_id)?.name??'Unresolved application',first_seen_at:saved?.first_seen_at??'',last_seen_at:snapshot!.observed_at});
    }
    return [...values.values()].filter(c=>`${c.name} ${c.local_address} ${c.remote_address??''} ${c.protocol} ${c.remote_port??''}`.toLowerCase().includes(query.toLowerCase()));
  });
  const currentConnections=$derived(new Set(snapshot?.connections.map(c=>c.connection_id)??[]));
  const alerts=$derived((history?.alerts??[]).filter(a=>a.detail.toLowerCase().includes(query.toLowerCase())));
  const snoozed=$derived(Boolean(history?.settings.snooze_until&&Date.parse(history.settings.snooze_until)>Date.now()));
  const unseen=$derived(snoozed?0:(history?.alerts.filter(a=>!a.acknowledged).length??0));
  const tcp=$derived(snapshot?.connections.filter(c=>c.protocol==='tcp'&&c.state==='established').length??0);
  let active=false;let generation=0;let refreshingHistory=false;
  async function loadHistory() {
    const key=++generation;const range=minutes;const app=appId;
    try {const value=await api.history(range,app||undefined);if(active&&key===generation){history=value;retention=value.settings.retention_days;error='';}}
    catch(e){if(active&&key===generation)error=e instanceof Error?e.message:'History is unavailable.';}
  }
  $effect(()=>{minutes;appId; if(active){paused=false;selected=null;void loadHistory();}});
  async function loadRules(){try{rules=await api.firewall();rulesError='';}catch(e){rules=null;rulesError=e instanceof Error?e.message:'Firewall rules are unavailable.';}}
  onMount(()=>{
    active=true;let timer:ReturnType<typeof setTimeout>;let ticks=0;
    async function poll(){
      try{const value=await api.snapshot();if(active){snapshot=value;error='';
        const at=Date.parse(value.observed_at)/1000;
        if((value.status==='ready'||value.status==='history_unavailable')&&Number.isFinite(at)&&at!==(livePoints.at(-1)?.at)&&value.last_interval_ms&&value.last_sent_bytes!=null&&value.last_received_bytes!=null){
          livePoints=[...livePoints,{at,sent_bytes:value.last_sent_bytes,received_bytes:value.last_received_bytes,measured_ms:value.last_interval_ms}].slice(-300);
        }}}
      catch(e){if(active){error=e instanceof Error?e.message:'Live host data is unavailable.';snapshot=null;}}
      if(active&&ticks++%5===0&&!refreshingHistory){refreshingHistory=true;void loadHistory().finally(()=>refreshingHistory=false);}
      if(active)timer=setTimeout(()=>void poll(),2000);
    }
    void poll();void loadRules();
    return()=>{active=false;generation++;clearTimeout(timer);};
  });
  function pause(){if(paused){paused=false;selected=null;}else{pausedPoints=chartPoints;frozen=history;paused=true;}}
  function inspect(event:MouseEvent){if(!chartPoints.length)return;const rect=(event.currentTarget as SVGSVGElement).getBoundingClientRect();const at=graphStart+(event.clientX-rect.left)/rect.width*(graphEnd-graphStart);selected=chartPoints.reduce((a,b)=>Math.abs(b.at-at)<Math.abs(a.at-at)?b:a);if(!paused){pausedPoints=chartPoints;frozen=history;paused=true;}}
  function blocked(app:UsageApplication,direction:'inbound'|'outbound'){return rules?.some(r=>r.name===`NeonHearth-App-${app.app_id}-${direction}`&&r.enabled.toLowerCase()==='true'&&r.action.toLowerCase()==='block')??false;}
  async function control(){
    if(!decision)return;const chosen=decision;busy=true;notice='';
    try{const result=await api.control(chosen.app.app_id,chosen.direction,chosen.blocked,chosen.expected);notice=result.blocked?`Windows verified the ${chosen.direction} block rule for ${chosen.app.name}.`:`NeonHearth's ${chosen.direction} block was removed. Other Windows rules still apply.`;if(!result.all_profiles_enabled)notice+=' Some Windows firewall profiles are disabled; the rule may not enforce on those networks.';decision=null;}
    catch(e){notice=e instanceof Error?e.message:'The firewall outcome is unknown.';}
    finally{await loadRules();busy=false;}
  }
  async function saveSettings(value:HostSettings){busy=true;try{const saved=await api.settings(value);if(history)history={...history,settings:saved};notice='Monitoring preferences saved.';}catch(e){notice=e instanceof Error?e.message:'Settings were not saved.';}finally{busy=false;}}
  function saveBudget(){
    if(!history)return;
    const amount=budgetGiB.trim()===''?null:Number(budgetGiB)*1024**3;
    if(amount!==null&&(!Number.isFinite(amount)||amount<1||amount>1_000_000_000_000_000)){notice='Enter a positive traffic target in GiB, or leave it blank to disable the target.';return;}
    void saveSettings({...history.settings,monthly_budget_bytes:amount===null?null:Math.round(amount)});
  }
  async function acknowledge(id:number){try{await api.acknowledge(id);await loadHistory();}catch(e){notice=e instanceof Error?e.message:'Could not acknowledge the alert.';}}
  function exportCsv(){
    const rows:unknown[][]=tab==='connections'?[['Application','Protocol','Local address','Local port','Remote address','Remote port','First observed','Last observed'],...connections.map(c=>[c.name,c.protocol,c.local_address,c.local_port,c.remote_address,c.remote_port,c.first_seen_at,c.last_seen_at])]
      :tab==='apps'?[['Application','Executable','Measured TCP sent bytes','Measured TCP received bytes','Measurement buckets','First observed','Last observed'],...apps.map(a=>[a.name,a.executable,a.samples?a.sent_bytes:null,a.samples?a.received_bytes:null,a.samples,a.first_seen_at,a.last_seen_at])]
      :[['Time UTC','Sent bytes','Received bytes','Measured milliseconds','Coverage'],...points.map(p=>[new Date(p.at*1000).toISOString(),p.sent_bytes,p.received_bytes,p.measured_ms,displayed?.coverage])];
    const url=URL.createObjectURL(new Blob([trafficCsv(rows)],{type:'text/csv;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download=`neonhearth-${tab}.csv`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  function date(value:string|number){return value===''?'Not recorded':new Date(value).toLocaleString([],{dateStyle:'medium',timeStyle:'short'});}
</script>
<section class="traffic-view" aria-labelledby="traffic-heading">
  <div class="view-heading"><div><p class="kicker">TRAFFIC / THIS COMPUTER</p><h1 id="traffic-heading">See your network activity.</h1><p class="muted">Applications, destinations, and measured traffic on the computer running NeonHearth.</p></div><button type="button" onclick={()=>mini=!mini} aria-pressed={mini}>Mini graph</button></div>
  <div class="traffic-metrics"><article><Icon name="down"/><div><span>Download now</span><strong>{formatThroughput(snapshot?.download_bytes_per_second)}</strong></div></article><article><Icon name="up"/><div><span>Upload now</span><strong>{formatThroughput(snapshot?.upload_bytes_per_second)}</strong></div></article><article><Icon name="devices"/><div><span>Applications with sockets</span><strong>{available?new Set(snapshot?.applications.map(a=>a.app_id)).size:'Unavailable'}</strong></div></article><article><Icon name="pulse"/><div><span>Established TCP</span><strong>{available?tcp:'Unavailable'}</strong></div></article></div>
  {#if error}<p role="alert">{error}</p>{/if}
  {#if snapshot}<p class="coverage-note">{snapshot.detail}</p>{/if}
  {#if snapshot?.app_counters==='requires_elevation'}<p class="permission-note">Application connections are visible. Per-application TCP byte collection and firewall changes require the collector to run with Windows administrator permission.</p>{/if}
  <div class="traffic-tabs" role="group" aria-label="Traffic view">{#each [['graph','Graph'],['apps','Applications'],['connections','Connections'],['alerts',`Alerts${unseen?` · ${unseen}`:''}`],['settings','Preferences']] as [key,label]}<button type="button" class:active={tab===key} aria-pressed={tab===key} onclick={()=>{tab=key as typeof tab;query='';}}>{label}</button>{/each}</div>
  {#if notice}<p role="status" class="notice">{notice}</p>{/if}
  {#if ['graph','apps','connections'].includes(tab)}
    <div class="traffic-controls"><label>Time range<select bind:value={minutes}><option value={5}>5 minutes</option><option value={60}>1 hour</option><option value={360}>6 hours</option><option value={1440}>24 hours</option><option value={10080}>7 days</option><option value={43200}>30 days</option></select></label><label>Traffic source<select bind:value={appId}><option value="">This computer · physical interfaces</option>{#each appOptions as app}<option value={app.app_id}>{app.name} · sampled TCP</option>{/each}</select></label><button type="button" onclick={exportCsv}>Export CSV</button></div>
  {/if}
  {#if tab==='graph'}
    <div class="traffic-chart"><div class="chart-top"><span>{formatThroughput(graphMax)} <small>scale</small></span><button type="button" aria-pressed={paused} onclick={pause}>{paused?'Resume graph':'Pause graph'}</button></div>
      {#if chartPoints.length}
        <svg viewBox="0 0 900 200" role="button" tabindex="0" aria-label="Inspect upload and download traffic history" onclick={inspect} onkeydown={event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();selected=chartPoints.at(-1)??null;if(selected&&!paused){pausedPoints=chartPoints;frozen=history;paused=true;}}}}><path class="grid" d="M0 20H900M0 60H900M0 100H900M0 140H900M0 180H900"/><path class="download" d={trafficPath(chartPoints,'received_bytes',graphStart,graphEnd,graphMax,appId?displayed?.bucket_seconds??60:Math.max(5,displayed?.bucket_seconds??60))}/><path class="upload" d={trafficPath(chartPoints,'sent_bytes',graphStart,graphEnd,graphMax,appId?displayed?.bucket_seconds??60:Math.max(5,displayed?.bucket_seconds??60))}/>{#each chartPoints as point}<circle cx={Math.max(0,Math.min(900,(point.at-graphStart)/Math.max(1,graphEnd-graphStart)*900))} cy={180-point.received_bytes*1000/Math.max(1,point.measured_ms)/graphMax*160} r="2" class="point"><title>{date(point.at*1000)} · received {formatBytes(point.received_bytes)} · sent {formatBytes(point.sent_bytes)}</title></circle>{/each}</svg>
        <label class="inspect-time">Inspect a reading<select aria-label="Inspect traffic reading" onchange={e=>{selected=e.currentTarget.value===''?null:chartPoints[Number(e.currentTarget.value)]??null;if(selected&&!paused){pausedPoints=chartPoints;frozen=history;paused=true;}}}><option value="">Choose a time</option>{#each chartPoints as p,i}<option value={i}>{date(p.at*1000)}</option>{/each}</select></label>
      {:else}<div class="chart-empty"><Icon name="pulse" size={40}/><strong>No measured traffic in this view yet</strong><p>Choose this computer for interface traffic. Application graphs need available TCP counters. Recording begins while the collector is running.</p></div>{/if}
      <div class="chart-times"><time>{displayed?date(displayed.since):'Waiting'}</time><span><i class="down-key"></i>Download <i class="up-key"></i>Upload</span><time>{displayed?date(displayed.until):''}</time></div>
    </div>
    {#if selected}<p class="point-detail">{date(selected.at*1000)} · downloaded {formatBytes(selected.received_bytes)} · uploaded {formatBytes(selected.sent_bytes)} · measured for {(selected.measured_ms/1000).toFixed(1)} seconds</p>{/if}
    <div class="usage-summary"><div><span>Downloaded in view</span><strong>{formatBytes(totals.received)}</strong></div><div><span>Uploaded in view</span><strong>{formatBytes(totals.sent)}</strong></div><div><span>Total measured</span><strong>{formatBytes(totals.sent+totals.received)}</strong></div></div>
    <p class="coverage-note">{appId?'Sampled TCP payload bytes. Connections shorter than the sampling interval and UDP traffic are not included.':'Physical-interface bytes include local and Internet traffic. They are not a measure of all devices on the home network.'} Gaps represent missing measurements. Historical readings are grouped into {displayed?.bucket_seconds??60}-second buckets.</p>
  {:else if tab==='apps'}
    <label class="traffic-search">Find an application<input bind:value={query} placeholder="Application name or executable path"/></label>
    <div class="app-list">{#each apps as app (app.app_id)}{@const current=currentApps.get(app.app_id)}<article class="host-app"><div class="app-heading"><span class="app-icon"><Icon name="devices"/></span><div><h2>{app.name}</h2><p class="executable">{app.executable??'Executable path unavailable'}</p></div><span class="app-live">{current?'Observed now':'In history'}</span></div><div class="app-facts"><p><b>Sent / received</b>{app.samples?`${formatBytes(app.sent_bytes)} / ${formatBytes(app.received_bytes)}`:'Not measured'}<small>Sampled TCP in the selected range</small></p><p><b>Working memory</b>{formatBytes(current?.memory_bytes)}</p><p><b>First observed</b>{date(app.first_seen_at)}</p><p><b>Last observed</b>{date(app.last_seen_at)}</p></div><div class="app-actions"><button onclick={()=>{appId=app.app_id;tab='graph';}}>View graph</button><button onclick={()=>{appId=app.app_id;tab='connections';}}>View connections</button>{#each ['inbound','outbound'] as direction}<button disabled={busy||!snapshot?.firewall_available||!app.executable||rules===null} onclick={()=>{const expected=blocked(app,direction as 'inbound'|'outbound');decision={app,direction:direction as 'inbound'|'outbound',blocked:!expected,expected};}}>{blocked(app,direction as 'inbound'|'outbound')?'Release':'Block'} {direction}</button>{/each}</div></article>{:else}<p>No applications match this view.</p>{/each}</div>
    {#if rulesError}<p class="coverage-note">{rulesError}</p>{/if}<p class="coverage-note">Firewall buttons manage only NeonHearth's Windows rules. “Release” removes our block; other firewall rules still apply.</p>
  {:else if tab==='connections'}
    <label class="traffic-search">Find a connection<input bind:value={query} placeholder="Application, address, port, or protocol"/></label>
    <div class="connection-list">{#each connections as connection (connection.connection_id)}<article><div><strong>{connection.name}</strong><span class="connection-state">{currentConnections.has(connection.connection_id)?connection.state.replaceAll('_',' '):'Previously observed'}</span></div><p><span class="protocol">{connection.protocol.toUpperCase()}</span> {connection.local_address}:{connection.local_port} → {connection.remote_address?`${connection.remote_address}:${connection.remote_port}`:'Listening / bound endpoint; no peer reported'}</p><small>First {date(connection.first_seen_at)} · Last {date(connection.last_seen_at)}</small></article>{:else}<p>No matching connections in this period.</p>{/each}</div><p class="coverage-note">Shows current endpoints plus up to 2,048 saved observations. A port number suggests a service; encrypted traffic does not reveal the application protocol by itself.</p>
  {:else if tab==='alerts'}
    <div class="traffic-controls"><label class="traffic-search">Find an alert<input bind:value={query} placeholder="Application or event details"/></label>{#if history}<button disabled={busy} onclick={()=>void saveSettings({...history!.settings,snooze_until:snoozed?null:new Date(Date.now()+23*60*60*1000+59*60*1000).toISOString()})}>{snoozed?'Resume alert badges':'Snooze badges for 24 hours'}</button>{/if}</div>
    {#if snoozed}<p class="coverage-note">Alert badges are snoozed. Events remain recorded here.</p>{/if}
    <div class="connection-list">{#each alerts as alert (alert.id)}<article class:acknowledged={alert.acknowledged}><div><strong>{alert.kind.replaceAll('_',' ')}</strong><time>{date(alert.at)}</time></div><p>{alert.detail}</p>{#if !alert.acknowledged}<button onclick={()=>void acknowledge(alert.id)}>Mark reviewed</button>{:else}<small>Reviewed</small>{/if}</article>{:else}<p>No recorded alerts match.</p>{/each}</div>
  {:else if tab==='settings'&&history}
    <div class="traffic-preferences"><h2>Local history</h2><label><input type="checkbox" checked={history.settings.record_history} disabled={busy} onchange={e=>void saveSettings({...history!.settings,record_history:e.currentTarget.checked})}/>Record traffic and connection history</label><p>Turning recording off keeps live readings available and leaves existing history intact.</p><label>Keep history for<select bind:value={retention}><option value={1}>1 day</option><option value={7}>7 days</option><option value={30}>30 days</option><option value={90}>90 days</option><option value={365}>365 days</option></select></label><p>Older history expires automatically. Storage is bounded to 500,000 measurement buckets, 20,000 endpoints, and 2,000 alerts.</p><button disabled={busy} onclick={()=>void saveSettings({...history!.settings,retention_days:retention})}>Save retention</button><h2>Monthly traffic target</h2><p>Retained measurements this calendar month (UTC): {formatBytes((history.month_usage?.sent_bytes??0)+(history.month_usage?.received_bytes??0))}. Includes local traffic. Missing days and expired history are not estimated.</p><p>Current target: {history.settings.monthly_budget_bytes?formatBytes(history.settings.monthly_budget_bytes):'Disabled'}</p><label>Target in GiB<input bind:value={budgetGiB} inputmode="decimal" placeholder="For example, 1000" maxlength="16"/></label><p>Leave blank to disable the target. Reaching it creates a local alert.</p><button disabled={busy} onclick={saveBudget}>Save traffic target</button><h2>Measurement coverage</h2><p>Interface readings count this computer's traffic across its active physical adapters. VPN and virtual adapters are listed below and excluded from the combined total to avoid counting the same traffic twice.</p>{#each snapshot?.interfaces??[] as intf}<p><b>{intf.name}</b> · {intf.physical?'included in host total':'virtual / other; excluded from total'}</p>{/each}<p>Application byte measurements cover sampled TCP connections when Windows provides the counters. Short connections and UDP traffic need a packet/event collector for complete application attribution.</p></div>
  {/if}
  {#if decision}<FirewallReview name={decision.app.name} path={decision.app.executable} direction={decision.direction} blocked={decision.blocked} {busy} onconfirm={()=>void control()} oncancel={()=>decision=null}/>{/if}
  {#if mini}<aside class="mini-traffic" aria-label="Mini traffic graph"><div><strong>This computer</strong><button aria-label="Close mini graph" onclick={()=>mini=false}>×</button></div><p>↓ {formatThroughput(snapshot?.download_bytes_per_second)}<br/>↑ {formatThroughput(snapshot?.upload_bytes_per_second)}</p><svg viewBox="0 0 900 200" role="img" aria-label="Compact traffic history"><path class="download" d={trafficPath(chartPoints,'received_bytes',graphStart,graphEnd,graphMax,appId?displayed?.bucket_seconds??60:Math.max(5,displayed?.bucket_seconds??60))}/><path class="upload" d={trafficPath(chartPoints,'sent_bytes',graphStart,graphEnd,graphMax,appId?displayed?.bucket_seconds??60:Math.max(5,displayed?.bucket_seconds??60))}/></svg></aside>{/if}
</section>
<style>
  .traffic-view{min-width:0}.traffic-view button,.traffic-view select,.traffic-view input:not([type=checkbox]){min-height:40px;padding:8px 12px;background:var(--surface);color:var(--ink);border:1px solid var(--line-strong);border-radius:6px;max-width:100%;box-sizing:border-box}.traffic-view button{cursor:pointer}.traffic-view button:disabled{opacity:.45;cursor:not-allowed}.traffic-view button:hover:not(:disabled){border-color:var(--accent)}.traffic-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}.traffic-metrics article{display:flex;align-items:center;gap:12px;padding:20px 14px;border:1px solid var(--line-mid);border-radius:10px;background:var(--surface);color:var(--accent)}.traffic-metrics span,.usage-summary span{display:block;font-size:11px;color:var(--muted-strong);margin-bottom:7px}.traffic-metrics strong{font:600 23px var(--font-display);color:var(--ink)}.traffic-tabs{display:flex;gap:8px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding:8px 0 14px;margin-top:18px}.traffic-tabs button.active{border-color:var(--accent);background:var(--surface-raised);color:var(--accent)}.coverage-note,.permission-note,.traffic-preferences p{font-size:12px;color:var(--muted-strong);line-height:1.6}.permission-note{padding:12px;border:1px solid var(--gold);border-radius:8px}.traffic-controls{display:flex;gap:12px;align-items:end;flex-wrap:wrap;margin:18px 0}.traffic-controls label{display:grid;gap:6px;font-size:12px;min-width:0;max-width:100%}.traffic-controls select{max-width:350px}.traffic-chart{border:1px solid var(--line-mid);border-radius:12px;padding:18px;background:radial-gradient(ellipse at 50% 100%,#17344055,transparent 60%),var(--surface)}.chart-top{display:flex;justify-content:space-between;align-items:center;gap:10px;font:12px var(--font-mono)}.chart-top small{color:var(--muted)}svg{width:100%;height:auto;min-height:140px;display:block}.grid{stroke:var(--line);stroke-dasharray:4 6;fill:none}.download,.upload{stroke:var(--accent);stroke-width:2;fill:none;stroke-linejoin:round}.upload{stroke:var(--gold)}.point{fill:var(--accent)}.chart-times{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;color:var(--muted-strong);font-size:10px}.chart-times span{display:flex;gap:7px;align-items:center}.down-key,.up-key{display:inline-block;width:10px;height:3px;background:var(--accent)}.up-key{background:var(--gold)}.chart-empty{min-height:220px;display:grid;align-content:center;justify-items:center;text-align:center;gap:12px;color:var(--muted-strong)}.chart-empty p{max-width:500px;font-size:12px;line-height:1.6}.chart-empty strong{color:var(--ink)}.inspect-time{display:flex;gap:12px;align-items:center;font-size:11px;margin:10px 0;flex-wrap:wrap}.inspect-time select{max-width:100%}.usage-summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0}.usage-summary div{border-left:2px solid var(--line-strong);padding:12px}.usage-summary strong{font:600 24px var(--font-display)}.point-detail,.notice{border:1px solid var(--line-strong);padding:12px;border-radius:6px;font-size:12px;line-height:1.6;overflow-wrap:anywhere}.traffic-search{display:grid;gap:7px;font-size:12px;margin:18px 0}.traffic-search input{width:100%}.app-list,.connection-list{display:grid;gap:12px}.host-app,.connection-list article,.traffic-preferences{padding:18px;border:1px solid var(--line-mid);border-radius:10px;background:var(--surface);min-width:0}.app-heading{display:flex;align-items:center;gap:12px}.app-heading>div{flex:1;min-width:0}.app-heading h2{font-size:16px;margin:0 0 6px}.app-icon{padding:11px;border:1px solid var(--line-strong);border-radius:8px;color:var(--accent)}.executable{overflow-wrap:anywhere;font:11px var(--font-mono);color:var(--muted-strong)}.app-live{font-size:11px;color:var(--accent)}.app-facts{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;font-size:12px}.app-facts b{display:block;font:10px var(--font-mono);color:var(--muted-strong);margin:8px 0}.app-facts small{display:block;font-size:10px;color:var(--muted);margin-top:5px}.app-actions{display:flex;gap:8px;flex-wrap:wrap}.connection-list article>div{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}.connection-list p{font:12px var(--font-mono);overflow-wrap:anywhere;line-height:1.6}.connection-list small,.connection-list time,.connection-state{font-size:11px;color:var(--muted-strong)}.connection-list strong{text-transform:capitalize}.protocol{color:var(--accent)}.acknowledged{opacity:.65}.traffic-preferences h2{font-size:18px;margin:20px 0 14px}.traffic-preferences label{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:13px}.mini-traffic{position:fixed;right:24px;bottom:90px;width:240px;z-index:8;background:var(--surface);border:1px solid var(--accent);border-radius:10px;padding:14px;box-shadow:0 8px 30px #000a}.mini-traffic>div{display:flex;justify-content:space-between;align-items:center;font-size:12px}.mini-traffic svg{min-height:0}.mini-traffic p{font:13px var(--font-mono);line-height:1.7}@media(max-width:1100px){.traffic-metrics{grid-template-columns:repeat(2,1fr)}.app-facts{grid-template-columns:repeat(2,1fr)}}@media(max-width:650px){.traffic-metrics article{padding:14px 10px}.traffic-metrics strong{font-size:18px}.usage-summary{grid-template-columns:1fr}.app-heading{flex-wrap:wrap}.app-live{margin-left:55px}.traffic-controls label{width:100%}.traffic-controls select{max-width:100%}.chart-times{display:grid;grid-template-columns:1fr}.traffic-chart{padding:12px}.mini-traffic{right:12px;width:210px}.view-heading{flex-wrap:wrap}}
</style>
