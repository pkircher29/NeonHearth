<script lang="ts">
  // History: the hash-chained audit log, newest first, with the chain's
  // verification state shown beside it so an owner can tell "what happened"
  // from "and nothing has been altered since".
  import { onMount } from 'svelte';
  import type { ApiClient, AuditActor, AuditCategory, AuditEntry, AuditVerify, ChainHead } from '../api/client';
  import Icon from './Icon.svelte';

  type HistoryClient = Pick<ApiClient, 'auditPage' | 'auditVerify'>;
  interface Props { client: HistoryClient; pageSize?: number }
  let { client, pageSize = 50 }: Props = $props();

  const CATEGORY_LABEL: Record<AuditCategory, string> = { approval: 'Approval', scan: 'Scan', enforcement: 'Enforcement', doctor_action: 'Doctor', audit_module: 'Audit module' };
  const ACTOR_LABEL: Record<AuditActor, string> = { owner: 'You', service: 'NeonHearth', module: 'Audit module' };

  let entries = $state<AuditEntry[]>([]);
  let head = $state<ChainHead | null>(null);
  let nextBefore = $state<number | null>(null);
  let loading = $state(true);
  let loadingMore = $state(false);
  let loadError = $state<string | null>(null);
  let category = $state<AuditCategory | 'all'>('all');
  let actor = $state<AuditActor | 'all'>('all');
  let verify = $state<AuditVerify | null>(null);
  let verifying = $state(false);
  let verifyError = $state<string | null>(null);
  let expanded = $state<Set<number>>(new Set());
  let generation = 0;

  const groups = $derived.by(() => {
    const byDay = new Map<string, AuditEntry[]>();
    for (const entry of entries) {
      const day = new Date(entry.occurred_at).toLocaleDateString([], { dateStyle: 'medium' });
      const list = byDay.get(day);
      if (list) list.push(entry); else byDay.set(day, [entry]);
    }
    return [...byDay.entries()];
  });

  function filterOptions() {
    return { ...(category === 'all' ? {} : { category }), ...(actor === 'all' ? {} : { actor }) };
  }

  async function load() {
    const token = ++generation;
    loading = true; loadError = null;
    try {
      const page = await client.auditPage({ limit: pageSize, ...filterOptions() });
      if (token !== generation) return;
      entries = page.entries; head = page.head; nextBefore = page.next_before; expanded = new Set();
    } catch {
      if (token !== generation) return;
      loadError = 'The collector could not read the audit log. It may be busy or restarting.';
    } finally { if (token === generation) loading = false; }
  }

  async function loadMore() {
    if (nextBefore === null || loadingMore) return;
    const token = generation;
    loadingMore = true;
    try {
      const page = await client.auditPage({ limit: pageSize, before: nextBefore, ...filterOptions() });
      if (token !== generation) return;
      entries = [...entries, ...page.entries]; nextBefore = page.next_before;
    } catch {
      if (token === generation) loadError = 'Older entries could not be loaded. Try again.';
    } finally { loadingMore = false; }
  }

  async function runVerify() {
    verifying = true; verifyError = null;
    try { verify = await client.auditVerify(); }
    catch { verifyError = 'Verification could not run right now.'; }
    finally { verifying = false; }
  }

  function toggle(id: number) {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id); else next.add(id);
    expanded = next;
  }

  function time(value: string): string { return new Date(value).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' }); }
  function shortHash(hash: string): string { return `${hash.slice(0, 8)}…${hash.slice(-6)}`; }
  function detailText(detail: unknown): string { try { return JSON.stringify(detail, null, 2); } catch { return String(detail); } }
  function cueFor(entry: AuditEntry): 'secure' | 'watch' | 'risk' | 'info' {
    if (entry.category === 'enforcement') return 'risk';
    if (entry.category === 'doctor_action' || entry.category === 'scan') return 'watch';
    if (entry.category === 'approval') return 'secure';
    return 'info';
  }

  onMount(() => { void load(); void runVerify(); });
</script>

<section class="history-view" aria-labelledby="history-heading">
  <div class="view-heading"><div><p class="kicker">HISTORY / AUDIT CHAIN</p><h1 id="history-heading">Every action, on the record.</h1><p class="muted">Approvals, scans, enforcement and repairs are written to a hash-chained log. Each entry commits to the one before it, so a gap or a rewrite shows up here.</p></div></div>

  <div class="chain-strip" class:valid={verify?.valid === true} class:broken={verify !== null && !verify.valid} role="status" aria-live="polite">
    <span class="chain-icon"><Icon name={verify === null ? 'dot' : verify.valid ? 'check' : 'alert'} size={16} strokeWidth={2.2} /></span>
    <div>
      {#if verifying && verify === null}<strong>Verifying the chain…</strong><small>Recomputing every hash from the trusted root.</small>
      {:else if verifyError}<strong>Chain not verified</strong><small>{verifyError}</small>
      {:else if verify === null}<strong>Chain not verified yet</strong>
      {:else if verify.valid}<strong>Chain intact</strong><small>{verify.report.checked} entr{verify.report.checked === 1 ? 'y' : 'ies'} checked{verify.report.anchored ? ' from the trusted root' : ''}{verify.head ? ` · head #${verify.head.id} ${shortHash(verify.head.entry_hash)}` : ''}</small>
      {:else}<strong>Chain break at entry #{verify.report.first_break?.id}</strong><small>{verify.report.first_break?.kind.replaceAll('_', ' ')}. Treat entries at and after this point as unverified and export your backup.</small>{/if}
    </div>
    <button type="button" class="quiet" onclick={runVerify} disabled={verifying}>{verifying ? 'Verifying…' : 'Verify again'}</button>
  </div>

  <div class="history-filters" role="group" aria-label="Filter history">
    <label><span>Category</span><select bind:value={category} onchange={load}><option value="all">All</option>{#each Object.entries(CATEGORY_LABEL) as [value, label]}<option {value}>{label}</option>{/each}</select></label>
    <label><span>Actor</span><select bind:value={actor} onchange={load}><option value="all">Anyone</option>{#each Object.entries(ACTOR_LABEL) as [value, label]}<option {value}>{label}</option>{/each}</select></label>
    {#if head}<span class="head-note">Latest entry #{head.id}</span>{/if}
  </div>

  {#if loading}
    <p class="unavailable-copy" role="status">Loading the audit log…</p>
  {:else if loadError && entries.length === 0}
    <div class="empty-state"><span class="empty-icon"><Icon name="alert" size={26} /></span><div><strong>History is unavailable</strong><p class="muted">{loadError}</p><button type="button" class="quiet" onclick={load}>Reload</button></div></div>
  {:else if entries.length === 0}
    <div class="empty-state"><span class="empty-icon"><Icon name="history" size={26} /></span><div><strong>Nothing on the record yet</strong><p class="muted">{category === 'all' && actor === 'all' ? 'Approvals, scans and repairs will appear here as they happen.' : 'No entries match these filters.'}</p></div></div>
  {:else}
    {#each groups as [day, list] (day)}
      <h2 class="day-heading">{day}</h2>
      <ol class="audit-list">
        {#each list as entry (entry.id)}
          <li class="audit-row" class:open={expanded.has(entry.id)}>
            <button type="button" class="audit-summary" aria-expanded={expanded.has(entry.id)} aria-controls={`audit-detail-${entry.id}`} onclick={() => toggle(entry.id)}>
              <span class="event-kind {cueFor(entry)}" aria-hidden="true"><Icon name={cueFor(entry) === 'risk' ? 'alert' : cueFor(entry) === 'secure' ? 'check' : 'dot'} size={12} strokeWidth={2.2} /></span>
              <span class="audit-main"><strong>{entry.action.replaceAll('.', ' · ').replaceAll('_', ' ')}</strong><small>{CATEGORY_LABEL[entry.category]} · {ACTOR_LABEL[entry.actor]}{entry.subject ? ` · ${entry.subject}` : ''}</small></span>
              <time datetime={entry.occurred_at}>{time(entry.occurred_at)}</time>
              <span class="audit-id mono">#{entry.id}</span>
            </button>
            {#if expanded.has(entry.id)}
              <div class="audit-detail" id={`audit-detail-${entry.id}`}>
                <dl>
                  <div><dt>Entry hash</dt><dd class="mono">{entry.entry_hash}</dd></div>
                  <div><dt>Previous</dt><dd class="mono">{entry.prev_hash}</dd></div>
                </dl>
                <pre>{detailText(entry.detail)}</pre>
              </div>
            {/if}
          </li>
        {/each}
      </ol>
    {/each}
    {#if loadError}<p class="pair-error" role="alert">{loadError}</p>{/if}
    {#if nextBefore !== null}<button type="button" class="quiet load-more" onclick={loadMore} disabled={loadingMore}>{loadingMore ? 'Loading…' : 'Load older entries'}</button>{/if}
  {/if}
</section>

<style>
  .chain-strip { margin-top: 24px; display: grid; grid-template-columns: auto 1fr auto; gap: 14px; align-items: center; padding: 14px 16px; border: 1px solid var(--line-mid); border-radius: var(--radius); background: var(--surface); }
  .chain-strip strong { display: block; }
  .chain-strip small { display: block; margin-top: 3px; color: var(--muted); font: 11px var(--font-mono); }
  .chain-icon { display: inline-grid; place-items: center; width: 30px; height: 30px; border-radius: 50%; border: 1px solid currentColor; color: var(--muted); }
  .chain-strip.valid .chain-icon { color: var(--ok); }
  .chain-strip.broken { border-color: var(--risk); }
  .chain-strip.broken .chain-icon { color: var(--risk); }
  .history-filters { display: flex; flex-wrap: wrap; gap: 14px; align-items: end; margin: 22px 0 6px; }
  .history-filters label { display: grid; gap: 6px; color: var(--muted); font: 10px var(--font-mono); text-transform: uppercase; letter-spacing: .1em; }
  .history-filters select { min-height: 40px; min-width: 150px; padding: 0 10px; border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--surface); color: var(--ink); font: 13px var(--font-body); }
  .head-note { margin-left: auto; align-self: center; color: var(--faint); font: 11px var(--font-mono); }
  .day-heading { margin: 22px 0 6px; font: 600 12px var(--font-mono); letter-spacing: .08em; text-transform: uppercase; color: var(--accent); }
  .audit-list { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--line); }
  .audit-row { border-bottom: 1px solid var(--line); }
  .audit-summary { width: 100%; min-height: 56px; display: grid; grid-template-columns: 25px 1fr auto auto; gap: 12px; align-items: center; padding: 8px 4px; border: 0; background: none; color: inherit; text-align: left; cursor: pointer; font: inherit; }
  .audit-summary:hover { background: color-mix(in srgb, var(--surface-raised) 60%, transparent); }
  .audit-main strong, .audit-main small { display: block; }
  .audit-main small { margin-top: 3px; color: var(--muted); font-size: 11px; }
  .audit-summary time { color: var(--faint); font: 10px var(--font-mono); }
  .audit-id { color: var(--faint); font-size: 10px; }
  .mono { font-family: var(--font-mono); }
  .event-kind { display: inline-grid; place-items: center; width: 21px; height: 21px; border: 1px solid currentColor; border-radius: 4px; color: var(--info); }
  .event-kind.secure { color: var(--ok); }
  .event-kind.watch { color: var(--watch); border-style: dashed; }
  .event-kind.risk { color: var(--risk); border-width: 2px; }
  .audit-detail { padding: 4px 8px 14px 41px; display: grid; gap: 10px; }
  .audit-detail dl { margin: 0; display: grid; gap: 6px; }
  .audit-detail dt { color: var(--faint); font: 10px var(--font-mono); text-transform: uppercase; }
  .audit-detail dd { margin: 2px 0 0; color: var(--muted-strong); font-size: 11px; overflow-wrap: anywhere; }
  .audit-detail pre { margin: 0; padding: 10px 12px; border-radius: var(--radius-sm); background: var(--bg); color: var(--muted-strong); font: 11px/1.5 var(--font-mono); overflow-x: auto; max-height: 320px; }
  .quiet { min-height: 40px; padding: 8px 14px; border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: transparent; color: var(--ink); font: 600 12px var(--font-body); cursor: pointer; }
  .quiet:disabled { opacity: .5; cursor: progress; }
  .load-more { margin-top: 18px; }
  .pair-error { margin: 12px 0 0; padding: 9px; border: 1px solid var(--risk); border-radius: var(--radius-sm); color: var(--risk); font: 11px var(--font-mono); }
  @media (max-width: 850px) { .chain-strip { grid-template-columns: auto 1fr; } .chain-strip .quiet { grid-column: 2; justify-self: start; } .audit-summary { grid-template-columns: 25px 1fr auto; } .audit-id { display: none; } }
</style>
