<script lang="ts">
  import type { ApiClient, OwnerActionInput } from '../api/client';
  import type { GuardPolicy, LiveState } from '../stores/live';

  type PolicyActionClient = Pick<ApiClient, 'policyAction'>;
  type Decision = 'approve' | 'reject' | 'quarantine';

  // The prop keeps its public name `state`; the local alias avoids shadowing
  // the `$state` rune used for the owner-action UI state below.
  let { state: live, client = null }: { state: LiveState; client?: PolicyActionClient | null } = $props();
  const policies = $derived(Object.values(live.policies).sort((a, b) => rank(b) - rank(a)));
  const attention = $derived(policies.filter((policy) => policy.requested_action !== 'none').length);
  const verified = $derived(policies.filter((policy) => policy.enforcement_result === 'verified').length);

  function rank(policy: GuardPolicy): number {
    if (policy.enforcement_result === 'failed') return 5;
    if (policy.requested_action === 'owner_attention') return 4;
    if (policy.requested_action === 'permanent_ban') return 3;
    if (policy.requested_action === 'quarantine') return 2;
    return 1;
  }
  function title(policy: GuardPolicy): string {
    const device = live.devices[policy.device_id];
    return device?.owner_name ?? device?.identity.classification ?? 'Unconfirmed device';
  }
  function action(policy: GuardPolicy): string {
    return policy.requested_action === 'none' ? 'Monitoring'
      : policy.requested_action === 'owner_attention' ? 'Owner attention'
      : policy.requested_action === 'permanent_ban' ? 'Permanent ban'
      : 'Quarantine';
  }
  function reason(policy: GuardPolicy): string {
    return policy.evaluation.reason.replaceAll('_', ' ');
  }
  function deadline(policy: GuardPolicy): string {
    if (!policy.evaluation.deadline) return 'No active deadline';
    return `Due ${new Date(policy.evaluation.deadline.due_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}`;
  }
  function lifecycleKey(policy: GuardPolicy): string {
    return [policy.device_id, policy.evaluation.policy_version, policy.requested_action, policy.enforcement_result, policy.evaluation.reason, policy.evaluation.deadline?.due_at ?? '', policy.evaluation.warning ?? '', policy.undo_available, policy.delivery_pending].join('|');
  }

  // Owner decision availability mirrors the domain rules in
  // lattice-domain/src/policy.rs and lattice-policy: reasons where the owner
  // decision is still pending accept every decision; protected devices only
  // accept approval; a verified destructive decision can be released (Approve)
  // only while the actuator reports undo as available.
  const pendingReasons = new Set(['pending_confirmation', 'owner_extension', 'high_confidence_danger', 'unknown_deadline_expired', 'automatic_deadline_expired']);
  function decisions(policy: GuardPolicy): Decision[] {
    if (policy.evaluation.reason === 'protected_device') return ['approve'];
    if (pendingReasons.has(policy.evaluation.reason)) return ['approve', 'reject', 'quarantine'];
    if ((policy.evaluation.reason === 'owner_rejected' || policy.evaluation.reason === 'owner_quarantined') && policy.undo_available) return ['approve'];
    return [];
  }
  // The one-use extension (DevicePolicy.extension_until; the repository owns
  // the one-use constraint) only moves a live confirmation deadline later.
  // reason=owner_extension means the single extension is already spent.
  function extendState(policy: GuardPolicy): 'available' | 'used' | 'hidden' {
    if (policy.evaluation.reason === 'owner_extension') return 'used';
    if (policy.evaluation.reason === 'pending_confirmation' && policy.evaluation.deadline) return 'available';
    return 'hidden';
  }
  function extendUntil(policy: GuardPolicy): string | null {
    const due = policy.evaluation.deadline?.due_at;
    return due ? new Date(new Date(due).getTime() + 24 * 60 * 60 * 1000).toISOString() : null;
  }

  let confirming = $state<Record<string, Decision | null>>({});
  let busy = $state<Record<string, string | null>>({});
  let errors = $state<Record<string, string | null>>({});

  function arm(deviceId: string, decision: Decision): void {
    confirming = { ...confirming, [deviceId]: decision };
  }
  function disarm(deviceId: string): void {
    confirming = { ...confirming, [deviceId]: null };
  }
  async function submit(policy: GuardPolicy, action: OwnerActionInput, label: string): Promise<void> {
    if (!client) return;
    const id = policy.device_id;
    confirming = { ...confirming, [id]: null };
    errors = { ...errors, [id]: null };
    busy = { ...busy, [id]: label };
    try {
      await client.policyAction(id, action);
      // Success is intentionally not applied locally: the verified outcome
      // arrives through the live event stream and replaces this card.
    } catch (cause) {
      errors = { ...errors, [id]: `Could not ${label} ${title(policy)}: ${cause instanceof Error ? cause.message : 'request failed'}` };
    } finally {
      busy = { ...busy, [id]: null };
    }
  }
</script>

<section class="guard-view" aria-labelledby="guard-heading">
  <div class="view-heading">
    <div>
      <p class="kicker">GUARD / APPROVAL POLICY</p>
      <h1 id="guard-heading">Every guest earns trust.</h1>
      <p class="muted">Deadlines, owner decisions, and enforcement stay visible from first sighting to verified action.</p>
    </div>
  </div>

  <div class="guard-meter" class:active={attention > 0}>
    <div class="guard-orbit" aria-hidden="true"><span></span><span></span><span></span></div>
    <div><strong>{attention}</strong><span>need attention</span></div>
    <div><strong>{verified}</strong><span>verified actions</span></div>
    <div><strong>{policies.length}</strong><span>policy records live</span></div>
  </div>

  {#if policies.length === 0}
    <div class="empty-state guard-empty">
      <span class="empty-icon" aria-hidden="true">◇</span>
      <div><strong>No policy decisions yet</strong><p class="muted">When a device is evaluated, its countdown and enforcement proof will animate here.</p></div>
    </div>
  {:else}
    <div class="policy-grid" aria-live="polite">
      {#each policies as policy (lifecycleKey(policy))}
        {@const name = title(policy)}
        {@const allowed = client ? decisions(policy) : []}
        {@const extend = client ? extendState(policy) : 'hidden'}
        {@const inFlight = Boolean(busy[policy.device_id])}
        <article class="policy-card action-{policy.requested_action} enforcement-{policy.enforcement_result}" data-lifecycle-key={lifecycleKey(policy)}>
          <div class="policy-head">
            <span class="policy-signal" aria-hidden="true"></span>
            <div><p class="kicker">{action(policy)}</p><h2>{title(policy)}</h2></div>
            <span class="enforcement"><span aria-hidden="true">{policy.enforcement_result === 'verified' ? '✓' : policy.enforcement_result === 'failed' ? '!' : '◇'}</span> {policy.delivery_pending ? 'delivery pending' : policy.enforcement_result.replaceAll('_', ' ')}</span>
          </div>
          <div class="policy-path" aria-label="Policy lifecycle">
            <span class="done">Seen</span><i></i><span class="done">Evaluated</span><i></i><span class:done={policy.enforcement_result === 'verified'}>{policy.enforcement_result === 'verified' ? 'Verified' : 'Awaiting proof'}</span>
          </div>
          <dl><div><dt>Reason</dt><dd>{reason(policy)}</dd></div><div><dt>Deadline</dt><dd>{deadline(policy)}</dd></div><div><dt>Owner undo</dt><dd>{policy.undo_available ? 'Available' : 'Not available'}</dd></div></dl>
          {#if policy.evaluation.warning}<p class="warning"><span aria-hidden="true">△</span> Countdown warning: {policy.evaluation.warning.replace('hours', '').replace('hour', '')} hour{policy.evaluation.warning === 'hour1' ? '' : 's'} remain</p>{/if}
          {#if policy.evaluation.reason === 'protected_device'}
            <p class="protected-note"><span aria-hidden="true">⌾</span> Protected device — the router, collector, administrator phone, and safety devices cannot be rejected or quarantined. Approve it to clear this attention flag.</p>
          {/if}
          {#if allowed.length > 0 || extend !== 'hidden'}
            <div class="owner-actions" role="group" aria-label="Owner decision for {name}" aria-busy={inFlight}>
              {#if errors[policy.device_id]}<p class="action-error" role="alert">{errors[policy.device_id]}</p>{/if}
              {#if allowed.includes('approve')}
                <button type="button" class="act" aria-label="Approve {name}" disabled={inFlight} onclick={() => void submit(policy, 'approve', 'approve')}>Approve</button>
              {/if}
              {#if allowed.includes('reject')}
                {#if confirming[policy.device_id] === 'reject'}
                  <span class="confirm-step"><span class="confirm-question">Reject {name}?</span>
                    <button type="button" class="act danger" aria-label="Confirm reject {name}" disabled={inFlight} onclick={() => void submit(policy, 'reject', 'reject')}>Confirm reject</button>
                    <button type="button" class="act" aria-label="Cancel reject {name}" disabled={inFlight} onclick={() => disarm(policy.device_id)}>Cancel</button>
                  </span>
                {:else}
                  <button type="button" class="act danger" aria-label="Reject {name}" disabled={inFlight} onclick={() => arm(policy.device_id, 'reject')}>Reject</button>
                {/if}
              {/if}
              {#if allowed.includes('quarantine')}
                {#if confirming[policy.device_id] === 'quarantine'}
                  <span class="confirm-step"><span class="confirm-question">Quarantine {name}?</span>
                    <button type="button" class="act danger" aria-label="Confirm quarantine {name}" disabled={inFlight} onclick={() => void submit(policy, 'quarantine', 'quarantine')}>Confirm quarantine</button>
                    <button type="button" class="act" aria-label="Cancel quarantine {name}" disabled={inFlight} onclick={() => disarm(policy.device_id)}>Cancel</button>
                  </span>
                {:else}
                  <button type="button" class="act danger" aria-label="Quarantine {name}" disabled={inFlight} onclick={() => arm(policy.device_id, 'quarantine')}>Quarantine</button>
                {/if}
              {/if}
              {#if extend !== 'hidden'}
                <button type="button" class="act" aria-label="Extend once {name}" disabled={extend === 'used' || inFlight} onclick={() => { const until = extendUntil(policy); if (until) void submit(policy, { extend_once: { until } }, 'extend'); }}>{extend === 'used' ? 'Extension used' : 'Extend once'}</button>
              {/if}
            </div>
          {/if}
        </article>
      {/each}
    </div>
  {/if}
</section>

<style>
  .guard-meter{margin:28px 0;min-height:150px;display:grid;grid-template-columns:150px repeat(3,1fr);align-items:center;border:1px solid var(--line-mid);border-radius:12px;background:radial-gradient(circle at 75px,#123641 0,transparent 130px),var(--surface);overflow:hidden}.guard-meter>div:not(.guard-orbit){padding:22px;border-left:1px solid var(--line-mid);display:grid;gap:6px}.guard-meter strong{font:700 30px var(--font-display)}.guard-meter span{color:var(--muted);font:10px var(--font-mono);text-transform:uppercase;letter-spacing:.09em}.guard-orbit{position:relative;width:84px;height:84px;margin:auto;border:1px solid var(--line-strong);border-radius:50%;animation:orbit 9s linear infinite}.guard-orbit:before,.guard-orbit:after{content:'';position:absolute;border:1px dashed var(--line-strong);border-radius:50%;inset:12px}.guard-orbit:after{inset:28px;background:var(--accent);box-shadow:0 0 20px var(--accent)80}.guard-orbit span{position:absolute;width:8px;height:8px;border-radius:50%;background:var(--blue);box-shadow:0 0 12px currentColor}.guard-orbit span:nth-child(1){left:4px;top:22px}.guard-orbit span:nth-child(2){right:2px;bottom:22px;background:var(--gold)}.guard-orbit span:nth-child(3){left:40px;bottom:-4px;background:var(--pink)}.guard-meter.active .guard-orbit{border-color:var(--gold);animation-duration:3s}.policy-grid{display:grid;gap:13px}.policy-card{position:relative;padding:19px;border:1px solid var(--line-mid);border-left:4px solid var(--blue);border-radius:8px;background:var(--surface);overflow:hidden;animation:arrive .45s cubic-bezier(.2,.9,.2,1) both}.policy-card:after{content:'';position:absolute;inset:0;pointer-events:none;background:linear-gradient(100deg,transparent 20%,var(--accent)0a 48%,transparent 72%);transform:translateX(-100%);animation:sweep 5s ease-in-out infinite}.action-quarantine,.action-permanent_ban{border-left-color:var(--gold)}.action-owner_attention,.enforcement-failed{border-left-color:var(--pink)}.enforcement-verified{box-shadow:inset 0 0 22px var(--accent)09}.policy-head{display:grid;grid-template-columns:18px 1fr auto;gap:12px;align-items:center}.policy-head h2{margin:4px 0 0;font:600 18px var(--font-display)}.policy-signal{width:10px;height:10px;border:2px solid var(--blue);border-radius:50%;box-shadow:0 0 9px var(--blue)}.action-quarantine .policy-signal,.action-permanent_ban .policy-signal{border-color:var(--gold);box-shadow:0 0 9px var(--gold)}.action-owner_attention .policy-signal,.enforcement-failed .policy-signal{border-color:var(--pink);box-shadow:0 0 9px var(--pink)}.enforcement{padding:5px 8px;border:1px solid var(--line-strong);border-radius:4px;color:var(--muted-strong);font:10px var(--font-mono);text-transform:uppercase}.enforcement-verified .enforcement{color:var(--accent);border-color:var(--accent)}.enforcement-failed .enforcement{color:var(--pink);border-color:var(--pink)}.policy-path{display:grid;grid-template-columns:auto 1fr auto 1fr auto;align-items:center;gap:8px;margin:20px 0;color:var(--faint);font:10px var(--font-mono);text-transform:uppercase}.policy-path i{height:1px;background:var(--line-strong)}.policy-path span.done{color:var(--accent)}.policy-path span.done+i{background:linear-gradient(90deg,var(--accent),var(--line-strong))}dl{margin:0;display:grid;grid-template-columns:repeat(3,1fr);gap:10px}dl div{padding-top:12px;border-top:1px solid var(--line)}dt{color:var(--faint);font:10px var(--font-mono);text-transform:uppercase}dd{margin:5px 0 0;color:var(--ink);font-size:12px;text-transform:capitalize}.warning{margin:14px 0 0;padding:9px;border:1px dashed var(--gold);color:var(--gold);font:11px var(--font-mono)}.guard-empty{margin-top:25px}@keyframes orbit{to{transform:rotate(360deg)}}@keyframes arrive{from{opacity:0;transform:translateY(14px) scale(.985)}}@keyframes sweep{50%,100%{transform:translateX(100%)}}@media(max-width:950px){.guard-meter{grid-template-columns:110px 1fr}.guard-meter>div:not(.guard-orbit){border-bottom:1px solid var(--line-mid)}.guard-orbit{grid-row:span 3;width:68px;height:68px}.guard-orbit:after{inset:23px}dl{grid-template-columns:1fr}.policy-head{grid-template-columns:18px 1fr}.enforcement{grid-column:2;justify-self:start}}@media(prefers-reduced-motion:reduce){.guard-orbit,.policy-card,.policy-card:after{animation:none!important}}
  .protected-note{margin:14px 0 0;padding:9px;border:1px dashed var(--accent);color:var(--accent);font:11px var(--font-mono)}.owner-actions{margin-top:16px;padding-top:14px;border-top:1px solid var(--line);display:flex;flex-wrap:wrap;gap:8px;align-items:center}.act{min-height:34px;padding:7px 14px;border:1px solid var(--line-strong);border-radius:5px;background:var(--surface-raised);color:var(--ink);font:600 12px var(--font-display);cursor:pointer}.act:hover:not(:disabled){border-color:var(--accent)}.act:disabled{opacity:.45;cursor:not-allowed}.act.danger{border-color:#8a4a5e;color:#ffb3cd}.act.danger:hover:not(:disabled){border-color:var(--pink)}.confirm-step{display:inline-flex;flex-wrap:wrap;gap:8px;align-items:center;padding:4px 8px;border:1px dashed var(--pink);border-radius:5px}.confirm-question{color:#ffb3cd;font:11px var(--font-mono);text-transform:uppercase}.action-error{flex-basis:100%;margin:0;padding:8px;border:1px solid var(--pink);border-radius:5px;color:var(--pink);font:11px var(--font-mono)}
</style>
