<script lang="ts">
  import type { GuardPolicy, LiveState } from '../stores/live';

  let { state }: { state: LiveState } = $props();
  const policies = $derived(Object.values(state.policies).sort((a, b) => rank(b) - rank(a)));
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
    const device = state.devices[policy.device_id];
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
        </article>
      {/each}
    </div>
  {/if}
</section>

<style>
  .guard-meter{margin:28px 0;min-height:150px;display:grid;grid-template-columns:150px repeat(3,1fr);align-items:center;border:1px solid #20424b;border-radius:12px;background:radial-gradient(circle at 75px,#123641 0,transparent 130px),#0b1c26;overflow:hidden}.guard-meter>div:not(.guard-orbit){padding:22px;border-left:1px solid #20424b;display:grid;gap:6px}.guard-meter strong{font:700 30px Arial}.guard-meter span{color:#77959d;font:10px monospace;text-transform:uppercase;letter-spacing:.09em}.guard-orbit{position:relative;width:84px;height:84px;margin:auto;border:1px solid #28505a;border-radius:50%;animation:orbit 9s linear infinite}.guard-orbit:before,.guard-orbit:after{content:'';position:absolute;border:1px dashed #28505a;border-radius:50%;inset:12px}.guard-orbit:after{inset:28px;background:#63f3f0;box-shadow:0 0 20px #63f3f080}.guard-orbit span{position:absolute;width:8px;height:8px;border-radius:50%;background:#548cff;box-shadow:0 0 12px currentColor}.guard-orbit span:nth-child(1){left:4px;top:22px}.guard-orbit span:nth-child(2){right:2px;bottom:22px;background:#ffcd66}.guard-orbit span:nth-child(3){left:40px;bottom:-4px;background:#ff5c9b}.guard-meter.active .guard-orbit{border-color:#ffcd66;animation-duration:3s}.policy-grid{display:grid;gap:13px}.policy-card{position:relative;padding:19px;border:1px solid #20424b;border-left:4px solid #548cff;border-radius:8px;background:#0b1c26;overflow:hidden;animation:arrive .45s cubic-bezier(.2,.9,.2,1) both}.policy-card:after{content:'';position:absolute;inset:0;pointer-events:none;background:linear-gradient(100deg,transparent 20%,#63f3f00a 48%,transparent 72%);transform:translateX(-100%);animation:sweep 5s ease-in-out infinite}.action-quarantine,.action-permanent_ban{border-left-color:#ffcd66}.action-owner_attention,.enforcement-failed{border-left-color:#ff5c9b}.enforcement-verified{box-shadow:inset 0 0 22px #63f3f009}.policy-head{display:grid;grid-template-columns:18px 1fr auto;gap:12px;align-items:center}.policy-head h2{margin:4px 0 0;font:600 18px Arial}.policy-signal{width:10px;height:10px;border:2px solid #548cff;border-radius:50%;box-shadow:0 0 9px #548cff}.action-quarantine .policy-signal,.action-permanent_ban .policy-signal{border-color:#ffcd66;box-shadow:0 0 9px #ffcd66}.action-owner_attention .policy-signal,.enforcement-failed .policy-signal{border-color:#ff5c9b;box-shadow:0 0 9px #ff5c9b}.enforcement{padding:5px 8px;border:1px solid #28505a;border-radius:4px;color:#9bb7bb;font:10px monospace;text-transform:uppercase}.enforcement-verified .enforcement{color:#63f3f0;border-color:#63f3f0}.enforcement-failed .enforcement{color:#ff5c9b;border-color:#ff5c9b}.policy-path{display:grid;grid-template-columns:auto 1fr auto 1fr auto;align-items:center;gap:8px;margin:20px 0;color:#64838b;font:10px monospace;text-transform:uppercase}.policy-path i{height:1px;background:#28505a}.policy-path span.done{color:#63f3f0}.policy-path span.done+i{background:linear-gradient(90deg,#63f3f0,#28505a)}dl{margin:0;display:grid;grid-template-columns:repeat(3,1fr);gap:10px}dl div{padding-top:12px;border-top:1px solid #17323d}dt{color:#64838b;font:10px monospace;text-transform:uppercase}dd{margin:5px 0 0;color:#cce4e7;font-size:12px;text-transform:capitalize}.warning{margin:14px 0 0;padding:9px;border:1px dashed #ffcd66;color:#ffcd66;font:11px monospace}.guard-empty{margin-top:25px}@keyframes orbit{to{transform:rotate(360deg)}}@keyframes arrive{from{opacity:0;transform:translateY(14px) scale(.985)}}@keyframes sweep{50%,100%{transform:translateX(100%)}}@media(max-width:950px){.guard-meter{grid-template-columns:110px 1fr}.guard-meter>div:not(.guard-orbit){border-bottom:1px solid #20424b}.guard-orbit{grid-row:span 3;width:68px;height:68px}.guard-orbit:after{inset:23px}dl{grid-template-columns:1fr}.policy-head{grid-template-columns:18px 1fr}.enforcement{grid-column:2;justify-self:start}}@media(prefers-reduced-motion:reduce){.guard-orbit,.policy-card,.policy-card:after{animation:none!important}}
</style>
