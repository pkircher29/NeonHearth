<script lang="ts">
  import { onMount } from 'svelte';
  import { isCheckNeedsConsent, isCheckUnavailable } from '../api/client';
  import type { ApiClient, CheckResult, Confidence, DiagnosisKind, DoctorApproval, DoctorRun, DoctorSettings, GuidedAction, Measurement, RepairPlan, RepairReport, RollbackOutcome } from '../api/client';

  type DoctorClient = Pick<ApiClient, 'doctorRun' | 'doctorReport' | 'doctorApprove' | 'doctorRepair'> & Partial<Pick<ApiClient, 'doctorSettings'>>;
  // `deviceName` resolves a claimant MAC to the owner's name for that device,
  // when one is known. It is optional so the view works without an inventory.
  // `onOpenSettings` takes the owner to the Doctor settings, where the
  // permission to probe outside the home network is granted. Nothing here
  // changes that setting.
  let { client, deviceName = () => null, onOpenSettings }: { client: DoctorClient; deviceName?: (mac: string) => string | null; onOpenSettings?: () => void } = $props();

  let loading = $state(true);
  let run = $state<DoctorRun | null>(null);
  let running = $state(false);
  let runError = $state<string | null>(null);
  // A failed report load is its own state with a reload path; it must never
  // read as "no diagnostic has run yet" (audit M-30).
  let loadError = $state<string | null>(null);
  // Per-finding UI state keyed by run id + finding index, so a repair that
  // resolves after a newer run cannot attach to the wrong finding.
  let approvals = $state<Record<string, DoctorApproval | null>>({});
  let busy = $state<Record<string, boolean>>({});
  let errors = $state<Record<string, string | null>>({});
  let repairs = $state<Record<string, RepairReport | null>>({});
  // The claimant the owner picked to keep a duplicated address, per finding.
  let choices = $state<Record<string, string>>({});
  const repairing = $derived(Object.values(busy).some(Boolean));
  let active = true;
  let settings = $state<DoctorSettings | null>(null);
  let settingsLoadedFor = '';
  const needsPermission = $derived(run?.report.checks.some(isCheckNeedsConsent) ?? false);
  // Name the real targets in the permission notice, once per run.
  $effect(() => {
    if (!run || !needsPermission || !client.doctorSettings || settingsLoadedFor === run.run_id) return;
    settingsLoadedFor = run.run_id;
    client.doctorSettings().then((loaded) => { if (active) settings = loaded; }).catch(() => { /* the notice reads fine without the names */ });
  });
  const probeTargets = $derived.by(() => {
    if (!settings) return null;
    return { resolvers: [...new Set([...settings.configured_resolvers, settings.independent_resolver])], internet: `${settings.internet_probe_address}:${settings.internet_probe_port}` };
  });

  async function loadReport(): Promise<void> {
    loading = true;
    loadError = null;
    try {
      const latest = await client.doctorReport();
      if (active) run = latest;
    } catch (cause) {
      if (active) loadError = `Could not load the latest diagnostic: ${message(cause)}`;
    } finally {
      if (active) loading = false;
    }
  }

  onMount(() => {
    active = true;
    void loadReport();
    return () => { active = false; };
  });

  function message(cause: unknown): string {
    return cause instanceof Error ? cause.message : 'request failed';
  }

  async function runDiagnostic(): Promise<void> {
    running = true;
    runError = null;
    try {
      const outcome = await client.doctorRun();
      if (outcome.status === 'already_running') {
        runError = 'A diagnostic is already running. Only one diagnostic runs at a time — try again in a moment.';
      } else {
        run = outcome.run;
        loadError = null;
        approvals = {}; busy = {}; errors = {}; repairs = {}; choices = {};
      }
    } catch (cause) {
      runError = `Could not run diagnostic: ${message(cause)}`;
    } finally {
      running = false;
    }
  }

  async function requestApproval(key: string, kind: DiagnosisKind, chosen?: string): Promise<void> {
    errors = { ...errors, [key]: null };
    busy = { ...busy, [key]: true };
    try {
      const approval = chosen === undefined ? await client.doctorApprove(kind) : await client.doctorApprove(kind, chosen);
      approvals = { ...approvals, [key]: approval };
    } catch (cause) {
      errors = { ...errors, [key]: `Could not request approval: ${message(cause)}` };
    } finally {
      busy = { ...busy, [key]: false };
    }
  }

  async function executeRepair(key: string, kind: DiagnosisKind, approvalId?: string, chosen?: string): Promise<void> {
    errors = { ...errors, [key]: null };
    busy = { ...busy, [key]: true };
    try {
      const report = approvalId === undefined ? await client.doctorRepair(kind)
        : chosen === undefined ? await client.doctorRepair(kind, approvalId)
        : await client.doctorRepair(kind, approvalId, chosen);
      repairs = { ...repairs, [key]: report };
      approvals = { ...approvals, [key]: null };
    } catch (cause) {
      errors = { ...errors, [key]: `Could not execute repair: ${message(cause)}` };
    } finally {
      busy = { ...busy, [key]: false };
    }
  }

  function cancelApproval(key: string): void {
    approvals = { ...approvals, [key]: null };
  }

  const label = (value: string) => value.replaceAll('_', ' ');
  function claimantLabel(mac: string): string {
    const name = deviceName(mac);
    return name ? `${name} (${mac})` : mac;
  }
  function keepsSentence(count: number, address: string): string {
    return `This device keeps ${address}; ${count > 2 ? 'the others' : 'the other'} will get a new one.`;
  }
  function title(kind: DiagnosisKind): string {
    const text = label(kind.kind);
    return text[0].toUpperCase() + text.slice(1);
  }
  const confidencePercent = (confidence: Confidence) => `${Math.round(confidence.basis_points / 100)}%`;
  const unitSuffix = { milliseconds: ' ms', percent: '%', dbm: ' dBm', bytes: ' bytes', megabits_per_second: ' Mbps', count: '', boolean: '' } as const;
  function formatValue(measurement: Measurement): string {
    if (measurement.unit === 'boolean') return measurement.value === 0 ? 'no' : 'yes';
    const rounded = Math.round(measurement.value * 100) / 100;
    return `${rounded}${unitSuffix[measurement.unit]}`;
  }
  function formatMeasurement(measurement: Measurement): string {
    return `${label(measurement.metric)}: ${formatValue(measurement)}`;
  }
  function statusText(check: CheckResult): string {
    if (check.status.state === 'passed') return 'Passed';
    if (check.status.state === 'failed') return 'Failed';
    const because = check.status.because;
    if (because.reason === 'consent_required') return 'Needs your permission';
    if (because.reason === 'dependency_consent_required') return `Needs your permission — waits on: ${label(because.dependency)}`;
    if (because.reason === 'probe_unsupported' || because.reason === 'dependency_unavailable') return 'Not available in this build';
    if (because.reason === 'budget_exhausted') return 'Skipped — probe budget exhausted';
    const relation = because.reason === 'dependency_failed' ? 'dependency failed' : 'dependency skipped';
    return `Skipped — ${relation}: ${label(because.dependency)}`;
  }
  function statusIcon(check: CheckResult): string {
    if (isCheckNeedsConsent(check)) return '?';
    if (isCheckUnavailable(check)) return '–';
    return check.status.state === 'passed' ? '✓' : check.status.state === 'failed' ? '!' : '◇';
  }
  // The collector check is the only one this build can answer; when every
  // other check is unavailable the whole network side was never assessed.
  const networkUnavailable = $derived.by(() => {
    const network = run?.report.checks.filter((check) => check.kind !== 'collector_health') ?? [];
    return network.length > 0 && network.every(isCheckUnavailable);
  });
  const planClassLabel = { safe_automatic: 'Safe automatic repair', approval_required_reversible: 'Reversible repair — approval required', guided_physical: 'Guided physical repair', observation_only: 'Observation only' } as const;
  const expiry = (at: string) => new Date(at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

  const guidedSteps: Record<GuidedAction, string[]> = {
    check_cables: [
      'Follow the network cable from this device to the router or switch.',
      'Unplug and firmly reseat both ends of the cable.',
      'Replace the cable if a connector or the jacket looks damaged.',
      'Run the diagnostic again to confirm the link is up.'
    ],
    move_hardware: [
      'Move the device and the Wi-Fi access point closer together, with fewer walls between them.',
      'Keep both away from microwaves, cordless phones, and metal enclosures.',
      'If distance cannot change, consider a wired connection or an additional access point.',
      'Run the diagnostic again to confirm the signal improved.'
    ],
    contact_isp: [
      'Re-run the diagnostic to confirm the outage is still present.',
      'Check your internet provider’s status page or app for a reported outage.',
      'Contact your provider and report that the local network is healthy but the internet side is down.',
      'Ask for an estimated restoration time, then re-run the diagnostic after service returns.'
    ],
    factory_reset: [
      'Record or photograph the device’s current settings first.',
      'Hold the recessed reset button for the time the manufacturer specifies.',
      'Reconfigure the device from your saved settings.',
      'Run the diagnostic again to confirm recovery.'
    ],
    install_firmware: [
      'Download the latest firmware for this exact model from the manufacturer.',
      'Install it through the device’s management interface without interrupting power.',
      'Wait for the device to fully restart.',
      'Run the diagnostic again to confirm the fault is resolved.'
    ]
  };

  // What the owner does by hand when this build cannot make the change. Only
  // shown for a plan the service reported as not executable.
  function manualFix(plan: RepairPlan): string {
    if (plan.class === 'safe_automatic') {
      switch (plan.action.action) {
        case 'restart_collector_worker': return 'Restart the NeonHearth service (or the app), then run the diagnostic again.';
        case 'refresh_app_caches': return 'Restart NeonHearth so it rebuilds its caches.';
        case 'renew_collector_lease': return 'Release and renew this computer’s network address from the operating system’s network settings, then run the diagnostic again.';
        case 'retry_router_session': return 'Open the router’s admin page, sign in again, and confirm it responds.';
        case 'repair_tailscale_serve': return 'Open Settings, turn remote access off and on again, and check that the status is healthy.';
      }
    }
    if (plan.class === 'approval_required_reversible') {
      const action = plan.action;
      switch (action.action) {
        case 'reset_adapter': return `Disable and re-enable the network adapter “${action.interface}” in the operating system’s network settings.`;
        case 'change_dns_servers': return `In the adapter’s network settings (or on the router), set the DNS servers to ${action.servers.join(', ')}.`;
        case 'renew_dhcp_lease': return `Release and renew the address for “${action.interface}” from the operating system’s network settings.`;
        case 'set_interface_mtu': return `In the adapter’s advanced settings, set the MTU of “${action.interface}” to ${action.mtu}.`;
        case 'set_dhcp_reservation': return `In the router’s DHCP settings, reserve ${action.address} for the one device that should keep it, then restart the other device’s network connection.`;
        case 'reboot_router': return 'Power-cycle the router: unplug it for 30 seconds, plug it back in, and wait a few minutes.';
        case 'block_device': case 'unblock_device': return 'Use the router’s access-control page to change this device’s access.';
      }
    }
    return plan.rationale;
  }

  type Headline = { tone: 'success' | 'neutral' | 'regressed' | 'unverified'; text: string };
  function repairHeadline(report: RepairReport): Headline {
    if (report.outcome.outcome === 'completed') {
      if (report.outcome.verdict === 'improved') return { tone: 'success', text: 'Repair verified — the symptom improved.' };
      if (report.outcome.verdict === 'unchanged') return { tone: 'neutral', text: 'Repair verified — no measurable change in the symptom.' };
      return { tone: 'regressed', text: 'Repair made the symptom worse.' };
    }
    // No verification exists: this must never read as success.
    const failure = report.outcome.outcome === 'apply_failed' ? 'the repair could not be applied'
      : report.outcome.outcome === 'snapshot_failed' ? 'the pre-repair snapshot failed'
      : report.outcome.outcome === 'baseline_failed' ? 'the baseline measurement failed'
      : 'the outcome could not be verified';
    return { tone: 'unverified', text: `Unverified — ${failure}: ${report.outcome.error}. This repair is not confirmed as successful.` };
  }
  function rollbackBanner(rollback: RollbackOutcome): { text: string; failed: boolean } | null {
    if (rollback.outcome === 'succeeded') return { text: 'Rolled back — the change was reverted to the pre-repair snapshot.', failed: false };
    if (rollback.outcome === 'failed') return { text: `Rollback failed — the change may still be in effect: ${rollback.error}`, failed: true };
    if (rollback.reason === 'not_reversible') return { text: 'Rollback not attempted — this action cannot be undone by restoring the snapshot.', failed: false };
    return null; // not_needed: nothing regressed, nothing to report.
  }
</script>

<section class="doctor-view" aria-labelledby="doctor-heading">
  <div class="view-heading doctor-heading">
    <div>
      <p class="kicker">DOCTOR / NETWORK DIAGNOSTICS</p>
      <h1 id="doctor-heading">Find it, prove it, fix it.</h1>
      <p class="muted">Every check carries its evidence, and no repair is called done without a before-and-after measurement.</p>
    </div>
    <button type="button" class="run-action" aria-label="Run diagnostic" disabled={running || loading || repairing} onclick={() => void runDiagnostic()}>{running ? 'Running diagnostic…' : 'Run diagnostic'}</button>
  </div>

  {#if runError}<p class="doctor-error" role="alert">{runError}</p>{/if}
  {#if running}<p class="run-progress" role="status"><span aria-hidden="true">◒</span> Diagnostic in progress — walking the check graph within the probe budget…</p>{/if}

  {#if loading}
    <p class="doctor-loading" role="status">Loading the latest diagnostic…</p>
  {:else if loadError}
    <div class="doctor-load-error" role="alert">
      <p>{loadError}</p>
      <button type="button" class="act" onclick={() => void loadReport()}>Reload</button>
    </div>
  {:else if !run}
    <div class="empty-state doctor-empty">
      <span class="empty-icon" aria-hidden="true">✚</span>
      <div><strong>No diagnostic has run yet</strong><p class="muted">Run a diagnostic to walk the check graph and see typed findings with their safest repair.</p></div>
    </div>
  {:else}
    <section class="doctor-checks" aria-labelledby="doctor-checks-heading">
      <h2 id="doctor-checks-heading">Diagnostic checks</h2>
      <p class="muted run-facts">Run started {new Date(run.report.started_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })} · {run.report.probes_used} probes used</p>
      {#if networkUnavailable}<p class="doctor-notice" role="note">Doctor can currently check only that the collector is healthy. Network checks (adapter, address, gateway, DNS, internet) are not available in this build yet.</p>{/if}
      {#if needsPermission}
        <div class="permission-notice" role="note" aria-label="Permission needed">
          <p><strong>Some checks need your permission.</strong> They contact servers outside your home network, so they have not run.{#if probeTargets} The Doctor would ask the DNS resolvers {probeTargets.resolvers.join(', ')} and connect to the internet test address {probeTargets.internet}.{/if} Nothing is sent but a standard test request: a name lookup, a ping or a plain connection attempt.</p>
          {#if onOpenSettings}<button type="button" class="act" onclick={() => onOpenSettings?.()}>Review Doctor settings</button>{/if}
        </div>
      {/if}
      {#if run.report.budget_exhausted}<p class="budget-warning"><span aria-hidden="true">△</span> The probe budget ran out — these results are partial.</p>{/if}
      <ul class="check-list">
        {#each run.report.checks as check (check.kind)}
          <li class="check-row state-{check.status.state}" class:unavailable={isCheckUnavailable(check)} class:consent={isCheckNeedsConsent(check)}>
            <h3>{label(check.kind)}</h3>
            <p class="check-status"><span class="status-mark" aria-hidden="true">{statusIcon(check)}</span> {statusText(check)}</p>
            {#if !isCheckUnavailable(check) && !isCheckNeedsConsent(check)}<p class="check-confidence">{confidencePercent(check.confidence)} confidence</p>{/if}
            {#if check.evidence.length > 0}
              <ul class="measurements" aria-label="Measurements for {label(check.kind)}">
                {#each check.evidence as measurement}<li>{formatMeasurement(measurement)}</li>{/each}
              </ul>
            {/if}
          </li>
        {/each}
      </ul>
    </section>

    <section class="doctor-findings" aria-labelledby="doctor-findings-heading">
      <h2 id="doctor-findings-heading">Findings</h2>
      {#if run.findings.length === 0}
        <p class="muted no-findings">{networkUnavailable ? 'No faults were found by the checks that could run.' : 'No faults were found. Every completed check passed.'}</p>
      {:else}
        <ul class="finding-list">
          {#each run.findings as finding, index (`${run.run_id}:${index}`)}
            {@const key = `${run.run_id}:${index}`}
            {@const plan = finding.plan}
            {@const name = title(finding.diagnosis.kind)}
            {@const inFlight = Boolean(busy[key])}
            {@const report = repairs[key] ?? null}
            {@const approval = approvals[key] ?? null}
            {@const duplicate = finding.diagnosis.kind.kind === 'duplicate_ip' ? finding.diagnosis.kind : null}
            {@const chosen = choices[key]}
            <li class="finding-card class-{plan.class}" aria-busy={inFlight}>
              <h3>{name}</h3>
              <p class="impact">{finding.diagnosis.impact}</p>
              <p class="finding-confidence">{confidencePercent(finding.diagnosis.confidence)} confidence</p>
              {#if finding.diagnosis.evidence.length > 0}
                <ul class="measurements" aria-label="Evidence for {name}">
                  {#each finding.diagnosis.evidence as measurement}<li>{formatMeasurement(measurement)}</li>{/each}
                </ul>
              {/if}
              <p class="plan-class">{planClassLabel[plan.class]}</p>
              <p class="rationale">{plan.rationale}</p>
              {#if errors[key]}<p class="doctor-error" role="alert">{errors[key]}</p>{/if}
              {#if report}
                {@const headline = repairHeadline(report)}
                {@const rollback = rollbackBanner(report.rollback)}
                <div class="repair-report tone-{headline.tone}">
                  <p class="repair-headline">{headline.text}</p>
                  {#if rollback}
                    {#if rollback.failed}
                      <p class="rollback-banner failed" role="alert">{rollback.text}</p>
                    {:else}
                      <p class="rollback-banner">{rollback.text}</p>
                    {/if}
                  {/if}
                  {#if report.verification}
                    <div class="verify-grid" aria-label="Verification for {name}">
                      <div><h4>Before</h4><p>{formatMeasurement(report.verification.before)}</p></div>
                      <div><h4>After</h4><p>{formatMeasurement(report.verification.after)}</p></div>
                    </div>
                  {:else}
                    <p class="unverified-note">No before-and-after verification is available for this repair.</p>
                  {/if}
                </div>
              {:else if finding.executable === false && (plan.class === 'safe_automatic' || plan.class === 'approval_required_reversible')}
                <div class="guidance-only" aria-label="Guidance for {name}">
                  <p class="guidance-lead">NeonHearth can’t make this change for you in this build. To fix it yourself:</p>
                  <p class="guidance-fix">{manualFix(plan)}</p>
                  {#if finding.unavailable_detail}<p class="muted guidance-reason">{finding.unavailable_detail}</p>{/if}
                </div>
              {:else if plan.class === 'safe_automatic'}
                <div class="repair-actions">
                  <button type="button" class="act" aria-label="Repair {name}" disabled={inFlight} onclick={() => void executeRepair(key, finding.diagnosis.kind)}>{inFlight ? 'Repairing…' : 'Repair'}</button>
                </div>
              {:else if plan.class === 'approval_required_reversible'}
                {#if duplicate}
                  <fieldset class="claimant-choice" disabled={inFlight || approval !== null}>
                    <legend>Which device should keep {duplicate.address}?</legend>
                    {#each duplicate.macs as mac (mac)}
                      <label class="claimant"><input type="radio" name="claimant-{key}" value={mac} checked={chosen === mac} onchange={() => { choices = { ...choices, [key]: mac }; }} /> <span>{claimantLabel(mac)}</span></label>
                    {/each}
                    <p class="muted claimant-note">{keepsSentence(duplicate.macs.length, duplicate.address)}</p>
                  </fieldset>
                {/if}
                <div class="repair-actions">
                  {#if approval}
                    <span class="confirm-step">
                      <span class="confirm-question">Approval expires {expiry(approval.expires_at)}</span>
                      <button type="button" class="act danger" aria-label="Confirm repair {name}" disabled={inFlight} onclick={() => void executeRepair(key, finding.diagnosis.kind, approval.approval_id, duplicate ? chosen : undefined)}>{inFlight ? 'Repairing…' : 'Confirm repair'}</button>
                      <button type="button" class="act" aria-label="Cancel repair {name}" disabled={inFlight} onclick={() => cancelApproval(key)}>Cancel</button>
                    </span>
                  {:else}
                    <button type="button" class="act" aria-label="Request approval for {name}" disabled={inFlight || (duplicate !== null && !chosen)} onclick={() => void requestApproval(key, finding.diagnosis.kind, duplicate ? chosen : undefined)}>{inFlight ? 'Requesting…' : 'Request approval'}</button>
                  {/if}
                </div>
              {:else if plan.class === 'guided_physical'}
                <ol class="guided-steps" aria-label="Guided steps for {name}">
                  {#each guidedSteps[plan.action] as step}<li>{step}</li>{/each}
                </ol>
              {:else}
                <p class="observation-note">The Doctor is only observing this fault — no safe action can be proposed yet.</p>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </section>
  {/if}
</section>

<style>
  .doctor-heading{display:flex;justify-content:space-between;align-items:flex-start;gap:18px}
  .run-action{min-height:44px;padding:10px 16px;border:1px solid var(--accent);border-radius:5px;background:var(--accent);color:var(--accent-ink);font:700 13px var(--font-display);cursor:pointer}
  .run-action:disabled{opacity:.5;cursor:not-allowed}
  .run-progress{margin:16px 0 0;padding:10px;border:1px dashed var(--blue);color:#9cc0ff;font:11px var(--font-mono)}
  .run-progress span{color:var(--accent)}
  .doctor-loading{margin-top:24px;color:var(--muted-strong)}
  .doctor-empty{margin-top:28px}
  .doctor-error{margin:14px 0 0;padding:9px;border:1px solid var(--pink);border-radius:5px;color:var(--pink);font:11px var(--font-mono)}
  .doctor-load-error{margin-top:24px;padding:14px;border:1px dashed var(--pink);border-radius:7px;display:flex;flex-wrap:wrap;gap:12px;align-items:center}
  .doctor-load-error p{margin:0;color:#ffb4cc;font-size:12px}
  .doctor-checks h2,.doctor-findings h2{margin:30px 0 6px;font:600 17px var(--font-display)}
  .run-facts{font-size:12px}
  .doctor-notice{margin:12px 0 0;padding:9px;border:1px dashed var(--line-strong);border-radius:5px;color:var(--muted);font:11px var(--font-mono)}
  .check-row.unavailable{opacity:.85}
  .check-row.consent{border-left-color:var(--blue);border-style:dashed}
  .permission-notice{margin:12px 0 0;padding:12px;border:1px dashed var(--blue);border-radius:5px;display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between}
  .permission-notice p{margin:0;color:var(--ink);font-size:12px;flex:1 1 320px}
  .budget-warning{margin:12px 0 0;padding:9px;border:1px dashed var(--gold);color:var(--gold);font:11px var(--font-mono)}
  .check-list{margin:14px 0 0;padding:0;list-style:none;display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px}
  .check-row{padding:13px;border:1px solid var(--line-mid);border-left:4px solid var(--accent);border-radius:7px;background:var(--surface)}
  .check-row.state-failed{border-left-color:var(--pink)}
  .check-row.state-skipped{border-left-color:var(--muted);border-style:dashed}
  .check-row h3{margin:0;font:600 13px var(--font-display);text-transform:capitalize}
  .check-status{margin:7px 0 0;color:var(--ink);font-size:12px}
  .status-mark{display:inline-grid;place-items:center;width:17px;height:17px;border:1px solid var(--line-strong);border-radius:4px;font:10px var(--font-mono)}
  .state-passed .status-mark{color:var(--accent);border-color:var(--accent)}
  .state-failed .status-mark{color:var(--pink);border-color:var(--pink)}
  .state-skipped .status-mark{color:var(--muted)}
  .check-confidence,.finding-confidence{margin:6px 0 0;color:var(--muted);font:10px var(--font-mono);text-transform:uppercase;letter-spacing:.08em}
  .measurements{margin:9px 0 0;padding:0;list-style:none;display:grid;gap:4px}
  .measurements li{color:var(--muted-strong);font:11px var(--font-mono)}
  .measurements li::before{content:'· ';color:var(--blue)}
  .finding-list{margin:14px 0 0;padding:0;list-style:none;display:grid;gap:13px}
  .finding-card{padding:18px;border:1px solid var(--line-mid);border-left:4px solid var(--gold);border-radius:8px;background:var(--surface)}
  .finding-card.class-safe_automatic{border-left-color:var(--accent)}
  .finding-card.class-observation_only{border-left-color:var(--muted)}
  .finding-card h3{margin:0;font:600 17px var(--font-display)}
  .impact{margin:8px 0 0;color:var(--ink);font-size:13px}
  .plan-class{margin:14px 0 0;color:var(--accent);font:10px var(--font-mono);text-transform:uppercase;letter-spacing:.08em}
  .class-approval_required_reversible .plan-class{color:var(--gold)}
  .class-guided_physical .plan-class,.class-observation_only .plan-class{color:var(--muted-strong)}
  .rationale{margin:5px 0 0;color:var(--muted-strong);font-size:12px}
  .repair-actions{margin-top:14px;padding-top:12px;border-top:1px solid var(--line);display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  .act{min-height:34px;padding:7px 14px;border:1px solid var(--line-strong);border-radius:5px;background:var(--surface-raised);color:var(--ink);font:600 12px var(--font-display);cursor:pointer}
  .act:hover:not(:disabled){border-color:var(--accent)}
  .act:disabled{opacity:.45;cursor:not-allowed}
  .act.danger{border-color:#8a6a3e;color:#ffe0a3}
  .act.danger:hover:not(:disabled){border-color:var(--gold)}
  .confirm-step{display:inline-flex;flex-wrap:wrap;gap:8px;align-items:center;padding:4px 8px;border:1px dashed var(--gold);border-radius:5px}
  .confirm-question{color:#ffe0a3;font:11px var(--font-mono);text-transform:uppercase}
  .claimant-choice{margin:14px 0 0;padding:10px 12px;border:1px solid var(--line-strong);border-radius:5px;display:grid;gap:6px}
  .claimant-choice legend{padding:0 6px;color:var(--ink);font:600 12px var(--font-display)}
  .claimant{display:flex;gap:8px;align-items:center;color:var(--ink);font:12px var(--font-mono);cursor:pointer}
  .claimant-note{margin:4px 0 0;font-size:12px}
  .guidance-only{margin-top:14px;padding:10px 12px;border:1px dashed var(--line-strong);border-radius:5px}
  .guidance-lead{margin:0;color:var(--muted-strong);font-size:12px}
  .guidance-fix{margin:6px 0 0;color:var(--ink);font-size:13px}
  .guidance-reason{margin:6px 0 0;font-size:11px}
  .guided-steps{margin:14px 0 0;padding-left:22px;display:grid;gap:6px;color:var(--ink);font-size:12px}
  .guided-steps li::marker{color:var(--accent);font-weight:700}
  .observation-note{margin:14px 0 0;padding:9px;border:1px dashed var(--muted);color:var(--muted-strong);font:11px var(--font-mono)}
  .repair-report{margin-top:14px;padding:12px;border:1px solid var(--line-strong);border-radius:7px;background:#081720}
  .repair-report.tone-success{border-color:var(--accent)}
  .repair-report.tone-regressed{border-color:var(--pink)}
  .repair-report.tone-unverified{border-color:var(--gold);border-style:dashed}
  .repair-headline{margin:0;font:600 13px var(--font-display);color:var(--ink)}
  .tone-success .repair-headline{color:var(--accent)}
  .tone-regressed .repair-headline{color:var(--pink)}
  .tone-unverified .repair-headline{color:var(--gold)}
  .rollback-banner{margin:10px 0 0;padding:9px;border:1px solid var(--gold);border-radius:5px;color:var(--gold);font:11px var(--font-mono)}
  .rollback-banner.failed{border-color:var(--pink);color:var(--pink)}
  .verify-grid{margin-top:12px;display:grid;grid-template-columns:1fr 1fr;gap:10px}
  .verify-grid div{padding:9px;border:1px solid var(--line);border-radius:5px}
  .verify-grid h4{margin:0;color:var(--muted);font:10px var(--font-mono);text-transform:uppercase;letter-spacing:.08em}
  .verify-grid p{margin:6px 0 0;color:var(--ink);font:12px var(--font-mono)}
  .unverified-note{margin:10px 0 0;color:var(--gold);font:11px var(--font-mono)}
  .no-findings{margin-top:12px}
  @media(max-width:850px){.doctor-heading{display:block}.run-action{margin-top:14px;width:100%}.verify-grid{grid-template-columns:1fr}.check-list{grid-template-columns:1fr}}
</style>
