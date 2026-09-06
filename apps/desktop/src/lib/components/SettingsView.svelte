<script lang="ts">
  // Settings: who may look in (session, phone pairing, sessions, integration
  // tokens), how the Network Doctor probes, and how this browser renders.
  // Secrets minted here are shown exactly once and never stored by the app.
  import { onMount } from 'svelte';
  import type { ApiClient, DoctorSettings, IntegrationScope, IntegrationToken, PhoneSession, RemoteStatus } from '../api/client';
  import { INTEGRATION_SCOPES } from '../api/client';
  import { formatPairingCode, type AuthState } from '../auth/session';
  import { applyMotion, readMotion, type MotionPreference } from '../stores/preferences';
  import Icon from './Icon.svelte';

  type SettingsClient = Pick<ApiClient, 'pairPhone' | 'remoteStatus' | 'remoteServe' | 'remoteSessions' | 'revokePhoneSession' | 'integrationTokens' | 'mintIntegrationToken' | 'revokeIntegrationToken' | 'doctorSettings' | 'updateDoctorSettings'>;
  interface Props { client: SettingsClient; auth: AuthState; onsignout: () => void }
  let { client, auth, onsignout }: Props = $props();

  const isOwner = $derived(auth.credential?.kind !== 'phone');
  const principal = $derived(auth.credential?.kind === 'owner' ? 'Owner token' : auth.credential?.kind === 'phone' ? 'Paired phone' : 'Development proxy');

  // --- appearance
  let motion = $state<MotionPreference>('auto');
  function setMotion(next: MotionPreference) { motion = next; applyMotion(next); }

  // --- phone pairing (owner)
  let deviceLabel = $state('');
  let pin = $state('');
  let pairBusy = $state(false);
  let pairError = $state<string | null>(null);
  let minted = $state<{ code: string; expires_at: string } | null>(null);

  async function pair(event: SubmitEvent) {
    event.preventDefault();
    if (deviceLabel.trim().length === 0) { pairError = 'Give the phone a name.'; return; }
    if (!/^[0-9]{6}$/.test(pin)) { pairError = 'The PIN is exactly six digits.'; return; }
    pairBusy = true; pairError = null; minted = null;
    try {
      const response = await client.pairPhone(deviceLabel.trim(), pin);
      minted = { code: formatPairingCode(response.session_id, response.secret), expires_at: response.expires_at };
      deviceLabel = ''; pin = '';
      void loadSessions();
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : '';
      pairError = /status 401\b/.test(message) ? 'Only the owner token can pair a phone.' : 'The collector could not create the pairing right now.';
    } finally { pairBusy = false; }
  }

  // --- remote access status + sessions (owner)
  let remote = $state<RemoteStatus | null>(null);
  let remoteError = $state<string | null>(null);
  let serveBusy = $state(false);
  let serveNotice = $state<string | null>(null);
  let sessions = $state<PhoneSession[]>([]);
  let sessionsError = $state<string | null>(null);
  let revoking = $state<Set<string>>(new Set());

  async function loadRemote() {
    remoteError = null;
    try { remote = await client.remoteStatus(); } catch { remoteError = 'Tailscale status is unavailable right now.'; }
  }
  async function enableServe() {
    serveBusy = true; serveNotice = null;
    try {
      const result = await client.remoteServe();
      serveNotice = result.configured ? (result.changed ? `Private access is on at https://${result.dns_name ?? 'your tailnet name'}:${result.https_port}.` : 'Private access was already on.') : 'Serve could not be configured.';
      await loadRemote();
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : '';
      serveNotice = /status 409\b/.test(message) ? 'Refused: Funnel (public exposure) is enabled for that port. Turn Funnel off in Tailscale first.' : 'The collector could not configure Serve. Is Tailscale running?';
    } finally { serveBusy = false; }
  }
  async function loadSessions() {
    sessionsError = null;
    try { sessions = await client.remoteSessions(); } catch { sessionsError = 'Phone sessions could not be listed.'; }
  }
  async function revokeSession(id: string) {
    revoking = new Set([...revoking, id]);
    try { await client.revokePhoneSession(id); await loadSessions(); }
    catch { sessionsError = 'That session could not be revoked. Try again.'; }
    finally { const next = new Set(revoking); next.delete(id); revoking = next; }
  }

  // --- integration tokens (owner)
  let tokens = $state<IntegrationToken[]>([]);
  let tokensError = $state<string | null>(null);
  let tokenName = $state('');
  let tokenScopes = $state<IntegrationScope[]>(['devices:read']);
  let tokenBusy = $state(false);
  let tokenError = $state<string | null>(null);
  let mintedToken = $state<{ name: string; token: string } | null>(null);

  async function loadTokens() {
    tokensError = null;
    try { tokens = await client.integrationTokens(); } catch { tokensError = 'Integration tokens could not be listed.'; }
  }
  function toggleScope(scope: IntegrationScope) { tokenScopes = tokenScopes.includes(scope) ? tokenScopes.filter((item) => item !== scope) : [...tokenScopes, scope]; }
  async function mint(event: SubmitEvent) {
    event.preventDefault();
    if (tokenName.trim().length === 0) { tokenError = 'Name the integration.'; return; }
    if (tokenScopes.length === 0) { tokenError = 'Pick at least one scope.'; return; }
    tokenBusy = true; tokenError = null; mintedToken = null;
    try {
      const result = await client.mintIntegrationToken(tokenName.trim(), tokenScopes);
      mintedToken = { name: result.name, token: result.token };
      tokenName = '';
      await loadTokens();
    } catch { tokenError = 'The collector could not mint a token right now.'; }
    finally { tokenBusy = false; }
  }
  async function revokeToken(id: string) {
    revoking = new Set([...revoking, id]);
    try { await client.revokeIntegrationToken(id); await loadTokens(); }
    catch { tokensError = 'That token could not be revoked. Try again.'; }
    finally { const next = new Set(revoking); next.delete(id); revoking = next; }
  }

  // --- doctor targets (owner)
  let doctor = $state<DoctorSettings | null>(null);
  let doctorError = $state<string | null>(null);
  let doctorForm = $state({ gateway: '', configured_resolvers: '', independent_resolver: '', internet_probe_address: '', internet_probe_port: '', dns_probe_name: '', external_probes_confirmed: false });
  let doctorBusy = $state(false);
  let doctorNotice = $state<string | null>(null);

  function fillDoctorForm(settings: DoctorSettings) {
    doctorForm = { gateway: settings.gateway ?? '', configured_resolvers: settings.configured_resolvers.join(', '), independent_resolver: settings.independent_resolver, internet_probe_address: settings.internet_probe_address, internet_probe_port: String(settings.internet_probe_port), dns_probe_name: settings.dns_probe_name, external_probes_confirmed: settings.external_probes_confirmed };
  }
  async function loadDoctor() {
    doctorError = null;
    try { doctor = await client.doctorSettings(); fillDoctorForm(doctor); } catch { doctorError = 'Doctor settings could not be loaded.'; }
  }
  async function saveDoctor(event: SubmitEvent) {
    event.preventDefault();
    const port = Number(doctorForm.internet_probe_port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) { doctorNotice = 'The probe port must be 1 to 65535.'; return; }
    doctorBusy = true; doctorNotice = null;
    try {
      const outcome = await client.updateDoctorSettings({
        gateway: doctorForm.gateway.trim(),
        configured_resolvers: doctorForm.configured_resolvers.split(',').map((item) => item.trim()).filter(Boolean),
        independent_resolver: doctorForm.independent_resolver.trim(),
        internet_probe_address: doctorForm.internet_probe_address.trim(),
        internet_probe_port: port,
        dns_probe_name: doctorForm.dns_probe_name.trim(),
        external_probes_confirmed: doctorForm.external_probes_confirmed
      });
      if (outcome.status === 'saved') { doctor = outcome.settings; fillDoctorForm(outcome.settings); doctorNotice = 'Saved. The next diagnostic uses these targets.'; }
      else doctorNotice = outcome.error;
    } catch { doctorNotice = 'The collector could not save these settings.'; }
    finally { doctorBusy = false; }
  }

  function when(value: string | null): string { return value ? new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'never'; }

  onMount(() => {
    motion = readMotion();
    if (isOwner) { void loadRemote(); void loadSessions(); void loadTokens(); void loadDoctor(); }
  });
</script>

<section class="settings-view" aria-labelledby="settings-heading">
  <div class="view-heading"><div><p class="kicker">SETTINGS</p><h1 id="settings-heading">Who may look in.</h1><p class="muted">Credentials stay on the device that holds them. The collector only ever sees a bearer token or a paired phone session.</p></div></div>

  <section class="settings-card" aria-labelledby="session-heading">
    <h2 id="session-heading">This session</h2>
    <dl class="settings-facts">
      <div><dt>Signed in as</dt><dd>{principal}</dd></div>
      <div><dt>Remembered</dt><dd>{auth.remembered ? 'Until this tab closes' : 'No'}</dd></div>
      {#if auth.stepupUntil}<div><dt>PIN unlock until</dt><dd>{new Date(auth.stepupUntil).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}</dd></div>{/if}
    </dl>
    {#if auth.credential}<button type="button" class="quiet" onclick={onsignout}>Sign out</button>{/if}
  </section>

  <section class="settings-card" aria-labelledby="appearance-heading">
    <h2 id="appearance-heading">Appearance</h2>
    <p class="muted">Motion is decorative: the hearth breathes and sparks drift. Readings never depend on it.</p>
    <div class="choice-row" role="group" aria-label="Motion">
      <button type="button" class="choice" class:active={motion === 'auto'} aria-pressed={motion === 'auto'} onclick={() => setMotion('auto')}>Follow system</button>
      <button type="button" class="choice" class:active={motion === 'reduced'} aria-pressed={motion === 'reduced'} onclick={() => setMotion('reduced')}>Reduce motion</button>
    </div>
  </section>

  {#if isOwner}
    <section class="settings-card" aria-labelledby="remote-heading">
      <h2 id="remote-heading">Private phone access</h2>
      <p class="muted">Your phone reaches NeonHearth over your own Tailscale network only. Nothing is published to the internet; Serve with Funnel is refused.</p>
      {#if remoteError}<p class="pair-error" role="alert">{remoteError} <button type="button" class="link" onclick={loadRemote}>Retry</button></p>
      {:else if remote}
        <dl class="settings-facts">
          <div><dt>Tailscale</dt><dd>{remote.daemon ? (remote.daemon.running ? `Running · ${remote.daemon.backend_state}` : `Not running · ${remote.daemon.backend_state}`) : remote.daemon_error ?? 'Not detected'}</dd></div>
          <div><dt>Tailnet name</dt><dd>{remote.daemon?.dns_name ?? 'unknown'}</dd></div>
          <div><dt>Private serve</dt><dd>{remote.serve_configured ? 'On' : 'Off'}{remote.funnel_conflict ? ' · Funnel conflict' : ''}</dd></div>
        </dl>
        {#if remote.funnel_conflict}<p class="pair-error" role="alert">Funnel is enabled for the serve port. NeonHearth will not expose itself publicly; turn Funnel off in Tailscale, then enable private access here.</p>{/if}
        <button type="button" class="confirm" disabled={serveBusy || remote.funnel_conflict || !remote.daemon?.running} onclick={enableServe}>{serveBusy ? 'Configuring…' : remote.serve_configured ? 'Re-apply private access' : 'Turn on private access'}</button>
        {#if serveNotice}<p class="notice" role="status">{serveNotice}</p>{/if}
      {:else}<p class="unavailable-copy">Checking Tailscale…</p>{/if}
    </section>

    <section class="settings-card" aria-labelledby="pair-heading">
      <h2 id="pair-heading">Pair a phone</h2>
      <p class="muted">Creates a phone session that can read your home over your tailnet. High-impact actions on the phone need the PIN you choose here.</p>
      <form class="pair-form" onsubmit={pair}>
        <label class="search"><span>Phone name</span><input type="text" maxlength="128" bind:value={deviceLabel} placeholder="e.g. Paul's phone" /></label>
        <label class="search"><span>Six-digit PIN</span><input type="password" inputmode="numeric" autocomplete="off" maxlength="6" bind:value={pin} /></label>
        {#if pairError}<p class="pair-error" role="alert">{pairError}</p>{/if}
        <button type="submit" class="confirm" disabled={pairBusy}>{pairBusy ? 'Pairing…' : 'Create pairing code'}</button>
      </form>
      {#if minted}
        <div class="pairing-code" role="status" aria-live="polite">
          <p class="kicker">PAIRING CODE — SHOWN ONCE</p>
          <code>{minted.code}</code>
          <p class="muted">Enter it on the phone's sign-in screen. The session expires {new Date(minted.expires_at).toLocaleDateString([], { dateStyle: 'medium' })} unless the phone keeps using it.</p>
        </div>
      {/if}
      <h3>Paired phones</h3>
      {#if sessionsError}<p class="pair-error" role="alert">{sessionsError} <button type="button" class="link" onclick={loadSessions}>Retry</button></p>{/if}
      {#if sessions.length}
        <ul class="row-list">
          {#each sessions as session (session.session_id)}
            <li class:revoked={session.revoked}>
              <span class="row-icon"><Icon name="devices" size={16} /></span>
              <span class="row-main"><strong>{session.device_label}</strong><small>{session.revoked ? 'Revoked' : `Last used ${when(session.last_used_at)} · expires ${when(session.expires_at)}`}</small></span>
              {#if !session.revoked}<button type="button" class="quiet danger" disabled={revoking.has(session.session_id)} onclick={() => revokeSession(session.session_id)}>{revoking.has(session.session_id) ? 'Revoking…' : 'Revoke'}</button>{/if}
            </li>
          {/each}
        </ul>
      {:else if !sessionsError}<p class="unavailable-copy">No phones are paired.</p>{/if}
    </section>

    <section class="settings-card" aria-labelledby="integrations-heading">
      <h2 id="integrations-heading">Integrations</h2>
      <p class="muted">Read-only tokens for Home Assistant or your own scripts. Each token sees only the scopes you tick and can be revoked at any time.</p>
      <form class="pair-form" onsubmit={mint}>
        <label class="search"><span>Integration name</span><input type="text" maxlength="128" bind:value={tokenName} placeholder="e.g. Home Assistant" /></label>
        <fieldset class="scopes"><legend class="kicker">SCOPES</legend>{#each INTEGRATION_SCOPES as scope}<label><input type="checkbox" checked={tokenScopes.includes(scope)} onchange={() => toggleScope(scope)} /> {scope}</label>{/each}</fieldset>
        {#if tokenError}<p class="pair-error" role="alert">{tokenError}</p>{/if}
        <button type="submit" class="confirm" disabled={tokenBusy}>{tokenBusy ? 'Minting…' : 'Mint token'}</button>
      </form>
      {#if mintedToken}
        <div class="pairing-code" role="status" aria-live="polite">
          <p class="kicker">TOKEN FOR {mintedToken.name.toUpperCase()} — SHOWN ONCE</p>
          <code>{mintedToken.token}</code>
          <p class="muted">Send it as <span class="mono">Authorization: Bearer …</span> to the integration endpoints under /api/v1/integrations/v1/.</p>
        </div>
      {/if}
      <h3>Active tokens</h3>
      {#if tokensError}<p class="pair-error" role="alert">{tokensError} <button type="button" class="link" onclick={loadTokens}>Retry</button></p>{/if}
      {#if tokens.length}
        <ul class="row-list">
          {#each tokens as token (token.id)}
            <li class:revoked={token.revoked}>
              <span class="row-icon"><Icon name="lock" size={16} /></span>
              <span class="row-main"><strong>{token.name}</strong><small>{token.revoked ? 'Revoked' : token.scopes.join(' · ')} · created {when(token.created_at)}</small></span>
              {#if !token.revoked}<button type="button" class="quiet danger" disabled={revoking.has(token.id)} onclick={() => revokeToken(token.id)}>{revoking.has(token.id) ? 'Revoking…' : 'Revoke'}</button>{/if}
            </li>
          {/each}
        </ul>
      {:else if !tokensError}<p class="unavailable-copy">No integration tokens yet.</p>{/if}
    </section>

    <section class="settings-card" aria-labelledby="doctor-heading">
      <h2 id="doctor-heading">Network Doctor targets</h2>
      <p class="muted">The Doctor pings your gateway and resolvers, then a known-good resolver and one internet address. Anything outside your private network is only probed after you confirm it here.</p>
      {#if doctorError}<p class="pair-error" role="alert">{doctorError} <button type="button" class="link" onclick={loadDoctor}>Retry</button></p>
      {:else if doctor}
        <form class="pair-form doctor-form" onsubmit={saveDoctor}>
          <div class="two-up">
            <label class="search"><span>Gateway {doctor.gateway_source === 'owner' ? '' : `(detected: ${doctor.gateway_source})`}</span><input type="text" bind:value={doctorForm.gateway} placeholder="192.168.1.1" /></label>
            <label class="search"><span>Local resolvers (comma separated)</span><input type="text" bind:value={doctorForm.configured_resolvers} placeholder="192.168.1.1" /></label>
            <label class="search"><span>Independent resolver</span><input type="text" bind:value={doctorForm.independent_resolver} placeholder="9.9.9.9" /></label>
            <label class="search"><span>Internet probe address</span><input type="text" bind:value={doctorForm.internet_probe_address} placeholder="1.1.1.1" /></label>
            <label class="search"><span>Internet probe port</span><input type="text" inputmode="numeric" bind:value={doctorForm.internet_probe_port} placeholder="443" /></label>
            <label class="search"><span>DNS probe name</span><input type="text" bind:value={doctorForm.dns_probe_name} placeholder="example.com" /></label>
          </div>
          <label class="checkbox"><input type="checkbox" bind:checked={doctorForm.external_probes_confirmed} /> I own this network and allow the Doctor to probe the external targets above.</label>
          {#if doctorNotice}<p class="notice" role="status">{doctorNotice}</p>{/if}
          <button type="submit" class="confirm" disabled={doctorBusy}>{doctorBusy ? 'Saving…' : 'Save targets'}</button>
        </form>
      {:else}<p class="unavailable-copy">Loading Doctor settings…</p>{/if}
    </section>
  {/if}
</section>

<style>
  .settings-card { margin-top: 26px; padding: 20px; border: 1px solid var(--line-mid); border-radius: var(--radius-lg); background: var(--surface); display: grid; gap: 12px; }
  .settings-card h2 { margin: 0; font: 600 17px var(--font-display); }
  .settings-card h3 { margin: 10px 0 0; font: 600 13px var(--font-display); color: var(--muted-strong); }
  .settings-facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin: 0; }
  .settings-facts div { padding-top: 10px; border-top: 1px solid var(--line-mid); }
  .settings-facts dt { color: var(--muted); font: 10px var(--font-mono); text-transform: uppercase; }
  .settings-facts dd { margin: 5px 0 0; color: var(--ink); font-size: 12px; }
  .pair-form { display: grid; gap: 10px; }
  .pair-form .search { margin: 0; }
  .two-up { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }
  .checkbox { display: flex; gap: 10px; align-items: flex-start; font-size: 12px; color: var(--muted-strong); line-height: 1.45; }
  .checkbox input { margin-top: 2px; accent-color: var(--accent); }
  .scopes { display: flex; flex-wrap: wrap; gap: 8px 16px; margin: 0; padding: 0; border: 0; font: 12px var(--font-mono); color: var(--muted-strong); }
  .scopes legend { padding: 0; margin-bottom: 6px; }
  .scopes label { display: inline-flex; gap: 6px; align-items: center; min-height: 32px; }
  .scopes input { accent-color: var(--accent); }
  .pair-error { margin: 0; padding: 9px; border: 1px solid var(--risk); border-radius: var(--radius-sm); color: var(--risk); font: 11px var(--font-mono); }
  .notice { margin: 0; padding: 9px; border: 1px solid var(--line-strong); border-radius: var(--radius-sm); color: var(--muted-strong); font: 11px var(--font-mono); }
  .confirm, .quiet, .choice { min-height: 44px; padding: 10px 14px; border: 1px solid var(--accent); border-radius: var(--radius-sm); background: var(--accent); color: var(--accent-ink); font: 700 12px var(--font-body); cursor: pointer; justify-self: start; }
  .quiet, .choice { color: var(--ink); border-color: var(--line-strong); background: transparent; font-weight: 600; }
  .quiet.danger { color: var(--risk); }
  .choice.active { border-color: var(--accent); color: var(--accent); }
  .choice-row { display: flex; gap: 8px; }
  .confirm:disabled, .quiet:disabled { opacity: .5; cursor: not-allowed; }
  .link { border: 0; background: none; color: inherit; text-decoration: underline; cursor: pointer; font: inherit; padding: 0; }
  .pairing-code { padding: 14px; border: 1px dashed var(--gold); border-radius: var(--radius); display: grid; gap: 8px; }
  .pairing-code code { display: block; padding: 10px; border-radius: var(--radius-sm); background: var(--bg); color: var(--gold); font: 13px var(--font-mono); overflow-wrap: anywhere; user-select: all; }
  .mono { font-family: var(--font-mono); }
  .row-list { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--line); }
  .row-list li { display: grid; grid-template-columns: 24px 1fr auto; gap: 12px; align-items: center; min-height: 56px; padding: 8px 0; border-bottom: 1px solid var(--line); }
  .row-list li.revoked { opacity: .55; }
  .row-icon { color: var(--accent); display: inline-grid; place-items: center; }
  .row-main strong, .row-main small { display: block; }
  .row-main small { margin-top: 3px; color: var(--muted); font-size: 11px; }
  .unavailable-copy { margin: 0; color: var(--muted); font-size: 12px; }
</style>
