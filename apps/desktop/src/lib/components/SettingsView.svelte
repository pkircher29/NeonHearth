<script lang="ts">
  // Settings: session state and phone pairing (audit M-25). Pairing mints a
  // phone session from a signed-in owner; the code is shown exactly once.
  import type { ApiClient } from '../api/client';
  import { formatPairingCode, type AuthState } from '../auth/session';

  type PairingClient = Pick<ApiClient, 'pairPhone'>;
  interface Props { client: PairingClient; auth: AuthState; onsignout: () => void }
  let { client, auth, onsignout }: Props = $props();

  let deviceLabel = $state('');
  let pin = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let minted = $state<{ code: string; expires_at: string } | null>(null);

  const principal = $derived(auth.credential?.kind === 'owner' ? 'Owner token' : auth.credential?.kind === 'phone' ? 'Paired phone' : 'Proxy or none');

  async function pair(event: SubmitEvent) {
    event.preventDefault();
    if (deviceLabel.trim().length === 0) { error = 'Give the phone a name.'; return; }
    if (!/^[0-9]{6}$/.test(pin)) { error = 'The PIN is exactly six digits.'; return; }
    busy = true; error = null; minted = null;
    try {
      const response = await client.pairPhone(deviceLabel.trim(), pin);
      minted = { code: formatPairingCode(response.session_id, response.secret), expires_at: response.expires_at };
      deviceLabel = ''; pin = '';
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : '';
      error = /status 401\b/.test(message) ? 'Only the owner token can pair a phone.' : 'The collector could not create the pairing right now.';
    } finally { busy = false; }
  }
</script>

<section class="settings-view" aria-labelledby="settings-heading">
  <div class="view-heading"><div><p class="kicker">SETTINGS / ACCESS</p><h1 id="settings-heading">Who may look in.</h1><p class="muted">Credentials stay on the device that holds them. The collector only ever sees a bearer or a paired phone session.</p></div></div>

  <section class="settings-card" aria-labelledby="session-heading">
    <h2 id="session-heading">This session</h2>
    <dl class="settings-facts">
      <div><dt>Signed in as</dt><dd>{principal}</dd></div>
      <div><dt>Remembered</dt><dd>{auth.remembered ? 'Until this tab closes' : 'No'}</dd></div>
      {#if auth.stepupUntil}<div><dt>PIN unlock until</dt><dd>{new Date(auth.stepupUntil).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}</dd></div>{/if}
    </dl>
    {#if auth.credential}<button type="button" class="quiet" onclick={onsignout}>Sign out</button>{/if}
  </section>

  {#if auth.credential?.kind !== 'phone'}
    <section class="settings-card" aria-labelledby="pair-heading">
      <h2 id="pair-heading">Pair a phone</h2>
      <p class="muted">Creates a phone session that can read your home over your private tailnet. High-impact actions on the phone need the PIN you choose here.</p>
      <form class="pair-form" onsubmit={pair}>
        <label class="search"><span>Phone name</span><input type="text" maxlength="128" bind:value={deviceLabel} placeholder="e.g. Paul's phone" /></label>
        <label class="search"><span>Six-digit PIN</span><input type="password" inputmode="numeric" autocomplete="off" maxlength="6" bind:value={pin} /></label>
        {#if error}<p class="pair-error" role="alert">{error}</p>{/if}
        <button type="submit" class="confirm" disabled={busy}>{busy ? 'Pairing…' : 'Create pairing code'}</button>
      </form>
      {#if minted}
        <div class="pairing-code" role="status" aria-live="polite">
          <p class="kicker">PAIRING CODE — SHOWN ONCE</p>
          <code>{minted.code}</code>
          <p class="muted">Enter it on the phone's sign-in screen. The session expires {new Date(minted.expires_at).toLocaleDateString([], { dateStyle: 'medium' })} unless the phone keeps using it.</p>
        </div>
      {/if}
    </section>
  {/if}
</section>

<style>
  .settings-card { margin-top: 26px; padding: 20px; border: 1px solid var(--line-mid); border-radius: 12px; background: var(--surface); display: grid; gap: 12px; }
  .settings-card h2 { margin: 0; font: 600 17px var(--font-display); }
  .settings-facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin: 0; }
  .settings-facts div { padding-top: 10px; border-top: 1px solid var(--line-mid); }
  .settings-facts dt { color: var(--muted); font: 10px var(--font-mono); text-transform: uppercase; }
  .settings-facts dd { margin: 5px 0 0; color: var(--ink); font-size: 12px; }
  .pair-form { display: grid; gap: 10px; }
  .pair-form .search { margin: 0; }
  .pair-error { margin: 0; padding: 9px; border: 1px solid var(--pink); border-radius: 5px; color: var(--pink); font: 11px var(--font-mono); }
  .confirm, .quiet { min-height: 44px; padding: 10px 14px; border: 1px solid var(--accent); border-radius: 5px; background: var(--accent); color: var(--accent-ink); font: 700 12px var(--font-display); cursor: pointer; justify-self: start; }
  .quiet { color: var(--ink); border-color: var(--line-strong); background: transparent; }
  .confirm:disabled { opacity: .5; cursor: not-allowed; }
  .pairing-code { padding: 14px; border: 1px dashed var(--gold); border-radius: 8px; display: grid; gap: 8px; }
  .pairing-code code { display: block; padding: 10px; border-radius: 5px; background: var(--bg); color: var(--gold); font: 13px var(--font-mono); overflow-wrap: anywhere; user-select: all; }
</style>
