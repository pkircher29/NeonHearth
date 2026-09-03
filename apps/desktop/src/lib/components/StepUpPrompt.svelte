<script lang="ts">
  // PIN step-up for phone sessions: a high-impact route answered 403, so the
  // service wants the six-digit PIN before the five-minute grace window opens.
  interface Props {
    onsubmit: (pin: string) => Promise<void>;
    oncancel: () => void;
  }
  let { onsubmit, oncancel }: Props = $props();
  let pin = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!/^[0-9]{6}$/.test(pin)) { error = 'Enter the six digits of your PIN.'; return; }
    busy = true; error = null;
    try {
      await onsubmit(pin);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : '';
      error = /status 429\b/.test(message) ? 'Too many attempts. Wait fifteen minutes and try again.'
        : /status 403\b/.test(message) ? 'That PIN did not match.'
        : 'The collector could not verify the PIN right now.';
    } finally { busy = false; }
  }
</script>

<div class="stepup-backdrop" role="dialog" aria-modal="true" aria-labelledby="stepup-heading">
  <form class="stepup" onsubmit={submit}>
    <p class="kicker">PHONE / STEP-UP</p>
    <h2 id="stepup-heading">Confirm with your PIN</h2>
    <p class="muted">This action changes your network. Enter the PIN you chose when pairing; the unlock lasts five minutes.</p>
    <label class="search"><span>Six-digit PIN</span>
      <input type="password" inputmode="numeric" autocomplete="one-time-code" maxlength="6" bind:value={pin} aria-invalid={error !== null} />
    </label>
    {#if error}<p class="stepup-error" role="alert">{error}</p>{/if}
    <div class="stepup-actions">
      <button type="submit" class="confirm" disabled={busy}>{busy ? 'Checking…' : 'Unlock'}</button>
      <button type="button" class="quiet" onclick={oncancel} disabled={busy}>Cancel</button>
    </div>
  </form>
</div>

<style>
  .stepup-backdrop { position: fixed; inset: 0; z-index: 20; display: grid; place-items: center; background: #06101999; backdrop-filter: blur(3px); }
  .stepup { width: min(420px, 92vw); padding: 22px; border: 1px solid #28505a; border-radius: 12px; background: #0b1c26; display: grid; gap: 10px; }
  .stepup h2 { margin: 0; font: 700 22px Arial; }
  .stepup .search { margin: 8px 0 0; }
  .stepup-error { margin: 0; padding: 9px; border: 1px solid #ff5c9b; border-radius: 5px; color: #ff5c9b; font: 11px monospace; }
  .stepup-actions { display: flex; gap: 9px; }
  .stepup-actions button { min-height: 44px; padding: 10px 14px; border: 1px solid #63f3f0; border-radius: 5px; background: #63f3f0; color: #031418; font: 700 12px Arial; cursor: pointer; }
  .stepup-actions .quiet { color: #cce4e7; border-color: #28505a; background: transparent; }
  .stepup-actions button:disabled { opacity: .5; cursor: not-allowed; }
</style>
