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
  .stepup-backdrop { position: fixed; inset: 0; z-index: 20; display: grid; place-items: center; background: var(--bg)99; backdrop-filter: blur(3px); }
  .stepup { width: min(420px, 92vw); padding: 22px; border: 1px solid var(--line-strong); border-radius: 12px; background: var(--surface); display: grid; gap: 10px; }
  .stepup h2 { margin: 0; font: 700 22px var(--font-display); }
  .stepup .search { margin: 8px 0 0; }
  .stepup-error { margin: 0; padding: 9px; border: 1px solid var(--pink); border-radius: 5px; color: var(--pink); font: 11px var(--font-mono); }
  .stepup-actions { display: flex; gap: 9px; }
  .stepup-actions button { min-height: 44px; padding: 10px 14px; border: 1px solid var(--accent); border-radius: 5px; background: var(--accent); color: var(--accent-ink); font: 700 12px var(--font-display); cursor: pointer; }
  .stepup-actions .quiet { color: var(--ink); border-color: var(--line-strong); background: transparent; }
  .stepup-actions button:disabled { opacity: .5; cursor: not-allowed; }
</style>
