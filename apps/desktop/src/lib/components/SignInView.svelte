<script lang="ts">
  // Shown when the service answers 401 and no credential is held (audit M-25).
  // Desktop: the owner pastes the service token. Phone: the pairing code the
  // owner minted from a signed-in desktop (Settings → Pair a phone).
  import type { AuthFailure } from '../auth/session';

  interface Props {
    failure?: AuthFailure;
    onowner: (token: string, remember: boolean) => void;
    onphone: (pairingCode: string, remember: boolean) => void;
  }
  let { failure = null, onowner, onphone }: Props = $props();

  type Mode = 'owner' | 'phone';
  let mode = $state<Mode>('owner');
  let token = $state('');
  let pairingCode = $state('');
  let remember = $state(false);

  const failureText = $derived(
    failure === 'rejected' ? 'That credential was not accepted. Check it and try again.'
      : failure === 'invalid_format' ? (mode === 'owner' ? 'The service token is at least 32 characters with no spaces.' : 'A pairing code looks like session-id:secret, exactly as the desktop showed it.')
      : null);

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (mode === 'owner') onowner(token, remember);
    else onphone(pairingCode, remember);
  }
</script>

<section class="sign-in" aria-labelledby="sign-in-heading">
  <p class="kicker">SIGN IN / PROTECTED</p>
  <h1 id="sign-in-heading">Unlock your home.</h1>
  <p class="muted">The collector refused an unauthenticated request. Sign in with the credential for this device; nothing is stored beyond this browser tab unless you ask.</p>
  <div class="tabs" role="tablist" aria-label="Credential kind">
    <button type="button" role="tab" aria-selected={mode === 'owner'} class:active={mode === 'owner'} onclick={() => (mode = 'owner')}>This computer</button>
    <button type="button" role="tab" aria-selected={mode === 'phone'} class:active={mode === 'phone'} onclick={() => (mode = 'phone')}>A paired phone</button>
  </div>
  <form class="sign-in-form" onsubmit={submit}>
    {#if mode === 'owner'}
      <label class="search"><span>Service token</span>
        <input type="password" autocomplete="off" spellcheck="false" bind:value={token} placeholder="Paste the owner service token" aria-describedby="owner-help" />
      </label>
      <p id="owner-help" class="muted small">On Linux it is in /etc/neonhearth/service.env; on Windows the installer keeps it in the service configuration. It never leaves this machine.</p>
    {:else}
      <label class="search"><span>Pairing code</span>
        <input type="password" autocomplete="off" spellcheck="false" bind:value={pairingCode} placeholder="session-id:secret" aria-describedby="phone-help" />
      </label>
      <p id="phone-help" class="muted small">Mint one on the desktop under Settings → Pair a phone. High-impact actions will also ask for the six-digit PIN you chose there.</p>
    {/if}
    <label class="remember"><input type="checkbox" bind:checked={remember} /> Remember on this device until the tab closes</label>
    {#if failureText}<p class="sign-in-error" role="alert">{failureText}</p>{/if}
    <button type="submit" class="sign-in-submit">Sign in</button>
  </form>
</section>

<style>
  .sign-in { max-width: 530px; margin: 10vh auto; }
  .sign-in h1 { margin: 9px 0 8px; font: 700 clamp(2rem, 4vw, 3.4rem)/.95 var(--font-display); letter-spacing: -.05em; }
  .sign-in-form { display: grid; gap: 14px; margin-top: 8px; }
  .small { font-size: 12px; margin: -6px 0 0; }
  .remember { display: flex; gap: 9px; align-items: center; color: var(--muted-strong); font-size: 12px; }
  .remember input { width: 16px; height: 16px; accent-color: var(--accent); }
  .sign-in-error { margin: 0; padding: 9px; border: 1px solid var(--pink); border-radius: 5px; color: var(--pink); font: 11px var(--font-mono); }
  .sign-in-submit { min-height: 44px; padding: 10px 16px; border: 1px solid var(--accent); border-radius: 5px; background: var(--accent); color: var(--accent-ink); font: 700 13px var(--font-display); cursor: pointer; justify-self: start; }
</style>
