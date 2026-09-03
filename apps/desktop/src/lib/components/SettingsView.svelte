<script lang="ts">
  import { onMount } from 'svelte';
  import type { LiveState } from '../stores/live';

  interface Props {
    state?: LiveState | null;
  }

  let { state: liveState = null }: Props = $props();

  // Load preferences from localStorage or sensible defaults
  let autoQuarantine = $state(true);
  let tailscaleServe = $state(true);
  let reduceMotion = $state(false);
  let offlinePassiveOnly = $state(true);
  let savedNotice = $state(false);
  let noticeTimeout: ReturnType<typeof setTimeout> | undefined;

  onMount(() => {
    try {
      const storedPassive = localStorage.getItem('neonhearth.passive_only');
      if (storedPassive !== null) {
        offlinePassiveOnly = storedPassive === 'true';
      }
      const storedAutoQ = localStorage.getItem('neonhearth.auto_quarantine');
      if (storedAutoQ !== null) {
        autoQuarantine = storedAutoQ === 'true';
      }
      const storedMotion = localStorage.getItem('neonhearth.reduce_motion');
      if (storedMotion !== null) {
        reduceMotion = storedMotion === 'true';
      }
    } catch {
      // LocalStorage access may be restricted in sandboxes
    }
  });

  function triggerSave() {
    try {
      localStorage.setItem('neonhearth.passive_only', String(offlinePassiveOnly));
      localStorage.setItem('neonhearth.auto_quarantine', String(autoQuarantine));
      localStorage.setItem('neonhearth.reduce_motion', String(reduceMotion));
    } catch {
      // Ignore
    }

    savedNotice = true;
    if (noticeTimeout) clearTimeout(noticeTimeout);
    noticeTimeout = setTimeout(() => {
      savedNotice = false;
    }, 2500);
  }
</script>

<section class="settings-view" aria-labelledby="settings-heading">
  <div class="view-heading">
    <div>
      <p class="kicker">SYSTEM / CONFIGURATION</p>
      <h1 id="settings-heading">Settings & Security Policy</h1>
      <p class="muted">Manage local-first collection parameters, probe safety, and remote access gates.</p>
    </div>
    {#if savedNotice}
      <div class="save-pill" role="status">✓ Preferences Saved</div>
    {/if}
  </div>

  <div class="settings-grid">
    <article class="setting-card">
      <div class="setting-info">
        <div class="setting-title-row">
          <strong>Passive-Only Packet Sniffing</strong>
          <span class="mode-badge" class:active={offlinePassiveOnly}>
            {offlinePassiveOnly ? 'PASSIVE ACTIVE' : 'ACTIVE PROBING ENABLED'}
          </span>
        </div>
        <p class="muted">
          {#if offlinePassiveOnly}
            Network discovery is restricted strictly to passive listening on local mDNS, SSDP, and DHCP broadcast traffic. No ARP or ICMP ping probes are transmitted across your subnets.
          {:else}
            Active discovery sends targeted, rate-limited unicast ARP and ICMP ping probes to homeowner-approved RFC 1918 subnets for accelerated device inventory discovery.
          {/if}
        </p>
      </div>
      <label class="switch" aria-label="Toggle passive-only packet sniffing">
        <input type="checkbox" bind:checked={offlinePassiveOnly} onchange={triggerSave} />
        <span class="slider"></span>
      </label>
    </article>

    <article class="setting-card">
      <div class="setting-info">
        <strong>Auto-Quarantine High-Risk Devices</strong>
        <p class="muted">Automatically trigger W6 appliance isolation when a device exhibits high-confidence danger signals without owner approval.</p>
      </div>
      <label class="switch" aria-label="Toggle auto-quarantine for high-risk devices">
        <input type="checkbox" bind:checked={autoQuarantine} onchange={triggerSave} />
        <span class="slider"></span>
      </label>
    </article>

    <article class="setting-card">
      <div class="setting-info">
        <strong>Tailscale Serve Phone Access</strong>
        <p class="muted">Expose encrypted local API over Tailscale tailnet. Identity headers are stripped and PIN step-up is strictly enforced.</p>
      </div>
      <label class="switch" aria-label="Toggle Tailscale Serve phone access">
        <input type="checkbox" bind:checked={tailscaleServe} onchange={triggerSave} />
        <span class="slider"></span>
      </label>
    </article>

    <article class="setting-card">
      <div class="setting-info">
        <strong>Reduce Dashboard Motion</strong>
        <p class="muted">Pause continuous orbital rotation and hearth breathing pulses for lower resource utilization or accessibility.</p>
      </div>
      <label class="switch" aria-label="Toggle dashboard motion reduction">
        <input type="checkbox" bind:checked={reduceMotion} onchange={triggerSave} />
        <span class="slider"></span>
      </label>
    </article>
  </div>

  <div class="system-meta-box">
    <h3>Local Daemon Verification</h3>
    <div class="meta-row">
      <span>Service Binding:</span>
      <code>127.0.0.1:58120 (Loopback Only)</code>
    </div>
    <div class="meta-row">
      <span>Audit Storage Engine:</span>
      <code>SQLite WAL + SHA-256 Chained Triggers</code>
    </div>
    <div class="meta-row">
      <span>Discovery Boundary:</span>
      <code>RFC 1918 / ULA TargetGuard Enforced</code>
    </div>
    <div class="meta-row">
      <span>Sniffing Mode:</span>
      <code>{offlinePassiveOnly ? 'Passive Broadcast Only (No Active Probing)' : 'Active + Passive Subnet Probing'}</code>
    </div>
  </div>
</section>

<style>
  .settings-view {
    display: flex;
    flex-direction: column;
    gap: 24px;
  }

  .view-heading {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .save-pill {
    background: rgba(99, 243, 240, 0.15);
    border: 1px solid #63f3f0;
    color: #63f3f0;
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
  }

  .settings-grid {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .setting-card {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    background: #0b1c26;
    border: 1px solid #17323d;
    padding: 18px 22px;
    border-radius: 8px;
  }

  .setting-title-row {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .setting-info strong {
    display: block;
    font-size: 14px;
    color: #e9fbfc;
  }

  .mode-badge {
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.5px;
    padding: 2px 8px;
    border-radius: 4px;
    font-family: monospace;
    background: rgba(255, 205, 102, 0.15);
    color: #ffcd66;
    border: 1px solid rgba(255, 205, 102, 0.4);
  }

  .mode-badge.active {
    background: rgba(99, 243, 240, 0.15);
    color: #63f3f0;
    border-color: rgba(99, 243, 240, 0.4);
  }

  .setting-info p {
    font-size: 12px;
    color: #77959d;
    margin-top: 6px;
    max-width: 600px;
    line-height: 1.45;
  }

  /* Accessible Switch Control */
  .switch {
    position: relative;
    display: inline-block;
    width: 46px;
    height: 26px;
    flex-shrink: 0;
  }

  .switch input {
    opacity: 0;
    width: 0;
    height: 0;
  }

  .slider {
    position: absolute;
    cursor: pointer;
    inset: 0;
    background-color: #17323d;
    transition: 0.2s;
    border-radius: 26px;
    border: 1px solid #28505a;
  }

  .slider:before {
    position: absolute;
    content: "";
    height: 18px;
    width: 18px;
    left: 3px;
    bottom: 3px;
    background-color: #77959d;
    transition: 0.2s;
    border-radius: 50%;
  }

  input:checked + .slider {
    background-color: rgba(99, 243, 240, 0.25);
    border-color: #63f3f0;
  }

  input:checked + .slider:before {
    transform: translateX(20px);
    background-color: #63f3f0;
  }

  .system-meta-box {
    background: #08151d;
    border: 1px dashed #17323d;
    padding: 16px 20px;
    border-radius: 8px;
  }

  .system-meta-box h3 {
    font-size: 11px;
    color: #9bb7bb;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-bottom: 12px;
  }

  .meta-row {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    padding: 6px 0;
    border-bottom: 1px solid rgba(23, 50, 61, 0.4);
  }

  .meta-row:last-child {
    border-bottom: none;
  }

  .meta-row span {
    color: #77959d;
  }

  .meta-row code {
    color: #ffcd66;
    font-family: monospace;
  }

  @media (max-width: 700px) {
    .setting-card {
      flex-direction: column;
      align-items: flex-start;
      gap: 14px;
    }
  }
</style>
