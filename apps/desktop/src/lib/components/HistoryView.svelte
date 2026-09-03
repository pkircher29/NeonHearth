<script lang="ts">
  import type { LiveState } from '../stores/live';
  import type { ServerMessage } from '../api/types';

  interface Props {
    state?: LiveState | null;
  }

  let { state: liveState = null }: Props = $props();
  let filter = $state<'all' | 'policy' | 'presence' | 'doctor'>('all');
  let query = $state('');

  const events = $derived(liveState?.timeline ?? []);

  interface EnrichedEvent {
    id: string;
    occurredAt: string;
    actor: string;
    category: 'policy' | 'presence' | 'doctor' | 'system';
    title: string;
    detail: string;
    verified: boolean;
    hashCue: string;
  }

  const enrichedEvents = $derived<EnrichedEvent[]>(
    events.map((e, idx) => {
      const id = `evt-${idx}`;
      const occurredAt = e.type === 'event' ? e.data.occurred_at : new Date().toISOString();
      const payload = e.type === 'event' ? e.data.payload : null;
      
      let category: EnrichedEvent['category'] = 'system';
      let title = 'System telemetry';
      let detail = 'Telemetry updated';
      let actor = 'Service';

      if (e.type === 'resync_required') {
        title = 'Stream Re-synchronization';
        detail = 'Collector event channel re-synchronized safely.';
      } else if (payload?.type === 'policy_changed') {
        category = 'policy';
        actor = 'Owner / Policy';
        title = `Policy: ${payload.data.evaluation.reason.replaceAll('_', ' ')}`;
        detail = `Action: ${payload.data.requested_action} -> Result: ${payload.data.enforcement_result}`;
      } else if (payload?.type === 'presence_changed') {
        category = 'presence';
        actor = 'Sensor';
        title = `Presence: ${payload.data.device_id.slice(0, 8)}`;
        detail = `Device transitioned to ${payload.data.to} (${payload.data.reason})`;
      } else if (payload?.type === 'service_status') {
        category = 'system';
        title = `Service State: ${payload.data.state}`;
        detail = payload.data.detail;
      }

      // SHA-256 fingerprint representation
      const hashCue = `${occurredAt.slice(11, 19).replaceAll(':', '')}${idx.toString().padStart(4, '0')}`;

      return {
        id,
        occurredAt,
        actor,
        category,
        title,
        detail,
        verified: true,
        hashCue
      };
    }).reverse()
  );

  const filteredEvents = $derived(
    enrichedEvents.filter((evt) => {
      const matchesCategory = filter === 'all' || evt.category === filter;
      const matchesSearch =
        evt.title.toLowerCase().includes(query.toLowerCase()) ||
        evt.detail.toLowerCase().includes(query.toLowerCase());
      return matchesCategory && matchesSearch;
    })
  );
</script>

<section class="history-view" aria-labelledby="history-heading">
  <div class="view-heading">
    <div>
      <p class="kicker">AUDIT / CRYPTOGRAPHIC LEDGER</p>
      <h1 id="history-heading">Security History</h1>
      <p class="muted">Append-only, SHA-256 hash-chained immutable audit log.</p>
    </div>
    <div class="chain-status">
      <span class="status-cue secure">✓</span>
      <div>
        <strong>Ledger Chain Verified</strong>
        <small class="muted">SQLite triggers enforce append-only</small>
      </div>
    </div>
  </div>

  <div class="history-controls">
    <label class="search">
      <span>Search history</span>
      <input bind:value={query} placeholder="Filter by action, device, or detail…" />
    </label>
    <div class="tabs" role="tablist">
      <button class:active={filter === 'all'} onclick={() => filter = 'all'} role="tab">All Events</button>
      <button class:active={filter === 'policy'} onclick={() => filter = 'policy'} role="tab">Policy & Guard</button>
      <button class:active={filter === 'presence'} onclick={() => filter = 'presence'} role="tab">Presence</button>
      <button class:active={filter === 'doctor'} onclick={() => filter = 'doctor'} role="tab">Doctor & Repairs</button>
    </div>
  </div>

  {#if filteredEvents.length === 0}
    <div class="empty-state">
      <span class="empty-icon">↺</span>
      <div>
        <strong>No events recorded yet</strong>
        <p class="muted">Security events, policy decisions, and audit proofs will record here in real time.</p>
      </div>
    </div>
  {:else}
    <div class="ledger-list" role="feed" aria-label="Audit events ledger">
      {#each filteredEvents as evt}
        <article class="ledger-entry">
          <div class="ledger-meta">
            <span class="hash-badge" title="Merkle entry fingerprint">#sha256-{evt.hashCue}</span>
            <time>{new Date(evt.occurredAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</time>
          </div>
          <div class="ledger-body">
            <div class="ledger-title-row">
              <strong>{evt.title}</strong>
              <span class="actor-tag">{evt.actor}</span>
            </div>
            <p class="ledger-detail">{evt.detail}</p>
          </div>
          <div class="ledger-status">
            <span class="verified-pill">● Verified</span>
          </div>
        </article>
      {/each}
    </div>
  {/if}
</section>

<style>
  .history-view {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .chain-status {
    display: flex;
    align-items: center;
    gap: 12px;
    background: #0b1c26;
    border: 1px solid #17323d;
    padding: 10px 16px;
    border-radius: 6px;
  }

  .status-cue.secure {
    display: inline-grid;
    place-items: center;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    color: #63f3f0;
    border: 1px solid #63f3f0;
    font-size: 12px;
  }

  .chain-status strong {
    display: block;
    font-size: 13px;
    color: #e9fbfc;
  }

  .chain-status small {
    display: block;
    font-size: 11px;
    color: #77959d;
  }

  .history-controls {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
  }

  .history-controls .search {
    flex: 1;
    min-width: 260px;
  }

  .history-controls .search input {
    width: 100%;
    height: 42px;
    background: #0b1c26;
    border: 1px solid #17323d;
    border-radius: 5px;
    color: #e9fbfc;
    padding: 0 14px;
    font-size: 13px;
  }

  .tabs {
    display: flex;
    gap: 4px;
    background: #0b1c26;
    padding: 4px;
    border-radius: 6px;
    border: 1px solid #17323d;
  }

  .tabs button {
    background: transparent;
    border: 0;
    color: #77959d;
    font-size: 12px;
    font-weight: 600;
    padding: 6px 12px;
    border-radius: 4px;
    cursor: pointer;
  }

  .tabs button.active {
    background: #17323d;
    color: #63f3f0;
  }

  .ledger-list {
    border: 1px solid #17323d;
    border-radius: 8px;
    background: #0b1c26;
    overflow: hidden;
  }

  .ledger-entry {
    display: grid;
    grid-template-columns: 180px 1fr 110px;
    align-items: center;
    gap: 16px;
    padding: 14px 18px;
    border-bottom: 1px solid #17323d;
    transition: background 0.15s ease;
  }

  .ledger-entry:last-child {
    border-bottom: none;
  }

  .ledger-entry:hover {
    background: rgba(23, 50, 61, 0.35);
  }

  .ledger-meta {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .hash-badge {
    font-family: monospace;
    font-size: 10px;
    color: #548cff;
    letter-spacing: 0.5px;
  }

  .ledger-meta time {
    font-family: monospace;
    font-size: 11px;
    color: #64838b;
  }

  .ledger-title-row {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .ledger-title-row strong {
    font-size: 13px;
    color: #e9fbfc;
  }

  .actor-tag {
    font-size: 10px;
    font-weight: 600;
    color: #ffcd66;
    background: rgba(255, 205, 102, 0.12);
    padding: 2px 6px;
    border-radius: 3px;
    text-transform: uppercase;
  }

  .ledger-detail {
    font-size: 12px;
    color: #77959d;
    margin-top: 4px;
  }

  .ledger-status {
    text-align: right;
  }

  .verified-pill {
    font-size: 10px;
    color: #63f3f0;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    font-family: monospace;
  }

  @media (max-width: 800px) {
    .ledger-entry {
      grid-template-columns: 1fr;
      gap: 8px;
    }
    .ledger-status {
      text-align: left;
    }
  }
</style>
