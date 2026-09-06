<script lang="ts">
  import type { DeviceLabel, DeviceLabelsApi } from '../api/deviceLabels';
  import type { NameSuggestion } from '../deviceRecognition';
  let {device, suggestion = null, api = null, onsaved}: {
    device: DeviceLabel; suggestion?: NameSuggestion | null; api?: DeviceLabelsApi | null;
    onsaved?: (label: DeviceLabel) => void;
  } = $props();
  let editing = $state(false); let draft = $state(''); let baseline = $state<DeviceLabel | null>(null);
  let busy = $state(false); let error = $state(''); let dismissed = $state('');
  const prompt = $derived(!device.owner_confirmed && suggestion && dismissed !== suggestion.name);
  function edit() { draft = device.owner_name ?? suggestion?.name ?? ''; baseline = {...device}; editing = true; error = ''; }
  async function save(name: string, expected = device) {
    if (!api || busy) return;
    busy = true; error = '';
    try { const label = await api.confirm({...expected}, name); editing = false; onsaved?.(label); }
    catch (e) { error = e instanceof Error ? e.message : 'Could not save the name.'; }
    finally { busy = false; }
  }
</script>
{#if api}
  <div class="name-confirmation" aria-busy={busy}>
    {#if editing}
      <form onsubmit={e => {e.preventDefault(); void save(draft, baseline ?? device);}}>
        <label>Device name<input bind:value={draft} maxlength="128" required disabled={busy} /></label>
        <button disabled={busy} type="submit">{busy ? 'Saving…' : 'Save name'}</button>
        <button disabled={busy} type="button" onclick={() => editing = false}>Cancel</button>
      </form>
      <small>This confirms the label. Network access is controlled separately in Guard.</small>
    {:else if prompt && suggestion}
      <p><strong>Is “{suggestion.name}” the right name?</strong><small>Reported by {suggestion.source}. Confirm it or enter your own name.</small></p>
      <div class="actions"><button disabled={busy} type="button" onclick={() => void save(suggestion!.name)}>Confirm name</button><button disabled={busy} type="button" onclick={edit}>Edit name</button><button disabled={busy} type="button" onclick={() => dismissed = suggestion!.name}>Later</button></div>
      <small>Confirming a name does not approve network access.</small>
    {:else}
      <button type="button" onclick={edit}>{device.owner_confirmed ? 'Edit name' : 'Name this device'}</button>
    {/if}
    {#if error}<p role="alert">{error}</p>{/if}
  </div>
{/if}
<style>
  .name-confirmation{padding-top:12px;border-top:1px solid var(--line);overflow-wrap:anywhere}p{margin:0 0 9px;font-size:13px}small{display:block;color:var(--muted-strong);font-size:11px;line-height:1.5;margin-top:6px}.actions,form{display:flex;gap:8px;flex-wrap:wrap;align-items:end}label{display:grid;gap:6px;flex:1;min-width:160px;font-size:12px}input{min-width:0;width:100%;box-sizing:border-box;min-height:40px;padding:8px;color:var(--ink);background:var(--surface);border:1px solid var(--line-strong);border-radius:6px}button{min-height:38px;padding:8px 12px;color:var(--ink);background:var(--surface);border:1px solid var(--line-strong);border-radius:6px;cursor:pointer}.actions button:first-child,button[type=submit]{border-color:var(--accent)}button:disabled{opacity:.5;cursor:wait}[role=alert]{color:var(--pink);margin-top:10px}
</style>
