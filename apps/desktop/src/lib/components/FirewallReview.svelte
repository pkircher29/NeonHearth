<script lang="ts">
  import {onMount} from 'svelte';
  let {name,path,direction,blocked,busy,onconfirm,oncancel}: {name:string;path:string|null;direction:string;blocked:boolean;busy:boolean;onconfirm:()=>void;oncancel:()=>void}=$props();
  let dialog:HTMLDialogElement;let cancel:HTMLButtonElement;
  onMount(()=>{dialog.showModal();cancel.focus();return()=>dialog.close();});
</script>
<dialog bind:this={dialog} oncancel={event=>{event.preventDefault();if(!busy)oncancel();}} aria-labelledby="firewall-review-title">
  <h2 id="firewall-review-title">{blocked?'Block':'Release'} {direction} traffic for {name}?</h2><p class="path">{path}</p><p>{blocked?'This changes Windows Firewall for every process using this executable.':"This removes the matching NeonHearth rule. Other Windows firewall rules remain in force."}</p><div><button disabled={busy} onclick={onconfirm}>{busy?'Applying…':'Confirm firewall change'}</button><button bind:this={cancel} disabled={busy} onclick={oncancel}>Cancel</button></div>
</dialog>
<style>
  dialog{width:min(600px,calc(100vw - 48px));max-height:85vh;box-sizing:border-box;padding:24px;background:var(--surface);color:var(--ink);border:2px solid var(--gold);border-radius:12px}dialog::backdrop{background:#000a}h2{font-size:18px;overflow-wrap:anywhere}p{font-size:13px;line-height:1.6}.path{overflow-wrap:anywhere;font:11px var(--font-mono);color:var(--muted-strong)}div{display:flex;gap:10px;flex-wrap:wrap}button{min-height:42px;padding:8px 12px;background:var(--surface);color:var(--ink);border:1px solid var(--line-strong);border-radius:6px;cursor:pointer}button:disabled{opacity:.5}
</style>
