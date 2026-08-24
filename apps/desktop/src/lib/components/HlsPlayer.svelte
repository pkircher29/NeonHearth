<script lang="ts">
  import { onMount } from 'svelte';

  let { playlistUrl, authorize }: { playlistUrl: string; authorize: (xhr: XMLHttpRequest, url: string) => void } = $props();
  let video = $state(null as HTMLVideoElement | null);
  let playerStatus = $state<'loading' | 'ready' | 'unsupported' | 'failed'>('loading');
  onMount(() => {
    const media = video; if (!media) return;
    let cancelled = false; let hls: { destroy(): void } | null = null;
    void import('hls.js/light').then(({ default: Hls }) => {
      if (cancelled) return;
      if (!Hls.isSupported()) { playerStatus = 'unsupported'; return; }
      const instance = new Hls({ xhrSetup: (xhr: XMLHttpRequest, url: string) => authorize(xhr, url) });
      hls = instance;
      instance.on(Hls.Events.ERROR, (_event: string, data: { fatal: boolean }) => { if (data.fatal) playerStatus = 'failed'; });
      instance.loadSource(playlistUrl); instance.attachMedia(media); playerStatus = 'ready';
    }).catch(() => { if (!cancelled) playerStatus = 'failed'; });
    return () => { cancelled = true; hls?.destroy(); media.removeAttribute('src'); };
  });
</script>

{#if playerStatus === 'unsupported'}<div class="live-fallback" role="status"><span aria-hidden="true">◌</span><strong>Live video is not supported in this browser</strong><p>Use Capture snapshot instead.</p></div>{:else if playerStatus === 'failed'}<div class="live-fallback" role="alert"><span aria-hidden="true">△</span><strong>Live video stopped unexpectedly</strong><p>Close it, then try again or capture a snapshot.</p></div>{:else}<video bind:this={video} controls autoplay muted aria-label="Live camera view"><track kind="captions" /></video>{#if playerStatus === 'loading'}<p class="live-loading" role="status">Preparing live video…</p>{/if}{/if}
