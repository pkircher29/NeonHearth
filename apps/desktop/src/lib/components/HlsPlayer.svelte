<script lang="ts">
  import { onMount } from 'svelte';

  let { playlistUrl, authorize }: { playlistUrl: string; authorize: (xhr: XMLHttpRequest, url: string) => void } = $props();
  let video = $state(null as HTMLVideoElement | null);
  const STARTUP_GRACE_MS = 30_000; const STARTUP_RETRY_MS = 1_500;
  let playerStatus = $state<'loading' | 'ready' | 'unsupported' | 'failed'>('loading');
  onMount(() => {
    const media = video; if (!media) return;
    let cancelled = false; let hls: { destroy(): void } | null = null; let retry: ReturnType<typeof setTimeout> | undefined;
    void import('hls.js/light').then(({ default: Hls }) => {
      if (cancelled) return;
      if (!Hls.isSupported()) { playerStatus = 'unsupported'; return; }
      const instance = new Hls({ xhrSetup: (xhr: XMLHttpRequest, url: string) => authorize(xhr, url) });
      hls = instance;
      // The collector answers 404 for the playlist until ffmpeg has written the
      // first segment (a few seconds). That is the stream starting, not failing:
      // keep asking for a bounded time before reporting a failure.
      const startedAt = Date.now(); let playing = false;
      instance.on(Hls.Events.FRAG_LOADED, () => { playing = true; });
      instance.on(Hls.Events.ERROR, (_event: string, data: { fatal: boolean; type?: string }) => {
        if (!data.fatal) return;
        if (!playing && data.type === 'networkError' && Date.now() - startedAt < STARTUP_GRACE_MS) {
          retry = setTimeout(() => { if (!cancelled) instance.loadSource(playlistUrl); }, STARTUP_RETRY_MS);
          return;
        }
        playerStatus = 'failed';
      });
      instance.loadSource(playlistUrl); instance.attachMedia(media); playerStatus = 'ready';
    }).catch(() => { if (!cancelled) playerStatus = 'failed'; });
    return () => { cancelled = true; clearTimeout(retry); hls?.destroy(); media.removeAttribute('src'); };
  });
</script>

{#if playerStatus === 'unsupported'}<div class="live-fallback" role="status"><span aria-hidden="true">◌</span><strong>Live video is not supported in this browser</strong><p>Use Capture snapshot instead.</p></div>{:else if playerStatus === 'failed'}<div class="live-fallback" role="alert"><span aria-hidden="true">△</span><strong>Live video stopped unexpectedly</strong><p>Close it, then try again or capture a snapshot.</p></div>{:else}<video bind:this={video} controls autoplay muted aria-label="Live camera view"><track kind="captions" /></video>{#if playerStatus === 'loading'}<p class="live-loading" role="status">Preparing live video…</p>{/if}{/if}
<style>
  video { display: block; width: 100%; height: 100%; max-height: 420px; object-fit: contain; background: var(--ground); }
  .live-fallback { max-width: 330px; padding: 22px; text-align: center; }
  .live-fallback span { display: block; margin-bottom: 11px; color: var(--ink-mute); font-size: 34px; }
  .live-fallback strong { display: block; color: var(--ink); }
  .live-fallback p { margin: 0; color: var(--ink-mute); font-size: 12.5px; line-height: 1.5; }
  .live-loading { margin: 6px 0 0; color: var(--ink-mute); font: 400 11px var(--font-mono); }
</style>
