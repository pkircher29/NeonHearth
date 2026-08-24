<script lang="ts">
  import { onMount } from 'svelte';
  import Hls from 'hls.js';

  let { playlistUrl, authorize }: { playlistUrl: string; authorize: (xhr: XMLHttpRequest, url: string) => boolean } = $props();
  let video = $state(null as HTMLVideoElement | null);
  let playerStatus = $state<'ready' | 'unsupported' | 'failed'>('ready');
  onMount(() => {
    const media = video; if (!media) return;
    let hls: Hls | null = null;
    if (Hls.isSupported()) {
      hls = new Hls({ xhrSetup: (xhr, url) => { authorize(xhr, url); } });
      hls.on(Hls.Events.ERROR, (_event, data) => { if (data.fatal) playerStatus = 'failed'; });
      hls.loadSource(playlistUrl); hls.attachMedia(media);
    } else if (media.canPlayType('application/vnd.apple.mpegurl')) media.src = playlistUrl;
    else playerStatus = 'unsupported';
    return () => { hls?.destroy(); media.removeAttribute('src'); };
  });
</script>

{#if playerStatus === 'ready'}<video bind:this={video} controls autoplay muted aria-label="Live camera view"><track kind="captions" /></video>{:else if playerStatus === 'unsupported'}<div class="live-fallback" role="status"><span aria-hidden="true">◌</span><strong>Live video is not supported in this browser</strong><p>Use Capture snapshot instead.</p></div>{:else}<div class="live-fallback" role="alert"><span aria-hidden="true">△</span><strong>Live video stopped unexpectedly</strong><p>Close it, then try again or capture a snapshot.</p></div>{/if}
