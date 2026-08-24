// @vitest-environment jsdom
import { render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';

let fatal: ((event: string, data: { fatal: boolean }) => void) | undefined;
const destroy = vi.fn(); const loadSource = vi.fn(); const attachMedia = vi.fn();
vi.mock('hls.js', () => ({ default: class { static isSupported = () => true; static Events = { ERROR: 'error' }; constructor(_config: unknown) {} on(_event: string, callback: typeof fatal) { fatal = callback; } loadSource = loadSource; attachMedia = attachMedia; destroy = destroy; } }));
import HlsPlayer from './HlsPlayer.svelte';

describe('HlsPlayer MSE', () => {
  it('starts MSE playback, reports fatal errors, and destroys it on unmount', async () => {
    const view = render(HlsPlayer, { playlistUrl: '/api/v1/camera-sessions/018f47a0-9b5c-7a22-8a33-112233445500/playlist.m3u8', authorize: vi.fn(() => true) });
    expect(loadSource).toHaveBeenCalledTimes(1); expect(attachMedia).toHaveBeenCalledTimes(1);
    fatal?.('error', { fatal: true });
    expect(await screen.findByText(/Live video stopped unexpectedly/i)).toBeTruthy();
    view.unmount(); expect(destroy).toHaveBeenCalledTimes(1);
  });
});
