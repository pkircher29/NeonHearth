// @vitest-environment jsdom
import { render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import HlsPlayer from './HlsPlayer.svelte';

const playlist = '/api/v1/camera-sessions/018f47a0-9b5c-7a22-8a33-112233445500/playlist.m3u8';
describe('HlsPlayer', () => {
  it('shows a safe unsupported state when MSE is unavailable', async () => {
    render(HlsPlayer, { playlistUrl: playlist, authorize: vi.fn(() => false) });
    expect(await screen.findByText(/Live video is not supported/i)).toBeTruthy();
    expect(screen.queryByText(playlist)).toBeNull();
  });
});
