// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import type { ApiClient } from '../api/client';
import CamerasView from './CamerasView.svelte';

const id = '018f47a0-9b5c-7a22-8a33-112233445599';
const detail = { camera_id: id, classification: 'camera', confidence: .91, health: 'healthy', observed_at: '2026-01-01T00:00:00Z', inventory: { manufacturer: 'Luma', model: 'Porch', firmware: '1.2', serial: 'OWNER-4', capabilities: ['snapshot'], health: 'healthy' }, streams: [] };
function clientStub(overrides: Partial<ApiClient> = {}) { return { cameras: vi.fn(async () => ({ items: [detail], next_after: null })), camera: vi.fn(async () => detail), cameraSnapshot: vi.fn(async () => new Blob(['safe'], { type: 'image/jpeg' })), ...overrides } as unknown as ApiClient; }

describe('CamerasView', () => {
  it('renders a safe camera card with confidence, health, inventory and a snapshot action', async () => {
    render(CamerasView, { client: clientStub() });
    expect(await screen.findByRole('heading', { name: 'Watch the threshold.' })).toBeTruthy();
    expect(screen.getAllByText('91% confident')).toHaveLength(2);
    expect(screen.getAllByText('Healthy')).toHaveLength(3);
    expect(screen.getAllByText('Luma Porch')).toHaveLength(2);
    const snapshot = screen.getByRole('button', { name: /capture snapshot/i });
    expect(snapshot.tabIndex).toBe(0);
    await fireEvent.click(snapshot);
    expect(screen.getByAltText('Latest camera snapshot')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/rtsp|192\.168|aa:bb|password/i);
  });

  it.each([[404, /No longer available/i], [429, /Try again shortly/i], [503, /Collector is unavailable/i]])('shows actionable %s status', async (status, message) => {
    render(CamerasView, { client: clientStub({ cameras: vi.fn(async () => { throw new Error(`Request failed with status ${status}`); }) }) });
    expect(await screen.findByText(message)).toBeTruthy();
  });

  it('offers a retry on failure that reloads the list (M-28)', async () => {
    const cameras = vi.fn().mockRejectedValueOnce(new Error('Request failed with status 503')).mockResolvedValue({ items: [detail], next_after: null });
    render(CamerasView, { client: clientStub({ cameras }) });
    expect(await screen.findByText(/Collector is unavailable/i)).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findAllByText('Luma Porch')).toHaveLength(2);
    expect(cameras).toHaveBeenCalledTimes(2);
  });

  it('shows the readable cameras with a count of the unreadable ones', async () => {
    const other = '018f47a0-9b5c-7a22-8a33-112233445588';
    const client = clientStub({
      cameras: vi.fn(async () => ({ items: [detail, { ...detail, camera_id: other }], next_after: null })),
      camera: vi.fn(async (cameraId: string) => { if (cameraId === other) throw new Error('Request failed with status 404'); return detail; })
    });
    render(CamerasView, { client });
    expect(await screen.findByText(/1 camera could not be read this time/)).toBeTruthy();
    expect(screen.getAllByText('Luma Porch')).toHaveLength(2);
  });

  it('uses an honest live fallback and a mobile-safe grid', async () => {
    const view = render(CamerasView, { client: clientStub() });
    expect(await screen.findByText(/Live view needs a stream selected/i)).toBeTruthy();
    expect(view.container.querySelector('.camera-grid')).toBeTruthy();
    expect(view.container.querySelector('.camera-actions button')?.className).toBeTruthy();
  });
});
