import { describe, expect, it, vi } from 'vitest';
import type { ApiClient } from '../api/client';
import { createCameraStore } from './cameras';

const cameraId = '018f47a0-9b5c-7a22-8a33-112233445599';
const streamId = '018f47a0-9b5c-4a22-8a33-112233445599';
const sessionId = '018f47a0-9b5c-7a22-8a33-112233445500';
const item = { camera_id: cameraId, classification: 'camera', confidence: .91, health: 'healthy', observed_at: '2026-01-01T00:00:00Z', inventory: { manufacturer: 'Luma', model: 'Porch', firmware: '1.2', serial: 'OWNER-4', capabilities: ['snapshot'], health: 'healthy' } } as const;
function clientStub(overrides: Partial<ApiClient> = {}) { return { cameras: vi.fn(async () => ({ items: [item], next_after: null })), camera: vi.fn(async () => item), cameraSnapshot: vi.fn(async () => new Blob(['safe'], { type: 'image/jpeg' })), startCameraSession: vi.fn(async () => ({ session_id: sessionId })), closeCameraSession: vi.fn(async () => undefined), ...overrides } as unknown as ApiClient; }

describe('createCameraStore', () => {
  it('loads sanitized camera details and keeps only opaque IDs', async () => {
    const store = createCameraStore(clientStub());
    await store.load();
    expect(store.state.items).toEqual([item]);
    expect(JSON.stringify(store.state)).not.toMatch(/rtsp|192\.168|aa:bb|password/i);
    expect(store.state.loading).toBe(false);
  });

  it('turns service failures into an actionable safe status', async () => {
    const store = createCameraStore(clientStub({ cameras: vi.fn(async () => { throw new Error('Request failed with status 429'); }) }));
    await store.load();
    expect(store.state.error).toMatch(/Try again shortly/i);
    expect(store.state.items).toEqual([]);
  });

  it('keeps the readable cameras when one detail fetch fails and counts the rest (M-28)', async () => {
    const other = { ...item, camera_id: '018f47a0-9b5c-7a22-8a33-112233445588' };
    const client = clientStub({
      cameras: vi.fn(async () => ({ items: [item, other], next_after: null })),
      camera: vi.fn(async (id: string) => { if (id === other.camera_id) throw new Error('Request failed with status 404'); return item; }) as unknown as ApiClient['camera']
    });
    const store = createCameraStore(client);
    await store.load();
    expect(store.state.items).toEqual([item]);
    expect(store.state.unreadable).toBe(1);
    expect(store.state.error).toBeNull();
    expect(store.state.selected).toBe(cameraId);
  });

  it('reports an error only when every camera detail fails, and a retry recovers', async () => {
    const camera = vi.fn<() => Promise<unknown>>(async () => { throw new Error('Request failed with status 503'); });
    const store = createCameraStore(clientStub({ camera: camera as unknown as ApiClient['camera'] }));
    await store.load();
    expect(store.state.items).toEqual([]);
    expect(store.state.error).toMatch(/Collector is unavailable/);
    camera.mockImplementation(async () => item);
    await store.load();
    expect(store.state.items).toEqual([item]);
    expect(store.state.error).toBeNull();
    expect(store.state.unreadable).toBe(0);
  });

  it('revokes a replaced snapshot and closes its session during disposal', async () => {
    const revoke = vi.fn(); const client = clientStub();
    const store = createCameraStore(client, { createObjectURL: vi.fn(() => 'blob:still'), revokeObjectURL: revoke });
    await store.load();
    await store.snapshot(cameraId);
    await store.snapshot(cameraId);
    await store.startSession(cameraId, streamId);
    await store.dispose();
    expect(revoke).toHaveBeenCalledTimes(2);
    expect(client.closeCameraSession).toHaveBeenCalledWith(sessionId);
  });

  it('ignores a late session start after selection changes', async () => {
    let resolve!: (value: { session_id: string }) => void;
    const client = clientStub({ startCameraSession: vi.fn(() => new Promise<{ session_id: string }>((done) => { resolve = done; })) });
    const store = createCameraStore(client);
    await store.load();
    const starting = store.startSession(cameraId, streamId);
    await Promise.resolve();
    store.select(null);
    resolve({ session_id: sessionId });
    await starting;
    expect(store.state.session).toBeNull();
    expect(client.closeCameraSession).toHaveBeenCalledWith(sessionId);
  });

  it('closes the prior live session and revokes its still before selecting another camera', async () => {
    const other = '018f47a0-9b5c-7a22-8a33-112233445588'; const revoke = vi.fn(); const client = clientStub();
    const store = createCameraStore(client, { createObjectURL: vi.fn(() => 'blob:still'), revokeObjectURL: revoke });
    await store.load(); await store.snapshot(cameraId); await store.startSession(cameraId, streamId);
    await store.select(other);
    expect(store.state.selected).toBe(other);
    expect(store.state.session).toBeNull(); expect(store.state.snapshotUrl).toBeNull();
    expect(revoke).toHaveBeenCalledWith('blob:still'); expect(client.closeCameraSession).toHaveBeenCalledWith(sessionId);
  });

  it('keeps cleanup idempotent when session closing fails', async () => {
    const client = clientStub({ closeCameraSession: vi.fn(async () => { throw new Error('Request failed with status 503'); }) });
    const store = createCameraStore(client); await store.load(); await store.startSession(cameraId, streamId);
    await store.closeSession(); await store.closeSession(); await store.dispose();
    expect(store.state.session).toBeNull(); expect(client.closeCameraSession).toHaveBeenCalledTimes(1);
  });

  it('a snapshot or live-view request does not strand the camera list in the loading state', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const client = clientStub({ cameras: vi.fn(async () => { await gate; return { items: [item], next_after: null }; }) });
    const store = createCameraStore(client);
    const loading = store.load();
    expect(store.state.loading).toBe(true);
    void store.snapshot(cameraId);
    void store.startSession(cameraId, streamId);
    release();
    await loading;
    expect(store.state.loading).toBe(false);
    expect(store.state.items).toEqual([item]);
  });

  it('selecting another camera drops a snapshot still in flight for the previous one', async () => {
    let finish!: (blob: Blob) => void;
    const client = clientStub({ cameraSnapshot: vi.fn(() => new Promise<Blob>((resolve) => { finish = resolve; })) as never });
    const urls = { createObjectURL: vi.fn(() => 'blob:x'), revokeObjectURL: vi.fn() };
    const store = createCameraStore(client, urls);
    await store.load();
    const pending = store.snapshot(cameraId);
    await store.select(null);
    finish(new Blob(['x']));
    await pending;
    expect(urls.createObjectURL).not.toHaveBeenCalled();
    expect(store.state.snapshotUrl).toBeNull();
  });
});

import { cameraError, describeCameraMedia } from './cameras';
const off = { enabled: false, reason: 'ffmpeg_not_found', detail: 'ffmpeg was expected at C:\Program Files\NeonHearth\ffmpeg.exe but is not there. Install it.', setup_available: false, setup_detail: 'No camera can be added yet.' };

describe('camera media status', () => {
  it('explains a missing ffmpeg in plain words and says nothing while media runs', () => {
    expect(describeCameraMedia(null)).toBeNull();
    expect(describeCameraMedia({ ...off, enabled: true, reason: 'ready' })).toBeNull();
    const described = describeCameraMedia(off);
    expect(described?.title).toMatch(/ffmpeg is not installed/i);
    expect(described?.action).toBe(off.detail);
    expect(describeCameraMedia({ ...off, reason: 'something_new' })?.title).toMatch(/off on this machine/i);
  });

  it('turns a 503 into the specific reason when media is off, and keeps the generic text otherwise', () => {
    const failure = new Error('Request failed with status 503');
    expect(cameraError(failure, off)).toMatch(/ffmpeg is not installed.*Install it/i);
    expect(cameraError(failure)).toMatch(/Collector is unavailable/);
    expect(cameraError(failure, { ...off, enabled: true, reason: 'ready' })).toMatch(/Collector is unavailable/);
  });

  it('loads the status beside the cameras and tolerates a service without the route', async () => {
    const withRoute = createCameraStore(clientStub({ cameraMedia: vi.fn(async () => off) as unknown as ApiClient['cameraMedia'] }));
    await withRoute.load();
    await vi.waitFor(() => expect(withRoute.state.media).toEqual(off));
    const without = createCameraStore(clientStub());
    await without.load();
    expect(without.state.media).toBeNull();
    expect(without.state.items).toEqual([item]);
  });

  it('shows the specific reason when a snapshot is refused because media is off', async () => {
    const store = createCameraStore(clientStub({
      cameraMedia: vi.fn(async () => off) as unknown as ApiClient['cameraMedia'],
      cameraSnapshot: vi.fn(async () => { throw new Error('Request failed with status 503'); }) as unknown as ApiClient['cameraSnapshot']
    }));
    await store.load();
    await vi.waitFor(() => expect(store.state.media).toEqual(off));
    await store.snapshot(cameraId);
    expect(store.state.error).toMatch(/ffmpeg is not installed/i);
  });
});
