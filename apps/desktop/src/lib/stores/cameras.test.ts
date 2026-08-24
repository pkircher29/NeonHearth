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
});
