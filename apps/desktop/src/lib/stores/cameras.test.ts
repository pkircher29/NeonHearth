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

import { addCameraError, removeCameraError } from './cameras';
import { ApiError } from '../api/client';

describe('adding and removing a camera', () => {
  const input = { address: '192.168.1.50', username: 'admin', password: 'sup3r-secret!' };
  const added = { camera_id: cameraId, name: null, streams: [{ stream_id: streamId }] };

  it('adds, selects the new camera and reloads the list', async () => {
    const newer = { ...item, camera_id: '018f47a0-9b5c-7a22-8a33-112233445588' };
    const cameras = vi.fn().mockResolvedValueOnce({ items: [item], next_after: null }).mockResolvedValue({ items: [item, newer], next_after: null });
    const camera = vi.fn(async (id: string) => (id === newer.camera_id ? newer : item));
    const addCamera = vi.fn(async () => ({ ...added, camera_id: newer.camera_id }));
    const store = createCameraStore(clientStub({ cameras, camera: camera as unknown as ApiClient['camera'], addCamera: addCamera as unknown as ApiClient['addCamera'] }));
    await store.load();
    await expect(store.add(input)).resolves.toBe(true);
    expect(addCamera).toHaveBeenCalledWith(input);
    expect(store.state.items.map((entry) => entry.camera_id)).toEqual([cameraId, newer.camera_id]);
    expect(store.state.selected).toBe(newer.camera_id);
    expect(store.state.adding).toBe(false);
    expect(store.state.addError).toBeNull();
    expect(JSON.stringify(store.state)).not.toContain('sup3r-secret!');
  });

  it('keeps a failure plain, never holds the password, and allows another try', async () => {
    const addCamera = vi.fn().mockRejectedValueOnce(new ApiError(422, 'sign_in_refused')).mockResolvedValue(added);
    const store = createCameraStore(clientStub({ addCamera: addCamera as unknown as ApiClient['addCamera'] }));
    await expect(store.add(input)).resolves.toBe(false);
    expect(store.state.addError).toMatch(/refused that user name or password/i);
    expect(store.state.adding).toBe(false);
    expect(JSON.stringify(store.state)).not.toContain('sup3r-secret!');
    await expect(store.add(input)).resolves.toBe(true);
    expect(store.state.addError).toBeNull();
  });

  it('ignores a second add while one is in flight', async () => {
    let finish: (value: typeof added) => void = () => undefined;
    const addCamera = vi.fn(() => new Promise<typeof added>((resolve) => { finish = resolve; }));
    const store = createCameraStore(clientStub({ addCamera: addCamera as unknown as ApiClient['addCamera'] }));
    const first = store.add(input);
    expect(store.state.adding).toBe(true);
    await expect(store.add(input)).resolves.toBe(false);
    finish(added);
    await expect(first).resolves.toBe(true);
    expect(addCamera).toHaveBeenCalledTimes(1);
  });

  it('removes a camera, clears the selection and reloads the list', async () => {
    const cameras = vi.fn().mockResolvedValueOnce({ items: [item], next_after: null }).mockResolvedValue({ items: [], next_after: null });
    const removeCamera = vi.fn(async () => undefined);
    const store = createCameraStore(clientStub({ cameras, removeCamera: removeCamera as unknown as ApiClient['removeCamera'] }));
    await store.load();
    expect(store.state.selected).toBe(cameraId);
    await expect(store.remove(cameraId)).resolves.toBe(true);
    expect(removeCamera).toHaveBeenCalledWith(cameraId);
    expect(store.state.items).toEqual([]);
    expect(store.state.selected).toBeNull();
    expect(store.state.removing).toBeNull();
  });

  it('closes a live view of the camera before removing it, and reports a failed removal plainly', async () => {
    const closeCameraSession = vi.fn(async () => undefined);
    const removeCamera = vi.fn(async () => { throw new ApiError(503, 'incomplete'); });
    const store = createCameraStore(clientStub({ closeCameraSession, removeCamera: removeCamera as unknown as ApiClient['removeCamera'] }));
    await store.load();
    await store.startSession(cameraId, streamId);
    expect(store.state.session).not.toBeNull();
    await expect(store.remove(cameraId)).resolves.toBe(false);
    expect(closeCameraSession).toHaveBeenCalledWith(sessionId);
    expect(store.state.removeError).toMatch(/some of its stored data could not be removed yet/i);
    expect(store.state.items).toHaveLength(1);
    expect(store.state.removing).toBeNull();
  });

  it('has a plain sentence for every way adding can fail', () => {
    const cases: Array<[unknown, RegExp]> = [
      [new ApiError(422, 'not_on_your_network'), /not on your network/i], [new ApiError(502, 'unreachable'), /could not reach the camera/i],
      [new ApiError(422, 'sign_in_refused'), /refused that user name or password/i], [new ApiError(422, 'streams_elsewhere'), /points its video somewhere else/i],
      [new ApiError(422, 'unexpected_answer'), /did not answer like a camera/i], [new ApiError(422, 'onvif_not_enabled'), /ONVIF does not appear to be enabled.*Turn ONVIF on/i], [new ApiError(422, 'no_streams'), /no video stream/i],
      [new ApiError(409, 'already_added'), /already added/i], [new ApiError(429, 'rate_limited'), /too many tries/i], [new ApiError(400, 'invalid_request'), /check the address/i],
      [new ApiError(503, 'video_unavailable', 'ffmpeg_not_found', 'Install ffmpeg.'), /Video support is not available: Install ffmpeg\./],
      [new ApiError(503, 'video_unavailable', 'ffmpeg_not_found', null), /Video support is not available: Live view is off because ffmpeg is not installed/],
      [new ApiError(503, 'video_unavailable'), /Video support is not available: it is off on this machine/],
      [new Error('Request failed with status 429'), /too many tries/i], [new Error('Request failed with status 503'), /could not be saved/i], [new Error('boom'), /could not be added/i]
    ];
    for (const [error, message] of cases) expect(addCameraError(error)).toMatch(message);
    expect(removeCameraError(new Error('Request failed with status 404'))).toMatch(/already gone/i);
    expect(removeCameraError(new ApiError(503, 'incomplete'))).toMatch(/remove it again/i);
    expect(removeCameraError(new Error('boom'))).toMatch(/could not be removed/i);
  });
});
