import type { ApiClient } from '../api/client';
import type { CameraDetail } from '../api/types';

export type CameraItem = CameraDetail & { streams?: Array<{ stream_id: string; label?: string }> };
export interface CameraSession { cameraId: string; streamId: string; sessionId: string; playlistUrl: string }
export interface CamerasState { loading: boolean; error: string | null; items: CameraItem[]; selected: string | null; session: CameraSession | null; snapshotUrl: string | null }
type ObjectUrlApi = Pick<typeof URL, 'createObjectURL' | 'revokeObjectURL'>;

export function cameraError(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (/status 404\b/.test(message)) return 'This camera is no longer available. Refresh the camera list and try again.';
  if (/status 429\b/.test(message)) return 'The collector is busy. Try again shortly.';
  if (/status 503\b/.test(message)) return 'Collector is unavailable. Check the local service, then try again.';
  return 'Camera data is unavailable right now. Try again shortly.';
}

export function createCameraStore(client: ApiClient, urls: ObjectUrlApi = URL) {
  let state: CamerasState = { loading: false, error: null, items: [], selected: null, session: null, snapshotUrl: null };
  const listeners = new Set<(next: CamerasState) => void>(); let request = 0; let disposed = false;
  const publish = () => listeners.forEach((listener) => listener(state));
  const update = (next: Partial<CamerasState>) => { state = { ...state, ...next }; publish(); };
  const close = async (session = state.session) => {
    if (!session) return;
    if (state.session?.sessionId === session.sessionId) update({ session: null });
    try { await client.closeCameraSession(session.sessionId); } catch { /* Service expiry is safe to treat as closed locally. */ }
  };
  return {
    get state() { return state; },
    subscribe(listener: (next: CamerasState) => void) { listeners.add(listener); listener(state); return () => listeners.delete(listener); },
    async select(cameraId: string | null) {
      request += 1;
      const priorSession = state.session;
      const snapshotUrl = state.snapshotUrl;
      update({ selected: cameraId, session: null, snapshotUrl: null, error: null });
      if (snapshotUrl) urls.revokeObjectURL(snapshotUrl);
      await close(priorSession);
    },
    async load() {
      const token = ++request; update({ loading: true, error: null });
      try {
        const page = await client.cameras();
        const items = await Promise.all(page.items.map((item) => client.camera(item.camera_id))) as CameraItem[];
        if (disposed || token !== request) return;
        update({ items, selected: state.selected && items.some((item) => item.camera_id === state.selected) ? state.selected : items[0]?.camera_id ?? null });
      } catch (error) { if (!disposed && token === request) update({ items: [], selected: null, error: cameraError(error) }); }
      finally { if (!disposed && token === request) update({ loading: false }); }
    },
    async snapshot(cameraId: string, streamId?: string) {
      const token = ++request;
      try {
        const blob = await client.cameraSnapshot(cameraId, streamId);
        if (disposed || token !== request) return;
        const snapshotUrl = urls.createObjectURL(blob);
        if (state.snapshotUrl) urls.revokeObjectURL(state.snapshotUrl);
        update({ snapshotUrl, error: null });
      } catch (error) { if (!disposed && token === request) update({ error: cameraError(error) }); }
    },
    async startSession(cameraId: string, streamId: string) {
      const token = ++request;
      await close();
      try {
        const response = await client.startCameraSession(cameraId, streamId);
        const session = { cameraId, streamId, sessionId: response.session_id, playlistUrl: `/api/v1/camera-sessions/${response.session_id}/playlist.m3u8` };
        if (disposed || token !== request || state.selected !== cameraId) { await close(session); return; }
        update({ session, error: null });
      } catch (error) { if (!disposed && token === request) update({ error: cameraError(error) }); }
    },
    closeSession: close,
    async dispose() { disposed = true; request += 1; if (state.snapshotUrl) urls.revokeObjectURL(state.snapshotUrl); update({ snapshotUrl: null }); await close(); listeners.clear(); }
  };
}
