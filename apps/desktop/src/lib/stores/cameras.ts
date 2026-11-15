import type { ApiClient } from '../api/client';
import type { CameraDetail, CameraMediaStatus } from '../api/types';

export type CameraItem = CameraDetail & { streams?: Array<{ stream_id: string; label?: string }> };
export interface CameraSession { cameraId: string; streamId: string; sessionId: string; playlistUrl: string }
export interface CamerasState {
  loading: boolean;
  error: string | null;
  items: CameraItem[];
  /** Cameras the list named but whose detail could not be read this load (audit M-28). */
  unreadable: number;
  selected: string | null;
  session: CameraSession | null;
  snapshotUrl: string | null;
  /** Whether live view and snapshots run on this machine (null until known, or when the service predates the route). */
  media: CameraMediaStatus | null;
}
type ObjectUrlApi = Pick<typeof URL, 'createObjectURL' | 'revokeObjectURL'>;

const mediaTitles: Record<string, string> = {
  ffmpeg_not_found: 'Live view is off because ffmpeg is not installed',
  ffmpeg_not_executable: 'Live view is off because ffmpeg cannot be run',
  vault_unavailable: 'Live view is off because the camera password store is unavailable',
  unsupported_platform: 'Live view is not supported on this operating system',
  output_dir_unavailable: 'Live view is off because its temporary video folder cannot be used',
  not_configured: 'Live view is not part of this build'
};

/** Plain-words explanation of why camera media is off, with what the owner can do; null while it is running. */
export function describeCameraMedia(media: CameraMediaStatus | null): { title: string; action: string } | null {
  if (!media || media.enabled) return null;
  return {
    title: mediaTitles[media.reason] ?? 'Live view is off on this machine',
    action: media.detail || 'Check the NeonHearth service log for the reason, fix it, and restart the service.'
  };
}

export function cameraError(error: unknown, media: CameraMediaStatus | null = null): string {
  const message = error instanceof Error ? error.message : '';
  if (/status 404\b/.test(message)) return 'This camera is no longer available. Refresh the camera list and try again.';
  if (/status 429\b/.test(message)) return 'The collector is busy. Try again shortly.';
  const off = /status 503\b/.test(message) ? describeCameraMedia(media) : null;
  if (off) return `${off.title}. ${off.action}`;
  if (/status 503\b/.test(message)) return 'Collector is unavailable. Check the local service, then try again.';
  return 'Camera data is unavailable right now. Try again shortly.';
}

export function createCameraStore(client: ApiClient, urls: ObjectUrlApi = URL) {
  let state: CamerasState = { loading: false, error: null, items: [], unreadable: 0, selected: null, session: null, snapshotUrl: null, media: null };
  const listeners = new Set<(next: CamerasState) => void>(); let disposed = false;
  // One counter per operation: a snapshot or live-view request must never invalidate the camera-list load (which left `loading` stuck on).
  let loadRequest = 0; let snapshotRequest = 0; let sessionRequest = 0; let selection = 0;
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
      selection += 1; snapshotRequest += 1; sessionRequest += 1; // a different camera: anything in flight for the old one is moot
      const priorSession = state.session;
      const snapshotUrl = state.snapshotUrl;
      update({ selected: cameraId, session: null, snapshotUrl: null, error: null });
      if (snapshotUrl) urls.revokeObjectURL(snapshotUrl);
      await close(priorSession);
    },
    async load() {
      const token = ++loadRequest; update({ loading: true, error: null });
      // Best effort and independent of the camera list: an older service has no such route.
      const mediaRequest = typeof client.cameraMedia === 'function' ? client.cameraMedia().catch(() => null) : Promise.resolve(null);
      void mediaRequest.then((media) => { if (!disposed && token === loadRequest) update({ media }); });
      try {
        const page = await client.cameras();
        // One unreadable camera must not empty the list: keep every detail
        // that resolved and report how many did not.
        const results = await Promise.allSettled(page.items.map((item) => client.camera(item.camera_id)));
        if (disposed || token !== loadRequest) return;
        const items = results.flatMap((result) => (result.status === 'fulfilled' ? [result.value as CameraItem] : []));
        const failures = results.filter((result) => result.status === 'rejected');
        if (items.length === 0 && failures.length > 0) {
          update({ items: [], unreadable: failures.length, selected: null, error: cameraError(failures[0]!.reason) });
          return;
        }
        update({ items, unreadable: failures.length, selected: state.selected && items.some((item) => item.camera_id === state.selected) ? state.selected : items[0]?.camera_id ?? null });
      } catch (error) { if (!disposed && token === loadRequest) update({ items: [], unreadable: 0, selected: null, error: cameraError(error) }); }
      finally { if (!disposed && token === loadRequest) update({ loading: false }); }
    },
    async snapshot(cameraId: string, streamId?: string) {
      const token = ++snapshotRequest;
      try {
        const blob = await client.cameraSnapshot(cameraId, streamId);
        if (disposed || token !== snapshotRequest) return;
        const snapshotUrl = urls.createObjectURL(blob);
        if (state.snapshotUrl) urls.revokeObjectURL(state.snapshotUrl);
        update({ snapshotUrl, error: null });
      } catch (error) { if (!disposed && token === snapshotRequest) update({ error: cameraError(error, state.media) }); }
    },
    async startSession(cameraId: string, streamId: string) {
      const token = ++sessionRequest;
      await close();
      try {
        const response = await client.startCameraSession(cameraId, streamId);
        const session = { cameraId, streamId, sessionId: response.session_id, playlistUrl: `/api/v1/camera-sessions/${response.session_id}/playlist.m3u8` };
        if (disposed || token !== sessionRequest || state.selected !== cameraId) { await close(session); return; }
        update({ session, error: null });
      } catch (error) { if (!disposed && token === sessionRequest) update({ error: cameraError(error, state.media) }); }
    },
    closeSession: close,
    async dispose() { disposed = true; loadRequest += 1; snapshotRequest += 1; sessionRequest += 1; if (state.snapshotUrl) urls.revokeObjectURL(state.snapshotUrl); update({ snapshotUrl: null }); await close(); listeners.clear(); }
  };
}
