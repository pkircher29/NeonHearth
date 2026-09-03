// The Live thread rail shows what changed at home, not every bandwidth tick.
// Bandwidth frames arrive several times a second and belong in the Pulse
// charts; here they would bury the presence and Guard events an owner
// actually needs to see.

import type { ServerMessage } from '../api/types';

export type ThreadCue = 'info' | 'secure' | 'watch' | 'risk';
export interface ThreadEntry { key: string; title: string; detail: string; cue: ThreadCue; at: string | null }

export function isNoteworthy(message: ServerMessage): boolean {
  return message.type === 'resync_required' || message.data.payload.type !== 'bandwidth_frame';
}

export function describeEvent(message: ServerMessage, index: number): ThreadEntry {
  if (message.type === 'resync_required') {
    return { key: `resync-${index}`, title: 'Stream resync requested', detail: 'Waiting for safe recovery', cue: 'watch', at: null };
  }
  const { payload, occurred_at, sequence } = message.data;
  const key = `${sequence}`;
  if (payload.type === 'service_status') {
    return { key, title: `Collector ${payload.data.state}`, detail: payload.data.detail, cue: payload.data.state === 'ready' ? 'secure' : 'watch', at: occurred_at };
  }
  if (payload.type === 'presence_changed') {
    const to = payload.data.to;
    return { key, title: `Presence: ${to}`, detail: payload.data.reason, cue: to === 'blocked' ? 'risk' : to === 'online' ? 'secure' : 'info', at: occurred_at };
  }
  if (payload.type === 'policy_changed') {
    const action = payload.data.requested_action;
    const result = payload.data.enforcement_result;
    return {
      key,
      title: `Guard: ${payload.data.evaluation.reason.replaceAll('_', ' ')}`,
      detail: `${action.replaceAll('_', ' ')} · ${result.replaceAll('_', ' ')}`,
      cue: result === 'failed' ? 'risk' : action === 'none' ? 'secure' : 'watch',
      at: occurred_at
    };
  }
  return { key, title: 'Bandwidth updated', detail: `${payload.data.samples.length} samples received`, cue: 'info', at: occurred_at };
}

/** Newest first, bandwidth frames removed, capped to `limit`. */
export function threadEntries(timeline: readonly ServerMessage[], limit = 6): ThreadEntry[] {
  const entries: ThreadEntry[] = [];
  for (let index = timeline.length - 1; index >= 0 && entries.length < limit; index -= 1) {
    const message = timeline[index]!;
    if (isNoteworthy(message)) entries.push(describeEvent(message, index));
  }
  return entries;
}

export function formatThreadTime(at: string | null): string {
  if (!at) return 'now';
  const date = new Date(at);
  return Number.isNaN(date.getTime()) ? 'now' : date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}
