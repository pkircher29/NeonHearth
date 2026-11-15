import { describe, expect, it } from 'vitest';

import type { ServerMessage } from '../api/types';
import { formatThreadTime, isNoteworthy, threadEntries } from './liveThread';

const at = '2026-08-23T00:00:00Z';
const frame = (sequence: number): ServerMessage => ({ type: 'event', data: { sequence, occurred_at: at, payload: { type: 'bandwidth_frame', data: { interval_ms: 1000, observed_at: at, emitted_at: at, samples: [] } } } });
const presence = (sequence: number, to: 'online' | 'blocked' | 'offline'): ServerMessage => ({ type: 'event', data: { sequence, occurred_at: at, payload: { type: 'presence_changed', data: { transition_id: sequence, device_id: 'd', from: 'unknown', to, reason: 'observed', occurred_at: at, trigger_source: 'sensor', trigger_kind: 'reply', evidence_observed_at: at, evidence_valid_until: null, trigger_arrival_at: at, correction_of: null } } } });
const resync: ServerMessage = { type: 'resync_required', data: { reason: 'gap' } } as unknown as ServerMessage;

describe('live thread', () => {
  it('drops bandwidth frames and keeps everything else, newest first', () => {
    const entries = threadEntries([presence(1, 'online'), frame(2), frame(3), presence(4, 'blocked'), frame(5)]);
    expect(entries.map((entry) => entry.title)).toEqual(['Presence: blocked', 'Presence: online']);
    expect(entries[0]!.cue).toBe('risk');
    expect(entries[1]!.cue).toBe('secure');
    expect(isNoteworthy(frame(9))).toBe(false);
    expect(isNoteworthy(resync)).toBe(true);
  });

  it('caps the list and gives every entry a stable key', () => {
    const many = Array.from({ length: 12 }, (_, index) => presence(index + 1, 'offline'));
    const entries = threadEntries(many, 6);
    expect(entries).toHaveLength(6);
    expect(new Set(entries.map((entry) => entry.key)).size).toBe(6);
  });

  it('formats missing or invalid times as now', () => {
    expect(formatThreadTime(null)).toBe('now');
    expect(formatThreadTime('not a date')).toBe('now');
  });
});
