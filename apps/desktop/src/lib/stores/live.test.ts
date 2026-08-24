import { describe, expect, it } from 'vitest';

import type { EventEnvelope } from '../api/types';
import { applySnapshot, initialLiveState, reduceLiveMessage } from './live';

const serviceStatus = (sequence: number, state = 'ready'): EventEnvelope => ({
  sequence,
  occurred_at: '2026-08-23T00:00:00Z',
  payload: { type: 'service_status', data: { state, detail: 'collector is ready' } }
});

const presence = (sequence: number): EventEnvelope => ({
  sequence,
  occurred_at: '2026-08-23T00:00:00Z',
  payload: {
    type: 'presence_changed',
    data: {
      device_id: '0198b9a7-cd5a-7e04-a7c4-7f8d5f5d6f6b',
      from: 'unknown',
      to: 'online',
      reason: 'observed'
    }
  }
});

describe('reduceLiveMessage', () => {
  it('returns the identical state for duplicate or out-of-order events', () => {
    const current = { ...initialLiveState, sequence: 4, connected: true, serviceStatus: 'ready' };

    expect(reduceLiveMessage(current, { type: 'event', data: serviceStatus(4) })).toBe(current);
    expect(reduceLiveMessage(current, { type: 'event', data: serviceStatus(3) })).toBe(current);
  });

  it('advances the sequence and service status for the next status event', () => {
    const result = reduceLiveMessage(initialLiveState, { type: 'event', data: serviceStatus(1, 'degraded') });

    expect(result).toEqual({ sequence: 1, connected: true, needsResync: false, serviceStatus: 'degraded' });
  });

  it('marks the stream untrusted for an event sequence gap', () => {
    const current = { ...initialLiveState, sequence: 4, connected: true, serviceStatus: 'ready' };

    expect(reduceLiveMessage(current, { type: 'event', data: serviceStatus(6, 'degraded') })).toEqual({
      sequence: 4,
      connected: false,
      needsResync: true,
      serviceStatus: 'ready'
    });
  });

  it('latches resync until a snapshot is applied', () => {
    const current = { ...initialLiveState, sequence: 4, connected: true, serviceStatus: 'ready' };
    const latched = reduceLiveMessage(current, { type: 'event', data: serviceStatus(6, 'degraded') });

    expect(reduceLiveMessage(latched, { type: 'event', data: serviceStatus(5, 'ready') })).toBe(latched);
    expect(reduceLiveMessage(latched, { type: 'event', data: serviceStatus(7, 'degraded') })).toBe(latched);
    expect(reduceLiveMessage(latched, { type: 'resync_required' })).toBe(latched);
    expect(applySnapshot(latched, { sequence: 7, devices: [], next_after: null, service_status: 'ready' })).toEqual({
      sequence: 7,
      connected: true,
      needsResync: false,
      serviceStatus: 'ready'
    });
  });

  it('marks the stream untrusted when the server requires a resync', () => {
    const current = { ...initialLiveState, sequence: 4, connected: true, serviceStatus: 'ready' };

    expect(reduceLiveMessage(current, { type: 'resync_required' })).toEqual({
      sequence: 4,
      connected: false,
      needsResync: true,
      serviceStatus: 'ready'
    });
  });

  it('advances a next presence event without changing service status', () => {
    const current = { ...initialLiveState, sequence: 4, connected: true, serviceStatus: 'ready' };

    expect(reduceLiveMessage(current, { type: 'event', data: presence(5) })).toEqual({
      sequence: 5,
      connected: true,
      needsResync: false,
      serviceStatus: 'ready'
    });
  });
});
