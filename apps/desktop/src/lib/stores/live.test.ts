import { describe, expect, it } from 'vitest';

import type { EventEnvelope } from '../api/types';
import { applySnapshot, bandwidthTier, initialLiveState, reduceLiveMessage, topDevices } from './live';

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
      transition_id: sequence,
      device_id: '0198b9a7-cd5a-7e04-a7c4-7f8d5f5d6f6b',
      from: 'unknown',
      to: 'online',
      reason: 'observed',
      occurred_at: '2026-08-23T00:00:00Z',
      trigger_source: 'sensor',
      trigger_kind: 'reply',
      evidence_observed_at: '2026-08-23T00:00:00Z',
      evidence_valid_until: null,
      trigger_arrival_at: '2026-08-23T00:00:00Z',
      correction_of: null
    }
  }
});
const bandwidth = (sequence: number): EventEnvelope => ({
  sequence,
  occurred_at: '2026-08-23T00:00:00Z',
  payload: { type: 'bandwidth_frame', data: { interval_ms: 1000, observed_at: '2026-08-23T00:00:00Z', emitted_at: '2026-08-23T00:00:00Z', samples: [{ device_id: '0198b9a7-cd5a-7e04-a7c4-7f8d5f5d6f6b', delta: { upload: 1, download: 2 }, upload_bytes_per_second: 2_000_000, download_bytes_per_second: 1_000_000, coverage: 'complete' }] } }
});
const policy = (sequence: number): EventEnvelope => ({
  sequence,
  occurred_at: '2026-08-23T00:00:00Z',
  payload: {
    type: 'policy_changed',
    data: {
      device_id: '0198b9a7-cd5a-7e04-a7c4-7f8d5f5d6f6b',
      policy_version: 1,
      evaluation: { policy_version: 1, reason: 'unknown_deadline_expired', requested_action: 'quarantine', deadline: null, warning: null },
      requested_action: 'quarantine',
      evidence_summary: 'identity=unknown;risk=none',
      enforcement_result: 'verified',
      undo_available: true
    }
  }
});

describe('reduceLiveMessage', () => {
  it('starts with a complete empty dashboard state and exact bandwidth tiers', () => {
    expect(initialLiveState.devices).toEqual({});
    expect(initialLiveState.coverage).toBe('unavailable');
    expect(initialLiveState.protocolMix).toBeNull();
    expect(bandwidthTier(999_999)).toBe('blue');
    expect(bandwidthTier(1_000_000)).toBe('cyan');
    expect(bandwidthTier(10_000_000)).toBe('cyan');
    expect(bandwidthTier(10_000_001)).toBe('gold');
    expect(bandwidthTier(30_000_000)).toBe('gold');
    expect(bandwidthTier(30_000_001)).toBe('pink');
  });
  it('returns the identical state for duplicate or out-of-order events', () => {
    const current = { ...initialLiveState, sequence: 4, connected: true, serviceStatus: 'ready' };

    expect(reduceLiveMessage(current, { type: 'event', data: serviceStatus(4) })).toBe(current);
    expect(reduceLiveMessage(current, { type: 'event', data: serviceStatus(3) })).toBe(current);
  });

  it('advances the sequence and service status for the next status event', () => {
    const result = reduceLiveMessage(initialLiveState, { type: 'event', data: serviceStatus(1, 'degraded') });

    expect(result).toMatchObject({ sequence: 1, connected: true, needsResync: false, serviceStatus: 'degraded' });
  });

  it('marks the stream untrusted for an event sequence gap', () => {
    const current = { ...initialLiveState, sequence: 4, connected: true, serviceStatus: 'ready' };

    expect(reduceLiveMessage(current, { type: 'event', data: serviceStatus(6, 'degraded') })).toMatchObject({
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
    expect(applySnapshot(latched, { sequence: 7, devices: [], next_after: null, service_status: 'ready' })).toMatchObject({
      sequence: 7,
      connected: false,
      needsResync: false,
      serviceStatus: 'ready'
    });
  });

  it('marks the stream untrusted when the server requires a resync', () => {
    const current = { ...initialLiveState, sequence: 4, connected: true, serviceStatus: 'ready' };

    expect(reduceLiveMessage(current, { type: 'resync_required' })).toMatchObject({
      sequence: 4,
      connected: false,
      needsResync: true,
      serviceStatus: 'ready'
    });
  });

  it('advances a next presence event without changing service status', () => {
    const current = { ...initialLiveState, sequence: 4, connected: true, serviceStatus: 'ready' };

    expect(reduceLiveMessage(current, { type: 'event', data: presence(5) })).toMatchObject({
      sequence: 5,
      connected: true,
      needsResync: false,
      serviceStatus: 'ready'
    });
  });

  it('creates an explicit unavailable placeholder for an event-only device', () => {
    const result = reduceLiveMessage(applySnapshot(initialLiveState, { sequence: 0, devices: [], next_after: null, service_status: 'ready' }), { type: 'event', data: bandwidth(1) });
    const device = result.devices['0198b9a7-cd5a-7e04-a7c4-7f8d5f5d6f6b'];
    expect(device.identity).toEqual({ available: false, classification: null, confidence: null });
    expect(result.deviceOrder).toEqual([device.device_id]);
    expect(result.coverage).toBe('complete');
    expect(result.aggregate).toEqual({ upload: 2_000_000, download: 1_000_000 });
  });

  it('keeps protocol mix unavailable for canonical bandwidth samples', () => {
    const result = reduceLiveMessage(initialLiveState, { type: 'event', data: bandwidth(1) });

    expect(result.protocolMix).toBeNull();
  });

  it('projects the latest policy state by device for the Guard view', () => {
    const result = reduceLiveMessage(initialLiveState, { type: 'event', data: policy(1) });

    expect(result.policies['0198b9a7-cd5a-7e04-a7c4-7f8d5f5d6f6b']).toMatchObject({
      requested_action: 'quarantine',
      enforcement_result: 'verified',
      undo_available: true
    });
    expect(result.timeline).toHaveLength(1);
  });

  it('hydrates durable policy state from a resync snapshot', () => {
    const device = {
      ...resultDevice('018f47a0-9b5c-7a22-8a33-112233445599'),
      policy: {
        owner_decision: 'quarantined' as const,
        protection: 'none' as const,
        evaluation: { policy_version: 1, reason: 'owner_quarantined' as const, requested_action: 'quarantine' as const, deadline: null, warning: null },
        enforcement_result: 'verified' as const,
        undo_available: true
      }
    };

    const hydrated = applySnapshot({ ...initialLiveState, needsResync: true }, {
      sequence: 12, next_after: null, service_status: 'ready', devices: [device]
    });

    expect(hydrated.needsResync).toBe(false);
    expect(hydrated.policies[device.device_id]).toMatchObject({
      requested_action: 'quarantine', enforcement_result: 'verified', undo_available: true
    });
  });

  it('excludes devices without available bandwidth from top devices', () => {
    const snapshot = applySnapshot(initialLiveState, {
      sequence: 1, next_after: null, service_status: 'ready', devices: [
        { ...resultDevice('unavailable'), bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null } },
        { ...resultDevice('available'), bandwidth: { available: true, upload: 1, download: 2, coverage: 'complete', observed_at: '2026-08-23T00:00:00Z' } }
      ]
    });
    expect(topDevices(snapshot)).toHaveLength(1);
    expect(topDevices(snapshot)[0]?.device_id).toBe('available');
  });
});

function resultDevice(device_id: string) {
  return { device_id, first_seen_at: '2026-08-23T00:00:00Z', last_seen_at: '2026-08-23T00:00:00Z', owner_name: null, owner_type: null, owner_confirmed: false, presence: { state: 'unknown' as const, observed_at: null, source: null, kind: null }, evidence: null, identity: { available: false, classification: null, confidence: null }, bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null }, policy: null };
}
