import type { ClockStatus, Coverage, DeviceSnapshot, EnforcementStatus, PolicyEvaluation, RequestedAction, ServerMessage, Snapshot } from '../api/types';
import { heatTier } from '../twin/heat';

export interface ThroughputPoint { at: string; upload: number; download: number }
export type CoverageSummary = Coverage | 'unavailable' | 'mixed';
export interface GuardPolicy {
  device_id: string;
  evaluation: PolicyEvaluation;
  requested_action: RequestedAction;
  enforcement_result: EnforcementStatus;
  undo_available: boolean;
  delivery_pending: boolean;
}
export interface LiveState {
  sequence: number;
  connected: boolean;
  needsResync: boolean;
  serviceStatus: string;
  devices: Record<string, DeviceSnapshot>;
  deviceOrder: string[];
  throughput: ThroughputPoint[];
  timeline: ServerMessage[];
  coverage: CoverageSummary;
  /** Sum of the fresh per-device readings; a direction is null when no fresh device reports it (never a fake zero). */
  aggregate: { upload: number | null; download: number | null };
  policies: Record<string, GuardPolicy>;
  /** Policy clock gate from the latest snapshot; absent against an older service. */
  clock?: ClockStatus;
}

export const initialLiveState: LiveState = { sequence: 0, connected: false, needsResync: false, serviceStatus: 'unknown', devices: {}, deviceOrder: [], throughput: [], timeline: [], coverage: 'unavailable', aggregate: { upload: null, download: null }, policies: {} };

function hasVerifiedBlock(policy: DeviceSnapshot['policy']): boolean {
  return policy?.enforcement_result === 'verified'
    && (policy.evaluation.requested_action === 'quarantine' || policy.evaluation.requested_action === 'permanent_ban');
}

/** A reading older than this (relative to the newest event) is no longer a measurement of the present. */
export const BANDWIDTH_STALE_MS = 15_000;
const UNAVAILABLE_BANDWIDTH: DeviceSnapshot['bandwidth'] = { available: false, upload: null, download: null, coverage: null, observed_at: null };

/** Single derived signal every view consumes: live, last-known (collector lost), or nothing known. */
export type LiveStatus = 'live' | 'stale' | 'offline';
export function liveStatus(state: Pick<LiveState, 'connected' | 'deviceOrder'> | null | undefined): LiveStatus {
  if (!state) return 'offline';
  if (state.connected) return 'live';
  return state.deviceOrder.length > 0 ? 'stale' : 'offline';
}

function sumKnown(values: Array<number | null>): number | null {
  let total: number | null = null;
  for (const value of values) if (value !== null) total = (total ?? 0) + value;
  return total;
}

function summarize(state: LiveState): LiveState {
  const bandwidth = Object.values(state.devices).map((device) => device.bandwidth).filter((value) => value.available);
  const coverages = new Set(bandwidth.map((value) => value.coverage).filter((value): value is Coverage => value !== null));
  return { ...state, aggregate: { upload: sumKnown(bandwidth.map((value) => value.upload)), download: sumKnown(bandwidth.map((value) => value.download)) }, coverage: coverages.size === 0 ? 'unavailable' : coverages.size === 1 ? [...coverages][0]! : 'mixed' };
}

/**
 * Readings whose observation is older than the threshold (against the newest
 * event time) become unavailable instead of lingering as live numbers.
 */
function expireBandwidth(devices: Record<string, DeviceSnapshot>, nowIso: string, keep: ReadonlySet<string> = new Set()): Record<string, DeviceSnapshot> {
  const now = Date.parse(nowIso);
  if (!Number.isFinite(now)) return devices;
  let next: Record<string, DeviceSnapshot> | null = null;
  for (const [id, device] of Object.entries(devices)) {
    if (keep.has(id) || !device.bandwidth.available) continue;
    const observed = device.bandwidth.observed_at ? Date.parse(device.bandwidth.observed_at) : NaN;
    if (Number.isFinite(observed) && now - observed <= BANDWIDTH_STALE_MS) continue;
    next ??= { ...devices };
    next[id] = { ...device, bandwidth: UNAVAILABLE_BANDWIDTH };
  }
  return next ?? devices;
}

export function applySnapshot(previous: LiveState, snapshot: Snapshot): LiveState {
  const devices: Record<string, DeviceSnapshot> = {};
  const deviceOrder: string[] = [];
  const policies: Record<string, GuardPolicy> = {};
  for (const device of snapshot.devices) {
    if (!(device.device_id in devices)) deviceOrder.push(device.device_id);
    devices[device.device_id] = hasVerifiedBlock(device.policy)
      ? { ...device, presence: { ...device.presence, state: 'blocked', source: 'policy', kind: 'enforcement_blocked' } }
      : device;
    if (device.policy) policies[device.device_id] = {
      device_id: device.device_id,
      evaluation: device.policy.evaluation,
      requested_action: device.policy.evaluation.requested_action,
      enforcement_result: device.policy.enforcement_result,
      undo_available: device.policy.undo_available,
      delivery_pending: device.policy.delivery_pending
    };
  }
  // A snapshot is a trustworthy baseline, but it is not evidence that the
  // event socket is open. The connection orchestrator marks it live on open.
  // A resync that does not go backwards continues the same history: the live
  // thread and throughput curve survive routine stale-watchdog refreshes. A
  // lower sequence means the service restarted, so the old history is dropped.
  const continuous = previous.sequence > 0 && snapshot.sequence >= previous.sequence;
  const next = { sequence: snapshot.sequence, connected: false, needsResync: false, serviceStatus: snapshot.service_status, devices, deviceOrder, throughput: continuous ? previous.throughput : [], timeline: continuous ? previous.timeline : [], coverage: 'unavailable' as CoverageSummary, aggregate: { upload: null, download: null }, policies, ...(snapshot.clock ? { clock: snapshot.clock } : {}) };
  return summarize(next);
}

function placeholder(id: string, occurredAt: string): DeviceSnapshot {
  return { device_id: id, first_seen_at: occurredAt, last_seen_at: occurredAt, owner_name: null, owner_type: null, owner_confirmed: false, presence: { state: 'unknown', observed_at: null, source: null, kind: null }, evidence: null, identity: { available: false, classification: null, confidence: null }, bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null }, policy: null };
}
export function reduceLiveMessage(state: LiveState, message: ServerMessage): LiveState {
  if (state.needsResync) return state;
  if (message.type === 'resync_required') return { ...state, connected: false, needsResync: true };
  const event = message.data;
  if (event.sequence <= state.sequence) return state;
  if (event.sequence > state.sequence + 1) return { ...state, connected: false, needsResync: true };
  const next: LiveState = { ...state, sequence: event.sequence, connected: true, devices: state.devices, deviceOrder: state.deviceOrder, throughput: state.throughput, timeline: [...state.timeline, message].slice(-120), coverage: state.coverage, aggregate: state.aggregate, policies: state.policies };
  if (event.payload.type === 'service_status') next.serviceStatus = event.payload.data.state;
  if (event.payload.type === 'presence_changed') {
    const id = event.payload.data.device_id;
    const current = next.devices[id] ?? placeholder(id, event.occurred_at);
    if (!(id in next.devices)) next.deviceOrder = [...next.deviceOrder, id];
    // Discovery cannot lift a verified control-plane block. Only a verified
    // policy release below changes the effective state away from blocked.
    if (current.presence.state !== 'blocked') {
      next.devices = { ...next.devices, [id]: { ...current, last_seen_at: event.occurred_at, presence: { state: event.payload.data.to, observed_at: event.payload.data.occurred_at, source: event.payload.data.trigger_source, kind: event.payload.data.trigger_kind } } };
    }
  }
  if (event.payload.type === 'bandwidth_frame') {
    const framed = new Set<string>();
    const devices = { ...next.devices };
    for (const sample of event.payload.data.samples) {
      framed.add(sample.device_id);
      const current = devices[sample.device_id] ?? placeholder(sample.device_id, event.occurred_at);
      if (!(sample.device_id in devices)) next.deviceOrder = [...next.deviceOrder, sample.device_id];
      devices[sample.device_id] = { ...current, last_seen_at: event.occurred_at, bandwidth: { available: true, upload: sample.upload_bytes_per_second, download: sample.download_bytes_per_second, coverage: sample.coverage, observed_at: event.payload.data.observed_at } };
    }
    // A device missing from the frame is not measured now: unavailable, not "still at its last rate".
    for (const [id, device] of Object.entries(devices)) {
      if (!framed.has(id) && device.bandwidth.available) devices[id] = { ...device, bandwidth: UNAVAILABLE_BANDWIDTH };
    }
    next.devices = devices;
    const summary = summarize(next);
    // One source: the curve point is the aggregate derived from the same readings.
    if (summary.aggregate.upload !== null && summary.aggregate.download !== null) {
      next.throughput = [...next.throughput, { at: event.occurred_at, upload: summary.aggregate.upload, download: summary.aggregate.download }].slice(-240);
    } else { next.throughput = []; }
  } else {
    next.devices = expireBandwidth(next.devices, event.occurred_at);
  }
  if (event.payload.type === 'policy_changed') {
    const policy = event.payload.data;
    const id = policy.device_id;
    // A typed policy event proves the durable outbox delivered the policy, so clear snapshot pending.
    next.policies = { ...next.policies, [id]: { ...policy, delivery_pending: false } };
    const verifiedBlock = policy.enforcement_result === 'verified'
      && (policy.requested_action === 'quarantine' || policy.requested_action === 'permanent_ban');
    const verifiedRelease = policy.enforcement_result === 'verified'
      && policy.requested_action === 'none' && policy.evaluation.reason === 'owner_approved';
    if (verifiedBlock || verifiedRelease) {
      const current = next.devices[id] ?? placeholder(id, event.occurred_at);
      if (!(id in next.devices)) next.deviceOrder = [...next.deviceOrder, id];
      next.devices = { ...next.devices, [id]: {
        ...current,
        presence: {
          state: verifiedBlock ? 'blocked' : 'unknown',
          observed_at: event.occurred_at,
          source: 'policy',
          kind: verifiedBlock ? 'enforcement_blocked' : 'enforcement_unblocked'
        }
      } };
    }
  }
  return summarize(next);
}

/** Tier for a rate in BYTES per second; shares the documented thresholds with the twin's heat ramp. */
export function bandwidthTier(totalBytesPerSecond: number): 'blue' | 'cyan' | 'gold' | 'pink' { const tier = heatTier(totalBytesPerSecond); return tier === 'unavailable' ? 'blue' : tier; }
export function topDevices(state: LiveState, limit = 5): DeviceSnapshot[] { return state.deviceOrder.map((id) => state.devices[id]).filter((device): device is DeviceSnapshot => Boolean(device) && device.bandwidth.available).sort((a, b) => (b.bandwidth.upload ?? 0) + (b.bandwidth.download ?? 0) - (a.bandwidth.upload ?? 0) - (a.bandwidth.download ?? 0)).slice(0, limit); }
