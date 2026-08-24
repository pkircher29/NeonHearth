import type { Coverage, DeviceSnapshot, EnforcementStatus, PolicyEvaluation, RequestedAction, ServerMessage, Snapshot } from '../api/types';

export interface ThroughputPoint { at: string; upload: number; download: number }
export type CoverageSummary = Coverage | 'unavailable' | 'mixed';
export type ProtocolMix = Record<string, number>;
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
  aggregate: { upload: number; download: number };
  protocolMix: ProtocolMix | null;
  policies: Record<string, GuardPolicy>;
}

export const initialLiveState: LiveState = { sequence: 0, connected: false, needsResync: false, serviceStatus: 'unknown', devices: {}, deviceOrder: [], throughput: [], timeline: [], coverage: 'unavailable', aggregate: { upload: 0, download: 0 }, protocolMix: null, policies: {} };

function summarize(state: LiveState): LiveState {
  const bandwidth = Object.values(state.devices).map((device) => device.bandwidth).filter((value) => value.available);
  const coverages = new Set(bandwidth.map((value) => value.coverage).filter((value): value is Coverage => value !== null));
  return { ...state, aggregate: { upload: bandwidth.reduce((sum, value) => sum + (value.upload ?? 0), 0), download: bandwidth.reduce((sum, value) => sum + (value.download ?? 0), 0) }, coverage: coverages.size === 0 ? 'unavailable' : coverages.size === 1 ? [...coverages][0]! : 'mixed' };
}

export function applySnapshot(_: LiveState, snapshot: Snapshot): LiveState {
  const devices: Record<string, DeviceSnapshot> = {};
  const deviceOrder: string[] = [];
  const policies: Record<string, GuardPolicy> = {};
  for (const device of snapshot.devices) {
    if (!(device.device_id in devices)) deviceOrder.push(device.device_id);
    devices[device.device_id] = device;
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
  const next = { sequence: snapshot.sequence, connected: false, needsResync: false, serviceStatus: snapshot.service_status, devices, deviceOrder, throughput: [], timeline: [], coverage: 'unavailable' as CoverageSummary, aggregate: { upload: 0, download: 0 }, protocolMix: null, policies };
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
  const next: LiveState = { ...state, sequence: event.sequence, connected: true, devices: state.devices, deviceOrder: state.deviceOrder, throughput: state.throughput, timeline: [...state.timeline, message].slice(-120), coverage: state.coverage, aggregate: state.aggregate, protocolMix: state.protocolMix, policies: state.policies };
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
    next.devices = { ...next.devices };
    let upload = 0; let download = 0;
    for (const sample of event.payload.data.samples) {
      upload += sample.upload_bytes_per_second; download += sample.download_bytes_per_second;
      const current = next.devices[sample.device_id] ?? placeholder(sample.device_id, event.occurred_at);
      if (!(sample.device_id in next.devices)) next.deviceOrder = [...next.deviceOrder, sample.device_id];
      next.devices[sample.device_id] = { ...current, last_seen_at: event.occurred_at, bandwidth: { available: true, upload: sample.upload_bytes_per_second, download: sample.download_bytes_per_second, coverage: sample.coverage, observed_at: event.payload.data.observed_at } };
    }
    next.aggregate = { upload, download };
    next.throughput = [...next.throughput, { at: event.occurred_at, upload, download }].slice(-240);
    // Rust's BandwidthSample intentionally has no protocol metadata, so this
    // projection remains unavailable rather than inventing a protocol mix.
    next.protocolMix = null;
  }
  if (event.payload.type === 'policy_changed') {
    const policy = event.payload.data;
    const id = policy.device_id;
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

export function bandwidthTier(totalBps: number): 'blue' | 'cyan' | 'gold' | 'pink' { const megabits = totalBps / 1_000_000; return megabits < 1 ? 'blue' : megabits <= 10 ? 'cyan' : megabits <= 30 ? 'gold' : 'pink'; }
export function topDevices(state: LiveState, limit = 5): DeviceSnapshot[] { return state.deviceOrder.map((id) => state.devices[id]).filter((device): device is DeviceSnapshot => Boolean(device) && device.bandwidth.available).sort((a, b) => (b.bandwidth.upload ?? 0) + (b.bandwidth.download ?? 0) - (a.bandwidth.upload ?? 0) - (a.bandwidth.download ?? 0)).slice(0, limit); }
