import type { Bandwidth, BandwidthFrame, CameraDetail, CameraHealth, CameraInventoryProjection, CameraList, CameraSessionResponse, DeviceSnapshot, EnforcementStatus, Evidence, EventTicket, Health, Identity, PolicyChanged, PolicyEvaluation, PolicyProjection, Presence, ServerMessage, Snapshot } from './types';

type ConnectionState = 'open' | 'closed' | 'error';

export interface ApiClientOptions {
  baseUrl: string;
  serviceToken: string;
  fetchImpl?: typeof fetch;
  WebSocketImpl?: typeof WebSocket;
}

export interface SnapshotPageOptions {
  limit?: number;
  after?: string;
}

/**
 * Wire shape of `OwnerAction` in lattice-service (serde snake_case, externally
 * tagged): unit variants travel as bare strings, ExtendOnce as an object.
 */
export type OwnerActionInput = 'approve' | 'reject' | 'quarantine' | { extend_once: { until: string } };
export interface PolicyActionResult {
  evaluation: PolicyEvaluation;
  enforcement_result: EnforcementStatus;
}

/**
 * Network Doctor wire types (M6 contract, docs/architecture/m6-doctor-contracts.md).
 * These mirror the serde snake_case shapes of the lattice-doctor Rust types
 * field-for-field: internally tagged enums carry their tag key ("state",
 * "reason", "detail", "kind", "class", "action", "outcome", "event"); unit
 * variants of untagged enums travel as bare strings.
 */
export type CheckKind = 'collector_health' | 'adapter_link' | 'address_dhcp' | 'duplicate_ip' | 'wifi_quality'
  | 'gateway' | 'router_health' | 'loss_latency' | 'mtu' | 'dns' | 'route_vpn' | 'internet_reachability';
export type Metric = 'collector_privileged' | 'capture_healthy' | 'worker_running' | 'link_up' | 'link_speed_mbps'
  | 'address_present' | 'lease_valid' | 'conflicting_mac_count' | 'rssi_dbm' | 'retry_percent' | 'rtt_ms'
  | 'loss_percent' | 'dns_latency_ms' | 'resolver_failure_count' | 'default_route_count' | 'router_responsive'
  | 'passing_mtu_bytes' | 'failing_mtu_bytes' | 'reachability_success';
export type Unit = 'milliseconds' | 'percent' | 'dbm' | 'bytes' | 'megabits_per_second' | 'count' | 'boolean';
export interface Confidence { basis_points: number }
export interface Measurement { metric: Metric; value: number; unit: Unit; observed_at: string }
export type SkipReason =
  | { reason: 'dependency_failed'; dependency: CheckKind }
  | { reason: 'dependency_skipped'; dependency: CheckKind }
  | { reason: 'budget_exhausted' };
export type CheckStatus = { state: 'passed' } | { state: 'failed' } | { state: 'skipped'; because: SkipReason };
export type LeaseState = 'static' | 'valid' | 'expired' | 'missing';
export type DnsFailureReason = 'timeout' | 'refused' | 'serv_fail' | 'no_answer';
export interface RouteEntry { interface: string; gateway: string; is_vpn: boolean; metric: number }
export type ResolverOutcome =
  | { outcome: 'answered'; latency_ms: number }
  | { outcome: 'failed'; reason: DnsFailureReason }
  | { outcome: 'unavailable'; error: string };
export interface ResolverEvidence { resolver: string; independent: boolean; outcome: ResolverOutcome }
export type CheckDetail =
  | { detail: 'probe_failure'; error: string }
  | { detail: 'collector'; privileged: boolean; capture_ok: boolean; worker_running: boolean }
  | { detail: 'link'; up: boolean }
  | { detail: 'address'; address: string | null; lease: LeaseState }
  | { detail: 'duplicate_ip'; address: string; macs: string[] }
  | { detail: 'wifi'; wireless: boolean; rssi_dbm: number | null; retry_percent: number | null }
  | { detail: 'gateway_ping'; sent: number; received: number }
  | { detail: 'router'; responsive: boolean }
  | { detail: 'loss_latency'; loss_percent: number; median_rtt_ms: number | null }
  | { detail: 'mtu'; largest_passing_bytes: number | null; smallest_failing_bytes: number | null }
  | { detail: 'dns'; resolvers: ResolverEvidence[] }
  | { detail: 'route'; default_routes: RouteEntry[]; vpn_conflict: boolean }
  | { detail: 'internet'; reachable: boolean; lan_ok: boolean };
export interface CheckResult { kind: CheckKind; status: CheckStatus; evidence: Measurement[]; confidence: Confidence; detail: CheckDetail | null }
export interface DiagnosticBudget { max_probes: number; per_probe_timeout_ms: number }
export interface DiagnosticReport { started_at: string; finished_at: string; budget: DiagnosticBudget; probes_used: number; budget_exhausted: boolean; checks: CheckResult[] }
export type DiagnosisKind =
  | { kind: 'collector_fault'; privileged: boolean; capture_ok: boolean; worker_running: boolean }
  | { kind: 'adapter_link_down' }
  | { kind: 'address_missing'; lease: LeaseState }
  | { kind: 'duplicate_ip'; address: string; macs: string[] }
  | { kind: 'weak_wifi_quality'; rssi_dbm: number }
  | { kind: 'gateway_unreachable' }
  | { kind: 'router_fault' }
  | { kind: 'loss_latency_degraded'; loss_percent: number; median_rtt_ms: number | null }
  | { kind: 'mtu_blackhole'; largest_passing_bytes: number | null; smallest_failing_bytes: number | null }
  | { kind: 'dns_failure'; resolvers: ResolverEvidence[] }
  | { kind: 'route_vpn_conflict'; default_routes: RouteEntry[] }
  | { kind: 'internet_unreachable'; lan_ok: boolean }
  | { kind: 'diagnostic_probe_failure'; check: CheckKind; error: string };
export interface Diagnosis { kind: DiagnosisKind; evidence: Measurement[]; confidence: Confidence; impact: string }
export type RepairClass = 'safe_automatic' | 'approval_required_reversible' | 'guided_physical' | 'observation_only';
export interface SafeAction { action: 'restart_collector_worker' | 'refresh_app_caches' | 'renew_collector_lease' | 'retry_router_session' | 'repair_tailscale_serve' }
export type ApprovalAction =
  | { action: 'reset_adapter'; interface: string }
  | { action: 'change_dns_servers'; servers: string[] }
  | { action: 'set_dhcp_reservation'; device: string; address: string }
  | { action: 'block_device'; device: string }
  | { action: 'unblock_device'; device: string }
  | { action: 'reboot_router' }
  | { action: 'renew_dhcp_lease'; interface: string }
  | { action: 'set_interface_mtu'; interface: string; mtu: number };
export type GuidedAction = 'check_cables' | 'move_hardware' | 'contact_isp' | 'factory_reset' | 'install_firmware';
export type RepairPlan =
  | { class: 'safe_automatic'; action: SafeAction; rationale: string }
  | { class: 'approval_required_reversible'; action: ApprovalAction; rationale: string }
  | { class: 'guided_physical'; action: GuidedAction; rationale: string }
  | { class: 'observation_only'; rationale: string };
export type StateKey = 'worker_state' | 'cache_state' | 'dhcp_lease' | 'router_session' | 'tailscale_config'
  | 'adapter_config' | 'dns_servers' | 'dhcp_reservations' | 'firewall_rules';
export type Verdict = 'improved' | 'unchanged' | 'regressed';
export interface Verification { verdict: Verdict; before: Measurement; after: Measurement }
export type RollbackSkipReason = 'not_needed' | 'not_reversible';
export type RollbackOutcome =
  | { outcome: 'not_attempted'; reason: RollbackSkipReason }
  | { outcome: 'succeeded' }
  | { outcome: 'failed'; error: string };
export type RepairEventKind =
  | { event: 'started'; class: RepairClass; description: string }
  | { event: 'snapshotted'; keys: StateKey[]; baseline: Measurement }
  | { event: 'applied' }
  | { event: 'apply_failed'; error: string }
  | { event: 'verified'; verdict: Verdict; before: Measurement; after: Measurement }
  | { event: 'verification_failed'; error: string }
  | { event: 'rolled_back'; outcome: RollbackOutcome };
export interface RepairEvent { sequence: number; at: string; kind: RepairEventKind }
export type RepairOutcome =
  | { outcome: 'completed'; verdict: Verdict }
  | { outcome: 'snapshot_failed'; error: string }
  | { outcome: 'baseline_failed'; error: string }
  | { outcome: 'apply_failed'; error: string }
  | { outcome: 'verification_failed'; error: string };
export interface RepairReport { class: RepairClass; description: string; outcome: RepairOutcome; verification: Verification | null; rollback: RollbackOutcome; events: RepairEvent[] }
/** Service envelope for POST /doctor/run and GET /doctor/report. */
export interface DoctorFinding { diagnosis: Diagnosis; plan: RepairPlan }
export interface DoctorRun { run_id: string; started_at: string; report: DiagnosticReport; findings: DoctorFinding[] }
/** A concurrent-run refusal (409) is a typed outcome, not an exception. */
export type DoctorRunOutcome = { status: 'completed'; run: DoctorRun } | { status: 'already_running' };
export interface DoctorApproval { approval_id: string; expires_at: string }

export interface ApiClient {
  health(): Promise<Health>;
  snapshot(options?: SnapshotPageOptions): Promise<Snapshot>;
  snapshotAll(options?: { limit?: number; maxPages?: number; maxRecords?: number }): Promise<Snapshot>;
  issueEventTicket(): Promise<EventTicket>;
  openEvents(
    afterSequence: number,
    onMessage: (message: ServerMessage) => void,
    onState: (state: ConnectionState) => void
  ): Promise<WebSocket>;
  cameras(options?: { limit?: number; after?: string }): Promise<CameraList>;
  camera(id: string): Promise<CameraDetail>;
  cameraHealth(id: string): Promise<CameraHealth>;
  cameraInventory(id: string): Promise<CameraInventoryProjection | null>;
  cameraSnapshot(id: string, streamId?: string): Promise<Blob>;
  startCameraSession(id: string, streamId: string): Promise<CameraSessionResponse>;
  closeCameraSession(sessionId: string): Promise<void>;
  authorizeCameraMediaXhr(xhr: XMLHttpRequest, url: string): void;
  policyAction(deviceId: string, action: OwnerActionInput): Promise<PolicyActionResult>;
  doctorRun(): Promise<DoctorRunOutcome>;
  doctorReport(): Promise<DoctorRun | null>;
  doctorApprove(diagnosisKind: DiagnosisKind): Promise<DoctorApproval>;
  doctorRepair(diagnosisKind: DiagnosisKind, approvalId?: string): Promise<RepairReport>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
function exact(value: Record<string, unknown>, keys: string[]): boolean { const actual = Object.keys(value).sort(); return actual.length === keys.length && actual.every((k, i) => k === [...keys].sort()[i]); }

/**
 * TypeScript numbers are accepted only through MAX_SAFE_INTEGER. At 4Hz this
 * exceeds the product lifetime; server and client must resync or reject any
 * value beyond it instead of silently rounding.
 */
export function isSequence(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isServerMessage(value: unknown): value is ServerMessage {
  if (!isRecord(value) || typeof value.type !== 'string') return false;
  if (value.type === 'resync_required') return !('data' in value);
  if (value.type !== 'event' || !isRecord(value.data)) return false;
  const event = value.data;
  if (!isSequence(event.sequence) || !isDate(event.occurred_at) || !isRecord(event.payload)) return false;
  const payload = event.payload;
  if (payload.type === 'service_status') return isRecord(payload.data) && typeof payload.data.state === 'string' && typeof payload.data.detail === 'string';
  if (payload.type === 'bandwidth_frame') return isBandwidthFrame(payload.data);
  if (payload.type === 'policy_changed') return isPolicyChanged(payload.data);
  return payload.type === 'presence_changed' && isRecord(payload.data)
    && isSequence(payload.data.transition_id)
    && isDeviceId(payload.data.device_id)
    && presenceStates.has(String(payload.data.from))
    && presenceStates.has(String(payload.data.to))
    && typeof payload.data.reason === 'string' && payload.data.reason.length > 0
    && isDate(payload.data.occurred_at) && typeof payload.data.trigger_source === 'string'
    && payload.data.trigger_source.length > 0 && typeof payload.data.trigger_kind === 'string' && payload.data.trigger_kind.length > 0 && isDate(payload.data.evidence_observed_at)
    && (payload.data.evidence_valid_until === null || isDate(payload.data.evidence_valid_until))
    && isDate(payload.data.trigger_arrival_at) && Object.hasOwn(payload.data, 'correction_of')
    && (payload.data.correction_of === null || isSequence(payload.data.correction_of));
}

function isHealth(value: unknown): value is Health {
  return isRecord(value) && typeof value.status === 'string' && typeof value.api_version === 'string';
}

const presenceStates = new Set(['online', 'quiet', 'offline', 'blocked', 'unknown']);
const evidenceFamilies = new Set(['link_layer', 'addressing', 'naming', 'service', 'cryptographic', 'router_hint', 'owner']);
const coverages = new Set(['complete', 'router-reported', 'local-only', 'estimated']);
const policyReasons = new Set(['pending_confirmation', 'baseline_exempt', 'high_confidence_danger', 'unknown_deadline_expired', 'automatic_deadline_expired', 'owner_extension', 'owner_approved', 'owner_rejected', 'owner_quarantined', 'protected_device']);
const requestedActions = new Set(['none', 'quarantine', 'permanent_ban', 'owner_attention']);
const enforcementStatuses = new Set(['not_requested', 'verified', 'manual_required', 'failed']);
const deadlineKinds = new Set(['unknown48_hours', 'automatic7_days']);
const deadlineWarnings = new Set(['hours24', 'hours6', 'hour1']);
const ownerDecisions = new Set(['pending', 'approved', 'rejected', 'quarantined']);
const protections = new Set(['none', 'router', 'collector', 'administrator_phone', 'safety_device']);
const cameraClassifications = new Set(['camera', 'possible_camera', 'unknown']);
const cameraHealths = new Set(['healthy', 'degraded', 'unknown']);
const inventoryHealths = new Set(['healthy', 'degraded']);
const actionForReason = new Map([
  ['pending_confirmation', 'none'], ['baseline_exempt', 'none'], ['high_confidence_danger', 'quarantine'],
  ['unknown_deadline_expired', 'quarantine'], ['automatic_deadline_expired', 'quarantine'],
  ['owner_extension', 'none'], ['owner_approved', 'none'], ['owner_rejected', 'permanent_ban'],
  ['owner_quarantined', 'quarantine'], ['protected_device', 'owner_attention']
]);
const utcRfc3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const isDate = (value: unknown): value is string => {
  if (typeof value !== 'string' || !utcRfc3339.test(value)) return false;
  const date = new Date(value);
  return !Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 19) === value.slice(0, 19);
};
const isConfidence = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;
const isBytes = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const isDeviceId = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-7][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const isOpaqueId = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);

function isPresence(value: unknown): value is Presence {
  if (!isRecord(value) || !presenceStates.has(String(value.state))) return false;
  const fields = [value.observed_at, value.source, value.kind];
  const noTransition = fields.every((field) => field === null);
  const transition = isDate(value.observed_at)
    && typeof value.source === 'string' && value.source.length > 0
    && typeof value.kind === 'string' && value.kind.length > 0;
  return noTransition ? value.state === 'unknown' : transition;
}
function isEvidence(value: unknown): value is Evidence {
  return isRecord(value) && typeof value.family === 'string' && evidenceFamilies.has(value.family)
    && typeof value.source === 'string' && value.source.length > 0 && isConfidence(value.confidence)
    && isDate(value.observed_at) && (value.expires_at === null || isDate(value.expires_at));
}
function isIdentity(value: unknown): value is Identity {
  if (!isRecord(value) || typeof value.available !== 'boolean') return false;
  if (!value.available) return value.classification === null && value.confidence === null;
  return typeof value.classification === 'string' && value.classification.length > 0 && isConfidence(value.confidence);
}
function isBandwidth(value: unknown): value is Bandwidth {
  if (!isRecord(value) || typeof value.available !== 'boolean') return false;
  const fields = [value.upload, value.download, value.coverage, value.observed_at];
  if (!value.available) return fields.every((field) => field === null);
  return isBytes(value.upload) && isBytes(value.download) && typeof value.coverage === 'string'
    && coverages.has(value.coverage) && isDate(value.observed_at);
}
function isBandwidthFrame(value: unknown): value is BandwidthFrame {
  if (!isRecord(value) || !isSequence(value.interval_ms) || value.interval_ms < 1 || !isDate(value.observed_at) || !isDate(value.emitted_at) || !Array.isArray(value.samples) || value.samples.length > 4096) return false;
  return value.samples.every((sample) => isRecord(sample) && isDeviceId(sample.device_id) && isRecord(sample.delta)
    && isBytes(sample.delta.upload) && isBytes(sample.delta.download) && isBytes(sample.upload_bytes_per_second)
    && isBytes(sample.download_bytes_per_second) && typeof sample.coverage === 'string' && coverages.has(sample.coverage));
}
function isPolicyVersion(value: unknown): value is number {
  return isSequence(value) && value <= 0xffff_ffff;
}
function isPolicyEvaluation(value: unknown): value is PolicyEvaluation {
  if (!isRecord(value) || !isPolicyVersion(value.policy_version)
    || typeof value.reason !== 'string' || !policyReasons.has(value.reason)
    || typeof value.requested_action !== 'string' || !requestedActions.has(value.requested_action)
    || !(value.warning === null || (typeof value.warning === 'string' && deadlineWarnings.has(value.warning)))) return false;
  if (actionForReason.get(value.reason) !== value.requested_action) return false;
  return value.deadline === null || (isRecord(value.deadline)
    && typeof value.deadline.kind === 'string' && deadlineKinds.has(value.deadline.kind)
    && isDate(value.deadline.due_at));
}
function isPolicyProjection(value: unknown): value is PolicyProjection {
  return isRecord(value)
    && typeof value.owner_decision === 'string' && ownerDecisions.has(value.owner_decision)
    && typeof value.protection === 'string' && protections.has(value.protection)
    && isPolicyEvaluation(value.evaluation)
    && typeof value.enforcement_result === 'string' && enforcementStatuses.has(value.enforcement_result)
    && typeof value.undo_available === 'boolean' && typeof value.delivery_pending === 'boolean';
}
function isPolicyChanged(value: unknown): value is PolicyChanged {
  return isRecord(value) && isDeviceId(value.device_id) && isPolicyVersion(value.policy_version)
    && isPolicyEvaluation(value.evaluation) && value.policy_version === value.evaluation.policy_version
    && typeof value.requested_action === 'string' && requestedActions.has(value.requested_action)
    && value.requested_action === value.evaluation.requested_action
    && typeof value.evidence_summary === 'string' && value.evidence_summary.length > 0 && value.evidence_summary.length <= 4096
    && typeof value.enforcement_result === 'string' && enforcementStatuses.has(value.enforcement_result)
    && typeof value.undo_available === 'boolean';
}
function isDeviceSnapshot(value: unknown): value is DeviceSnapshot {
  return isRecord(value) && isDeviceId(value.device_id) && isDate(value.first_seen_at) && isDate(value.last_seen_at)
    && (value.owner_name === null || typeof value.owner_name === 'string')
    && (value.owner_type === null || typeof value.owner_type === 'string') && typeof value.owner_confirmed === 'boolean'
    && isPresence(value.presence) && (value.evidence === null || isEvidence(value.evidence))
    && isIdentity(value.identity) && isBandwidth(value.bandwidth)
    && Object.hasOwn(value, 'policy') && (value.policy === null || isPolicyProjection(value.policy));
}

function isSnapshot(value: unknown): value is Snapshot {
  return isRecord(value) && isSequence(value.sequence) && Array.isArray(value.devices)
    && value.devices.every(isDeviceSnapshot) && (value.next_after === null || isDeviceId(value.next_after))
    && typeof value.service_status === 'string';
}
function isCameraSummary(value: unknown): value is import('./types').CameraSummary { return isRecord(value) && exact(value,['camera_id','classification','confidence','health','observed_at']) && isOpaqueId(value.camera_id) && typeof value.classification === 'string' && cameraClassifications.has(value.classification) && isConfidence(value.confidence) && typeof value.health === 'string' && cameraHealths.has(value.health) && isDate(value.observed_at); }
function isCameraList(value: unknown): value is CameraList { return isRecord(value) && exact(value,['items','next_after']) && Array.isArray(value.items) && value.items.length <= 256 && value.items.every(isCameraSummary) && (value.next_after === null || isOpaqueId(value.next_after)); }
function isInventory(value: unknown): value is CameraInventoryProjection { return isRecord(value) && exact(value,['manufacturer','model','firmware','serial','capabilities','health']) && ['manufacturer','model','firmware','serial'].every(k => value[k] === null || (typeof value[k] === 'string' && value[k].length > 0 && value[k].length <= 128)) && Array.isArray(value.capabilities) && value.capabilities.length <= 32 && value.capabilities.every(v => typeof v === 'string' && v.length > 0 && v.length <= 128) && typeof value.health === 'string' && inventoryHealths.has(value.health); }
function isCameraStream(value: unknown): boolean { return isRecord(value) && exact(value, ['stream_id']) && isOpaqueId(value.stream_id); }
function isCameraDetail(value: unknown): value is CameraDetail { return isRecord(value) && exact(value, ['camera_id', 'classification', 'confidence', 'health', 'observed_at', 'inventory', 'streams']) && isCameraSummary({ camera_id: value.camera_id, classification: value.classification, confidence: value.confidence, health: value.health, observed_at: value.observed_at }) && (value.inventory === null || isInventory(value.inventory)) && Array.isArray(value.streams) && value.streams.length <= 64 && value.streams.every(isCameraStream); }
function isCameraHealth(value: unknown): value is CameraHealth { return isRecord(value) && exact(value,['health','confidence']) && typeof value.health === 'string' && cameraHealths.has(value.health) && isConfidence(value.confidence); }
const isSessionId = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
function isSession(value: unknown): value is CameraSessionResponse { return isRecord(value) && exact(value,['session_id']) && isSessionId(value.session_id); }

const ownerActionKinds = new Set(['approve', 'reject', 'quarantine']);
function isOwnerActionInput(value: unknown): value is OwnerActionInput {
  if (typeof value === 'string') return ownerActionKinds.has(value);
  return isRecord(value) && exact(value, ['extend_once']) && isRecord(value.extend_once)
    && exact(value.extend_once, ['until']) && isDate(value.extend_once.until);
}
function isPolicyActionResult(value: unknown): value is PolicyActionResult {
  return isRecord(value) && exact(value, ['evaluation', 'enforcement_result'])
    && isPolicyEvaluation(value.evaluation)
    && typeof value.enforcement_result === 'string' && enforcementStatuses.has(value.enforcement_result);
}

function isEventTicket(value: unknown): value is EventTicket {
  return isRecord(value) && typeof value.ticket === 'string' && value.ticket.length > 0 && isSequence(value.expires_in_seconds);
}

// ---- Network Doctor validators (strict: unknown shapes are rejected) ----
const checkKinds = new Set(['collector_health', 'adapter_link', 'address_dhcp', 'duplicate_ip', 'wifi_quality', 'gateway', 'router_health', 'loss_latency', 'mtu', 'dns', 'route_vpn', 'internet_reachability']);
const doctorMetrics = new Set(['collector_privileged', 'capture_healthy', 'worker_running', 'link_up', 'link_speed_mbps', 'address_present', 'lease_valid', 'conflicting_mac_count', 'rssi_dbm', 'retry_percent', 'rtt_ms', 'loss_percent', 'dns_latency_ms', 'resolver_failure_count', 'default_route_count', 'router_responsive', 'passing_mtu_bytes', 'failing_mtu_bytes', 'reachability_success']);
const doctorUnits = new Set(['milliseconds', 'percent', 'dbm', 'bytes', 'megabits_per_second', 'count', 'boolean']);
const leaseStates = new Set(['static', 'valid', 'expired', 'missing']);
const dnsFailureReasons = new Set(['timeout', 'refused', 'serv_fail', 'no_answer']);
const repairClasses = new Set(['safe_automatic', 'approval_required_reversible', 'guided_physical', 'observation_only']);
const safeActions = new Set(['restart_collector_worker', 'refresh_app_caches', 'renew_collector_lease', 'retry_router_session', 'repair_tailscale_serve']);
const guidedActions = new Set(['check_cables', 'move_hardware', 'contact_isp', 'factory_reset', 'install_firmware']);
const doctorStateKeys = new Set(['worker_state', 'cache_state', 'dhcp_lease', 'router_session', 'tailscale_config', 'adapter_config', 'dns_servers', 'dhcp_reservations', 'firewall_rules']);
const verdicts = new Set(['improved', 'unchanged', 'regressed']);
const rollbackSkipReasons = new Set(['not_needed', 'not_reversible']);
const isFiniteNumber = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value);
const isU16 = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 0xffff;
const isU32 = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 0xffff_ffff;
const isI16 = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= -32768 && value <= 32767;
const isBoundedText = (value: unknown, max = 4096): value is string => typeof value === 'string' && value.length > 0 && value.length <= max;
const boundedArray = (value: unknown, max: number): value is unknown[] => Array.isArray(value) && value.length <= max;
// Mirrors ApprovalId::try_new: non-empty, at most 128 bytes, no control characters.
// eslint-disable-next-line no-control-regex
const controlChars = /[\u0000-\u001f\u007f-\u009f]/;
const isApprovalIdToken = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 128 && !controlChars.test(value);

function isDoctorConfidence(value: unknown): value is Confidence {
  return isRecord(value) && exact(value, ['basis_points']) && typeof value.basis_points === 'number'
    && Number.isSafeInteger(value.basis_points) && value.basis_points >= 0 && value.basis_points <= 10_000;
}
function isDoctorMeasurement(value: unknown): value is Measurement {
  return isRecord(value) && exact(value, ['metric', 'value', 'unit', 'observed_at'])
    && doctorMetrics.has(String(value.metric)) && isFiniteNumber(value.value)
    && doctorUnits.has(String(value.unit)) && isDate(value.observed_at);
}
function isSkipReason(value: unknown): value is SkipReason {
  if (!isRecord(value)) return false;
  if (value.reason === 'budget_exhausted') return exact(value, ['reason']);
  return (value.reason === 'dependency_failed' || value.reason === 'dependency_skipped')
    && exact(value, ['reason', 'dependency']) && checkKinds.has(String(value.dependency));
}
function isCheckStatus(value: unknown): value is CheckStatus {
  if (!isRecord(value)) return false;
  if (value.state === 'passed' || value.state === 'failed') return exact(value, ['state']);
  return value.state === 'skipped' && exact(value, ['state', 'because']) && isSkipReason(value.because);
}
function isRouteEntry(value: unknown): value is RouteEntry {
  return isRecord(value) && exact(value, ['interface', 'gateway', 'is_vpn', 'metric'])
    && isBoundedText(value.interface, 128) && isBoundedText(value.gateway, 128)
    && typeof value.is_vpn === 'boolean' && isU32(value.metric);
}
function isResolverOutcome(value: unknown): value is ResolverOutcome {
  if (!isRecord(value)) return false;
  if (value.outcome === 'answered') return exact(value, ['outcome', 'latency_ms']) && isFiniteNumber(value.latency_ms);
  if (value.outcome === 'failed') return exact(value, ['outcome', 'reason']) && dnsFailureReasons.has(String(value.reason));
  return value.outcome === 'unavailable' && exact(value, ['outcome', 'error']) && isBoundedText(value.error);
}
function isResolverEvidence(value: unknown): value is ResolverEvidence {
  return isRecord(value) && exact(value, ['resolver', 'independent', 'outcome'])
    && isBoundedText(value.resolver, 256) && typeof value.independent === 'boolean' && isResolverOutcome(value.outcome);
}
function isCheckDetail(value: unknown): value is CheckDetail {
  if (!isRecord(value) || typeof value.detail !== 'string') return false;
  switch (value.detail) {
    case 'probe_failure': return exact(value, ['detail', 'error']) && isBoundedText(value.error);
    case 'collector': return exact(value, ['detail', 'privileged', 'capture_ok', 'worker_running'])
      && [value.privileged, value.capture_ok, value.worker_running].every((flag) => typeof flag === 'boolean');
    case 'link': return exact(value, ['detail', 'up']) && typeof value.up === 'boolean';
    case 'address': return exact(value, ['detail', 'address', 'lease'])
      && (value.address === null || isBoundedText(value.address, 64)) && leaseStates.has(String(value.lease));
    case 'duplicate_ip': return exact(value, ['detail', 'address', 'macs']) && isBoundedText(value.address, 64)
      && boundedArray(value.macs, 64) && value.macs.every((mac) => isBoundedText(mac, 64));
    case 'wifi': return exact(value, ['detail', 'wireless', 'rssi_dbm', 'retry_percent'])
      && typeof value.wireless === 'boolean' && (value.rssi_dbm === null || isI16(value.rssi_dbm))
      && (value.retry_percent === null || isFiniteNumber(value.retry_percent));
    case 'gateway_ping': return exact(value, ['detail', 'sent', 'received']) && isU32(value.sent) && isU32(value.received);
    case 'router': return exact(value, ['detail', 'responsive']) && typeof value.responsive === 'boolean';
    case 'loss_latency': return exact(value, ['detail', 'loss_percent', 'median_rtt_ms'])
      && isFiniteNumber(value.loss_percent) && (value.median_rtt_ms === null || isFiniteNumber(value.median_rtt_ms));
    case 'mtu': return exact(value, ['detail', 'largest_passing_bytes', 'smallest_failing_bytes'])
      && (value.largest_passing_bytes === null || isU16(value.largest_passing_bytes))
      && (value.smallest_failing_bytes === null || isU16(value.smallest_failing_bytes));
    case 'dns': return exact(value, ['detail', 'resolvers']) && boundedArray(value.resolvers, 64) && value.resolvers.every(isResolverEvidence);
    case 'route': return exact(value, ['detail', 'default_routes', 'vpn_conflict'])
      && boundedArray(value.default_routes, 64) && value.default_routes.every(isRouteEntry) && typeof value.vpn_conflict === 'boolean';
    case 'internet': return exact(value, ['detail', 'reachable', 'lan_ok'])
      && typeof value.reachable === 'boolean' && typeof value.lan_ok === 'boolean';
    default: return false;
  }
}
function isCheckResult(value: unknown): value is CheckResult {
  return isRecord(value) && exact(value, ['kind', 'status', 'evidence', 'confidence', 'detail'])
    && checkKinds.has(String(value.kind)) && isCheckStatus(value.status)
    && boundedArray(value.evidence, 64) && value.evidence.every(isDoctorMeasurement)
    && isDoctorConfidence(value.confidence) && (value.detail === null || isCheckDetail(value.detail));
}
function isDiagnosticBudget(value: unknown): value is DiagnosticBudget {
  return isRecord(value) && exact(value, ['max_probes', 'per_probe_timeout_ms'])
    && isU32(value.max_probes) && value.max_probes >= 1
    && isU32(value.per_probe_timeout_ms) && value.per_probe_timeout_ms >= 1 && value.per_probe_timeout_ms <= 10_000;
}
function isDiagnosticReport(value: unknown): value is DiagnosticReport {
  return isRecord(value) && exact(value, ['started_at', 'finished_at', 'budget', 'probes_used', 'budget_exhausted', 'checks'])
    && isDate(value.started_at) && isDate(value.finished_at) && isDiagnosticBudget(value.budget)
    && isU32(value.probes_used) && typeof value.budget_exhausted === 'boolean'
    && boundedArray(value.checks, 64) && value.checks.every(isCheckResult);
}
function isDiagnosisKind(value: unknown): value is DiagnosisKind {
  if (!isRecord(value) || typeof value.kind !== 'string') return false;
  switch (value.kind) {
    case 'collector_fault': return exact(value, ['kind', 'privileged', 'capture_ok', 'worker_running'])
      && [value.privileged, value.capture_ok, value.worker_running].every((flag) => typeof flag === 'boolean');
    case 'adapter_link_down': case 'gateway_unreachable': case 'router_fault': return exact(value, ['kind']);
    case 'address_missing': return exact(value, ['kind', 'lease']) && leaseStates.has(String(value.lease));
    case 'duplicate_ip': return exact(value, ['kind', 'address', 'macs']) && isBoundedText(value.address, 64)
      && boundedArray(value.macs, 64) && value.macs.every((mac) => isBoundedText(mac, 64));
    case 'weak_wifi_quality': return exact(value, ['kind', 'rssi_dbm']) && isI16(value.rssi_dbm);
    case 'loss_latency_degraded': return exact(value, ['kind', 'loss_percent', 'median_rtt_ms'])
      && isFiniteNumber(value.loss_percent) && (value.median_rtt_ms === null || isFiniteNumber(value.median_rtt_ms));
    case 'mtu_blackhole': return exact(value, ['kind', 'largest_passing_bytes', 'smallest_failing_bytes'])
      && (value.largest_passing_bytes === null || isU16(value.largest_passing_bytes))
      && (value.smallest_failing_bytes === null || isU16(value.smallest_failing_bytes));
    case 'dns_failure': return exact(value, ['kind', 'resolvers']) && boundedArray(value.resolvers, 64) && value.resolvers.every(isResolverEvidence);
    case 'route_vpn_conflict': return exact(value, ['kind', 'default_routes']) && boundedArray(value.default_routes, 64) && value.default_routes.every(isRouteEntry);
    case 'internet_unreachable': return exact(value, ['kind', 'lan_ok']) && typeof value.lan_ok === 'boolean';
    case 'diagnostic_probe_failure': return exact(value, ['kind', 'check', 'error']) && checkKinds.has(String(value.check)) && isBoundedText(value.error);
    default: return false;
  }
}
function isDiagnosis(value: unknown): value is Diagnosis {
  return isRecord(value) && exact(value, ['kind', 'evidence', 'confidence', 'impact'])
    && isDiagnosisKind(value.kind) && boundedArray(value.evidence, 64) && value.evidence.every(isDoctorMeasurement)
    && isDoctorConfidence(value.confidence) && isBoundedText(value.impact);
}
function isSafeAction(value: unknown): value is SafeAction {
  return isRecord(value) && exact(value, ['action']) && safeActions.has(String(value.action));
}
function isApprovalAction(value: unknown): value is ApprovalAction {
  if (!isRecord(value) || typeof value.action !== 'string') return false;
  switch (value.action) {
    case 'reset_adapter': case 'renew_dhcp_lease': return exact(value, ['action', 'interface']) && isBoundedText(value.interface, 128);
    case 'change_dns_servers': return exact(value, ['action', 'servers']) && boundedArray(value.servers, 16) && value.servers.every((server) => isBoundedText(server, 128));
    case 'set_dhcp_reservation': return exact(value, ['action', 'device', 'address']) && isBoundedText(value.device, 128) && isBoundedText(value.address, 128);
    case 'block_device': case 'unblock_device': return exact(value, ['action', 'device']) && isBoundedText(value.device, 128);
    case 'reboot_router': return exact(value, ['action']);
    case 'set_interface_mtu': return exact(value, ['action', 'interface', 'mtu']) && isBoundedText(value.interface, 128) && isU16(value.mtu);
    default: return false;
  }
}
function isRepairPlan(value: unknown): value is RepairPlan {
  if (!isRecord(value) || typeof value.class !== 'string') return false;
  switch (value.class) {
    case 'safe_automatic': return exact(value, ['class', 'action', 'rationale']) && isSafeAction(value.action) && isBoundedText(value.rationale);
    case 'approval_required_reversible': return exact(value, ['class', 'action', 'rationale']) && isApprovalAction(value.action) && isBoundedText(value.rationale);
    case 'guided_physical': return exact(value, ['class', 'action', 'rationale']) && guidedActions.has(String(value.action)) && isBoundedText(value.rationale);
    case 'observation_only': return exact(value, ['class', 'rationale']) && isBoundedText(value.rationale);
    default: return false;
  }
}
function isVerification(value: unknown): value is Verification {
  return isRecord(value) && exact(value, ['verdict', 'before', 'after'])
    && verdicts.has(String(value.verdict)) && isDoctorMeasurement(value.before) && isDoctorMeasurement(value.after);
}
function isRollbackOutcome(value: unknown): value is RollbackOutcome {
  if (!isRecord(value)) return false;
  if (value.outcome === 'succeeded') return exact(value, ['outcome']);
  if (value.outcome === 'failed') return exact(value, ['outcome', 'error']) && isBoundedText(value.error);
  return value.outcome === 'not_attempted' && exact(value, ['outcome', 'reason']) && rollbackSkipReasons.has(String(value.reason));
}
function isRepairEventKind(value: unknown): value is RepairEventKind {
  if (!isRecord(value) || typeof value.event !== 'string') return false;
  switch (value.event) {
    case 'started': return exact(value, ['event', 'class', 'description']) && repairClasses.has(String(value.class)) && isBoundedText(value.description);
    case 'snapshotted': return exact(value, ['event', 'keys', 'baseline'])
      && boundedArray(value.keys, 16) && value.keys.every((key) => doctorStateKeys.has(String(key))) && isDoctorMeasurement(value.baseline);
    case 'applied': return exact(value, ['event']);
    case 'apply_failed': case 'verification_failed': return exact(value, ['event', 'error']) && isBoundedText(value.error);
    case 'verified': return exact(value, ['event', 'verdict', 'before', 'after'])
      && verdicts.has(String(value.verdict)) && isDoctorMeasurement(value.before) && isDoctorMeasurement(value.after);
    case 'rolled_back': return exact(value, ['event', 'outcome']) && isRollbackOutcome(value.outcome);
    default: return false;
  }
}
function isRepairEvent(value: unknown): value is RepairEvent {
  return isRecord(value) && exact(value, ['sequence', 'at', 'kind'])
    && isU32(value.sequence) && isDate(value.at) && isRepairEventKind(value.kind);
}
function isRepairOutcome(value: unknown): value is RepairOutcome {
  if (!isRecord(value) || typeof value.outcome !== 'string') return false;
  if (value.outcome === 'completed') return exact(value, ['outcome', 'verdict']) && verdicts.has(String(value.verdict));
  return ['snapshot_failed', 'baseline_failed', 'apply_failed', 'verification_failed'].includes(value.outcome)
    && exact(value, ['outcome', 'error']) && isBoundedText(value.error);
}
function isRepairReport(value: unknown): value is RepairReport {
  return isRecord(value) && exact(value, ['class', 'description', 'outcome', 'verification', 'rollback', 'events'])
    && repairClasses.has(String(value.class)) && isBoundedText(value.description)
    && isRepairOutcome(value.outcome) && (value.verification === null || isVerification(value.verification))
    && isRollbackOutcome(value.rollback) && boundedArray(value.events, 256) && value.events.every(isRepairEvent);
}
function isDoctorFinding(value: unknown): value is DoctorFinding {
  return isRecord(value) && exact(value, ['diagnosis', 'plan']) && isDiagnosis(value.diagnosis) && isRepairPlan(value.plan);
}
function isDoctorRun(value: unknown): value is DoctorRun {
  return isRecord(value) && exact(value, ['run_id', 'started_at', 'report', 'findings'])
    && isBoundedText(value.run_id, 128) && isDate(value.started_at) && isDiagnosticReport(value.report)
    && boundedArray(value.findings, 64) && value.findings.every(isDoctorFinding);
}
function isDoctorApproval(value: unknown): value is DoctorApproval {
  return isRecord(value) && exact(value, ['approval_id', 'expires_at'])
    && isApprovalIdToken(value.approval_id) && isDate(value.expires_at);
}

export function createApiClient({ baseUrl, serviceToken, fetchImpl = fetch, WebSocketImpl = WebSocket }: ApiClientOptions): ApiClient {
  const apiUrl = (path: string) => new URL(path, baseUrl).toString();

  async function request(path: string, init?: RequestInit): Promise<unknown> {
    const response = await fetchImpl(apiUrl(path), init);
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
    return response.json() as Promise<unknown>;
  }

  function authorized(method: 'GET' | 'POST') {
    return { method, headers: { Authorization: `Bearer ${serviceToken}` } };
  }

  async function health(): Promise<Health> {
    const value = await request('/api/v1/health');
    if (!isHealth(value)) throw new Error('Invalid health response');
    return value;
  }

  async function snapshot(options?: SnapshotPageOptions): Promise<Snapshot> {
    if (options?.limit !== undefined && (!Number.isSafeInteger(options.limit) || options.limit < 1 || options.limit > 256)) {
      throw new Error('Invalid snapshot page');
    }
    if (options?.after !== undefined && !isDeviceId(options.after)) {
      throw new Error('Invalid snapshot page');
    }
    const params = new URLSearchParams();
    if (options?.limit !== undefined) params.set('limit', String(options.limit));
    if (options?.after !== undefined) params.set('after', options.after);
    const query = params.toString();
    const value = await request(query ? `/api/v1/state?${query}` : '/api/v1/state', authorized('GET'));
    if (!isSnapshot(value)) throw new Error('Invalid snapshot response');
    return value;
  }

  async function snapshotAll(options: { limit?: number; maxPages?: number; maxRecords?: number } = {}): Promise<Snapshot> {
    const limit = options.limit ?? 256;
    const maxPages = options.maxPages ?? 256;
    const maxRecords = options.maxRecords ?? 65536;
    if (!Number.isSafeInteger(maxPages) || maxPages < 1 || maxPages > 256 || !Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > 65536) throw new Error('Invalid snapshot bounds');
    const devices: DeviceSnapshot[] = [];
    let after: string | undefined;
    let sequence: number | undefined;
    let serviceStatus = 'unknown';
    const cursors = new Set<string>();
    for (let page = 0; page < maxPages; page += 1) {
      const current = await snapshot({ limit, ...(after ? { after } : {}) });
      if (sequence === undefined) sequence = current.sequence;
      if (current.sequence !== sequence) throw new Error('Snapshot sequence changed');
      serviceStatus = current.service_status;
      devices.push(...current.devices);
      if (devices.length > maxRecords) throw new Error('Snapshot exceeds safety bound');
      if (current.next_after === null) return { sequence, devices, next_after: null, service_status: serviceStatus };
      if (cursors.has(current.next_after)) throw new Error('Snapshot cursor cycle');
      cursors.add(current.next_after);
      after = current.next_after;
    }
    throw new Error('Snapshot page bound exceeded');
  }

  async function issueEventTicket(): Promise<EventTicket> {
    const value = await request('/api/v1/events/ticket', authorized('POST'));
    if (!isEventTicket(value)) throw new Error('Invalid event ticket response');
    return value;
  }

  async function openEvents(afterSequence: number, onMessage: (message: ServerMessage) => void, onState: (state: ConnectionState) => void): Promise<WebSocket> {
      if (!isSequence(afterSequence)) throw new Error('Invalid event sequence');
      const { ticket } = await issueEventTicket();
      const url = new URL('/api/v1/events', baseUrl);
      url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
      url.search = new URLSearchParams({ ticket, after_sequence: String(afterSequence) }).toString();
      const socket = new WebSocketImpl(url.toString());
      socket.onopen = () => onState('open');
      socket.onclose = () => onState('closed');
      socket.onerror = () => onState('error');
      socket.onmessage = (event) => {
        if (typeof event.data !== 'string') return;
        try {
          const message: unknown = JSON.parse(event.data);
          if (isServerMessage(message)) onMessage(message);
        } catch {
          // Ignore malformed network data; only typed server messages enter the live store.
        }
      };
      return socket;
  }

  async function cameras(options: { limit?: number; after?: string } = {}): Promise<CameraList> { if (options.limit !== undefined && (!Number.isSafeInteger(options.limit) || options.limit < 1 || options.limit > 256)) throw new Error('Invalid camera page'); if (options.after !== undefined && !isOpaqueId(options.after)) throw new Error('Invalid camera page'); const p=new URLSearchParams(); if(options.limit!==undefined)p.set('limit',String(options.limit)); if(options.after)p.set('after',options.after); const v=await request(`/api/v1/cameras${p.toString()?`?${p}`:''}`,authorized('GET')); if(!isCameraList(v))throw new Error('Invalid camera response'); return v; }
  async function camera(id: string): Promise<CameraDetail> { if(!isOpaqueId(id))throw new Error('Invalid camera id'); const v=await request(`/api/v1/cameras/${id}`,authorized('GET')); if(!isCameraDetail(v))throw new Error('Invalid camera response'); return v; }
  async function cameraHealth(id: string): Promise<CameraHealth> { if(!isOpaqueId(id)) throw new Error('Invalid camera id'); const v=await request(`/api/v1/cameras/${id}/health`, authorized('GET')); if (!isCameraHealth(v)) throw new Error('Invalid camera health'); return v; }
  async function cameraInventory(id: string): Promise<CameraInventoryProjection|null> { if(!isOpaqueId(id))throw new Error('Invalid camera id'); const v=await request(`/api/v1/cameras/${id}/inventory`,authorized('GET')); if(v!==null&&!isInventory(v))throw new Error('Invalid camera inventory'); return v as CameraInventoryProjection|null; }
  async function cameraSnapshot(id: string, streamId?: string): Promise<Blob> { if(!isOpaqueId(id)||(streamId!==undefined&&!isOpaqueId(streamId)))throw new Error('Invalid camera id'); const response=await fetchImpl(apiUrl(`/api/v1/cameras/${id}/snapshot${streamId?`?stream_id=${encodeURIComponent(streamId)}`:''}`),authorized('GET')); if(!response.ok)throw new Error(`Request failed with status ${response.status}`); if(response.headers.get('content-type')?.split(';')[0] !== 'image/jpeg') throw new Error('Invalid camera snapshot media type'); const blob=await response.blob(); if(blob.size > 8*1024*1024) throw new Error('Camera snapshot exceeds safety bound'); return blob; }
  async function startCameraSession(id: string, streamId: string): Promise<CameraSessionResponse> { if(!isOpaqueId(id)||!isOpaqueId(streamId))throw new Error('Invalid camera session id'); const v=await request(`/api/v1/cameras/${id}/sessions`,{...authorized('POST'),headers:{Authorization:`Bearer ${serviceToken}`,'content-type':'application/json'},body:JSON.stringify({stream_id:streamId})}); if(!isSession(v))throw new Error('Invalid camera session'); return v; }
  async function closeCameraSession(sessionId: string): Promise<void> { if(!isSessionId(sessionId))throw new Error('Invalid camera session id'); const response=await fetchImpl(apiUrl(`/api/v1/camera-sessions/${sessionId}`),{method:'DELETE',headers:{Authorization:`Bearer ${serviceToken}`}}); if(!response.ok)throw new Error(`Request failed with status ${response.status}`); }
  async function policyAction(deviceId: string, action: OwnerActionInput): Promise<PolicyActionResult> {
    if (!isDeviceId(deviceId) || !isOwnerActionInput(action)) throw new Error('Invalid policy action');
    const value = await request('/api/v1/policy/action', {
      method: 'POST',
      headers: { Authorization: `Bearer ${serviceToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId, action })
    });
    if (!isPolicyActionResult(value)) throw new Error('Invalid policy action response');
    return value;
  }
  async function doctorRun(): Promise<DoctorRunOutcome> {
    const response = await fetchImpl(apiUrl('/api/v1/doctor/run'), authorized('POST'));
    // One diagnostic at a time: a concurrent run is a typed outcome, not an error.
    if (response.status === 409) return { status: 'already_running' };
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
    const value: unknown = await response.json();
    if (!isDoctorRun(value)) throw new Error('Invalid doctor run response');
    return { status: 'completed', run: value };
  }
  async function doctorReport(): Promise<DoctorRun | null> {
    const response = await fetchImpl(apiUrl('/api/v1/doctor/report'), authorized('GET'));
    // 204: no diagnostic has completed yet.
    if (response.status === 204) return null;
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
    const value: unknown = await response.json();
    if (!isDoctorRun(value)) throw new Error('Invalid doctor report response');
    return value;
  }
  async function doctorApprove(diagnosisKind: DiagnosisKind): Promise<DoctorApproval> {
    if (!isDiagnosisKind(diagnosisKind)) throw new Error('Invalid doctor approval request');
    const value = await request('/api/v1/doctor/approvals', {
      method: 'POST',
      headers: { Authorization: `Bearer ${serviceToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ diagnosis_kind: diagnosisKind })
    });
    if (!isDoctorApproval(value)) throw new Error('Invalid doctor approval response');
    return value;
  }
  async function doctorRepair(diagnosisKind: DiagnosisKind, approvalId?: string): Promise<RepairReport> {
    if (!isDiagnosisKind(diagnosisKind) || (approvalId !== undefined && !isApprovalIdToken(approvalId))) {
      throw new Error('Invalid doctor repair request');
    }
    const value = await request('/api/v1/doctor/repair', {
      method: 'POST',
      headers: { Authorization: `Bearer ${serviceToken}`, 'content-type': 'application/json' },
      body: JSON.stringify(approvalId === undefined ? { diagnosis_kind: diagnosisKind } : { diagnosis_kind: diagnosisKind, approval_id: approvalId })
    });
    if (!isRecord(value) || !exact(value, ['repair']) || !isRepairReport(value.repair)) throw new Error('Invalid doctor repair response');
    return value.repair;
  }
  function authorizeCameraMediaXhr(xhr: XMLHttpRequest, url: string): void {
    const target = new URL(url, baseUrl); const origin = new URL(baseUrl).origin;
    if (target.origin !== origin || target.username || target.password || target.search || target.hash || target.pathname.includes('%') || !/^\/api\/v1\/camera-sessions\/[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\/(?:playlist\.m3u8|segments\/[A-Za-z0-9_.-]{1,255})$/.test(target.pathname)) throw new Error('Camera media request rejected');
    xhr.setRequestHeader('Authorization', `Bearer ${serviceToken}`);
  }

  return { health, snapshot, snapshotAll, issueEventTicket, openEvents, cameras, camera, cameraHealth, cameraInventory, cameraSnapshot, startCameraSession, closeCameraSession, authorizeCameraMediaXhr, policyAction, doctorRun, doctorReport, doctorApprove, doctorRepair };
}
