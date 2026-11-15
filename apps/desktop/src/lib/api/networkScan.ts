import type { AuthSource } from './client';
export interface ScanFinding { device_id: string | null; address: string; protocol: string; port: number | null; status: string; service_hint: string | null; facts: Record<string,string>; observed_at: string }
export interface ScanStatus { job_id: string | null; state: string; started_at: string | null; finished_at: string | null; devices: number; skipped_devices: number; total: number; completed: number; open_ports: number; refused: number; no_response: number; errors: number; findings: ScanFinding[]; results_truncated: boolean; detail: string }
export interface ScanInput { device_ids?: string[]; port_mode: 'common' | 'all' | 'custom' | 'none'; ports?: number[]; protocols: string[]; web_identification?: boolean; snmp?: { version: string; community?: string; username?: string; authentication_password?: string; privacy_password?: string } }
export interface CaptureReport { imported_at: string; findings: ScanFinding[]; detail: string }
export interface ScanApi { status(): Promise<ScanStatus>; start(input: ScanInput): Promise<ScanStatus>; cancel(): Promise<void>; capabilities(): Promise<Record<string,string>>; capture(file?: File): Promise<CaptureReport> }
export function createScanApi(auth: AuthSource): ScanApi {
  async function request(method: string, path = '', input?: ScanInput): Promise<ScanStatus> {
    const response = await fetch(`/api/v1/network/scan${path}`, { method, headers: { Authorization: auth.header() ?? '', ...(input ? { 'Content-Type':'application/json' } : {}) }, body: input ? JSON.stringify(input) : undefined, signal: AbortSignal.timeout(15_000) });
    if (!response.ok) throw new Error(({ 400:'Check the ports and SNMP credentials.', 401:'Sign in as the owner to run discovery.', 409:'A scan is already running.', 422:'No observed devices currently have a scannable address on this computer’s local network.' } as Record<number,string>)[response.status] ?? 'Network discovery is unavailable. Try again shortly.');
    if (response.status === 204) return null as unknown as ScanStatus;
    const v = await response.json();
    if (!v || typeof v.state !== 'string' || !Array.isArray(v.findings) || v.findings.length > 4096 || !Number.isSafeInteger(v.total) || !Number.isSafeInteger(v.completed)) throw new Error('The scan response could not be verified.');
    return v;
  }
  async function extra(path: string, file?: File) {
    if (file && file.size > 4 * 1024 * 1024) throw new Error('Choose an Ethernet PCAP smaller than 4 MiB.');
    const response = await fetch(`/api/v1/network/${path}`, { method: file ? 'POST' : 'GET', headers: { Authorization: auth.header() ?? '', ...(file ? {'Content-Type':'application/vnd.tcpdump.pcap'} : {}) }, body: file, signal: AbortSignal.timeout(15_000) });
    if (!response.ok) throw new Error('The capture could not be read. Use an Ethernet PCAP file up to 4 MiB.');
    return response.json();
  }
  return { status: () => request('GET'), start: input => request('POST','',input), cancel: async () => { await request('POST','/cancel'); }, capabilities: () => extra('capabilities'), capture: file => extra('capture',file) };
}
