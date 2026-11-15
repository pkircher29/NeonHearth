import { SIGN_IN_AGAIN, createHttp, problemText, type AuthSource } from './http';
export interface ScanFinding { device_id: string | null; address: string; protocol: string; port: number | null; status: string; service_hint: string | null; facts: Record<string,string>; observed_at: string }
export interface ScanStatus { job_id: string | null; state: string; started_at: string | null; finished_at: string | null; devices: number; skipped_devices: number; total: number; completed: number; open_ports: number; refused: number; no_response: number; errors: number; findings: ScanFinding[]; results_truncated: boolean; detail: string }
export interface ScanInput { device_ids?: string[]; port_mode: 'common' | 'all' | 'custom' | 'none'; ports?: number[]; protocols: string[]; web_identification?: boolean; snmp?: { version: string; community?: string; username?: string; authentication_password?: string; privacy_password?: string } }
export interface CaptureReport { imported_at: string; findings: ScanFinding[]; detail: string }
export interface ScanApi { status(): Promise<ScanStatus>; start(input: ScanInput): Promise<ScanStatus>; cancel(): Promise<void>; capabilities(): Promise<Record<string,string>>; capture(file?: File): Promise<CaptureReport> }
export const SNMP_NEEDS_DEVICES = 'SNMP is only sent to devices you choose. Select at least one device below, then scan.';
const SCAN_ERRORS: Record<number, string> = { 400: 'Check the ports, the chosen devices and the SNMP credentials.', 401: SIGN_IN_AGAIN, 409: 'A scan is already running.', 422: 'No observed devices currently have a scannable address on this computer’s local network.' };

export function createScanApi(auth: AuthSource, fetchImpl?: typeof fetch): ScanApi {
  const http = createHttp({ auth, fetchImpl });
  async function request(method: string, path = '', input?: ScanInput): Promise<ScanStatus> {
    // The service refuses SNMP without an explicit, non-empty device list; refuse it here with a usable reason first.
    if (input?.snmp || input?.protocols?.includes('snmp')) {
      if (!input.device_ids || input.device_ids.length === 0) throw new Error(SNMP_NEEDS_DEVICES);
    }
    const response = await http.send(`/api/v1/network/scan${path}`, { method, headers: http.authHeaders(input ? { 'Content-Type': 'application/json' } : {}), body: input ? JSON.stringify(input) : undefined }, { timeoutMs: 15_000 });
    if (!response.ok) {
      // A 4xx problem body from the service carries the specific reason (for example the SNMP device-list rule); show it.
      const reason = response.status >= 400 && response.status < 500 && response.status !== 401 ? await problemText(response) : null;
      throw new Error(reason ?? SCAN_ERRORS[response.status] ?? 'Network discovery is unavailable. Try again shortly.');
    }
    if (response.status === 204) return null as unknown as ScanStatus;
    const v = await response.json();
    if (!v || typeof v.state !== 'string' || !Array.isArray(v.findings) || v.findings.length > 4096 || !Number.isSafeInteger(v.total) || !Number.isSafeInteger(v.completed)) throw new Error('The scan response could not be verified.');
    return v;
  }
  async function extra(path: string, file?: File) {
    if (file && file.size > 4 * 1024 * 1024) throw new Error('Choose an Ethernet PCAP smaller than 4 MiB.');
    const response = await http.send(`/api/v1/network/${path}`, { method: file ? 'POST' : 'GET', headers: http.authHeaders(file ? { 'Content-Type': 'application/vnd.tcpdump.pcap' } : {}), body: file }, { timeoutMs: 15_000 });
    if (!response.ok) throw new Error(response.status === 401 ? SIGN_IN_AGAIN : 'The capture could not be read. Use an Ethernet PCAP file up to 4 MiB.');
    return response.json();
  }
  return { status: () => request('GET'), start: input => request('POST', '', input), cancel: async () => { await request('POST', '/cancel'); }, capabilities: () => extra('capabilities'), capture: file => extra('capture', file) };
}
