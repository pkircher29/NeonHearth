import { SIGN_IN_AGAIN, createHttp, isRecord, type AuthSource } from './http';
export interface NetworkSettings {discovery_enabled:boolean;interval_seconds:number;router_ip:string|null;router_port:number}
export interface NetworkPresence {device_id?:string|null;manufacturer?:string|null;interface:number;mac:string;ip:string;first_seen:string;last_seen:string;missed:number}
export interface NetworkSnapshot {
  settings:NetworkSettings;
  router:{status:string;observed_at:string|null;source:string|null;download:number|null;upload:number|null;connected_devices:number|null};
  discovery:{state:string;started_at:string|null;finished_at:string|null;total:number;completed:number;responding:number;errors:number;skipped_networks:number};
  devices:NetworkPresence[];events:Array<{id:number;at:string;mac:string;ip:string;kind:string}>;
  points:Array<{at:number;download:number;upload:number;samples:number}>;bucket_seconds:number;
}
export interface NetworkApi {snapshot(minutes?:number):Promise<NetworkSnapshot>;settings(value:NetworkSettings):Promise<NetworkSettings>;discover():Promise<void>;cancel():Promise<void>}
const record=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const text=(v:unknown):v is string=>typeof v==='string'&&v.length<=256;
const number=(v:unknown):v is number=>typeof v==='number'&&Number.isFinite(v)&&v>=0;
const nullable=(v:unknown,check:(v:unknown)=>boolean)=>v===null||check(v);
const rows=(v:unknown,max:number,check:(v:Record<string,unknown>)=>boolean)=>Array.isArray(v)&&v.length<=max&&v.every(r=>record(r)&&check(r));
const settings=(v:unknown):v is NetworkSettings=>record(v)&&typeof v.discovery_enabled==='boolean'&&number(v.interval_seconds)&&v.interval_seconds>=60&&v.interval_seconds<=3600&&nullable(v.router_ip,text)&&number(v.router_port)&&v.router_port>0&&v.router_port<=65535;
const deviceRow=(r:Record<string,unknown>)=>(r.device_id===undefined||nullable(r.device_id,text))&&(r.manufacturer===undefined||nullable(r.manufacturer,text))&&number(r.interface)&&text(r.mac)&&text(r.ip)&&text(r.first_seen)&&text(r.last_seen)&&number(r.missed);
const eventRow=(r:Record<string,unknown>)=>number(r.id)&&text(r.at)&&text(r.mac)&&text(r.ip)&&['discovered','responding_again','not_responding'].includes(r.kind as string);
const pointRow=(r:Record<string,unknown>)=>number(r.at)&&number(r.download)&&number(r.upload)&&number(r.samples);
const isDeviceRow=(r:unknown)=>record(r)&&deviceRow(r);
const isEventRow=(r:unknown)=>record(r)&&eventRow(r);
const isPointRow=(r:unknown)=>record(r)&&pointRow(r);
export function isNetworkSnapshot(v:unknown):v is NetworkSnapshot {
  if(!record(v)||!settings(v.settings)||!record(v.router)||!record(v.discovery))return false;
  const r=v.router,d=v.discovery;
  return text(r.status)&&nullable(r.observed_at,text)&&nullable(r.source,text)&&nullable(r.download,number)&&nullable(r.upload,number)&&nullable(r.connected_devices,number)
    &&text(d.state)&&nullable(d.started_at,text)&&nullable(d.finished_at,text)&&['total','completed','responding','errors','skipped_networks'].every(k=>number(d[k]))
    &&rows(v.devices,4096,deviceRow)
    &&rows(v.events,200,eventRow)
    &&rows(v.points,1441,pointRow)&&number(v.bucket_seconds)&&v.bucket_seconds>0;
}
export function createNetworkApi(auth: AuthSource, fetcher?: typeof fetch): NetworkApi {
  const http = createHttp({ auth, fetchImpl: fetcher });
  async function request(path: string, method = 'GET', body?: unknown): Promise<unknown> {
    const response = await http.send(`/api/v1/network/${path}`, { method, headers: http.authHeaders(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(body !== undefined ? { body: JSON.stringify(body) } : {}), credentials: 'omit', redirect: 'error' }, { timeoutMs: 15_000 });
    if (!response.ok) throw new Error(({ 400: 'Use the numeric IPv4 address of a router on your physical home network.', 401: SIGN_IN_AGAIN, 409: 'Discovery is already running.' } as Record<number, string>)[response.status] ?? 'Network monitoring is unavailable. Try again.');
    return response.json();
  }
  return {
    async snapshot(minutes = 5) {
      const v = await request(`monitor?minutes=${minutes}`);
      if (isNetworkSnapshot(v)) return v;
      // One bad device or event row must not blank the whole monitor: drop the rows that do not validate.
      if (isRecord(v)) {
        const lenient = { ...v, devices: Array.isArray(v.devices) ? v.devices.slice(0, 4096).filter(isDeviceRow) : v.devices, events: Array.isArray(v.events) ? v.events.slice(0, 200).filter(isEventRow) : v.events, points: Array.isArray(v.points) ? v.points.slice(0, 1441).filter(isPointRow) : v.points };
        if (isNetworkSnapshot(lenient)) return lenient;
      }
      throw new Error('Network readings could not be verified.');
    },
    async settings(value) { const v = await request('monitor/settings', 'PUT', value); if (!settings(v)) throw new Error('Settings could not be verified.'); return v; },
    async discover() { await request('discover', 'POST'); }, async cancel() { await request('discover/cancel', 'POST'); }
  };
}
