export interface HostApplication {app_id:string;name:string;executable:string|null;pid:number;started:string;cpu_time_ms:number|null;memory_bytes:number|null}
export interface HostConnection {connection_id:string;app_id:string;pid:number;protocol:string;local_address:string;local_port:number;remote_address:string|null;remote_port:number|null;state:string;sent_bytes:number|null;received_bytes:number|null}
export interface HostSnapshot {
  observed_at:string;status:string;detail:string;
  interfaces:Array<{id:string;name:string;physical:boolean;sent_bytes:number;received_bytes:number}>;
  applications:HostApplication[];connections:HostConnection[];
  upload_bytes_per_second:number|null;download_bytes_per_second:number|null;
  last_interval_ms?:number|null;last_sent_bytes?:number|null;last_received_bytes?:number|null;
  app_counters:string;firewall_available:boolean;memory_total_bytes:number|null;memory_available_bytes:number|null;
}
export interface HostSettings {record_history:boolean;snooze_until:string|null;retention_days:number;monthly_budget_bytes:number|null}
export interface TrafficPoint {at:number;sent_bytes:number;received_bytes:number;measured_ms:number}
export interface UsageApplication {app_id:string;name:string;executable:string|null;first_seen_at:string;last_seen_at:string;sent_bytes:number;received_bytes:number;samples:number}
export interface ConnectionHistory extends Omit<HostConnection,'pid'|'sent_bytes'|'received_bytes'> {name:string;first_seen_at:string;last_seen_at:string}
export interface HostAlert {id:number;at:string;kind:string;app_id:string|null;detail:string;acknowledged:boolean}
export interface HostHistory {since:string;until:string;bucket_seconds:number;scope:string;coverage:string;points:TrafficPoint[];applications:UsageApplication[];connections:ConnectionHistory[];alerts:HostAlert[];settings:HostSettings;month_usage?:{since:string;sent_bytes:number;received_bytes:number}}
export interface FirewallRule {name:string;direction:string;enabled:string;action:string;program:string}
export interface FirewallReceipt {blocked:boolean;rule_verified:boolean;all_profiles_enabled:boolean}
export interface HostApi {
  snapshot():Promise<HostSnapshot>;history(minutes:number,appId?:string):Promise<HostHistory>;
  settings(value:HostSettings):Promise<HostSettings>;acknowledge(id:number):Promise<void>;
  firewall():Promise<FirewallRule[]>;control(appId:string,direction:'inbound'|'outbound',blocked:boolean,expected:boolean):Promise<FirewallReceipt>;
}
const record=(v:unknown):v is Record<string,unknown>=>!!v && typeof v==='object' && !Array.isArray(v);
const text=(v:unknown):v is string=>typeof v==='string' && v.length<=4096;
const nullableText=(v:unknown)=>v===null || text(v);
const number=(v:unknown):v is number=>typeof v==='number' && Number.isFinite(v) && v>=0;
const nullableNumber=(v:unknown)=>v===null || number(v);
const rows=(v:unknown,max:number,check:(r:Record<string,unknown>)=>boolean)=>Array.isArray(v)&&v.length<=max&&v.every(r=>record(r)&&check(r));
export function isHostSnapshot(v:unknown):v is HostSnapshot {
  return record(v)&&text(v.observed_at)&&text(v.status)&&text(v.detail)&&text(v.app_counters)&&typeof v.firewall_available==='boolean'
    && nullableNumber(v.upload_bytes_per_second)&&nullableNumber(v.download_bytes_per_second)&&nullableNumber(v.memory_total_bytes)&&nullableNumber(v.memory_available_bytes)
    && [v.last_interval_ms,v.last_sent_bytes,v.last_received_bytes].every(value=>value===undefined||nullableNumber(value))
    && rows(v.interfaces,4096,r=>text(r.id)&&text(r.name)&&typeof r.physical==='boolean'&&number(r.sent_bytes)&&number(r.received_bytes))
    && rows(v.applications,8192,r=>text(r.app_id)&&text(r.name)&&nullableText(r.executable)&&number(r.pid)&&text(r.started)&&nullableNumber(r.cpu_time_ms)&&nullableNumber(r.memory_bytes))
    && rows(v.connections,8192,r=>text(r.connection_id)&&text(r.app_id)&&number(r.pid)&&text(r.protocol)&&text(r.local_address)&&number(r.local_port)&&nullableText(r.remote_address)&&nullableNumber(r.remote_port)&&text(r.state)&&nullableNumber(r.sent_bytes)&&nullableNumber(r.received_bytes));
}
function settings(v:unknown):v is HostSettings {return record(v)&&typeof v.record_history==='boolean'&&nullableText(v.snooze_until)&&number(v.retention_days)&&nullableNumber(v.monthly_budget_bytes);}
export function isHostHistory(v:unknown):v is HostHistory {
  return record(v)&&text(v.since)&&text(v.until)&&number(v.bucket_seconds)&&text(v.scope)&&text(v.coverage)&&settings(v.settings)
    && (v.month_usage===undefined||(record(v.month_usage)&&text(v.month_usage.since)&&number(v.month_usage.sent_bytes)&&number(v.month_usage.received_bytes)))
    && rows(v.points,1500,r=>number(r.at)&&number(r.sent_bytes)&&number(r.received_bytes)&&number(r.measured_ms))
    && rows(v.applications,2048,r=>text(r.app_id)&&text(r.name)&&nullableText(r.executable)&&text(r.first_seen_at)&&text(r.last_seen_at)&&number(r.sent_bytes)&&number(r.received_bytes)&&number(r.samples))
    && rows(v.connections,2048,r=>text(r.connection_id)&&text(r.app_id)&&text(r.name)&&text(r.protocol)&&text(r.local_address)&&number(r.local_port)&&nullableText(r.remote_address)&&nullableNumber(r.remote_port)&&text(r.state)&&text(r.first_seen_at)&&text(r.last_seen_at))
    && rows(v.alerts,2000,r=>number(r.id)&&text(r.at)&&text(r.kind)&&nullableText(r.app_id)&&text(r.detail)&&typeof r.acknowledged==='boolean');
}
export function createHostApi(auth:{header():string|null},fetchImpl:typeof fetch=fetch):HostApi {
  async function request(path:string,method='GET',body?:unknown):Promise<unknown> {
    const response=await fetchImpl(`/api/v1/host/${path}`,{method,headers:{Authorization:auth.header()??'',...(body!==undefined?{'Content-Type':'application/json'}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(path==='firewall'?25_000:15_000),credentials:'omit',redirect:'error'});
    if(!response.ok) throw new Error(({400:'Review the supplied options.',401:'Sign in as the owner to view this computer.',403:'Windows requires administrator permission for this action.',409:'Windows could not confirm this change. Refresh the rules and review the application.',423:'This application is protected to keep monitoring and remote access available.',501:'Application firewall control is not supported on this operating system.'} as Record<number,string>)[response.status]??'The local computer collector could not complete this request.');
    return response.json();
  }
  return {
    async snapshot(){const value=await request('snapshot');if(!isHostSnapshot(value))throw new Error('Host snapshot could not be verified.');return value;},
    async history(minutes,appId){const value=await request(`history?minutes=${minutes}${appId?`&app_id=${encodeURIComponent(appId)}`:''}`);if(!isHostHistory(value))throw new Error('Traffic history could not be verified.');return value;},
    async settings(value){const result=await request('settings','PUT',value);if(!settings(result))throw new Error('Settings could not be verified.');return result;},
    async acknowledge(id){await request(`alerts/${id}/acknowledge`,'POST');},
    async firewall(){const value=await request('firewall');if(!rows(value,4096,r=>text(r.name)&&text(r.direction)&&text(r.enabled)&&text(r.action)&&text(r.program)))throw new Error('Firewall rules could not be verified.');return value as FirewallRule[];},
    async control(appId,direction,blocked,expected){const value=await request('firewall','POST',{app_id:appId,direction,blocked,expected_blocked:expected,confirmed:true});if(!record(value)||typeof value.blocked!=='boolean'||value.blocked!==blocked||value.rule_verified!==true||typeof value.all_profiles_enabled!=='boolean')throw new Error('The firewall result could not be verified.');return value as unknown as FirewallReceipt;},
  };
}
