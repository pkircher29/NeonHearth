import type {LiveState} from './stores/live';
import type {NetworkDetails} from './api/automation';
import type {ScanStatus} from './api/networkScan';
import type {NetworkSnapshot,NetworkPresence} from './api/networkMonitor';
import {recognizeDevice} from './deviceRecognition';
import type {DeviceSnapshot} from './api/types';
import type {IconName} from './components/Icon.svelte';
export interface InventoryRow {key:string;device:DeviceSnapshot|null;name:string;kind:string;icon:IconName;ips:string[];macs:string[];maker:string;room:string|null;first:string;last:string;presence:NetworkPresence|null}
export function networkInventory(state:LiveState,details:NetworkDetails|null,monitor:NetworkSnapshot|null,scan:ScanStatus|null):InventoryRow[] {
  const result:InventoryRow[]=[];const consumed=new Set<string>();
  for(const id of state.deviceOrder){
    const device=state.devices[id];if(!device)continue;
    let info=details?.devices.find(d=>d.device_id===id);
    const matches=monitor?.devices.filter(s=>s.device_id===id||(!s.device_id&&info?.mac_addresses.some(m=>m.toUpperCase()===s.mac.toUpperCase()))).sort((a,b)=>b.last_seen.localeCompare(a.last_seen))??[];
    const sighting=matches[0]??null;
    for(const s of matches)consumed.add(`${s.interface}/${s.mac}`);
    info??=sighting?{device_id:id,mac_addresses:matches.map(s=>s.mac),ip_addresses:matches.map(s=>s.ip),home_assistant:null}:undefined;
    const macs=info?.mac_addresses??[];
    const identity=recognizeDevice(device,info,scan?.findings.filter(f=>f.device_id===id));
    result.push({key:id,device,name:identity.name,kind:identity.kind,icon:identity.icon,ips:[...new Set([...(info?.ip_addresses??[]),...(sighting?[sighting.ip]:[])])],macs,maker:info?.mac_assignments?.map(a=>a.organization).filter(Boolean).join(' · ')||sighting?.manufacturer||'',room:identity.room,first:device.first_seen_at,last:sighting?.last_seen??device.last_seen_at,presence:sighting});
  }
  for(const sighting of monitor?.devices??[]){const key=`${sighting.interface}/${sighting.mac}`;if(consumed.has(key))continue;
    result.push({key,device:null,name:`Device ${sighting.mac}`,kind:'Newly discovered device',icon:'unknown-device',ips:[sighting.ip],macs:[sighting.mac],maker:sighting.manufacturer??'',room:null,first:sighting.first_seen,last:sighting.last_seen,presence:sighting});}
  return result;
}
export function responseLabel(p:NetworkPresence|null,interval:number,now=Date.now()):string {
  if(!p)return 'No active discovery result';
  if(p.missed>=2)return 'Not responding';
  if(now-Date.parse(p.last_seen)>Math.max(interval*2,180)*1000)return 'Last response is old';
  return p.missed?'Response missed':'Responding';
}
