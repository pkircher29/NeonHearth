// @vitest-environment jsdom
import {cleanup,fireEvent,render,waitFor} from '@testing-library/svelte';
import {afterEach,expect,it,vi} from 'vitest';
import NetworkTrafficView from './NetworkTrafficView.svelte';
import {initialLiveState} from '../stores/live';
import {isNetworkSnapshot,type NetworkApi,type NetworkSnapshot} from '../api/networkMonitor';
import {networkInventory,responseLabel} from '../networkInventory';
import type {DeviceSnapshot} from '../api/types';
import type {HostApi} from '../api/hostMonitor';
afterEach(cleanup);
function fixture():NetworkSnapshot {const at=new Date().toISOString();return {
  settings:{discovery_enabled:false,interval_seconds:120,router_ip:'192.168.1.1',router_port:8080},router:{status:'ready',observed_at:at,source:'192.168.1.1:8080',download:125000,upload:1000,connected_devices:12},
  discovery:{state:'complete',started_at:at,finished_at:at,total:253,completed:253,responding:2,errors:0,skipped_networks:0},
  devices:[10,2].map(n=>({interface:20,ip:`192.168.1.${n}`,mac:`02:00:00:00:00:${n}`,first_seen:at,last_seen:at,missed:0})),events:[],points:[{at:Math.floor(Date.now()/1000),download:125000,upload:1000,samples:1}],bucket_seconds:2};}
it('shows router traffic and every discovered device by numeric IP without inventing device counters',async()=>{
  const value=fixture();const api:NetworkApi={snapshot:vi.fn(async()=>value),settings:vi.fn(async v=>v),discover:vi.fn(async()=>{}),cancel:vi.fn(async()=>{})};
  const hostApi={snapshot:vi.fn()} as unknown as HostApi;
  const view=render(NetworkTrafficView,{api,hostApi,liveState:initialLiveState,onselectdevice:vi.fn()});
  expect((await view.findAllByText('1.0 Mbps')).length).toBeGreaterThan(0);expect(hostApi.snapshot).not.toHaveBeenCalled();
  let cards=view.container.querySelectorAll('.network-device');expect(cards).toHaveLength(2);expect(cards[0]?.textContent).toContain('192.168.1.2');
  expect(view.getAllByText('Unavailable · no per-device counter source')).toHaveLength(2);
  await fireEvent.change(view.getByRole('combobox',{name:'Sort devices'}),{target:{value:'ip-desc'}});
  cards=view.container.querySelectorAll('.network-device');expect(cards[0]?.textContent).toContain('192.168.1.10');
  await fireEvent.input(view.getByRole('textbox',{name:'Search all devices'}),{target:{value:'192.168.1.10'}});expect(view.container.querySelectorAll('.network-device')).toHaveLength(1);
  await fireEvent.click(view.getByRole('button',{name:'Discover devices now'}));await waitFor(()=>expect(api.discover).toHaveBeenCalledTimes(1));
  expect(api.settings).not.toHaveBeenCalled();
});
it('validates rate data and keeps old or missed observations distinct from current responses',()=>{
  const value=fixture();expect(isNetworkSnapshot(value)).toBe(true);
  expect(isNetworkSnapshot({...value,router:{...value.router,download:NaN}})).toBe(false);
  expect(isNetworkSnapshot({...value,devices:Array(4097).fill(value.devices[0])})).toBe(false);
  expect(responseLabel({...value.devices[0]!,missed:2},120)).toBe('Not responding');
  expect(responseLabel({...value.devices[0]!,last_seen:'2000-01-01T00:00:00Z'},120)).toBe('Last response is old');
  expect(responseLabel(null,120)).toBe('No active discovery result');
});
it('correlates saved device IDs before slow address enrichment arrives without duplicate inventory rows',()=>{
  const monitor=fixture();monitor.devices=[{...monitor.devices[0]!,device_id:'saved-device',manufacturer:'Test maker'}];
  const at=new Date().toISOString();
  const device:DeviceSnapshot={device_id:'saved-device',owner_name:'Confirmed lamp',owner_type:null,owner_confirmed:true,first_seen_at:at,last_seen_at:at,evidence:null,identity:{available:false,classification:null,confidence:null},presence:{state:'quiet',observed_at:at,source:null,kind:null},bandwidth:{available:false,upload:null,download:null,coverage:null,observed_at:null},policy:null};
  const rows=networkInventory({...initialLiveState,deviceOrder:[device.device_id],devices:{[device.device_id]:device}},null,monitor,null);
  expect(rows).toHaveLength(1);expect(rows[0]?.name).toBe('Confirmed lamp');expect(rows[0]?.ips).toEqual(['192.168.1.10']);expect(rows[0]?.maker).toBe('Test maker');
  expect(device.presence.state).toBe('quiet');expect(device.owner_confirmed).toBe(true);
});
