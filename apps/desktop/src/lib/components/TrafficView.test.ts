// @vitest-environment jsdom
import {cleanup,fireEvent,render} from '@testing-library/svelte';
import {afterEach,expect,it,vi} from 'vitest';
import TrafficView from './TrafficView.svelte';
import type {HostApi,HostSnapshot,HostHistory} from '../api/hostMonitor';
afterEach(cleanup);
const at='2026-09-06T12:00:00Z';
const snapshot:HostSnapshot={observed_at:at,status:'ready',detail:'This computer only.',interfaces:[],applications:[],connections:[],upload_bytes_per_second:125000,download_bytes_per_second:null,app_counters:'requires_elevation',firewall_available:false,memory_total_bytes:null,memory_available_bytes:null};
const history:HostHistory={since:at,until:at,bucket_seconds:60,scope:'host',coverage:'physical_interfaces',points:[],applications:[{app_id:'a'.repeat(64),name:'<img src=x onerror=alert(1)>.exe',executable:'C:/Apps/test.exe',first_seen_at:at,last_seen_at:at,sent_bytes:0,received_bytes:0,samples:0}],connections:[],alerts:[],settings:{record_history:true,snooze_until:null,retention_days:30,monthly_budget_bytes:null}};
const client=():HostApi=>({snapshot:vi.fn(async()=>snapshot),history:vi.fn(async()=>history),settings:vi.fn(async v=>v),acknowledge:vi.fn(async()=>{}),firewall:vi.fn(async()=>[]),control:vi.fn(async()=>({blocked:true,rule_verified:true,all_profiles_enabled:true}))});
it('labels unavailable measurements and restricts firewall controls when OS authority is unavailable',async()=>{
  const api=client();const view=render(TrafficView,{api});
  expect(await view.findByText('1.0 Mbps')).toBeTruthy();expect(view.getByText(/administrator permission/)).toBeTruthy();
  await fireEvent.click(view.getByRole('button',{name:'Applications'}));
  expect(await view.findByText('<img src=x onerror=alert(1)>.exe')).toBeTruthy();expect(view.container.querySelector('img')).toBeNull();
  expect((view.getByRole('button',{name:'Block outbound'}) as HTMLButtonElement).disabled).toBe(true);expect(api.control).not.toHaveBeenCalled();
  expect(view.getAllByText('Not measured').length).toBeGreaterThan(0);
});
it('switches time ranges through the history API and keeps preference writes explicit',async()=>{
  const api=client();const view=render(TrafficView,{api});await view.findByText('This computer only.');
  await fireEvent.change(view.getByRole('combobox',{name:'Time range'}),{target:{value:'1440'}});
  expect(api.history).toHaveBeenLastCalledWith(1440,undefined);expect(api.settings).not.toHaveBeenCalled();
  await fireEvent.click(view.getByRole('button',{name:'Preferences'}));
  await fireEvent.click(view.getByRole('checkbox',{name:'Record traffic and connection history'}));
  expect(api.settings).toHaveBeenCalledWith(expect.objectContaining({record_history:false}));
});
it('keeps live applications and endpoints visible with recording disabled and no saved history',async()=>{
  const api=client();const id='b'.repeat(64);
  api.snapshot=async()=>({...snapshot,applications:[{app_id:id,name:'Live player.exe',executable:'C:/Apps/Live player.exe',pid:45,started:at,cpu_time_ms:null,memory_bytes:1024}],connections:[{connection_id:'live',app_id:id,pid:45,protocol:'tcp',local_address:'192.0.2.1',local_port:4321,remote_address:'192.0.2.2',remote_port:443,state:'established',sent_bytes:null,received_bytes:null}]});
  api.history=async()=>({...history,applications:[],settings:{...history.settings,record_history:false}});
  const view=render(TrafficView,{api});await view.findByText('This computer only.');
  await fireEvent.click(view.getByRole('button',{name:'Applications'}));
  expect(await view.findByText('Live player.exe')).toBeTruthy();expect(view.getByText('Not recorded')).toBeTruthy();
  await fireEvent.click(view.getByRole('button',{name:'View connections'}));
  expect(await view.findByText(/192\.0\.2\.2:443/)).toBeTruthy();expect(view.getByText('established')).toBeTruthy();
});
it('does not report a missing live snapshot as zero connections',async()=>{
  const api=client();api.snapshot=async()=>({...snapshot,status:'unavailable',upload_bytes_per_second:null});
  const view=render(TrafficView,{api});await view.findByText('This computer only.');
  expect(view.getAllByText('Unavailable')).toHaveLength(2);
});
