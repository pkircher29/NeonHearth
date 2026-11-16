// @vitest-environment jsdom
import {cleanup,fireEvent,render} from '@testing-library/svelte';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import PulseView from './PulseView.svelte';
import {initialLiveState} from '../stores/live';
import type {NetworkSnapshot} from '../api/networkMonitor';

beforeEach(()=>vi.spyOn(HTMLCanvasElement.prototype,'getContext').mockReturnValue(null));
afterEach(()=>{cleanup();vi.restoreAllMocks();});

function router(status='ready'):NetworkSnapshot {
  return {
    settings:{discovery_enabled:false,interval_seconds:120,router_ip:'192.168.1.1',router_port:8080},
    router:{status,observed_at:new Date().toISOString(),source:'192.168.1.1:8080',download:2500000,upload:125000,connected_devices:4},
    discovery:{state:'idle',started_at:null,finished_at:null,total:0,completed:0,responding:0,errors:0,skipped_networks:0},
    devices:[],events:[],points:[],bucket_seconds:1,
  };
}

it('explains a connected collector without device counters instead of asking to pair again',()=>{
  const view=render(PulseView,{state:{...initialLiveState,connected:true,serviceStatus:'ready'}});
  expect(view.getByText('Live readings connected')).toBeTruthy();
  expect(view.queryByText('Unavailable until paired')).toBeNull();
  expect(view.queryByText(/until the collector has a protected connection/)).toBeNull();
  expect(view.getByText('No per-device counter source')).toBeTruthy();
  expect(view.getByText('No recent events. The collector is connected.')).toBeTruthy();
});

it('shows router WAN rates separately without turning household totals into device usage',async()=>{
  const open=vi.fn();
  const view=render(PulseView,{state:{...initialLiveState,connected:true},network:router(),onopentraffic:open});
  const household=view.getByRole('region',{name:'Household internet traffic'});
  expect(household.textContent).toContain('20 Mbps');
  expect(household.textContent).toContain('1.0 Mbps');
  expect(household.textContent).not.toContain('Predator');
  expect(household.textContent).toContain('router-reported internet totals');
  expect(view.getByText('No per-device counter source')).toBeTruthy();
  expect(view.getByText('No usage data yet')).toBeTruthy();
  await fireEvent.click(view.getByRole('button',{name:'Open Traffic'}));
  expect(open).toHaveBeenCalledOnce();
});

it('hides stale router numbers and gives a setup route when its source is unavailable',()=>{
  const view=render(PulseView,{state:{...initialLiveState,connected:true},network:router('stale'),onopentraffic:vi.fn()});
  expect(view.queryByText('20 Mbps')).toBeNull();
  expect(view.getByRole('button',{name:'Open Traffic'})).toBeTruthy();
  expect(view.getByText(/No fresh router readings/)).toBeTruthy();
});

it('keeps a valid measured zero distinct from missing household measurements',()=>{
  const value=router();value.router.download=0;value.router.upload=0;
  const view=render(PulseView,{state:{...initialLiveState,connected:true},network:value,onopentraffic:vi.fn()});
  expect(view.getByRole('region',{name:'Household internet traffic'}).textContent).toContain('0 kbps');
  expect(view.queryByText(/No fresh router readings/)).toBeNull();
});

it('shows the traffic scope and the Flow Map together, with the angular overview heading',()=>{
  const view=render(PulseView,{state:{...initialLiveState,connected:true}});
  expect(view.getByRole('heading',{name:'Network control.'})).toBeTruthy();
  expect(view.getByRole('heading',{name:'Traffic scope'})).toBeTruthy();
  expect(view.getByRole('heading',{name:'Flow map'})).toBeTruthy();
  expect(view.getByRole('img',{name:/Network flow map:/})).toBeTruthy();
  expect(view.getByRole('complementary',{name:'How to read the flow map'})).toBeTruthy();
  view.unmount();
});

it('shows the Flow Map by default, can switch to the Hearth, and remembers the choice',async()=>{
  const memory=new Map<string,string>();
  vi.stubGlobal('localStorage',{getItem:(k:string)=>memory.get(k)??null,setItem:(k:string,v:string)=>{memory.set(k,v);},removeItem:(k:string)=>{memory.delete(k);}});
  const first=render(PulseView,{state:{...initialLiveState,connected:true}});
  expect(first.getByRole('img',{name:/Network flow map:/})).toBeTruthy();
  expect(first.getByRole('button',{name:'Flow'}).getAttribute('aria-pressed')).toBe('true');
  await fireEvent.click(first.getByRole('button',{name:'Hearth'}));
  expect(first.getByRole('img',{name:/Network hearth:/})).toBeTruthy();
  expect(first.getByRole('heading',{name:'Hearth'})).toBeTruthy();
  expect(first.getByRole('complementary',{name:'How to read the hearth'})).toBeTruthy();
  expect(first.queryByRole('img',{name:/Network flow map:/})).toBeNull();
  // The traffic scope stays whichever visual is chosen.
  expect(first.getByRole('heading',{name:'Traffic scope'})).toBeTruthy();
  first.unmount();
  const second=render(PulseView,{state:{...initialLiveState,connected:true}});
  expect(second.getByRole('img',{name:/Network hearth:/})).toBeTruthy();
  expect(memory.get('neonhearth.pulse.hero')).toBe('hearth');
  second.unmount();
  vi.unstubAllGlobals();
});

it('still switches visuals when browser storage throws',async()=>{
  const boom=()=>{throw new Error('storage blocked');};
  vi.stubGlobal('localStorage',{getItem:boom,setItem:boom,removeItem:boom});
  const view=render(PulseView,{state:{...initialLiveState,connected:true}});
  expect(view.getByRole('img',{name:/Network flow map:/})).toBeTruthy();
  await fireEvent.click(view.getByRole('button',{name:'Hearth'}));
  expect(view.getByRole('img',{name:/Network hearth:/})).toBeTruthy();
  view.unmount();
  vi.unstubAllGlobals();
});

it('says plainly that per-device traffic is unavailable and invents no flows when there are no counters',()=>{
  const view=render(PulseView,{state:{...initialLiveState,connected:true},network:router(),onopentraffic:vi.fn()});
  expect(view.getByRole('note').textContent).toContain('Per-device traffic is unavailable');
  expect(view.getByRole('note').textContent).not.toContain('uses per-device counters');
  expect(view.getByRole('img',{name:/Network flow map:/}).getAttribute('aria-label')).not.toMatch(/Top talkers/);
  // Router totals stay in the household card and are not fed to the map as device traffic.
  expect(view.getByRole('region',{name:'Household internet traffic'}).textContent).toContain('20 Mbps');
  expect(view.queryByText(/This computer/)).toBeNull();
  view.unmount();
});

it('says the collector is down rather than implying per-device data when disconnected',()=>{
  const view=render(PulseView,{state:{...initialLiveState,connected:false}});
  expect(view.getByRole('note').textContent).toContain('collector connection is down');
  view.unmount();
});

it('falls back to the host computer traffic, and says so, when per-device counters are unavailable',async()=>{
  const host={observed_at:new Date().toISOString(),status:'ready',detail:'This computer only.',interfaces:[],applications:[],connections:[],upload_bytes_per_second:1_000_000,download_bytes_per_second:50_000,app_counters:'sampled_tcp',firewall_available:false,memory_total_bytes:null,memory_available_bytes:null};
  const hostApi={snapshot:vi.fn(async()=>host)} as never;
  const automationApi={network:vi.fn(async()=>({status:'ready',observed_at:'',devices:[]}))} as never;
  const view=render(PulseView,{state:{...initialLiveState,connected:true},hostApi,automationApi});
  expect(await view.findByText(/shows this computer's live traffic/)).toBeTruthy();
  expect(view.getByText('This computer')).toBeTruthy();
  expect(view.getByRole('img',{name:/showing this computer only/})).toBeTruthy();
  expect(view.getByText(/not whole-home traffic/,{selector:'dd'})).toBeTruthy();
  view.unmount();
});

it('does not poll the host and keeps the per-device wording when per-device counters exist',async()=>{
  const hostApi={snapshot:vi.fn()} as never;
  const live={...initialLiveState,connected:true,throughput:[{at:'t',upload:1,download:1}],aggregate:{upload:1,download:1}};
  const view=render(PulseView,{state:live,hostApi});
  expect(view.getByText(/The flow map below uses per-device counters/)).toBeTruthy();
  expect((hostApi as {snapshot:ReturnType<typeof vi.fn>}).snapshot).not.toHaveBeenCalled();
  view.unmount();
});

it('says which side is missing instead of adding a fake zero, and drops the protocol-mix placeholder',()=>{
  const live={...initialLiveState,connected:true,aggregate:{upload:null,download:5_000_000}};
  const view=render(PulseView,{state:live});
  expect(view.getByText('Only download is reported')).toBeTruthy();
  const throughput=view.container.querySelector('.metrics article')!;
  expect(throughput.textContent).toContain('unavailable');
  expect(view.queryByText('PROTOCOL MIX')).toBeNull();
  expect(view.queryByText(/protocol mix/i)).toBeNull();
  view.unmount();
});

it('treats a connected stream with no fresh device readings as no throughput, not zero',()=>{
  const live={...initialLiveState,connected:true,aggregate:{upload:null,download:null},throughput:[{at:'2026-08-23T00:00:00Z',upload:9,download:9}]};
  const view=render(PulseView,{state:live});
  expect(view.getByText('No per-device counter source')).toBeTruthy();
  expect(view.container.querySelector('.metrics strong')!.textContent).toBe('unavailable');
  view.unmount();
});

it('lifts the pen across a time gap in the throughput curve instead of drawing over missing data',()=>{
  const at=(s:number)=>new Date(Date.UTC(2026,7,23,0,0,s)).toISOString();
  const live={...initialLiveState,connected:true,aggregate:{upload:1,download:1},throughput:[{at:at(0),upload:1,download:1},{at:at(1),upload:2,download:2},{at:at(60),upload:3,download:3},{at:at(61),upload:1,download:1}]};
  const view=render(PulseView,{state:live});
  const path=view.container.querySelector('.trace.down')!.getAttribute('d')!;
  expect(path.match(/M/g)!.length).toBe(2);
  expect(path.match(/L/g)!.length).toBe(2);
  view.unmount();
});

it('names the configured router source instead of a hard-coded model',()=>{
  const view=render(PulseView,{state:{...initialLiveState,connected:true},network:{...router(),router:{...router().router,source:'Acme AX7000'}},onopentraffic:()=>{}});
  expect(view.getByRole('region',{name:'Household internet traffic'}).textContent).toContain('Acme AX7000 · router-reported internet totals');
  view.unmount();
});

it('says plainly that a connected router sends no speed totals yet, without rates or zeros',()=>{
  const network={...router('connected'),router:{status:'connected',observed_at:new Date().toISOString(),source:'192.168.1.1:8080',download:null,upload:null,connected_devices:12}};
  const view=render(PulseView,{state:{...initialLiveState,connected:true},network,onopentraffic:vi.fn()});
  const household=view.getByRole('region',{name:'Household internet traffic'});
  expect(household.textContent).toContain('Router connected, no internet speed yet');
  expect(household.textContent).toContain('reports 12 devices');
  expect(household.textContent).toContain('admin page is open and signed in');
  expect(household.textContent).not.toContain('Household traffic is available');
  expect(household.textContent).not.toContain('No fresh router readings');
  expect(household.textContent).not.toMatch(/kbps|Mbps|Gbps/);
});
