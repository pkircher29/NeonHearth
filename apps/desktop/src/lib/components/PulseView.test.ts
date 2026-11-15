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

it('shows the angular Pulse overview without a decorative network visualization',()=>{
  const view=render(PulseView,{state:{...initialLiveState,connected:true}});
  expect(view.getByRole('heading',{name:'Network control.'})).toBeTruthy();
  expect(view.getByRole('heading',{name:'Traffic scope'})).toBeTruthy();
  expect(view.queryByRole('img',{name:/Network (flow map|hearth):/})).toBeNull();
  expect(view.queryByRole('group',{name:'Pulse visual'})).toBeNull();
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
