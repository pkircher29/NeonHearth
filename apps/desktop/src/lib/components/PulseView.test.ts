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
  expect(household.textContent).toContain('Predator Connect W6');
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

it('shows the Flow Map by default, can switch to the Hearth, and remembers the choice',async()=>{
  const memory=new Map<string,string>();
  vi.stubGlobal('localStorage',{getItem:(k:string)=>memory.get(k)??null,setItem:(k:string,v:string)=>{memory.set(k,v);},removeItem:(k:string)=>{memory.delete(k);}});
  const first=render(PulseView,{state:{...initialLiveState,connected:true}});
  expect(first.getByRole('img',{name:/Network flow map:/})).toBeTruthy();
  expect(first.getByRole('complementary',{name:'How to read the flow map'})).toBeTruthy();
  expect(first.getByText(/The flow map below uses per-device counters/)).toBeTruthy();
  expect(first.getByRole('button',{name:'Flow'}).getAttribute('aria-pressed')).toBe('true');
  await fireEvent.click(first.getByRole('button',{name:'Hearth'}));
  expect(first.getByRole('img',{name:/Network hearth:/})).toBeTruthy();
  expect(first.getByRole('complementary',{name:'How to read the hearth'})).toBeTruthy();
  expect(first.getByText(/The hearth below uses per-device counters/)).toBeTruthy();
  expect(first.queryByRole('img',{name:/Network flow map:/})).toBeNull();
  first.unmount();
  const second=render(PulseView,{state:{...initialLiveState,connected:true}});
  expect(second.getByRole('img',{name:/Network hearth:/})).toBeTruthy();
  expect(memory.get('neonhearth.pulse.hero')).toBe('hearth');
  vi.unstubAllGlobals();
});
