// @vitest-environment jsdom
import {cleanup,fireEvent,render} from '@testing-library/svelte';
import {afterEach,expect,it,vi} from 'vitest';
import DeviceNameConfirmation from './DeviceNameConfirmation.svelte';
afterEach(cleanup);
const device={device_id:'11111111-1111-4111-8111-111111111111',owner_name:null,owner_confirmed:false};
it('requires an explicit name confirmation and reports a verified save without a policy action',async()=>{
  const saved={...device,owner_name:'Kitchen light',owner_confirmed:true};const onsaved=vi.fn();const api={list:vi.fn(async()=>[]),confirm:vi.fn(async()=>saved)};
  const view=render(DeviceNameConfirmation,{device,suggestion:{name:'Kitchen light',source:'Bonjour / mDNS'},api,onsaved});
  expect(api.confirm).not.toHaveBeenCalled();expect(view.getByText(/does not approve network access/)).toBeTruthy();
  await fireEvent.click(view.getByRole('button',{name:'Confirm name'}));
  expect(api.confirm).toHaveBeenCalledWith(device,'Kitchen light');expect(onsaved).toHaveBeenCalledWith(saved);
});
it('keeps the reviewed baseline while editing and surfaces conflicts',async()=>{
  const api={list:vi.fn(async()=>[]),confirm:vi.fn(async()=>{throw new Error('The name changed in another window.');})};const onsaved=vi.fn();
  const view=render(DeviceNameConfirmation,{device,suggestion:{name:'Kitchen light',source:'Web'},api,onsaved});
  await fireEvent.click(view.getByRole('button',{name:'Edit name'}));await fireEvent.input(view.getByRole('textbox',{name:'Device name'}),{target:{value:'My lamp'}});
  await fireEvent.submit(view.container.querySelector('form')!);
  expect(api.confirm).toHaveBeenCalledWith(device,'My lamp');expect(view.getByRole('alert').textContent).toContain('another window');expect(onsaved).not.toHaveBeenCalled();
});
