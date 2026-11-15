// @vitest-environment jsdom
import { render, cleanup } from '@testing-library/svelte';
import { afterEach, expect, it } from 'vitest';
import TrafficScope from './TrafficScope.svelte';
afterEach(cleanup);
const points = [{at:'2026-11-15T12:00:00Z',download:1_250_000,upload:125_000},{at:'2026-11-15T12:00:01Z',download:2_500_000,upload:250_000}];
it('shows independent directions with the same scale and actual sample count',()=>{
 const view=render(TrafficScope,{points,connected:true});
 const chart=view.getByRole('img');
 expect(chart.getAttribute('aria-label')).toContain('Download 20 Mbps; upload 2.0 Mbps. 2 samples, shared scale 20 Mbps');
 expect(view.container.querySelectorAll('path.trace')).toHaveLength(2);
});
it('does not present retained samples as live after disconnect',()=>{
 const view=render(TrafficScope,{points,connected:false});
 expect(view.getByText('Signal unavailable')).toBeTruthy();
 expect(view.container.querySelectorAll('path.trace')).toHaveLength(0);
 expect(view.queryByText('20 Mbps')).toBeNull();
});
it('distinguishes measured zero from unavailable and supports a single sample',()=>{
 const view=render(TrafficScope,{connected:true,points:[{at:'2026-11-15T12:00:00Z',download:0,upload:0}]});
 expect(view.getAllByText('0 kbps')).toHaveLength(2);
 expect(view.container.querySelectorAll('rect')).toHaveLength(2);
 expect(view.container.querySelectorAll('path.trace')).toHaveLength(0);
});
it('does not plot invalid negative or nonfinite rates',()=>{
 const view=render(TrafficScope,{connected:true,points:[{at:'x',download:NaN,upload:0},{at:'x',download:0,upload:-1}]});
 expect(view.getByText('Waiting for device counters')).toBeTruthy();
 expect(view.container.querySelectorAll('path.trace')).toHaveLength(0);
});
