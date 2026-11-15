import { mount } from 'svelte';
import '../../src/app.css';
import TrafficScope from '../../src/lib/components/TrafficScope.svelte';
const down=[3,4,3,8,5,7,22,12,10,13,6,4,2,3,10,28,20,36,15,12,7,4,5,8,14,9,6,4,12,25,41,22,18,32,20,14,5,4,6,3,9,16,8,5,4,14,24,12,18,10,6,4,8,20,13,6,8,16,10,12];
const up=[1,2,1,3,2,4,7,3,5,2,1,2,1,3,4,2,8,4,6,3,1,2,5,3,7,4,2,1,3,7,11,8,5,9,6,4,2,1,3,2,1,7,5,4,3,9,6,3,5,2,1,3,7,9,5,2,4,7,3,4];
mount(TrafficScope,{target:document.getElementById('scope')!,props:{connected:true,points:down.map((download,i)=>({at:new Date(Date.UTC(2026,10,15,12,0,i)).toISOString(),download:download*125000,upload:up[i]*125000}))}});
