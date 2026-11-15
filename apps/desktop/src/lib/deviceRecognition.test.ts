import {expect,it} from 'vitest';
import {deviceWebUrl,recognizeDevice,webServices} from './deviceRecognition';
import type {DeviceSnapshot} from './api/types';
import type {ScanFinding} from './api/networkScan';
const device={device_id:'11111111-1111-4111-8111-111111111111',owner_name:null,owner_type:null,owner_confirmed:false,identity:{classification:null}} as DeviceSnapshot;
const finding=(facts:Record<string,string>,protocol='tcp'):ScanFinding=>({device_id:device.device_id,address:'192.168.1.2',port:80,status:'open',protocol,facts,service_hint:null,observed_at:'2026-09-06T12:00:00Z'});
it('suggests bounded reported names without overwriting an owner label or guessing from open ports',()=>{
  const clues=[finding({web_status:'200',web_title:'Kitchen Light Main Menu',web_identity_hint:'Tasmota'})];
  expect(recognizeDevice(device,undefined,clues)).toMatchObject({name:'Kitchen Light',kind:'Smart home device',suggestion:{name:'Kitchen Light',source:'Web page on port 80'}});
  expect(recognizeDevice({...device,owner_name:'My chosen name',owner_confirmed:true},undefined,clues).name).toBe('My chosen name');
  expect(recognizeDevice(device,undefined,[finding({})]).kind).toBe('Unidentified device');
  expect(recognizeDevice(device,undefined,[finding({web_status:'200',web_title:'<script>Fake device</script>'})]).suggestion).toBeNull();
  expect(recognizeDevice(device,undefined,[finding({fn:'Living room speaker'},'mdns_bonjour')]).suggestion?.name).toBe('Living room speaker');
  expect(recognizeDevice(device,undefined,[finding({service:'_googlezone._tcp.local'},'mdns_bonjour')]).suggestion).toBeNull();
  expect(recognizeDevice(device,undefined,[finding({service:'Office printer._ipp._tcp.local'},'mdns_bonjour')]).suggestion?.name).toBe('Office printer');
  expect(recognizeDevice(device,undefined,[finding({node_name:'OFFICEPC',node_name_kind:'unique'},'udp.nbns.137')]).suggestion?.name).toBe('OFFICEPC');
  expect(recognizeDevice(device,undefined,[finding({node_name:'WORKGROUP'},'udp.nbns.137')]).suggestion).toBeNull();
});
it('builds links from numeric addresses and validated web schemes only',()=>{
  expect(deviceWebUrl('192.168.1.2',8080,'http')).toBe('http://192.168.1.2:8080/');
  expect(deviceWebUrl('fd00::2',8443,'https')).toBe('https://[fd00::2]:8443/');
  for(const address of ['192.168.001.2','localhost','192.168.1.2@evil.example','evil.example','192.168.1.2/path','fe80::1%4','0x7f000001','127.1'])expect(deviceWebUrl(address,80,'http')).toBeNull();
  expect(deviceWebUrl('192.168.1.2',80,'javascript')).toBeNull();expect(deviceWebUrl('192.168.1.2',65536,'http')).toBeNull();
  expect(webServices([finding({web_scheme:'javascript',web_status:'200',web_redirect:'https://evil.example'})])).toEqual([]);
  expect(webServices([finding({web_scheme:'http',web_status:'302',web_redirect:'https://evil.example'})])[0]?.url).toBe('http://192.168.1.2/');
});
