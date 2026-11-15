import type { DeviceSnapshot } from './api/types';
import type { NetworkDetails } from './api/automation';
import type { ScanFinding } from './api/networkScan';
import { validDeviceName } from './api/deviceLabels';
import { ipSortKey } from './ipSort';
import type { IconName } from './components/Icon.svelte';

export type NetworkDevice = NetworkDetails['devices'][number];
export interface NameSuggestion { name: string; source: string }
export interface DeviceRecognition {
  name: string; suggestion: NameSuggestion | null; kind: string; icon: IconName;
  manufacturer: string | null; model: string | null; room: string | null; sources: string[];
}
export function findingsByDevice(findings: ScanFinding[]): Map<string, ScanFinding[]> {
  const grouped = new Map<string, ScanFinding[]>();
  for (const finding of findings) {
    if (!finding.device_id) continue;
    const rows = grouped.get(finding.device_id) ?? []; rows.push(finding); grouped.set(finding.device_id, rows);
  }
  return grouped;
}
const genericName = /^(?:home|welcome|index|login|sign in|main menu|web (?:server|interface)|admin(?:istration)?|dashboard|router|unknown|device)(?: page)?$/i;
function candidate(raw: string | null | undefined, source: string): NameSuggestion | null {
  const name = raw?.replace(/\s+[·|–-]\s+Main Menu$/i, '').replace(/\s+Main Menu$/i, '').replace(/\.local\.?$/i, '').trim();
  return name && validDeviceName(name) && !genericName.test(name) && !/^[_.]|[<>]/.test(name) ? {name, source} : null;
}
export function recognizeDevice(device: DeviceSnapshot, info?: NetworkDevice, findings: ScanFinding[] = []): DeviceRecognition {
  const ha = info?.home_assistant;
  const observed = findings.filter(f => ['open','responded','identified'].includes(f.status));
  const candidates: NameSuggestion[] = [];
  const add = (name: string | null | undefined, source: string) => { const v = candidate(name, source); if (v) candidates.push(v); };
  add(ha?.name, 'Home Assistant');
  for (const f of observed) {
    const facts = f.facts;
    if (f.protocol.startsWith('mdns')) {
      add(facts.fn, 'Bonjour / mDNS');
      if (facts.service?.includes('._')) add(facts.service.split('._')[0], 'Bonjour / mDNS');
      add(facts.endpoint?.replace(/:\d+$/, ''), 'Bonjour / mDNS');
    }
    if ((f.protocol === 'netbios' || f.protocol === 'udp.nbns.137') && facts.node_name_kind === 'unique') add(facts.node_name, 'NetBIOS');
    if (f.protocol.startsWith('snmp') || f.protocol === 'udp.snmp.161') add(facts.sys_name ?? facts.system_name ?? facts.sysName, 'SNMP');
    if (facts.web_status) add(facts.web_title ?? facts.web_auth_realm, `Web page on port ${f.port}`);
  }
  const suggestion = candidates[0] ?? null;
  const mdns = observed.find(f => f.protocol.startsWith('mdns'))?.facts;
  const manufacturer = ha?.manufacturer ?? mdns?.manufacturer ?? null;
  const model = ha?.model ?? mdns?.model ?? mdns?.md ?? mdns?.am ?? mdns?.ty ?? null;
  // Port numbers and network-chip vendors alone never establish device type.
  const clues = [device.owner_type, device.identity.classification, model,
    ...observed.flatMap(f => [f.facts.web_identity_hint, f.facts.service])].filter(Boolean).join(' ').toLowerCase();
  let kind = 'Unidentified device'; let icon: IconName = 'unknown-device';
  for (const [pattern,label,glyph] of [
    [/camera|reolink|hikvision|amcrest|_onvif/, 'Camera', 'cameras'],
    [/synology|qnap|nas\b/, 'Storage', 'server'],
    [/proxmox|server|pi-hole|adguard/, 'Server', 'server'],
    [/home assistant|_hap\.|_home-assistant|hub\b/, 'Automation hub', 'home'],
    [/openwrt|mikrotik|unifi|fritz|router|switch|access point/, 'Network equipment', 'router'],
    [/printer|_ipp\.|_ipps\.|_printer\./, 'Printer', 'printer'],
    [/iphone|android|smartphone|phone\b/, 'Phone', 'phone'],
    [/ipad|tablet/, 'Tablet', 'phone'],
    [/appletv|chromecast|_googlecast|_airplay|television|\btv\b/, 'Media device', 'devices'],
    [/tasmota|esphome|shelly|smart plug|light|sensor/, 'Smart home device', 'smart-device'],
    [/macbook|windows|computer|desktop|laptop/, 'Computer', 'devices'],
  ] as Array<[RegExp,string,IconName]>) { if (pattern.test(clues)) { kind = label; icon = glyph; break; } }
  return { name: device.owner_name ?? suggestion?.name ?? (info?.mac_addresses[0] ? `Device ${info.mac_addresses[0]}` : `Device …${device.device_id.slice(-8)}`),
    suggestion, kind, icon, manufacturer, model, room: ha?.area ?? null,
    sources: [...new Set([ha ? 'Home Assistant' : '', ...observed.filter(f => Object.keys(f.facts).length).map(f => f.facts.web_status ? 'Web page' : f.protocol.toUpperCase())].filter(Boolean))] };
}

/** Never navigate to a hostname, redirect, or URL supplied by a device. */
export function deviceWebUrl(address: string, port: number | null, scheme: string): string | null {
  if (!port || !Number.isInteger(port) || port < 1 || port > 65535 || !['http','https'].includes(scheme) || /[%\s\[\]]/.test(address)) return null;
  const key = ipSortKey(address);
  if (!key) return null;
  if (key[0] === 4 && address !== key.slice(1).join('.')) return null;
  const host = key[0] === 6 ? `[${address}]` : address;
  try { const url = new URL(`${scheme}://${host}:${port}/`); return url.href; } catch { return null; }
}
export function webServices(findings: ScanFinding[]) {
  const links = new Map<string, {url: string; label: string; unverified: boolean; address: string}>();
  for (const f of findings) {
    if (f.protocol !== 'tcp' || f.status !== 'open') continue;
    const scheme = f.facts.web_status ? f.facts.web_scheme : ({HTTP:'http',HTTPS:'https'} as Record<string,string>)[f.service_hint?.toUpperCase() ?? ''];
    const url = scheme ? deviceWebUrl(f.address, f.port, scheme) : null;
    if (url) links.set(url, {url,label:`Open ${scheme.toUpperCase()} ${f.port}`,unverified:!f.facts.web_status || f.facts.certificate_trust === 'unverified',address:f.address});
  }
  return [...links.values()];
}
