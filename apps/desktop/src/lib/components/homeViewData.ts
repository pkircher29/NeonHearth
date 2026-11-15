// Pure derivations that wire live network state into the Home tab (M5 integration · H8).
// Kept out of the component so every mapping rule is unit-testable in plain node.

import type { DeviceSnapshot, PresenceState } from '../api/types';
import { emptyHomePlan, type HomeApi, type HomeDeviceRef, type HomeSnapshot } from '../stores/home';
import type { NetworkDetails } from '../api/automation';
import type { TwinDevice } from '../twin/geometry';
import type { TwinDeviceInfo } from '../twin/twinCard';

/** Editor tray refs: the owner's name when set, otherwise null (the tray labels it). */
export function toHomeDeviceRefs(devices: Record<string, DeviceSnapshot>): HomeDeviceRef[] {
  return Object.values(devices).map((device) => ({ device_id: device.device_id, name: device.owner_name ?? null }));
}

/**
 * Tray refs enriched with what the network view knows: owner name, else the Home Assistant
 * name, else nothing (the tray then labels it by vendor and MAC). Automation-only devices follow.
 */
export function buildDeviceRefs(
  devices: Record<string, DeviceSnapshot>,
  network: Pick<NetworkDetails, 'devices'> | null | undefined,
  automationDevices: ReadonlyArray<{ device_id: string; name: string }> = []
): HomeDeviceRef[] {
  const info = new Map((network?.devices ?? []).map((device) => [device.device_id, device]));
  const live = Object.values(devices).map((device): HomeDeviceRef => {
    const known = info.get(device.device_id);
    return {
      device_id: device.device_id,
      name: device.owner_name ?? known?.home_assistant?.name ?? null,
      vendor: known?.mac_assignments?.find((assignment) => assignment.organization)?.organization ?? known?.home_assistant?.manufacturer ?? null,
      mac: known?.mac_addresses[0] ?? null,
      ip: known?.ip_addresses[0] ?? null
    };
  });
  return [...live, ...automationDevices.map((device) => ({ device_id: device.device_id, name: device.name }))];
}

export function isCameraClassification(classification: string | null): boolean {
  return classification !== null && classification.toLowerCase().includes('camera');
}

/** Twin presentation refs: label = owner name or a short id, camera flag from identity. */
export function toTwinDevices(devices: Record<string, DeviceSnapshot>): TwinDevice[] {
  return Object.values(devices).map((device) => ({
    device_id: device.device_id,
    label: device.owner_name ?? `Device ${device.device_id.slice(0, 8)}`,
    is_camera: isCameraClassification(device.identity.classification)
  }));
}

/**
 * Content equality for twin refs. Live state is replaced on every bandwidth
 * frame; the 3D scene must only rebuild when the device SET or its labels
 * change, so the caller keeps the previous array whenever this holds.
 */
export function sameTwinDevices(previous: TwinDevice[], next: TwinDevice[]): boolean {
  if (previous.length !== next.length) return false;
  for (let index = 0; index < previous.length; index += 1) {
    const a = previous[index]!;
    const b = next[index]!;
    if (a.device_id !== b.device_id || a.label !== b.label || Boolean(a.is_camera) !== Boolean(b.is_camera)) return false;
  }
  return true;
}

/** Detail-card facts per device: the evidence behind its identity and when it was last seen. */
export function toTwinDeviceInfo(devices: Record<string, DeviceSnapshot>): Record<string, TwinDeviceInfo> {
  const map: Record<string, TwinDeviceInfo> = {};
  for (const device of Object.values(devices)) {
    const evidence = device.evidence
      ? [`${device.evidence.family} via ${device.evidence.source} (${Math.round(device.evidence.confidence * 100)}%)`]
      : null;
    map[device.device_id] = { evidence, last_seen_at: device.last_seen_at };
  }
  return map;
}

export function toPresenceMap(devices: Record<string, DeviceSnapshot>): Record<string, PresenceState> {
  const map: Record<string, PresenceState> = {};
  for (const device of Object.values(devices)) map[device.device_id] = device.presence.state;
  return map;
}

/** Total bytes/sec (upload + download) per device; devices without bandwidth data are omitted. */
export function toBandwidthMap(devices: Record<string, DeviceSnapshot>): Record<string, number> {
  const map: Record<string, number> = {};
  for (const device of Object.values(devices)) {
    if (!device.bandwidth.available) continue;
    map[device.device_id] = (device.bandwidth.upload ?? 0) + (device.bandwidth.download ?? 0);
  }
  return map;
}

export function emptyHomeSnapshot(): HomeSnapshot {
  return { plan: emptyHomePlan(), placements: [], estimates: [] };
}

export function isNotFound(error: unknown): boolean {
  return error instanceof Error && /status 404$/.test(error.message);
}

/**
 * The home route may not exist yet in dev: a 404 from fetchHome degrades to an
 * empty-plan snapshot (the editor shows its "no floors yet" state) instead of
 * an error. Every other failure is rethrown so retry states stay honest.
 */
export function withEmptyPlanOn404(apiImpl: HomeApi): HomeApi {
  return {
    ...apiImpl,
    async fetchHome() {
      try {
        return await apiImpl.fetchHome();
      } catch (error) {
        if (isNotFound(error)) return emptyHomeSnapshot();
        throw error;
      }
    }
  };
}
