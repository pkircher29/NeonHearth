// Pure view-model for the twin's device detail card and room tooltip (spec E).

import type { PresenceState } from '../api/types';
import { roomAtPoint, type DevicePin, type HomePlan, type TwinDevice } from './geometry';

export const MISSING = '—'; // em dash for any value we do not have

/** Live per-device facts that must not trigger a scene rebuild when they change. */
export interface TwinDeviceInfo {
  evidence?: string[] | null;
  last_seen_at?: string | null;
}

export interface PinCard {
  device_id: string;
  name: string;
  presence: string;
  room: string;
  evidence: string;
  lastSeen: string;
}

const PRESENCE_LABEL: Record<string, string> = {
  online: 'Online',
  offline: 'Offline',
  unknown: 'Unknown'
};

export function presenceLabel(state: PresenceState | string | null | undefined): string {
  if (!state) return MISSING;
  return PRESENCE_LABEL[state] ?? state.charAt(0).toUpperCase() + state.slice(1);
}

/** Room area as shown on hover: one decimal, square meters. */
export function formatArea(area_m2: number | null | undefined): string {
  if (typeof area_m2 !== 'number' || !Number.isFinite(area_m2)) return MISSING;
  return `${area_m2.toFixed(1)} m²`;
}

export function formatList(values: string[] | null | undefined): string {
  const clean = (values ?? []).map((value) => value.trim()).filter((value) => value.length > 0);
  return clean.length > 0 ? clean.join(', ') : MISSING;
}

/** Local, compact timestamp; anything unparsable is an honest dash. */
export function formatLastSeen(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return MISSING;
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return MISSING;
  const seconds = Math.round((now.getTime() - at.getTime()) / 1000);
  if (seconds >= 0 && seconds < 60) return 'Just now';
  if (seconds >= 60 && seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds >= 3600 && seconds < 86_400) return `${Math.floor(seconds / 3600)} h ago`;
  return at.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function buildPinCard(
  pin: DevicePin,
  plan: HomePlan | null,
  device: TwinDevice | undefined,
  info: TwinDeviceInfo | undefined,
  presence: PresenceState | undefined,
  now: Date = new Date()
): PinCard {
  const floor = plan?.floors.find((candidate) => candidate.floor_id === pin.floor_id);
  const room = floor ? roomAtPoint(floor, pin.position) : null;
  return {
    device_id: pin.device_id,
    name: pin.label,
    presence: presenceLabel(presence ?? 'unknown'),
    room: room?.name?.trim() ? room.name : MISSING,
    evidence: formatList(info?.evidence ?? device?.evidence),
    lastSeen: formatLastSeen(info?.last_seen_at ?? device?.last_seen_at, now)
  };
}
