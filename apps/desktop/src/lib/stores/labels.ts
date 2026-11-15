import type { DeviceSnapshot } from '../api/types';
import type { DeviceLabel } from '../api/deviceLabels';

type Entry = { source: DeviceSnapshot; label: DeviceLabel | undefined; merged: DeviceSnapshot };

/**
 * Overlays owner labels on live devices without rebuilding unchanged ones: a
 * device whose snapshot object and label object are both the same as last time
 * keeps its previous merged object, so a 4 Hz bandwidth frame only allocates
 * for the devices that actually changed.
 */
export function createLabelMerger() {
  let cache = new Map<string, Entry>();
  let previousOut: Record<string, DeviceSnapshot> | null = null;
  return function merge(devices: Record<string, DeviceSnapshot>, labels: Record<string, DeviceLabel>): Record<string, DeviceSnapshot> {
    const next = new Map<string, Entry>();
    const out: Record<string, DeviceSnapshot> = {};
    let changed = previousOut === null || Object.keys(devices).length !== Object.keys(previousOut).length;
    for (const [id, device] of Object.entries(devices)) {
      const label = labels[id];
      const hit = cache.get(id);
      const entry = hit && hit.source === device && hit.label === label ? hit : { source: device, label, merged: label ? { ...device, ...label } : device };
      if (entry !== hit) changed = true;
      next.set(id, entry);
      out[id] = entry.merged;
    }
    cache = next;
    if (!changed && previousOut) return previousOut;
    previousOut = out;
    return out;
  };
}
