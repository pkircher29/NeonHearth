<script lang="ts" module>
  // Stroke icons on a 24-unit grid. Kept local so the app ships no icon font
  // and no runtime asset request; every glyph inherits currentColor.
  export type IconName = 'pulse' | 'devices' | 'guard' | 'cameras' | 'home' | 'doctor' | 'history' | 'settings' | 'more' | 'hearth' | 'lock' | 'down' | 'up' | 'search' | 'check' | 'alert' | 'dot' | 'unknown-device' | 'phone' | 'printer' | 'router' | 'server' | 'smart-device';
  const PATHS: Record<IconName, string> = {
    'unknown-device': 'M5 5h14v14H5zM9.5 9a2.5 2.5 0 115 0c0 2-2.5 2-2.5 4M12 16h.01',
    phone: 'M7 3h10v18H7zM11 18h2',
    printer: 'M7 8V3h10v5M7 17H3V8h18v9h-4M7 14h10v7H7zM17 11h.01',
    router: 'M3 13h18v7H3zM6 13V5M18 13V5M6 17h.01M10 17h.01M9 7a5 5 0 016 0',
    server: 'M4 3h16v8H4zM4 13h16v8H4zM7 7h.01M7 17h.01M12 7h5M12 17h5',
    'smart-device': 'M8 16a6 6 0 118 0M8 16h8v3H8zM10 22h4M12 2V1M2 10H1M23 10h-1',
    pulse: 'M3 12h4l2.5-6 4 12 2.5-6h5',
    devices: 'M4 5.5h16v9H4zM9 18.5h6M12 14.5v4',
    guard: 'M12 3l7 3v5.5c0 4.4-3 7.9-7 9.5-4-1.6-7-5.1-7-9.5V6zM9.5 12l1.8 1.8L15 10',
    cameras: 'M3.5 7.5h11a1 1 0 011 1v7a1 1 0 01-1 1h-11a1 1 0 01-1-1v-7a1 1 0 011-1zM15.5 10.5l5-2.5v8l-5-2.5',
    home: 'M4 11l8-7 8 7M6 9.5V20h12V9.5M10 20v-6h4v6',
    doctor: 'M12 21s-7-4.4-7-10a4 4 0 017-2.6A4 4 0 0119 11c0 5.6-7 10-7 10zM8.5 12h2l1.2-2.4 1.6 4 1.2-1.6h1.5',
    history: 'M4 12a8 8 0 108-8 8.2 8.2 0 00-5.6 2.3M4 4v4.5h4.5M12 8v4.5l3 1.8',
    settings: 'M4 7h9M17 7h3M4 12h3M11 12h9M4 17h11M19 17h1M13 4.8v4.4M7 9.8v4.4M15 14.8v4.4',
    more: 'M5 12h.01M12 12h.01M19 12h.01',
    hearth: 'M12 3c2.5 3 5 5.5 5 9a5 5 0 01-10 0c0-1.6.6-3 1.5-4.2.4 1.2 1.2 2 2.2 2.2C10.5 8 11 5.5 12 3z',
    lock: 'M7 11V8a5 5 0 0110 0v3M6 11h12v9H6z',
    down: 'M12 5v14M6 13l6 6 6-6',
    up: 'M12 19V5M6 11l6-6 6 6',
    search: 'M10.5 17a6.5 6.5 0 100-13 6.5 6.5 0 000 13zM20 20l-4.8-4.8',
    check: 'M5 12.5l4.5 4.5L19 7.5',
    alert: 'M12 4l9 16H3zM12 10v4M12 17.5v.5',
    dot: 'M12 12h.01'
  };
  export function iconPath(name: IconName): string { return PATHS[name]; }
</script>

<script lang="ts">
  interface Props { name: IconName; size?: number; label?: string | null; strokeWidth?: number }
  let { name, size = 20, label = null, strokeWidth = 1.8 }: Props = $props();
</script>

<svg class="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width={strokeWidth} stroke-linecap="round" stroke-linejoin="round" aria-hidden={label ? undefined : 'true'} role={label ? 'img' : undefined} aria-label={label ?? undefined}>
  <path d={iconPath(name)} />
</svg>

<style>
  .icon { display: inline-block; vertical-align: middle; flex: none; }
</style>
