<script lang="ts">
  let { name }: { name: string } = $props();
  const paths: Record<string, string> = {
    pulse: 'M2 12h4l3-7 5 14 3-7h5',
    devices: 'M3 4h18v12H3z M8 21h8 M12 16v5',
    guard: 'M12 2 3 6v6c0 5 9 10 9 10s9-5 9-10V6z M8 12l3 3 5-6',
    cameras: 'M3 7h12v12H3z M15 11l6-4v12l-6-4',
    home: 'M3 11 12 3l9 8 M5 10v11h14V10 M9 21v-7h6v7',
    doctor: 'M9 3h6v6h6v6h-6v6H9v-6H3V9h6z',
    history: 'M3 11a9 9 0 1 1 2 7 M3 4v7h7 M12 7v6l4 2',
    settings: 'M4 7h16 M4 17h16 M8 4v6 M16 14v6'
  };
</script>
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d={paths[name] ?? paths.devices}/></svg>
