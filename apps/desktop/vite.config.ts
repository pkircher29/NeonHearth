import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { createCollectorProxyOptions } from './vite.proxy-auth.js';

export const collectorProxy = {
  '/api': createCollectorProxyOptions(process.env.NEONHEARTH_DEV_SERVICE_TOKEN)
};

export default defineConfig({
  plugins: [svelte()],
  server: { proxy: collectorProxy },
  preview: { proxy: collectorProxy }
});
