import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';
import { createCollectorProxyOptions } from './vite.proxy-auth.js';

export const collectorProxy = {
  '/api': createCollectorProxyOptions(process.env.NEONHEARTH_DEV_SERVICE_TOKEN)
};

export default defineConfig({
  plugins: [svelte(), svelteTesting()],
  server: { proxy: collectorProxy },
  preview: { proxy: collectorProxy }
});
