import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';
import { createCollectorProxyOptions } from './vite.proxy-auth.js';

export const collectorProxy = {
  '/api': createCollectorProxyOptions(process.env.NEONHEARTH_DEV_SERVICE_TOKEN)
};

// Only loopback names may reach the dev and preview servers. This is the DNS-rebinding defence: a page on another
// name that resolves to 127.0.0.1 is refused by Vite before the proxy can attach the collector credential, and the
// proxy re-checks the Host header itself (vite.proxy-auth.ts).
export const allowedHosts = ['localhost', '127.0.0.1', '[::1]'];

export default defineConfig({
  plugins: [svelte(), svelteTesting()],
  server: { proxy: collectorProxy, allowedHosts },
  preview: { proxy: collectorProxy, allowedHosts }
});
