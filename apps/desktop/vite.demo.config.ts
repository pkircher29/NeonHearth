// Demo-only Vite config: same app, proxy pointed at the mock collector on
// 58121 instead of the real service on 58120. Started by hand; not part of
// any build or test. Delete freely.
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { createCollectorProxyOptions } from './vite.proxy-auth.js';

const proxy = createCollectorProxyOptions(process.env.NEONHEARTH_DEV_SERVICE_TOKEN);
proxy.target = 'http://127.0.0.1:58121';

export default defineConfig({
  plugins: [svelte()],
  server: { proxy: { '/api': proxy } }
});
