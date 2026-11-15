import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig, normalizePath } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';
import { createCollectorProxyOptions } from './vite.proxy-auth.js';

const projectRoot = realpathSync.native(fileURLToPath(new URL('.', import.meta.url)));
// Vitest DOM workers resolve root-relative modules against cwd; match Vite's native root.
if (process.env.VITEST) process.chdir(projectRoot);

export const collectorProxy = {
  '/api': createCollectorProxyOptions(process.env.NEONHEARTH_DEV_SERVICE_TOKEN)
};

export default defineConfig({
  // Use the OS-native path consistently across Windows drive aliases and junctions.
  root: normalizePath(projectRoot),
  plugins: [svelte(), svelteTesting()],
  server: { proxy: collectorProxy },
  preview: { proxy: collectorProxy }
});
