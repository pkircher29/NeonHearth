import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export const collectorProxy = {
  '/api': {
    target: 'http://127.0.0.1:58120',
    changeOrigin: false,
    ws: true
  }
};

export default defineConfig({
  plugins: [svelte()],
  server: { proxy: collectorProxy },
  preview: { proxy: collectorProxy }
});
