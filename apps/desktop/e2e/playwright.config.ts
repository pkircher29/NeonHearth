import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  timeout: 15_000,
  fullyParallel: false,
  use: { baseURL: 'http://127.0.0.1:4173', ...devices['Desktop Chrome'], reducedMotion: 'reduce' },
  webServer: { command: 'npm run dev -- --host 127.0.0.1 --port 4173', url: 'http://127.0.0.1:4173', reuseExistingServer: true },
});
