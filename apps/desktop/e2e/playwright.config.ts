import { defineConfig, devices } from '@playwright/test';

// E2E_PORT lets parallel checkouts run their own dev server instead of reusing another's.
const port = Number(process.env.E2E_PORT ?? 4173);
const origin = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: '.',
  timeout: 15_000,
  fullyParallel: false,
  use: { baseURL: origin, ...devices['Desktop Chrome'], reducedMotion: 'reduce' },
  webServer: { command: `npm run dev -- --host 127.0.0.1 --port ${port} --strictPort`, url: origin, reuseExistingServer: true },
});
