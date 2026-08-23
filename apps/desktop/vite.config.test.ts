import { describe, expect, it } from 'vitest';

import { collectorProxy } from './vite.config';

describe('collectorProxy', () => {
  it('keeps collector API and websocket paths same-origin in development and preview', () => {
    expect(collectorProxy).toEqual({
      '/api': { target: 'http://127.0.0.1:58120', changeOrigin: false, ws: true }
    });
  });
});
