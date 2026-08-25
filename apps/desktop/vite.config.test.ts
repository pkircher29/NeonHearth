import { describe, expect, it } from 'vitest';

import { createCollectorProxyOptions } from './vite.proxy-auth';

type Listener = (request: { setHeader: (name: string, value: string) => void; removeHeader: (name: string) => void }) => void;

function configuredProxyRequest(token: string | undefined, incomingAuthorization?: string) {
  let listener: Listener | undefined;
  const proxy = {
    on: (_event: string, callback: Listener) => {
      listener = callback;
    }
  };
  const request = {
    headers: incomingAuthorization ? { authorization: incomingAuthorization } : {},
    setHeader: (name: string, value: string) => {
      request.headers[name.toLowerCase() as 'authorization'] = value;
    },
    removeHeader: (name: string) => {
      delete request.headers[name.toLowerCase() as 'authorization'];
    }
  };

  createCollectorProxyOptions(token).configure(proxy);
  listener?.(request);
  return request.headers.authorization;
}

describe('collectorProxy', () => {
  it('keeps collector API and websocket paths same-origin in development and preview', () => {
    expect(createCollectorProxyOptions(undefined)).toMatchObject({
      target: 'http://127.0.0.1:58120',
      changeOrigin: false,
      ws: true
    });
  });

  it('injects the configured bearer token and overwrites browser authorization', () => {
    expect(configuredProxyRequest('server-secret', 'Bearer browser-secret')).toBe('Bearer server-secret');
  });

  it('does not invent credentials when the server token is absent', () => {
    expect(configuredProxyRequest(undefined, 'Bearer browser-secret')).toBeUndefined();
  });

  it('keeps the one-time websocket ticket flow unmodified', () => {
    const options = createCollectorProxyOptions('server-secret');
    const events: string[] = [];
    options.configure({
      on: (event) => events.push(event)
    });

    expect(events).toEqual(['proxyReq']);
    expect(JSON.stringify(options)).not.toContain('server-secret');
  });
});
