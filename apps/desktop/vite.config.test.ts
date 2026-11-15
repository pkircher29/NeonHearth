import { describe, expect, it } from 'vitest';

import { createCollectorProxyOptions, isLoopbackAddress, isLoopbackHost, isSameOriginRequest, type IncomingRequest } from './vite.proxy-auth';
import { allowedHosts } from './vite.config';

type Listener = (request: { setHeader: (name: string, value: string) => void; removeHeader: (name: string) => void }, incoming?: IncomingRequest) => void;

const loopbackRequest = (headers: IncomingRequest['headers'] = {}, localAddress = '127.0.0.1'): IncomingRequest => ({ headers: { host: '127.0.0.1:5173', ...headers }, socket: { localAddress } });

function configuredProxyRequest(token: string | undefined, incomingAuthorization?: string, incoming: IncomingRequest | null = loopbackRequest()) {
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
  listener?.(request, incoming ?? undefined);
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

  it('refuses the credential when the dev server is bound beyond loopback (M-24)', () => {
    expect(configuredProxyRequest('server-secret', undefined, loopbackRequest({}, '192.168.1.20'))).toBeUndefined();
    expect(configuredProxyRequest('server-secret', undefined, loopbackRequest({}, '::1'))).toBe('Bearer server-secret');
    expect(configuredProxyRequest('server-secret', undefined, loopbackRequest({}, '::ffff:127.0.0.1'))).toBe('Bearer server-secret');
    expect(configuredProxyRequest('server-secret', undefined, { headers: {} })).toBeUndefined();
    expect(configuredProxyRequest('server-secret', undefined, null)).toBeUndefined();
  });

  it('refuses cross-origin callers by fetch metadata while allowing same-origin and direct requests', () => {
    expect(configuredProxyRequest('server-secret', undefined, loopbackRequest({ 'sec-fetch-site': 'cross-site' }))).toBeUndefined();
    expect(configuredProxyRequest('server-secret', undefined, loopbackRequest({ 'sec-fetch-site': 'same-site' }))).toBeUndefined();
    expect(configuredProxyRequest('server-secret', undefined, loopbackRequest({ 'sec-fetch-site': 'same-origin' }))).toBe('Bearer server-secret');
    expect(configuredProxyRequest('server-secret', undefined, loopbackRequest({ 'sec-fetch-site': 'none' }))).toBe('Bearer server-secret');
    expect(configuredProxyRequest('server-secret', undefined, loopbackRequest({}))).toBe('Bearer server-secret');
  });

  it('exposes the loopback and fetch-site predicates', () => {
    expect(isLoopbackAddress('127.0.0.1')).toBe(true);
    expect(isLoopbackAddress('127.255.0.9')).toBe(true);
    expect(isLoopbackAddress('10.0.0.1')).toBe(false);
    expect(isLoopbackAddress(undefined)).toBe(false);
    expect(isSameOriginRequest({ 'sec-fetch-site': ['cross-site'] })).toBe(false);
    expect(isSameOriginRequest({})).toBe(true);
  });

  it('refuses DNS rebinding: a foreign Host, or none, never receives the credential even from a loopback socket', () => {
    for (const host of ['evil.example', 'evil.example:5173', '127.0.0.1.evil.example', 'localhost.evil.example:5173', '[::1]x', '']) {
      expect(configuredProxyRequest('server-secret', undefined, { headers: { host, 'sec-fetch-site': 'same-origin' }, socket: { localAddress: '127.0.0.1' } }), host).toBeUndefined();
    }
    expect(configuredProxyRequest('server-secret', undefined, { headers: { 'sec-fetch-site': 'same-origin' }, socket: { localAddress: '127.0.0.1' } })).toBeUndefined();
    for (const host of ['localhost:5173', '127.0.0.1:4201', '127.5.6.7', '[::1]:5173', 'LOCALHOST']) {
      expect(configuredProxyRequest('server-secret', undefined, { headers: { host }, socket: { localAddress: '127.0.0.1' } }), host).toBe('Bearer server-secret');
    }
  });

  it('exposes the loopback host predicate', () => {
    expect(isLoopbackHost({ host: 'localhost:5173' })).toBe(true);
    expect(isLoopbackHost({ host: ['evil.example'] })).toBe(false);
    expect(isLoopbackHost({})).toBe(false);
  });

  it('pins the dev and preview servers to loopback host names', async () => {
    expect(allowedHosts).toEqual(['localhost', '127.0.0.1', '[::1]']);
    const config = (await import('./vite.config')).default;
    expect(config.server?.allowedHosts).toEqual(allowedHosts);
    expect(config.preview?.allowedHosts).toEqual(allowedHosts);
  });
});
