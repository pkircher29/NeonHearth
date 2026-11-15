type ProxyRequest = {
  setHeader: (name: string, value: string) => void;
  removeHeader: (name: string) => void;
};

/** The browser's incoming request, as node's http.IncomingMessage exposes it. */
export type IncomingRequest = {
  headers: Record<string, string | string[] | undefined>;
  socket?: { localAddress?: string };
};

type ProxyServer = {
  on: (event: 'proxyReq', listener: (proxyRequest: ProxyRequest, request?: IncomingRequest) => void) => void;
};

export type CollectorProxyOptions = {
  target: string;
  changeOrigin: boolean;
  ws: boolean;
  configure: (proxy: ProxyServer) => void;
};

const LOOPBACK = /^(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|::ffff:127\.\d{1,3}\.\d{1,3}\.\d{1,3})$/;

/** Only a browser on this machine may borrow the dev credential. */
export function isLoopbackAddress(address: string | undefined): boolean {
  return address !== undefined && LOOPBACK.test(address);
}

const LOOPBACK_HOST = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d{1,5})?$/i;

/**
 * DNS rebinding: a hostile page whose name resolves to 127.0.0.1 reaches this server with its own name in the Host
 * header (and Sec-Fetch-Site: same-origin, since the page and the request share that name). Only a loopback Host
 * may borrow the credential; a missing Host is refused too.
 */
export function isLoopbackHost(headers: IncomingRequest['headers']): boolean {
  const raw = headers.host;
  const host = Array.isArray(raw) ? raw[0] : raw;
  return typeof host === 'string' && LOOPBACK_HOST.test(host.trim());
}

/**
 * A page from another origin can still reach the proxy through the browser
 * (a bodyless POST is a CORS "simple" request whose side effect lands even
 * though the response is opaque). Fetch metadata names the caller: only
 * same-origin navigations and requests may carry the credential. Requests
 * without the header (older clients, curl) are allowed; the loopback check
 * still applies to them.
 */
export function isSameOriginRequest(headers: IncomingRequest['headers']): boolean {
  const raw = headers['sec-fetch-site'];
  const site = Array.isArray(raw) ? raw[0] : raw;
  return site === undefined || site === 'same-origin' || site === 'none';
}

/**
 * Keeps the collector credential in the Vite process. The browser can only
 * reach the same-origin proxy and can never choose the upstream credential.
 */
export function createCollectorProxyOptions(serviceToken: string | undefined): CollectorProxyOptions {
  return {
    target: 'http://127.0.0.1:58120',
    changeOrigin: false,
    ws: true,
    configure(proxy) {
      proxy.on('proxyReq', (proxyRequest, request) => {
        proxyRequest.removeHeader('authorization');
        if (!serviceToken) return;
        // No request context (a synthetic call) is treated as untrusted.
        if (!request || !isLoopbackAddress(request.socket?.localAddress) || !isLoopbackHost(request.headers) || !isSameOriginRequest(request.headers)) return;
        proxyRequest.setHeader('authorization', `Bearer ${serviceToken}`);
      });
    }
  };
}
