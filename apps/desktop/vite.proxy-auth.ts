type ProxyRequest = {
  setHeader: (name: string, value: string) => void;
  removeHeader: (name: string) => void;
};

type ProxyServer = {
  on: (event: 'proxyReq', listener: (proxyRequest: ProxyRequest) => void) => void;
};

export type CollectorProxyOptions = {
  target: string;
  changeOrigin: boolean;
  ws: boolean;
  configure: (proxy: ProxyServer) => void;
};

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
      proxy.on('proxyReq', (proxyRequest) => {
        proxyRequest.removeHeader('authorization');
        if (serviceToken) {
          proxyRequest.setHeader('authorization', `Bearer ${serviceToken}`);
        }
      });
    }
  };
}
