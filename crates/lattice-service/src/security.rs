use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::{Arc, RwLock};

/// The loopback port the production service binds (`main.rs`); the default
/// until [`HostPolicy::set_port`] records the real one.
pub(crate) const DEFAULT_LOOPBACK_PORT: u16 = 58120;
/// Ports the Vite dev server and `vite preview` use. The dev proxy forwards
/// the browser's own `Host` (`changeOrigin: false`), so loopback names on
/// these ports must pass for the UI dev flow.
const DEV_SERVER_PORTS: [u16; 2] = [5173, 4173];
/// Header Tailscale attaches to requests that arrive through Funnel (public
/// exposure). UNVERIFIED against real Funnel traffic: the name is taken from
/// Tailscale's documentation; the service refuses anything carrying it and
/// never relies on its absence.
pub(crate) const FUNNEL_HEADER: &str = "tailscale-funnel-request";

#[derive(Debug)]
struct HostPolicyInner {
    /// The bound loopback port; `None` until the listener is bound (embedded
    /// and test routers), in which case any port on a loopback name passes.
    port: Option<u16>,
    /// Extra tailnet names (lowercase, no port) accepted as `Host`.
    names: Vec<String>,
}

/// Which `Host` values the service answers to. A DNS-rebinding page controls
/// both `Host` and `Origin`, so the same-origin check alone cannot stop it;
/// pinning `Host` to names the owner actually uses does.
#[derive(Clone, Debug)]
pub struct HostPolicy {
    inner: Arc<RwLock<HostPolicyInner>>,
}

impl Default for HostPolicy {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HostPolicyInner {
                port: None,
                names: Vec::new(),
            })),
        }
    }
}

impl HostPolicy {
    pub fn set_port(&self, port: u16) {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .port = Some(port);
    }

    pub fn port(&self) -> u16 {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .port
            .unwrap_or(DEFAULT_LOOPBACK_PORT)
    }

    /// Allows the configured tailnet DNS name (as reported by the daemon).
    pub fn allow_tailnet_name(&self, name: &str) {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() {
            return;
        }
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !inner.names.contains(&name) {
            inner.names.push(name);
        }
    }

    /// True when `host` (a raw `Host` header value) is one the service serves.
    pub fn allows(&self, host: &str) -> bool {
        let host = host.trim().to_ascii_lowercase();
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (name, port) = split_host_port(&host);
        let loopback = matches!(name, "127.0.0.1" | "localhost" | "[::1]");
        if loopback {
            return match inner.port {
                None => true,
                Some(bound) => {
                    port.is_some_and(|port| port == bound || DEV_SERVER_PORTS.contains(&port))
                }
            };
        }
        // Tailnet names are served by Tailscale on 443, so the port is
        // either absent or 443.
        matches!(port, None | Some(443)) && inner.names.iter().any(|allowed| allowed == name)
    }
}

fn split_host_port(host: &str) -> (&str, Option<u16>) {
    if let Some(end) = host.rfind(']') {
        // Bracketed IPv6 literal, optionally followed by :port.
        let name = &host[..=end];
        let port = host[end + 1..]
            .strip_prefix(':')
            .and_then(|port| port.parse().ok());
        return (name, port);
    }
    match host.rsplit_once(':') {
        Some((name, port)) => (name, port.parse().ok()),
        None => (host, None),
    }
}

/// Bearer authentication remains mandatory. Also refuse browser requests whose
/// origin differs from the exact host, requests for a `Host` the service does
/// not serve (DNS rebinding), and anything that arrived through Funnel.
pub async fn browser_boundary(
    State(policy): State<HostPolicy>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    let mut rejected = headers
        .get("sec-fetch-site")
        .is_some_and(|value| value == "cross-site");
    // Public (Funnel) traffic is never served, whatever its credentials.
    rejected |= headers.contains_key(FUNNEL_HEADER);
    // A request with no Host (HTTP/1.0, internal clients) is not a browser
    // and cannot be a rebinding page; a present Host must be one we serve.
    if let Some(host) = headers.get("host") {
        rejected |= !host.to_str().is_ok_and(|host| policy.allows(host));
    }
    if let Some(origin) = headers.get("origin") {
        let same = origin
            .to_str()
            .ok()
            .and_then(|origin| url::Url::parse(origin).ok())
            .is_some_and(|origin| {
                matches!(origin.scheme(), "http" | "https")
                    && headers
                        .get("host")
                        .and_then(|host| host.to_str().ok())
                        .is_some_and(|host| {
                            let expected = format!("{}://{host}", origin.scheme());
                            url::Url::parse(&expected)
                                .ok()
                                .is_some_and(|expected| expected.origin() == origin.origin())
                        })
            });
        rejected |= !same;
    }
    let mut response = if rejected {
        StatusCode::FORBIDDEN.into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; worker-src 'self' blob:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_and_rejected_host_forms() {
        let policy = HostPolicy::default();
        // Before the listener is bound only loopback *names* are checked.
        assert!(policy.allows("127.0.0.1:9999") && policy.allows("localhost"));
        assert!(!policy.allows("evil.example:9999"));
        policy.set_port(58121);
        policy.allow_tailnet_name("Neonhearth.tailnet.ts.net.");
        for allowed in [
            "127.0.0.1:58121",
            "localhost:58121",
            "LOCALHOST:58121",
            "[::1]:58121",
            // Vite dev server and preview ports (dev proxy forwards Host).
            "localhost:5173",
            "127.0.0.1:4173",
            // Tailscale Serve answers on 443.
            "neonhearth.tailnet.ts.net",
            "neonhearth.tailnet.ts.net:443",
        ] {
            assert!(policy.allows(allowed), "{allowed} should be allowed");
        }
        for rejected in [
            "evil.example",
            "evil.example:58121",
            "127.0.0.1",
            "localhost",
            "127.0.0.1:58120",
            "localhost:9999",
            "127.0.0.1.evil.example:58121",
            "evil.example:443",
            "neonhearth.tailnet.ts.net:8443",
            "other.tailnet.ts.net",
            "",
            "[::1]",
            "127.0.0.1:notaport",
        ] {
            assert!(!policy.allows(rejected), "{rejected:?} should be rejected");
        }
    }
}
