/**
 * Local pairing: bootstrap the service bearer token for the browser-served UI.
 *
 * The Start-menu launcher (packaging/windows/scripts/open-neonhearth.ps1)
 * opens `http://127.0.0.1:58120/#token=<value>`. URL fragments are never sent
 * over the network (and the listener is loopback-only regardless), so the
 * token reaches only this page. On load we:
 *   1. parse `#token=` from the fragment,
 *   2. validate it against the service's own token charset
 *      ([A-Za-z0-9._-], AppState::new in lattice-service/src/state.rs),
 *   3. persist it to sessionStorage so a reload keeps the session,
 *   4. strip the fragment via history.replaceState so the token does not
 *      linger in the address bar, browser history, or copied links.
 *
 * When neither a fragment nor a stored token exists, the result is '' —
 * exactly the pre-existing dev behavior, where the Vite proxy
 * (vite.proxy-auth.ts) owns the credential and the browser sends none.
 */

const STORAGE_KEY = 'neonhearth.service-token';
const FRAGMENT_PREFIX = '#token=';
const TOKEN_PATTERN = /^[A-Za-z0-9._-]+$/;

/** The pieces of `window` the bootstrap touches, injectable for tests. */
export interface PairingWindow {
  location: { hash: string; pathname: string; search: string };
  history: { replaceState(data: unknown, unused: string, url?: string | null): void };
  sessionStorage: {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
  };
}

function storedToken(win: PairingWindow): string {
  try {
    const stored = win.sessionStorage.getItem(STORAGE_KEY);
    return stored !== null && TOKEN_PATTERN.test(stored) ? stored : '';
  } catch {
    // sessionStorage can throw (disabled storage); fall back to unpaired.
    return '';
  }
}

export function bootstrapServiceToken(win: PairingWindow): string {
  const { hash, pathname, search } = win.location;
  if (!hash.startsWith(FRAGMENT_PREFIX)) return storedToken(win);
  const candidate = hash.slice(FRAGMENT_PREFIX.length);
  // Strip the fragment whether or not the token is valid: a malformed token
  // in the address bar is still residue nobody should copy around.
  try {
    win.history.replaceState(null, '', pathname + search);
  } catch {
    // A stubborn history API must not block pairing itself.
  }
  if (!TOKEN_PATTERN.test(candidate)) return storedToken(win);
  try {
    win.sessionStorage.setItem(STORAGE_KEY, candidate);
  } catch {
    // Storage failure only costs reload persistence, not this session.
  }
  return candidate;
}
