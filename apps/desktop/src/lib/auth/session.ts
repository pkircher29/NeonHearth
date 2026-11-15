// Credential session for the desktop and phone surfaces (audit M-25).
//
// The service accepts two principals: the owner bearer token
// (`Authorization: Bearer <token>`) and a phone session minted by the owner
// (`Authorization: PhoneSession <session_id>:<secret>`), the latter needing a
// six-digit PIN step-up (`POST /api/v1/remote/stepup`) before high-impact
// routes. Credentials live in memory; "remember on this device" uses
// sessionStorage only — never localStorage, never the URL.

import type { AuthSource } from '../api/client';

export type Credential =
  | { kind: 'owner'; token: string }
  | { kind: 'phone'; sessionId: string; secret: string };

export type AuthFailure = 'rejected' | 'invalid_format' | null;

export interface AuthState {
  credential: Credential | null;
  /** A request was refused with 401 while no valid credential was held. */
  challenged: boolean;
  /** A phone-session request was refused with 403: PIN step-up is needed. */
  stepupRequired: boolean;
  /** End of the current step-up grace window, when known. */
  stepupUntil: string | null;
  remembered: boolean;
  failure: AuthFailure;
}

export interface AuthSession extends AuthSource {
  readonly state: AuthState;
  unauthorized(): void;
  stepupRequired(): void;
  subscribe(listener: (state: AuthState) => void): () => void;
  signInOwner(token: string, remember: boolean): boolean;
  signInPhone(pairingCode: string, remember: boolean): boolean;
  stepupGranted(expiresAt: string): void;
  dismissStepup(): void;
  signOut(): void;
}

type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
export const SESSION_STORAGE_KEY = 'neonhearth.session';
const OWNER_TOKEN_MIN = 32;
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SECRET = /^[0-9a-f]{64}$/;

export function formatPairingCode(sessionId: string, secret: string): string { return `${sessionId}:${secret}`; }

/** `session_id:secret` as minted by `POST /api/v1/remote/pair`; whitespace-tolerant. */
export function parsePairingCode(code: string): { sessionId: string; secret: string } | null {
  const trimmed = code.trim().toLowerCase();
  const separator = trimmed.indexOf(':');
  if (separator < 0) return null;
  const sessionId = trimmed.slice(0, separator);
  const secret = trimmed.slice(separator + 1);
  return SESSION_ID.test(sessionId) && SECRET.test(secret) ? { sessionId, secret } : null;
}

export function credentialHeader(credential: Credential | null): string | null {
  if (!credential) return null;
  return credential.kind === 'owner' ? `Bearer ${credential.token}` : `PhoneSession ${credential.sessionId}:${credential.secret}`;
}

function readStored(storage: StorageLike | null): Credential | null {
  if (!storage) return null;
  try {
    const raw = storage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const value: unknown = JSON.parse(raw);
    if (typeof value !== 'object' || value === null) return null;
    const record = value as Record<string, unknown>;
    if (record.kind === 'owner' && typeof record.token === 'string' && record.token.length >= OWNER_TOKEN_MIN) return { kind: 'owner', token: record.token };
    if (record.kind === 'phone' && typeof record.sessionId === 'string' && typeof record.secret === 'string' && SESSION_ID.test(record.sessionId) && SECRET.test(record.secret)) {
      return { kind: 'phone', sessionId: record.sessionId, secret: record.secret };
    }
    return null;
  } catch {
    return null;
  }
}

export function createAuthSession(storage: StorageLike | null = null): AuthSession {
  const stored = readStored(storage);
  let state: AuthState = { credential: stored, challenged: false, stepupRequired: false, stepupUntil: null, remembered: stored !== null, failure: null };
  const listeners = new Set<(state: AuthState) => void>();
  const update = (next: Partial<AuthState>) => { state = { ...state, ...next }; listeners.forEach((listener) => listener(state)); };
  const persist = (credential: Credential | null, remember: boolean) => {
    if (!storage) return;
    try {
      if (credential && remember) storage.setItem(SESSION_STORAGE_KEY, JSON.stringify(credential));
      else storage.removeItem(SESSION_STORAGE_KEY);
    } catch { /* Storage may be unavailable (private mode); the credential still lives in memory. */ }
  };
  return {
    get state() { return state; },
    subscribe(listener) { listeners.add(listener); listener(state); return () => { listeners.delete(listener); }; },
    header() { return credentialHeader(state.credential); },
    unauthorized() {
      // The held credential (if any) was refused: drop it and ask again.
      const failure: AuthFailure = state.credential ? 'rejected' : state.failure;
      persist(null, false);
      update({ credential: null, challenged: true, stepupRequired: false, stepupUntil: null, remembered: false, failure });
    },
    stepupRequired() {
      if (state.credential?.kind === 'phone') update({ stepupRequired: true, stepupUntil: null });
    },
    stepupGranted(expiresAt) { update({ stepupRequired: false, stepupUntil: expiresAt }); },
    dismissStepup() { update({ stepupRequired: false }); },
    signInOwner(token, remember) {
      const trimmed = token.trim();
      if (trimmed.length < OWNER_TOKEN_MIN || /\s/.test(trimmed)) { update({ failure: 'invalid_format' }); return false; }
      const credential: Credential = { kind: 'owner', token: trimmed };
      persist(credential, remember);
      update({ credential, challenged: false, stepupRequired: false, stepupUntil: null, remembered: remember, failure: null });
      return true;
    },
    signInPhone(pairingCode, remember) {
      const parsed = parsePairingCode(pairingCode);
      if (!parsed) { update({ failure: 'invalid_format' }); return false; }
      const credential: Credential = { kind: 'phone', ...parsed };
      persist(credential, remember);
      update({ credential, challenged: false, stepupRequired: false, stepupUntil: null, remembered: remember, failure: null });
      return true;
    },
    signOut() {
      persist(null, false);
      update({ credential: null, challenged: true, stepupRequired: false, stepupUntil: null, remembered: false, failure: null });
    }
  };
}
