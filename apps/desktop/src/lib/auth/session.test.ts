import { describe, expect, it } from 'vitest';

import { SESSION_STORAGE_KEY, createAuthSession, credentialHeader, formatPairingCode, parsePairingCode } from './session';

const sessionId = '018f47a0-9b5c-7a22-8a33-112233445599';
const secret = 'a'.repeat(64);
const ownerToken = 'x'.repeat(48);

function memoryStorage() {
  const map = new Map<string, string>();
  return {
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => { map.set(key, value); },
    removeItem: (key: string) => { map.delete(key); },
    map
  };
}

describe('pairing codes', () => {
  it('round-trips the session id and secret and rejects malformed input', () => {
    const code = formatPairingCode(sessionId, secret);
    expect(parsePairingCode(code)).toEqual({ sessionId, secret });
    expect(parsePairingCode(`  ${code.toUpperCase()} \n`)).toEqual({ sessionId, secret });
    for (const bad of ['', sessionId, `${sessionId}:${'a'.repeat(63)}`, `not-a-uuid:${secret}`, `${sessionId}:${secret}:extra`]) {
      expect(parsePairingCode(bad)).toBeNull();
    }
  });

  it('formats headers per principal and never an empty bearer', () => {
    expect(credentialHeader(null)).toBeNull();
    expect(credentialHeader({ kind: 'owner', token: ownerToken })).toBe(`Bearer ${ownerToken}`);
    expect(credentialHeader({ kind: 'phone', sessionId, secret })).toBe(`PhoneSession ${sessionId}:${secret}`);
  });
});

describe('createAuthSession', () => {
  it('starts without a credential, becomes challenged on 401, and signs in as owner', () => {
    const session = createAuthSession(null);
    expect(session.header()).toBeNull();
    expect(session.state.challenged).toBe(false);
    session.unauthorized();
    expect(session.state.challenged).toBe(true);
    expect(session.state.failure).toBeNull();
    expect(session.signInOwner('short', false)).toBe(false);
    expect(session.state.failure).toBe('invalid_format');
    expect(session.signInOwner(`  ${ownerToken} `, false)).toBe(true);
    expect(session.header()).toBe(`Bearer ${ownerToken}`);
    expect(session.state.challenged).toBe(false);
  });

  it('drops a rejected credential and reports why', () => {
    const session = createAuthSession(null);
    session.signInOwner(ownerToken, false);
    session.unauthorized();
    expect(session.header()).toBeNull();
    expect(session.state.failure).toBe('rejected');
    expect(session.state.challenged).toBe(true);
  });

  it('remembers only into the provided storage and only when asked', () => {
    const storage = memoryStorage();
    const forgetful = createAuthSession(storage);
    forgetful.signInOwner(ownerToken, false);
    expect(storage.map.size).toBe(0);
    forgetful.signInPhone(formatPairingCode(sessionId, secret), true);
    expect(JSON.parse(storage.map.get(SESSION_STORAGE_KEY)!)).toEqual({ kind: 'phone', sessionId, secret });

    const restored = createAuthSession(storage);
    expect(restored.header()).toBe(`PhoneSession ${sessionId}:${secret}`);
    expect(restored.state.remembered).toBe(true);
    restored.signOut();
    expect(storage.map.size).toBe(0);
    expect(restored.header()).toBeNull();
  });

  it('ignores corrupt stored sessions', () => {
    const storage = memoryStorage();
    storage.setItem(SESSION_STORAGE_KEY, '{"kind":"owner","token":"short"}');
    expect(createAuthSession(storage).header()).toBeNull();
    storage.setItem(SESSION_STORAGE_KEY, 'not json');
    expect(createAuthSession(storage).header()).toBeNull();
  });

  it('tracks PIN step-up only for phone sessions', () => {
    const session = createAuthSession(null);
    session.signInOwner(ownerToken, false);
    session.stepupRequired();
    expect(session.state.stepupRequired).toBe(false);
    session.signInPhone(formatPairingCode(sessionId, secret), false);
    session.stepupRequired();
    expect(session.state.stepupRequired).toBe(true);
    session.stepupGranted('2026-09-03T10:05:00Z');
    expect(session.state.stepupRequired).toBe(false);
    expect(session.state.stepupUntil).toBe('2026-09-03T10:05:00Z');
    session.stepupRequired();
    session.dismissStepup();
    expect(session.state.stepupRequired).toBe(false);
  });
});
