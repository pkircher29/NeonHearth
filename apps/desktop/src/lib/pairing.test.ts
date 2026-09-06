import { describe, expect, it } from 'vitest';
import { bootstrapServiceToken, clearStoredToken, type PairingWindow } from './pairing';

const VALID = 'Abc123._-Abc123._-Abc123._-Abc123._-Abc123._-Abc1';

interface FakeWindow extends PairingWindow {
  replaced: Array<string | null | undefined>;
  store: Map<string, string>;
}

function fakeWindow(options: {
  hash?: string;
  pathname?: string;
  search?: string;
  stored?: string;
  brokenStorage?: boolean;
} = {}): FakeWindow {
  const store = new Map<string, string>();
  if (options.stored !== undefined) store.set('neonhearth.service-token', options.stored);
  const win: FakeWindow = {
    replaced: [],
    store,
    location: {
      hash: options.hash ?? '',
      pathname: options.pathname ?? '/',
      search: options.search ?? ''
    },
    history: {
      replaceState(_data, _unused, url) {
        win.replaced.push(url);
      }
    },
    sessionStorage: {
      getItem(key) {
        if (options.brokenStorage) throw new Error('storage disabled');
        return store.get(key) ?? null;
      },
      setItem(key, value) {
        if (options.brokenStorage) throw new Error('storage disabled');
        store.set(key, value);
      },
      removeItem(key) {
        if (options.brokenStorage) throw new Error('storage disabled');
        store.delete(key);
      }
    }
  };
  return win;
}

describe('bootstrapServiceToken', () => {
  it('parses a valid fragment token, persists it, and strips the fragment', () => {
    const win = fakeWindow({ hash: `#token=${VALID}`, pathname: '/', search: '' });
    expect(bootstrapServiceToken(win)).toBe(VALID);
    expect(win.store.get('neonhearth.service-token')).toBe(VALID);
    expect(win.replaced).toEqual(['/']);
  });

  it('preserves pathname and query when stripping the fragment', () => {
    const win = fakeWindow({ hash: `#token=${VALID}`, pathname: '/devices', search: '?tab=live' });
    expect(bootstrapServiceToken(win)).toBe(VALID);
    expect(win.replaced).toEqual(['/devices?tab=live']);
  });

  it('falls back to sessionStorage on reload (no fragment)', () => {
    const win = fakeWindow({ hash: '', stored: VALID });
    expect(bootstrapServiceToken(win)).toBe(VALID);
    expect(win.replaced).toEqual([]);
  });

  it('returns empty string when neither fragment nor storage exists (dev proxy flow)', () => {
    const win = fakeWindow({});
    expect(bootstrapServiceToken(win)).toBe('');
    expect(win.replaced).toEqual([]);
  });

  it('ignores tokens with characters outside [A-Za-z0-9._-] but still strips the fragment', () => {
    for (const bad of ['abc$def', 'abc def', 'abc/def', 'a+b=c', '<script>', 'abc%2Fdef']) {
      const win = fakeWindow({ hash: `#token=${bad}` });
      expect(bootstrapServiceToken(win), bad).toBe('');
      expect(win.store.size, bad).toBe(0);
      expect(win.replaced, bad).toEqual(['/']);
    }
  });

  it('ignores an empty fragment token', () => {
    const win = fakeWindow({ hash: '#token=' });
    expect(bootstrapServiceToken(win)).toBe('');
    expect(win.store.size).toBe(0);
  });

  it('prefers a valid fragment token over a stale stored one', () => {
    const win = fakeWindow({ hash: `#token=${VALID}`, stored: 'stale-but-valid-0123456789012345678901' });
    expect(bootstrapServiceToken(win)).toBe(VALID);
    expect(win.store.get('neonhearth.service-token')).toBe(VALID);
  });

  it('keeps the stored token when the fragment token is invalid', () => {
    const win = fakeWindow({ hash: '#token=inv alid', stored: VALID });
    expect(bootstrapServiceToken(win)).toBe(VALID);
    expect(win.replaced).toEqual(['/']);
  });

  it('ignores unrelated fragments', () => {
    const win = fakeWindow({ hash: '#section-2', stored: VALID });
    expect(bootstrapServiceToken(win)).toBe(VALID);
    expect(win.replaced).toEqual([]);
  });

  it('rejects a stored value that fails the charset check', () => {
    const win = fakeWindow({ stored: 'tampered value!' });
    expect(bootstrapServiceToken(win)).toBe('');
  });

  it('clearStoredToken forgets the stored pairing so a reload stays unpaired', () => {
    const win = fakeWindow({ stored: VALID });
    clearStoredToken(win);
    expect(win.store.size).toBe(0);
    expect(bootstrapServiceToken(win)).toBe('');
  });

  it('pairs again from a fresh #token fragment after the stored token was cleared', () => {
    const win = fakeWindow({ stored: 'stale-but-valid-0123456789012345678901' });
    clearStoredToken(win);
    win.location.hash = `#token=${VALID}`;
    expect(bootstrapServiceToken(win)).toBe(VALID);
    expect(win.store.get('neonhearth.service-token')).toBe(VALID);
    expect(win.replaced).toEqual(['/']);
  });

  it('clearStoredToken survives disabled sessionStorage', () => {
    expect(() => clearStoredToken(fakeWindow({ brokenStorage: true }))).not.toThrow();
  });

  it('survives disabled sessionStorage in both directions', () => {
    const withFragment = fakeWindow({ hash: `#token=${VALID}`, brokenStorage: true });
    expect(bootstrapServiceToken(withFragment)).toBe(VALID);
    const withoutFragment = fakeWindow({ brokenStorage: true });
    expect(bootstrapServiceToken(withoutFragment)).toBe('');
  });
});
