// The one fetch path every API module shares: base URL, credential header
// (never an empty `Authorization`), a hard timeout combined with the caller's
// abort signal, and auth refusals reported to the credential source together
// with the header that was actually sent, so a refusal of an OLD credential
// can never discard a newly entered one.

export interface AuthSource {
  header(): string | null;
  /** A request was refused with 401. `sentHeader` is what that request carried; implementations ignore it when the credential has since changed. */
  unauthorized?(sentHeader?: string | null): void;
  /** A phone-session request was refused with 403: PIN step-up is needed. */
  stepupRequired?(): void;
}

export interface HttpOptions {
  baseUrl?: string;
  auth?: AuthSource | null;
  /** Fixed owner bearer; superseded by `auth` when both are given. */
  serviceToken?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export interface SendOptions {
  signal?: AbortSignal;
  /** Overrides the default timeout for this request (0 disables). */
  timeoutMs?: number;
}

export interface Http {
  credential(): string | null;
  /** `Authorization` header object: empty when there is no credential. */
  authHeaders(extra?: Record<string, string>): Record<string, string>;
  send(path: string, init?: RequestInit, options?: SendOptions): Promise<Response>;
}

export function createHttp({ baseUrl, auth = null, serviceToken, fetchImpl, timeoutMs = 15_000 }: HttpOptions = {}): Http {
  const base = () => baseUrl ?? (typeof window !== 'undefined' ? window.location.origin : 'http://127.0.0.1');
  const doFetch = (input: string, init: RequestInit) => (fetchImpl ?? fetch)(input, init);
  const credential = (): string | null => {
    const header = auth ? auth.header() : (serviceToken ? `Bearer ${serviceToken}` : null);
    return header && header.trim().length > 0 ? header : null;
  };
  function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
    const header = credential();
    return header === null ? { ...extra } : { Authorization: header, ...extra };
  }
  async function send(path: string, init: RequestInit = {}, options: SendOptions = {}): Promise<Response> {
    const { signal } = options;
    const limit = options.timeoutMs ?? timeoutMs;
    const controller = new AbortController();
    const abort = () => controller.abort(signal?.reason ?? new Error('Request aborted'));
    if (signal?.aborted) abort();
    else signal?.addEventListener('abort', abort, { once: true });
    const timer = limit > 0 ? setTimeout(() => controller.abort(new Error('Request timed out')), limit) : undefined;
    const sent = credential();
    try {
      const response = await doFetch(new URL(path, base()).toString(), { ...init, signal: controller.signal });
      if (response.status === 401) auth?.unauthorized?.(sent);
      else if (response.status === 403 && sent?.startsWith('PhoneSession ')) auth?.stepupRequired?.();
      return response;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
    }
  }
  return { credential, authHeaders, send };
}

// ---- Shared validator helpers (payloads degrade row by row, never wholesale) ----
export const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
export const isText = (max: number) => (value: unknown): value is string => typeof value === 'string' && value.length <= max;
export const isNullableText = (max: number) => (value: unknown): value is string | null => value === null || isText(max)(value);
export const isCount = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0;

/** Keeps the rows that validate (bounded by `max`) and reports how many were dropped; never throws on a bad row. */
export function validRows<T>(value: unknown, max: number, check: (row: unknown) => row is T): { rows: T[]; dropped: number } | null {
  if (!Array.isArray(value)) return null;
  const rows: T[] = [];
  let dropped = Math.max(0, value.length - max);
  for (const row of value.slice(0, max)) { if (check(row)) rows.push(row); else dropped += 1; }
  return { rows, dropped };
}

/** A problem response body `{error}` or `{detail}` as short plain text, when the service gave one. */
export async function problemText(response: Response): Promise<string | null> {
  try {
    const body: unknown = await response.clone().json();
    if (isRecord(body)) {
      for (const key of ['error', 'detail', 'message', 'title']) { const value = body[key]; if (typeof value === 'string' && value.length > 0 && value.length <= 300) return value; }
    }
  } catch { /* not JSON */ }
  return null;
}

/** Copy for a refusal that is the same everywhere, matching the sign-in screen's wording. */
export const SIGN_IN_AGAIN = 'Your session is not accepted. Sign in again to continue.';
