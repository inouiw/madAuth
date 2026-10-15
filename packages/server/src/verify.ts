import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { SIGNING_ALG } from './keys.js';
import { userFromClaims, type SessionClaims } from './tokens.js';
import { API_KEY_PREFIX, SESSION_COOKIE, SESSION_TYP, bearerTokenOf, type MadauthUser } from './user.js';

export type { MadauthUser } from './user.js';

export interface SessionVerifierOptions {
  /** The madAuth server's public base URL (its MADAUTH_ISSUER). */
  issuer: string;
  /** Keys to verify with. Defaults to `<issuer>/.well-known/jwks.json` (fetched once, then cached). */
  jwks?: JWTVerifyGetKey;
}

/** Verifies a madAuth session for an app backend. Resolves to the user, or null if there is no valid session. */
export type SessionVerifier = (input: Request | string) => Promise<MadauthUser | null>;

function tokenFromCookieHeader(header: string | null): string | undefined {
  for (const part of header?.split(';') ?? []) {
    const [name, ...value] = part.trim().split('=');
    if (name === SESSION_COOKIE) return decodeURIComponent(value.join('='));
  }
  return undefined;
}

function tokenFrom(input: Request | string): string | undefined {
  if (typeof input !== 'string') {
    return bearerTokenOf(input.headers.get('authorization')) ?? tokenFromCookieHeader(input.headers.get('cookie'));
  }
  return input.includes(`${SESSION_COOKIE}=`) ? tokenFromCookieHeader(input) : input.trim() || undefined;
}

/**
 * Creates a function that checks madAuth sessions in your own backend (any Web-standard runtime).
 * It accepts a `Request` (session cookie or `Authorization: Bearer`), a `Cookie` header or a bare token.
 *
 * ```ts
 * const verifySession = createSessionVerifier({ issuer: 'https://auth.example.com' });
 * const user = await verifySession(request);
 * if (!user) return new Response('Unauthorized', { status: 401 });
 * ```
 */
export function createSessionVerifier(opts: SessionVerifierOptions): SessionVerifier {
  const issuer = opts.issuer.replace(/\/+$/, '');
  const keys = opts.jwks ?? createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
  return async (input) => {
    try {
      const token = tokenFrom(input);
      if (!token) return null;
      const { payload } = await jwtVerify<SessionClaims>(token, keys, {
        issuer,
        typ: SESSION_TYP,
        algorithms: [SIGNING_ALG],
      });
      if (typeof payload.sub !== 'string') return null;
      return userFromClaims(payload);
    } catch {
      return null;
    }
  };
}

/** Who calls with an API key: the key's user, and the key with the scopes that count now. */
export interface ApiKeyCaller {
  user: MadauthUser;
  apiKey: {
    /** The key's id (`key_…`), never the key. */
    id: string;
    name: string;
    /** The scopes that count now: those the key has, the app lists and its user holds the role for. */
    scopes: string[];
  };
}

export interface ApiKeyVerifierOptions {
  /** The madAuth server's public base URL (its MADAUTH_ISSUER). */
  issuer: string;
  /** How long an answer is reused, in seconds (default 60): a revoked key stops working within that time. */
  cacheSeconds?: number;
  /** The fetch that asks madAuth. Default: the global `fetch`. */
  fetch?: typeof fetch;
}

/** Verifies an API key for an app backend. Resolves to its caller, or null if the key doesn't work (or madAuth didn't answer). */
export type ApiKeyVerifier = (input: Request | string) => Promise<ApiKeyCaller | null>;

/** Answers kept at most; older ones go first when there are more. */
const MAX_CACHED_KEYS = 1000;

const sha256 = async (value: string): Promise<string> =>
  Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))), (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * Creates a function that checks the API keys your users made (`Authorization: Bearer madauth_…`), in your
 * own backend (any Web-standard runtime). It asks the madAuth server, and reuses an answer for `cacheSeconds`.
 * It accepts a `Request` or a bare key; check the scope your route needs in `apiKey.scopes`.
 *
 * ```ts
 * const verifyApiKey = createApiKeyVerifier({ issuer: 'https://auth.example.com' });
 * const caller = await verifyApiKey(request);
 * if (!caller?.apiKey.scopes.includes('orders:read')) return new Response('Forbidden', { status: 403 });
 * ```
 */
export function createApiKeyVerifier(opts: ApiKeyVerifierOptions): ApiKeyVerifier {
  const url = `${opts.issuer.replace(/\/+$/, '')}/auth/api-keys/verify`;
  const ttlMs = (opts.cacheSeconds ?? 60) * 1000;
  const fetcher = opts.fetch ?? fetch;
  // By the key's hash: the keys themselves are never kept.
  const answers = new Map<string, { caller: ApiKeyCaller; until: number }>();
  return async (input) => {
    const key = typeof input === 'string' ? input.trim() : bearerTokenOf(input.headers.get('authorization'));
    if (!key?.startsWith(API_KEY_PREFIX)) return null;
    const hash = await sha256(key);
    const kept = answers.get(hash);
    if (kept && kept.until > Date.now()) return kept.caller;
    answers.delete(hash);
    const res = await fetcher(url, { method: 'POST', headers: { Authorization: `Bearer ${key}` } }).catch((e: Error) => e);
    if (res instanceof Error || res.status >= 500) {
      console.error(`[madauth] createApiKeyVerifier: madAuth did not answer at ${url}: ${res instanceof Error ? res.message : res.status}`);
      return null;
    }
    if (!res.ok) return null;
    const caller = (await res.json()) as ApiKeyCaller;
    if (answers.size >= MAX_CACHED_KEYS) answers.delete(answers.keys().next().value!);
    answers.set(hash, { caller, until: Date.now() + ttlMs });
    return caller;
  };
}
