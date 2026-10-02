import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { SESSION_COOKIE, SESSION_TYP, type MadauthUser } from './user.js';

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
    const auth = input.headers.get('authorization');
    if (auth?.toLowerCase().startsWith('bearer ')) return auth.slice(7).trim();
    return tokenFromCookieHeader(input.headers.get('cookie'));
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
    const token = tokenFrom(input);
    if (!token) return null;
    try {
      const { payload } = await jwtVerify(token, keys, { issuer, typ: SESSION_TYP, algorithms: ['ES256'] });
      if (typeof payload.sub !== 'string') return null;
      const user: MadauthUser = { id: payload.sub };
      if (typeof payload.email === 'string') user.email = payload.email;
      if (typeof payload.name === 'string') user.name = payload.name;
      if (typeof payload.picture === 'string') user.picture = payload.picture;
      return user;
    } catch {
      return null;
    }
  };
}
