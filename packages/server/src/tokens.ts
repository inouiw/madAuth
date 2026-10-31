import { base64url, createLocalJWKSet, jwtVerify, type JWK, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import type { KeyService } from './key-service.js';
import { SIGNING_ALG } from './keys.js';
import { RENEWAL_TYP, SESSION_TYP, type MadauthUser } from './user.js';

/** A random URL-safe string (32 bytes by default). */
export function randomString(bytes = 32): string {
  return base64url.encode(crypto.getRandomValues(new Uint8Array(bytes)));
}

const encodeJson = (value: object) => base64url.encode(JSON.stringify(value));

/**
 * Signs a short-lived madAuth token with the key service's signing key of now. `typ` keeps the token kinds
 * (session, nonce, OAuth state) apart, so one can never be accepted as another.
 */
export async function signToken(keys: KeyService, issuer: string, typ: string, claims: JWTPayload, ttlSeconds: number): Promise<string> {
  const [signing] = await keys.verificationKeys();
  const kid = signing!.kid!;
  const now = Math.floor(Date.now() / 1000);
  const input = `${encodeJson({ alg: SIGNING_ALG, kid, typ })}.${encodeJson({ ...claims, iss: issuer, iat: now, exp: now + ttlSeconds })}`;
  const signature = await keys.sign(kid, new TextEncoder().encode(input));
  return `${input}.${base64url.encode(signature)}`;
}

/** The verification keys by `kid`, built once per list the key service answers. */
const keySets = new WeakMap<JWK[], JWTVerifyGetKey>();
const keySetOf = (keys: JWK[]): JWTVerifyGetKey => {
  const known = keySets.get(keys);
  if (known) return known;
  const set = createLocalJWKSet({ keys });
  keySets.set(keys, set);
  return set;
};

/**
 * Verifies a token from {@link signToken}, with any of the key service's keys. Returns null if it is invalid,
 * expired or of another kind. `allowExpired` accepts one that expired, for a token that only names who it was for
 * (an OpenID Connect `id_token_hint`).
 */
export async function readToken<T extends JWTPayload>(
  keys: KeyService,
  issuer: string,
  typ: string,
  token: string | undefined,
  { allowExpired = false } = {},
): Promise<(T & { iat: number; exp: number }) | null> {
  if (!token) return null;
  const keySet = keySetOf(await keys.verificationKeys());
  // Checked as of 1970, no token has expired yet.
  const asOf = allowExpired ? { currentDate: new Date(0) } : {};
  // jose answers every invalid token with an exception: they all mean "no token".
  const verified = await jwtVerify<T>(token, keySet, { issuer, typ, algorithms: [SIGNING_ALG], ...asOf }).catch(() => null);
  return verified ? (verified.payload as T & { iat: number; exp: number }) : null;
}

/** Claims of a madAuth session JWT. */
export interface SessionClaims extends JWTPayload {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
  amr: string[];
  /** The user's session version; a password reset increments it and so ends older sessions. */
  sv?: number;
  /**
   * When the user signed in (seconds since 1970, as in OpenID Connect): kept when the session is renewed, so
   * it says how recently the user proved who they are. Absent in tokens from before madAuth 0.6.
   */
  auth_time?: number;
  /** The user's claims when the session was issued. */
  claims?: Record<string, unknown>;
}

/** What a session carries next to the user: their session version, and when they signed in. */
export interface SessionExtra {
  sv?: number;
  auth_time?: number;
}

export function signSession(
  keys: KeyService,
  issuer: string,
  ttlSeconds: number,
  user: MadauthUser,
  amr: string[],
  extra: SessionExtra = {},
): Promise<string> {
  const claims: SessionClaims = {
    ...extra,
    sub: user.id,
    email: user.email,
    email_verified: user.email ? true : undefined,
    name: user.name,
    picture: user.picture,
    claims: user.claims && Object.keys(user.claims).length ? user.claims : undefined,
    amr,
  };
  return signToken(keys, issuer, SESSION_TYP, claims, ttlSeconds);
}

/**
 * Signs the renewal token of a session: who the user is and how they signed in, but not their claims,
 * which are read again at every renewal.
 */
export function signRenewal(
  keys: KeyService,
  issuer: string,
  ttlSeconds: number,
  user: MadauthUser,
  amr: string[],
  extra: SessionExtra = {},
): Promise<string> {
  const claims: SessionClaims = {
    ...extra,
    sub: user.id,
    email: user.email,
    email_verified: user.email ? true : undefined,
    name: user.name,
    picture: user.picture,
    amr,
  };
  return signToken(keys, issuer, RENEWAL_TYP, claims, ttlSeconds);
}

export function userFromClaims(claims: SessionClaims): MadauthUser {
  const user: MadauthUser = { id: claims.sub };
  if (claims.email) user.email = claims.email;
  if (claims.name) user.name = claims.name;
  if (claims.picture) user.picture = claims.picture;
  if (claims.claims && typeof claims.claims === 'object' && Object.keys(claims.claims).length) user.claims = claims.claims;
  if (Array.isArray(claims.amr)) user.amr = claims.amr.filter((value): value is string => typeof value === 'string');
  return user;
}
