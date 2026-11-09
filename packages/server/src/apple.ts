// Sign in with Apple (the kind `apple` in providers.ts): Apple IDs, through the OpenID Connect providers' redirect
// flow (routes/oidc.ts) and, for iOS apps, the identity token the app gets natively (routes/apple.ts). What differs
// is here: the endpoints are Apple's own, the client secret is a JWT madAuth signs with the key of the developer
// account, Apple answers the callback with a POST, the name comes only once and beside the token, and an address
// may be a relay address Apple made for the user. See docs/apple-security.md.
import { SignJWT, decodeJwt, importPKCS8, jwtVerify, type CryptoKey, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import type { OidcEndpoints } from './oidc.js';

/** Apple's issuer and the host of its endpoints. */
export const APPLE_ISSUER = 'https://appleid.apple.com';

/** Apple's endpoints, as Apple documents them; its discovery document names them too, but they never change. */
export const APPLE_ENDPOINTS: OidcEndpoints = {
  issuer: APPLE_ISSUER,
  authorizationEndpoint: `${APPLE_ISSUER}/auth/authorize`,
  tokenEndpoint: `${APPLE_ISSUER}/auth/token`,
  jwksUri: `${APPLE_ISSUER}/auth/keys`,
  clientAuth: 'client_secret_post',
};
/** Where a refresh token is given back, so Apple no longer lists the app for the user. */
export const APPLE_REVOKE_ENDPOINT = `${APPLE_ISSUER}/auth/revoke`;

/** The scopes Apple has: the name and the address. It has no `openid` or `profile`, and refuses unknown ones. */
export const APPLE_SCOPES = ['name', 'email'];

/** What Apple's `error` says when the user closes its page. */
export const APPLE_CANCELLED = 'user_cancelled_authorize';

/** How long a client secret madAuth signs lives: a few minutes, as each call signs a new one (Apple allows up to six months). */
const CLIENT_SECRET_TTL = 5 * 60;
/** How long a call to Apple's token or revoke endpoint may take. */
const APPLE_TIMEOUT_MS = 10_000;

/** A Team ID and a Key ID of an Apple developer account: ten letters and digits. */
const APPLE_ID = /^[A-Z0-9]{10}$/;
/** A Services ID or an App ID (bundle identifier): reverse-DNS, as Apple has them. */
const BUNDLE_ID = /^[A-Za-z0-9.-]{1,255}$/;
/** A private key as Apple's `.p8` file holds it: PKCS#8, PEM. */
const PKCS8_PEM = /^-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PRIVATE KEY-----$/;

/** Whether `value` can be the Team ID or the Key ID of an Apple developer account. */
export const isAppleId = (value: unknown): value is string => typeof value === 'string' && APPLE_ID.test(value);

/** Whether `value` can be a Services ID or an App ID (a bundle identifier). */
export const isBundleId = (value: unknown): value is string => typeof value === 'string' && BUNDLE_ID.test(value);

/**
 * The private key as an admin pasted it, as PEM with real line breaks: the `.p8` file's text, also with `\n`
 * written out (as a JSON string or an environment variable holds it) or on one line. Null if it isn't a PKCS#8 key.
 */
export function appleKeyPem(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const withBreaks = value.replace(/\\n/g, '\n').replace(/\r/g, '').trim();
  // Pasted on one line: the base64 between the markers, with spaces for the breaks.
  const oneLine = withBreaks.match(/^-----BEGIN PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PRIVATE KEY-----$/);
  if (!oneLine) return null;
  const body = oneLine[1]!.replace(/\s+/g, '');
  const pem = `-----BEGIN PRIVATE KEY-----\n${body.match(/.{1,64}/g)!.join('\n')}\n-----END PRIVATE KEY-----`;
  return PKCS8_PEM.test(pem) ? pem : null;
}

/** The key of {@link appleKeyPem}'s PEM, for ES256, or null if it is no such key (another curve, or no EC key at all). */
export async function importAppleKey(pem: string): Promise<CryptoKey | null> {
  return importPKCS8(pem, 'ES256').catch(() => null);
}

/** What signs a client secret: the developer account's key, as the provider has it. */
export interface AppleCredentials {
  teamId: string;
  keyId: string;
  /** The `.p8` key, PEM. */
  key: string;
}

/**
 * The client secret for a call to Apple as `clientId` (the Services ID for the web flow, an App ID for a
 * native app's code): a JWT signed with the developer account's key, as Apple asks for instead of a fixed
 * secret, valid for a few minutes. Null when the key doesn't import.
 */
export async function appleClientSecret(credentials: AppleCredentials, clientId: string): Promise<string | null> {
  const key = await importAppleKey(credentials.key);
  if (!key) return null;
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: credentials.keyId })
    .setIssuer(credentials.teamId)
    .setSubject(clientId)
    .setAudience(APPLE_ISSUER)
    .setIssuedAt(now)
    .setExpirationTime(now + CLIENT_SECRET_TTL)
    .sign(key);
}

/** Whether a JWT without any check names Apple as its issuer: what tells an Apple identity token from a Google one. */
export function isAppleToken(token: string): boolean {
  try {
    return decodeJwt(token).iss === APPLE_ISSUER;
  } catch {
    return false;
  }
}

/**
 * The claims of an Apple ID token (the web flow's) or identity token (a native app's), checked as OpenID Connect
 * Core asks: signed with one of Apple's published keys, by Apple, for one of `audiences` (the Services ID for the
 * web flow, an App ID of the provider's for a native app), not expired, with the sign-in's nonce and a `sub`.
 * Null if anything doesn't hold. Resolves the audience the token is for, which a native app's code is exchanged as.
 */
export async function verifyAppleIdToken(
  idToken: string,
  expected: { audiences: string[]; nonce: string; keys: JWTVerifyGetKey },
): Promise<(JWTPayload & { sub: string; aud: string }) | null> {
  const verified = await jwtVerify(idToken, expected.keys, { issuer: APPLE_ISSUER, audience: expected.audiences, algorithms: ['RS256', 'ES256'] }).catch(() => null);
  if (!verified) return null;
  const { payload } = verified;
  // Apple issues its tokens for one audience; several would leave the app the code belongs to open.
  if (typeof payload.aud !== 'string' || payload.nonce !== expected.nonce || typeof payload.sub !== 'string' || !payload.sub) return null;
  return { ...payload, sub: payload.sub, aud: payload.aud };
}

/** Apple sends its booleans as `true` or `"true"`, depending on the flow. */
const isTrue = (value: unknown) => value === true || value === 'true';

/**
 * What Apple's token says about the user: the address, verified when Apple says so (`email_verified`; a relay
 * address of Hide My Email, `…@privaterelay.appleid.com`, is Apple's own and comes verified too, and is taken as
 * the user's address like any other). The name isn't in the token: see {@link appleUserName}.
 */
export function appleProfile(claims: JWTPayload): { email?: string; verified: boolean } {
  const email = typeof claims.email === 'string' && claims.email ? claims.email : undefined;
  return { ...(email ? { email } : {}), verified: !!email && isTrue(claims.email_verified) };
}

/**
 * The user's name as Apple sends it once, at the first authorization only: the web flow's `user` form field (JSON,
 * `{ "name": { "firstName", "lastName" }, "email" }`), or a native app's `fullName`, which the app passes along as
 * the same object. Undefined without one. The user may have edited it on Apple's page: it is a display name, no proof.
 */
export function appleUserName(value: unknown): string | undefined {
  const parsed = typeof value === 'string' ? parseJson(value) : value;
  const name = parsed && typeof parsed === 'object' ? (parsed as { name?: unknown }).name : undefined;
  // A native app may pass the name it put together itself.
  if (typeof name === 'string') return name.trim() ? name.trim().slice(0, 200) : undefined;
  if (!name || typeof name !== 'object') return undefined;
  const { firstName, lastName } = name as { firstName?: unknown; lastName?: unknown };
  const full = [firstName, lastName]
    .filter((part): part is string => typeof part === 'string' && !!part.trim())
    .map((part) => part.trim())
    .join(' ');
  return full ? full.slice(0, 200) : undefined;
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** What the token endpoint answered a code exchange, as far as madAuth keeps it. */
export interface AppleTokens {
  idToken: string;
  /** For giving the authorization back when the account or the user is deleted. */
  refreshToken?: string;
}

/**
 * Exchanges an authorization code at Apple as `clientId`: the Services ID with the web flow's `redirectUri`, or
 * an App ID without one for a code a native app got. Null when Apple refuses, or answers without an ID token.
 */
export async function exchangeAppleCode(
  credentials: AppleCredentials,
  exchange: { clientId: string; code: string; redirectUri?: string },
  fetchFn: typeof fetch = fetch,
): Promise<AppleTokens | null> {
  const clientSecret = await appleClientSecret(credentials, exchange.clientId);
  if (!clientSecret) return null;
  const form = new URLSearchParams({ grant_type: 'authorization_code', code: exchange.code, client_id: exchange.clientId, client_secret: clientSecret });
  if (exchange.redirectUri) form.set('redirect_uri', exchange.redirectUri);
  const res = await fetchFn(APPLE_ENDPOINTS.tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: form.toString(),
    signal: AbortSignal.timeout(APPLE_TIMEOUT_MS),
  }).catch(() => null);
  if (!res?.ok) return null;
  const answer = (await res.json().catch(() => null)) as { id_token?: unknown; refresh_token?: unknown } | null;
  if (typeof answer?.id_token !== 'string') return null;
  return { idToken: answer.id_token, ...(typeof answer.refresh_token === 'string' ? { refreshToken: answer.refresh_token } : {}) };
}

/**
 * Gives a refresh token back to Apple (`/auth/revoke`), which ends the user's authorization of the app: Apple no
 * longer lists it under the user's "Sign in with Apple" apps, and a relay address stops forwarding. `clientId` is
 * the one the token was issued to. Resolves to Apple's status (200 when done, also for a token revoked already),
 * or null if Apple could not be reached.
 */
export async function revokeAppleToken(
  credentials: AppleCredentials,
  revoke: { clientId: string; refreshToken: string },
  fetchFn: typeof fetch = fetch,
): Promise<number | null> {
  const clientSecret = await appleClientSecret(credentials, revoke.clientId);
  if (!clientSecret) return null;
  const form = new URLSearchParams({ client_id: revoke.clientId, client_secret: clientSecret, token: revoke.refreshToken, token_type_hint: 'refresh_token' });
  const res = await fetchFn(APPLE_REVOKE_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
    signal: AbortSignal.timeout(APPLE_TIMEOUT_MS),
  }).catch(() => null);
  if (!res) return null;
  await res.body?.cancel();
  return res.status;
}
