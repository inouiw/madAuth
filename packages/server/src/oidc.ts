// Generic OpenID Connect providers (the kind `oidc` in providers.ts): finding a provider's endpoints from its
// discovery document, exchanging the code, checking the ID token, and reading the address. See "Providers" in
// docs/server.md.
import { createRemoteJWKSet, customFetch, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';

/** What madAuth uses of a provider's discovery document (`<issuer>/.well-known/openid-configuration`). */
export interface OidcEndpoints {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  /** Where the address is read when the ID token has none; absent if the provider has no userinfo endpoint. */
  userinfoEndpoint?: string;
  /** How the code exchange authenticates: `client_secret_basic` unless the provider supports only `client_secret_post`. */
  clientAuth: 'client_secret_basic' | 'client_secret_post';
}

/** How long an instance keeps a provider's endpoints before it reads the document again. */
const DISCOVERY_TTL_MS = 60 * 60 * 1000;
/** How long a discovery request may take. */
const DISCOVERY_TIMEOUT_MS = 10_000;

/** Whether a URL may be an endpoint: https, or http on localhost for development. */
function isEndpoint(value: unknown): value is string {
  if (typeof value !== 'string' || !URL.canParse(value)) return false;
  const url = new URL(value);
  return url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname));
}

/** Whether `value` can be an issuer: an endpoint URL without a query or a fragment. */
export function isIssuer(value: unknown): value is string {
  return isEndpoint(value) && !new URL(value).search && !new URL(value).hash;
}

/** The URL of an issuer's discovery document: the issuer, without a trailing slash, and the well-known path. */
export const discoveryUrl = (issuer: string): string => `${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;

/**
 * A provider's endpoints from its discovery document, or what is wrong with it. The document's `issuer` must be
 * exactly the configured one (OpenID Connect Discovery, section 4.3), and every endpoint https.
 */
export async function discover(issuer: string, fetchFn: typeof fetch = fetch): Promise<{ endpoints: OidcEndpoints } | { problem: string }> {
  const url = discoveryUrl(issuer);
  const res = await fetchFn(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS) }).catch((e: Error) => e);
  if (res instanceof Error) return { problem: `${url} could not be read: ${res.message}` };
  if (!res.ok) return { problem: `${url} answered HTTP ${res.status}` };
  const doc = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  if (!doc || typeof doc !== 'object') return { problem: `${url} is not a JSON discovery document` };
  if (doc.issuer !== issuer) return { problem: `${url} names the issuer "${String(doc.issuer)}", not "${issuer}": give the issuer exactly as the provider names it` };
  const endpoints = { authorizationEndpoint: doc.authorization_endpoint, tokenEndpoint: doc.token_endpoint, jwksUri: doc.jwks_uri };
  const wrong = Object.entries(endpoints).find(([, value]) => !isEndpoint(value));
  if (wrong) return { problem: `${url} has no https ${wrong[0]}` };
  const methods = doc.token_endpoint_auth_methods_supported;
  // The specification's default is client_secret_basic; post only when the provider names it and not basic.
  const clientAuth = Array.isArray(methods) && !methods.includes('client_secret_basic') && methods.includes('client_secret_post') ? 'client_secret_post' : 'client_secret_basic';
  if (Array.isArray(methods) && !methods.includes('client_secret_basic') && !methods.includes('client_secret_post')) {
    return { problem: `${url} supports neither client_secret_basic nor client_secret_post for the code exchange` };
  }
  return {
    endpoints: {
      issuer,
      authorizationEndpoint: endpoints.authorizationEndpoint as string,
      tokenEndpoint: endpoints.tokenEndpoint as string,
      jwksUri: endpoints.jwksUri as string,
      ...(isEndpoint(doc.userinfo_endpoint) ? { userinfoEndpoint: doc.userinfo_endpoint } : {}),
      clientAuth,
    },
  };
}

/** {@link discover} with what was found kept per issuer for an hour; a failure isn't kept, so the next call tries again. */
export function discoveryCache(fetchFn: typeof fetch = fetch): (issuer: string) => Promise<{ endpoints: OidcEndpoints } | { problem: string }> {
  const found = new Map<string, { endpoints: OidcEndpoints; at: number }>();
  return async (issuer) => {
    const kept = found.get(issuer);
    if (kept && Date.now() - kept.at < DISCOVERY_TTL_MS) return { endpoints: kept.endpoints };
    const result = await discover(issuer, fetchFn);
    if ('endpoints' in result) found.set(issuer, { endpoints: result.endpoints, at: Date.now() });
    return result;
  };
}

/** The tokens of a code exchange that madAuth uses. */
export interface OidcTokens {
  idToken: string;
  accessToken?: string;
}

/**
 * Exchanges the authorization code for the tokens, authenticating as the confidential client the provider
 * knows (`client_secret_basic` or `client_secret_post`, see {@link OidcEndpoints}), with the PKCE verifier.
 * Null when the provider refuses, or answers without an ID token.
 */
export async function exchangeCode(
  endpoints: OidcEndpoints,
  client: { clientId: string; clientSecret: string },
  exchange: { code: string; redirectUri: string; verifier: string },
  fetchFn: typeof fetch = fetch,
): Promise<OidcTokens | null> {
  const form = new URLSearchParams({ grant_type: 'authorization_code', code: exchange.code, redirect_uri: exchange.redirectUri, code_verifier: exchange.verifier });
  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
  if (endpoints.clientAuth === 'client_secret_basic') {
    // RFC 6749, section 2.3.1: both form-encoded before they are joined.
    headers.Authorization = `Basic ${Buffer.from(`${encodeURIComponent(client.clientId)}:${encodeURIComponent(client.clientSecret)}`).toString('base64')}`;
  } else {
    form.set('client_id', client.clientId);
    form.set('client_secret', client.clientSecret);
  }
  const res = await fetchFn(endpoints.tokenEndpoint, { method: 'POST', headers, body: form.toString(), signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS) }).catch(() => null);
  if (!res?.ok) return null;
  const answer = (await res.json().catch(() => null)) as { id_token?: unknown; access_token?: unknown } | null;
  if (typeof answer?.id_token !== 'string') return null;
  return { idToken: answer.id_token, ...(typeof answer.access_token === 'string' ? { accessToken: answer.access_token } : {}) };
}

/** The asymmetric algorithms an ID token may be signed with: never HS256 (the client secret) or none. */
const ID_TOKEN_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];

/** The providers' published keys, per `jwks_uri`, as jose caches and refreshes them. */
export function keysCache(fetchFn: typeof fetch = fetch): (jwksUri: string) => JWTVerifyGetKey {
  const sets = new Map<string, JWTVerifyGetKey>();
  return (jwksUri) => {
    const known = sets.get(jwksUri);
    if (known) return known;
    const set = createRemoteJWKSet(new URL(jwksUri), { [customFetch]: (url: string, options: RequestInit) => fetchFn(url, options) });
    sets.set(jwksUri, set);
    return set;
  };
}

/**
 * The claims of an ID token, checked as OpenID Connect Core (section 3.1.3.7) asks: signed with one of the
 * provider's published keys, by the issuer, for this client (and, with several audiences, authorized for it by
 * `azp`), not expired, with the sign-in's nonce and a `sub`. Null if anything doesn't hold.
 */
export async function verifyIdToken(
  idToken: string,
  expected: { issuer: string; clientId: string; nonce: string; keys: JWTVerifyGetKey },
): Promise<JWTPayload | null> {
  const verified = await jwtVerify(idToken, expected.keys, { issuer: expected.issuer, audience: expected.clientId, algorithms: ID_TOKEN_ALGORITHMS }).catch(() => null);
  if (!verified) return null;
  const { payload } = verified;
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (audiences.length > 1 && payload.azp !== expected.clientId) return null;
  if (payload.nonce !== expected.nonce || typeof payload.sub !== 'string' || !payload.sub) return null;
  return payload;
}

/** Whether a claims set says its address is verified: `true`, and `"true"`, which some providers send. */
const isVerified = (value: unknown) => value === true || value === 'true';

/**
 * The user's address and name from the ID token, or from the userinfo endpoint when the ID token has no
 * address. The address counts only when the same claims say `email_verified`, or when the provider is marked
 * `trustEmail` (the operator's own provider). The userinfo answer must be about the ID token's `sub`.
 */
export async function addressOf(
  claims: JWTPayload,
  from: { endpoints: OidcEndpoints; accessToken?: string; trustEmail: boolean },
  fetchFn: typeof fetch = fetch,
): Promise<{ email: string; name?: string } | { error: 'email_unverified' | 'verification_failed' }> {
  const read = (source: Record<string, unknown>) => {
    if (typeof source.email !== 'string' || !source.email) return null;
    if (!from.trustEmail && !isVerified(source.email_verified)) return { error: 'email_unverified' as const };
    const name = typeof source.name === 'string' && source.name ? source.name : typeof claims.name === 'string' ? claims.name : undefined;
    return { email: source.email, ...(name ? { name } : {}) };
  };
  const inToken = read(claims);
  if (inToken) return inToken;
  if (!from.endpoints.userinfoEndpoint || !from.accessToken) return { error: 'email_unverified' };
  const res = await fetchFn(from.endpoints.userinfoEndpoint, {
    headers: { Authorization: `Bearer ${from.accessToken}`, Accept: 'application/json' },
    signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
  }).catch(() => null);
  const userinfo = res?.ok ? ((await res.json().catch(() => null)) as Record<string, unknown> | null) : null;
  // OpenID Connect Core, section 5.3.2: the answer must be about the user the ID token is about.
  if (!userinfo || userinfo.sub !== claims.sub) return { error: 'verification_failed' };
  return read(userinfo) ?? { error: 'email_unverified' };
}
