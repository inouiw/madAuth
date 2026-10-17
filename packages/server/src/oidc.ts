// Generic OpenID Connect providers (the kind `oidc` in providers.ts): finding a provider's endpoints from its
// discovery document. See "Providers" in docs/server.md.

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
