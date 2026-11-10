// Facebook's side of Facebook sign-in (the kind `facebook` in providers.ts): Facebook Login's manual redirect flow,
// the code exchange and the account behind the access token, over the Graph API. The routes are the OpenID Connect
// providers' (routes/oidc.ts). Facebook says nothing about whether an address is confirmed, so madAuth confirms it by
// e-mail once. See "Facebook setup" in docs/server.md and docs/social-security.md.
import { createHmac } from 'node:crypto';

/** The Graph API version madAuth calls: each one works for at least two years after the next one comes out. */
export const FACEBOOK_API_VERSION = 'v26.0';
const DIALOG = `https://www.facebook.com/${FACEBOOK_API_VERSION}/dialog/oauth`;
const GRAPH = `https://graph.facebook.com/${FACEBOOK_API_VERSION}`;
/** The permissions madAuth asks for: the address and the public profile (id, name, picture), which need no app review. */
export const FACEBOOK_SCOPES = ['email', 'public_profile'];
/** How long one call to Facebook may take; a sign-in makes two. */
const TIMEOUT_MS = 10_000;

/** What Facebook says about the account that signed in. */
export interface SocialProfile {
  /** The account's id at the provider, which never changes (Facebook's is app-scoped: this app's only). */
  id: string;
  /** The address, if the provider gave one. */
  email?: string;
  /** Whether the provider says it confirmed the address. */
  verified: boolean;
  name?: string;
  picture?: string;
}

export type SocialProfileResult = { ok: true; profile: SocialProfile } | { ok: false; reason: string };

/** Facebook's login dialog for a sign-in: the state, no PKCE (the manual flow has none; the client secret protects the code). */
export function facebookAuthorizeUrl(request: { clientId: string; redirectUri: string; state: string }): string {
  const url = new URL(DIALOG);
  url.search = new URLSearchParams({
    client_id: request.clientId,
    redirect_uri: request.redirectUri,
    state: request.state,
    response_type: 'code',
    scope: FACEBOOK_SCOPES.join(','),
  }).toString();
  return url.href;
}

/** The access token for an authorization code, as Facebook's manual flow documents it, or null if Facebook issued none. */
export async function exchangeFacebookCode(
  app: { clientId: string; clientSecret: string },
  exchange: { code: string; redirectUri: string },
  fetchFn: typeof fetch = fetch,
): Promise<string | null> {
  const url = new URL(`${GRAPH}/oauth/access_token`);
  url.search = new URLSearchParams({ client_id: app.clientId, redirect_uri: exchange.redirectUri, client_secret: app.clientSecret, code: exchange.code }).toString();
  const res = await fetchFn(url.href, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(TIMEOUT_MS) }).catch(() => null);
  if (!res?.ok) {
    await res?.body?.cancel();
    return null;
  }
  const body = (await res.json().catch(() => null)) as { access_token?: unknown } | null;
  return typeof body?.access_token === 'string' && body.access_token ? body.access_token : null;
}

/**
 * The account behind an access token: `GET /me` with the id, name, address and picture, and `appsecret_proof`
 * (the token's HMAC with the app secret), which an app with "Require App Secret" demands. The address is never
 * counted as verified: Facebook's documentation only says it is the profile's primary one, when it has a valid one.
 */
export async function fetchFacebookProfile(token: string, appSecret: string, fetchFn: typeof fetch = fetch): Promise<SocialProfileResult> {
  const url = new URL(`${GRAPH}/me`);
  url.search = new URLSearchParams({ fields: 'id,name,email,picture.width(256).height(256)', appsecret_proof: createHmac('sha256', appSecret).update(token).digest('hex') }).toString();
  const res = await fetchFn(url.href, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }, signal: AbortSignal.timeout(TIMEOUT_MS) }).catch((e: Error) => e);
  if (res instanceof Error) return { ok: false, reason: res.message };
  if (!res.ok) {
    await res.body?.cancel();
    return { ok: false, reason: `GET /me answered ${res.status}` };
  }
  const me = (await res.json().catch(() => null)) as { id?: unknown; name?: unknown; email?: unknown; picture?: { data?: { url?: unknown; is_silhouette?: unknown } } } | null;
  if (typeof me?.id !== 'string' || !me.id) return { ok: false, reason: 'GET /me did not return an account' };
  const picture = me.picture?.data;
  return {
    ok: true,
    profile: {
      id: me.id,
      verified: false,
      ...(typeof me.email === 'string' && me.email ? { email: me.email } : {}),
      ...(typeof me.name === 'string' && me.name.trim() ? { name: me.name.trim() } : {}),
      ...(typeof picture?.url === 'string' && picture.url && picture.is_silhouette !== true ? { picture: picture.url } : {}),
    },
  };
}
