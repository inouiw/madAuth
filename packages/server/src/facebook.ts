// Facebook's side of Facebook sign-in (the kind `facebook` in providers.ts): Facebook Login's manual redirect flow,
// the code exchange and the account behind the access token, over the Graph API. The routes are the OpenID Connect
// providers' (routes/oidc.ts), through SOCIAL_FLOWS in social.ts. Facebook says nothing about whether an address is
// confirmed, so madAuth confirms it by e-mail once. See "Facebook setup" in docs/server.md and docs/social-security.md.
import { createHmac } from 'node:crypto';
import type { SocialAuthorizeRequest, SocialProfileResult } from './social.js';
import { cutName } from './user.js';

/** The Graph API version madAuth calls: each one works for at least two years after the next one comes out. */
export const FACEBOOK_API_VERSION = 'v26.0';
const DIALOG = `https://www.facebook.com/${FACEBOOK_API_VERSION}/dialog/oauth`;
const GRAPH = `https://graph.facebook.com/${FACEBOOK_API_VERSION}`;
/** The permissions madAuth asks for: the address and the public profile (id, name, picture), which need no app review. */
export const FACEBOOK_SCOPES = ['email', 'public_profile'];
/** How long one call to Facebook may take; a sign-in makes two. */
const TIMEOUT_MS = 10_000;

/** Facebook's login dialog for a sign-in: the state, no PKCE (the manual flow has none; the client secret protects the code). */
export function facebookAuthorizeUrl(request: Pick<SocialAuthorizeRequest, 'clientId' | 'redirectUri' | 'state'>): string {
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

/**
 * The access token for an authorization code, or null if Facebook issued none. Facebook's manual flow documents a
 * GET; the endpoint takes the same parameters as a form, which keeps the App Secret out of URLs and their logs.
 */
export async function exchangeFacebookCode(
  app: { clientId: string; clientSecret: string },
  exchange: { code: string; redirectUri: string },
  fetchFn: typeof fetch = fetch,
): Promise<string | null> {
  const res = await fetchFn(`${GRAPH}/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({ client_id: app.clientId, redirect_uri: exchange.redirectUri, client_secret: app.clientSecret, code: exchange.code }).toString(),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  }).catch(() => null);
  if (!res?.ok) {
    await res?.body?.cancel();
    return null;
  }
  const body = (await res.json().catch(() => null)) as { access_token?: unknown } | null;
  return typeof body?.access_token === 'string' && body.access_token ? body.access_token : null;
}

/**
 * The account behind an access token: `GET /me` with the id, name and address, and `appsecret_proof` (the token's
 * HMAC with the app secret), which an app with "Require App Secret" demands. The address is never counted as
 * verified: Facebook's documentation only says it is the profile's primary one, when it has a valid one. No
 * picture: Facebook's are signed CDN links that expire within days.
 */
export async function fetchFacebookProfile(token: string, appSecret: string, fetchFn: typeof fetch = fetch): Promise<SocialProfileResult> {
  const url = new URL(`${GRAPH}/me`);
  url.search = new URLSearchParams({ fields: 'id,name,email', appsecret_proof: createHmac('sha256', appSecret).update(token).digest('hex') }).toString();
  const res = await fetchFn(url.href, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }, signal: AbortSignal.timeout(TIMEOUT_MS) }).catch((e: Error) => e);
  if (res instanceof Error) return { ok: false, reason: res.message };
  if (!res.ok) {
    await res.body?.cancel();
    return { ok: false, reason: `GET /me answered ${res.status}` };
  }
  const me = (await res.json().catch(() => null)) as { id?: unknown; name?: unknown; email?: unknown } | null;
  if (typeof me?.id !== 'string' || !me.id) return { ok: false, reason: 'GET /me did not return an account' };
  return {
    ok: true,
    profile: {
      id: me.id,
      verified: false,
      ...(typeof me.email === 'string' && me.email ? { email: me.email } : {}),
      ...(cutName(me.name) ? { name: cutName(me.name) } : {}),
    },
  };
}
