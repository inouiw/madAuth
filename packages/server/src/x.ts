// X's side of X sign-in (the kind `x` in providers.ts): X's OAuth 2.0 authorization-code flow with PKCE, the code
// exchange and the account behind the access token, over the X API v2. The routes are the OpenID Connect providers'
// (routes/oidc.ts). The address comes as `confirmed_email`, with the scope `users.email`; an account without one
// types it. See "X setup" in docs/server.md and docs/social-security.md.
import type { SocialProfile, SocialProfileResult } from './facebook.js';
import { cutName } from './user.js';

const AUTHORIZE = 'https://x.com/i/oauth2/authorize';
const TOKEN = 'https://api.x.com/2/oauth2/token';
const ME = 'https://api.x.com/2/users/me';
/** The scopes madAuth asks for: `users.read` (which needs `tweet.read`) for the account, `users.email` for its confirmed address. */
export const X_SCOPES = ['tweet.read', 'users.read', 'users.email'];
/** How long one call to X may take; a sign-in makes two. */
const TIMEOUT_MS = 10_000;

/** X's authorization page for a sign-in: the state and PKCE (`S256`), which X requires. */
export function xAuthorizeUrl(request: { clientId: string; redirectUri: string; state: string; codeChallenge: string }): string {
  const url = new URL(AUTHORIZE);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: request.clientId,
    redirect_uri: request.redirectUri,
    scope: X_SCOPES.join(' '),
    state: request.state,
    code_challenge: request.codeChallenge,
    code_challenge_method: 'S256',
  }).toString();
  return url.href;
}

/** The access token for an authorization code, authenticating as the confidential client (HTTP Basic), or null if X issued none. */
export async function exchangeXCode(
  app: { clientId: string; clientSecret: string },
  exchange: { code: string; redirectUri: string; verifier: string },
  fetchFn: typeof fetch = fetch,
): Promise<string | null> {
  const res = await fetchFn(TOKEN, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
      // RFC 6749, section 2.3.1: both form-encoded before they are joined.
      Authorization: `Basic ${Buffer.from(`${encodeURIComponent(app.clientId)}:${encodeURIComponent(app.clientSecret)}`).toString('base64')}`,
    },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: exchange.code, redirect_uri: exchange.redirectUri, code_verifier: exchange.verifier }).toString(),
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
 * The account behind an access token: `GET /2/users/me` with the id, name, username, picture and
 * `confirmed_email`, the address X confirmed, which counts as verified. Without it (an account made with a phone
 * number) the profile has no address.
 */
export async function fetchXProfile(token: string, fetchFn: typeof fetch = fetch): Promise<SocialProfileResult> {
  const url = `${ME}?${new URLSearchParams({ 'user.fields': 'profile_image_url,confirmed_email' }).toString()}`;
  const res = await fetchFn(url, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }, signal: AbortSignal.timeout(TIMEOUT_MS) }).catch((e: Error) => e);
  if (res instanceof Error) return { ok: false, reason: res.message };
  if (!res.ok) {
    await res.body?.cancel();
    return { ok: false, reason: `GET /2/users/me answered ${res.status}` };
  }
  const answer = (await res.json().catch(() => null)) as { data?: { id?: unknown; name?: unknown; username?: unknown; profile_image_url?: unknown; confirmed_email?: unknown } } | null;
  const user = answer?.data;
  if (typeof user?.id !== 'string' || !user.id) return { ok: false, reason: 'GET /2/users/me did not return an account' };
  const email = typeof user.confirmed_email === 'string' && user.confirmed_email ? user.confirmed_email : undefined;
  const name = cutName(user.name) ?? cutName(user.username);
  const profile: SocialProfile = {
    id: user.id,
    verified: !!email,
    ...(email ? { email } : {}),
    ...(name ? { name } : {}),
    ...(typeof user.profile_image_url === 'string' && user.profile_image_url ? { picture: user.profile_image_url } : {}),
  };
  return { ok: true, profile };
}
