// GitHub's side of GitHub sign-in: the code exchange and the account behind an access token, over GitHub's
// REST API, and revoking the OAuth App's authorization. Every call carries a User-Agent, which
// api.github.com insists on.

const TOKEN_ENDPOINT = 'https://github.com/login/oauth/access_token';
const API = 'https://api.github.com';
const API_VERSION = '2022-11-28';
const USER_AGENT = 'madauth';
/** GitHub's stand-in for a private address: listed as verified, but nothing sent to it arrives. */
const NOREPLY_DOMAIN = '@users.noreply.github.com';
/** How long one call to GitHub may take; a sign-in makes three. */
const TIMEOUT_MS = 10_000;

/** What GitHub says about the account that signed in. */
export interface GitHubAccount {
  /** GitHub's numeric user id, as a string; the login can change, this never does. */
  id: string;
  /** The primary address, verified by GitHub, or another verified one if the primary is not. */
  email: string;
  /** The display name, or the login if the account has none. */
  name: string;
  picture?: string;
}

export type GitHubAccountResult =
  | { ok: true; account: GitHubAccount }
  | { ok: false; error: 'verification_failed' | 'email_unverified'; reason: string };

export interface GitHubAppCredentials {
  clientId: string;
  clientSecret: string;
}

const apiHeaders = (token: string) => ({
  Authorization: `Bearer ${token}`,
  Accept: 'application/vnd.github+json',
  'X-GitHub-Api-Version': API_VERSION,
  'User-Agent': USER_AGENT,
});

/**
 * The access token for an authorization code, or null if GitHub did not issue one. GitHub answers a bad or
 * used code with HTTP 200 and `{ error }`, so only a token in the body counts.
 */
export async function exchangeGitHubCode(
  app: GitHubAppCredentials,
  code: string,
  redirectUri: string,
  verifier: string,
): Promise<string | null> {
  try {
    const res = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': USER_AGENT },
      body: new URLSearchParams({
        client_id: app.clientId,
        client_secret: app.clientSecret,
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { access_token?: unknown };
    return typeof body.access_token === 'string' && body.access_token ? body.access_token : null;
  } catch {
    return null;
  }
}

/**
 * The account behind an access token: `GET /user` for the id, name and picture, and `GET /user/emails`
 * (scope `user:email`) for an address GitHub has verified: the primary one, else another verified one, but
 * never the `noreply` stand-in GitHub lists for users who keep their address private. The public address on
 * the profile is not used: it can be any address the user typed in.
 */
export async function fetchGitHubAccount(token: string): Promise<GitHubAccountResult> {
  const failed = (reason: string): GitHubAccountResult => ({ ok: false, error: 'verification_failed', reason });
  let user: { id?: unknown; login?: unknown; name?: unknown; avatar_url?: unknown };
  let emails: { email?: unknown; primary?: unknown; verified?: unknown }[];
  try {
    const [userRes, emailsRes] = await Promise.all([
      fetch(`${API}/user`, { headers: apiHeaders(token), signal: AbortSignal.timeout(TIMEOUT_MS) }),
      fetch(`${API}/user/emails`, { headers: apiHeaders(token), signal: AbortSignal.timeout(TIMEOUT_MS) }),
    ]);
    if (!userRes.ok) return failed(`GET /user answered ${userRes.status}`);
    if (!emailsRes.ok) return failed(`GET /user/emails answered ${emailsRes.status}`);
    user = (await userRes.json()) as typeof user;
    emails = (await emailsRes.json()) as typeof emails;
  } catch (e) {
    return failed((e as Error).message);
  }
  const id = typeof user.id === 'number' ? String(user.id) : typeof user.id === 'string' ? user.id : '';
  if (!id || typeof user.login !== 'string') return failed('GET /user did not return an account');
  if (!Array.isArray(emails)) return failed('GET /user/emails did not return a list');
  const verified = emails.filter((e) => typeof e.email === 'string' && e.email && e.verified === true && !e.email.endsWith(NOREPLY_DOMAIN));
  const address = verified.find((e) => e.primary === true) ?? verified[0];
  if (!address) return { ok: false, error: 'email_unverified', reason: 'the GitHub account has no verified e-mail address' };
  const account: GitHubAccount = {
    id,
    email: address.email as string,
    name: typeof user.name === 'string' && user.name.trim() ? user.name.trim() : user.login,
  };
  if (typeof user.avatar_url === 'string' && user.avatar_url) account.picture = user.avatar_url;
  return { ok: true, account };
}

/**
 * Revokes the OAuth App's authorization for the account behind `token`, which takes every token the app has
 * for it with it: `DELETE /applications/{client_id}/grant`, authenticated as the app. Resolves to GitHub's
 * status (204 when revoked, 404 when the token was gone already), or null if GitHub could not be reached.
 */
export async function revokeGitHubGrant(app: GitHubAppCredentials, token: string): Promise<number | null> {
  try {
    const res = await fetch(`${API}/applications/${encodeURIComponent(app.clientId)}/grant`, {
      method: 'DELETE',
      headers: {
        Authorization: `Basic ${Buffer.from(`${app.clientId}:${app.clientSecret}`).toString('base64')}`,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
        'X-GitHub-Api-Version': API_VERSION,
        'User-Agent': USER_AGENT,
      },
      body: JSON.stringify({ access_token: token }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    return res.status;
  } catch {
    return null;
  }
}
