import type { Hono } from 'hono';
import type { AppContext } from '../app.js';
import type { MadauthConfig } from '../config.js';
import { exchangeGitHubCode, fetchGitHubAccount, revokeGitHubGrant } from '../github.js';
import { decrypt, encrypt } from '../crypto.js';
import { githubAccountKey, type StoredAccount } from '../users.js';
import { linkingUser, linkProviderAccount, pkceChallenge, redirectBack, resolveProviderUser, startOAuth, takeOAuthState, type OAuthProvider } from './oauth.js';

const GITHUB_AUTH_ENDPOINT = 'https://github.com/login/oauth/authorize';

/** The state cookie comes back on the redirect to /auth/github/callback only. */
const COOKIE_PATH = '/auth/github';

const GITHUB: OAuthProvider = { method: 'github', name: 'GitHub' };

type GitHubConfig = NonNullable<MadauthConfig['github']>;

/**
 * GitHub sign-in: the server-side authorization-code flow with PKCE, the only one GitHub has. The access
 * token is kept on the account, encrypted with `tokenKey`, for one thing: revoking the OAuth App's
 * authorization when the user deletes their account.
 */
export function githubRoutes(app: Hono, ctx: AppContext, github: GitHubConfig, tokenKey: Buffer): void {
  const callbackUrl = `${ctx.config.issuer}/auth/github/callback`;

  app.get('/auth/github/start', async (c) => {
    const returnUrl = ctx.allowedUrl(c.req.query('return_to'));
    if (!returnUrl) return c.text('return_to must be an absolute URL whose origin is in ALLOWED_ORIGINS', 400);
    // The browser is on its way from the app: a method that is off sends it back there, with the error.
    if (!(await ctx.enabled(c, 'github'))) return redirectBack(c, returnUrl.href, 'github')('method_disabled');
    // `link=1`: the signed-in user adds GitHub to their methods.
    const linking = await linkingUser(c, ctx);
    if (linking && 'error' in linking) return redirectBack(c, returnUrl.href, 'github')(linking.error);
    const oauth = await startOAuth(c, ctx, COOKIE_PATH, returnUrl, linking?.link);

    const url = new URL(GITHUB_AUTH_ENDPOINT);
    url.search = new URLSearchParams({
      client_id: github.clientId,
      redirect_uri: callbackUrl,
      // Only the addresses: the profile's id, name and picture come with any token.
      scope: 'user:email',
      state: oauth.state,
      code_challenge: await pkceChallenge(oauth.verifier),
      code_challenge_method: 'S256',
    }).toString();
    return c.redirect(url.href, 302);
  });

  app.get('/auth/github/callback', async (c) => {
    const oauth = await takeOAuthState(c, ctx, COOKIE_PATH);
    if (!oauth) return c.text('Sign-in expired or was started in another browser. Please try again.', 400);
    const back = redirectBack(c, oauth.returnTo, 'github');
    if (!(await ctx.enabled(c, 'github'))) return back('method_disabled');

    if (c.req.query('error')) return back(c.req.query('error') === 'access_denied' ? 'cancelled' : 'verification_failed');
    const code = c.req.query('code');
    if (!code || c.req.query('state') !== oauth.state) return back('verification_failed');

    const token = await exchangeGitHubCode(github, code, callbackUrl, oauth.verifier);
    if (!token) return back('verification_failed');
    const result = await fetchGitHubAccount(token);
    if (!result.ok) return back(result.error);
    const { account } = result;
    const profile = { key: githubAccountKey(account.id), email: account.email, name: account.name, secret: encrypt(tokenKey, Buffer.from(token)) };

    if (oauth.link) {
      // Still the user who started it: the session cookie comes along on the redirect.
      if ((await ctx.currentUser(c))?.id !== oauth.link) return back('no_session');
      const linked = await linkProviderAccount(ctx, GITHUB, oauth.link, profile);
      return linked.ok ? back(undefined, undefined, [], true) : back(linked.error);
    }
    const resolved = await resolveProviderUser(ctx, GITHUB, profile, oauth.locale);
    if (!resolved.ok) return back(resolved.error);
    const step = await ctx.secondStep(c, resolved.user, ['github'], 'github', { name: account.name, picture: account.picture });
    if ('disabled' in step) return back('method_disabled');
    // The app continues with the second step (a code, or the app's setup); the challenge cookie is set.
    if ('next' in step) return back(undefined, step.next, step.factors);
    return back();
  });
}

/**
 * Takes the OAuth App's authorization away at GitHub, with the token of the user's last sign-in, before the
 * user is deleted: madAuth then no longer appears under the user's authorized apps. Best effort: the
 * deletion goes ahead whatever happens here, and a failure is logged.
 */
export async function revokeGrant(github: GitHubConfig, tokenKey: Buffer, account: StoredAccount | null): Promise<void> {
  if (!account) return;
  const token = account.secret ? decrypt(tokenKey, account.secret) : null;
  if (!token) {
    console.error(`[madauth] The GitHub token of user ${account.userId} can't be read (was MADAUTH_SIGNING_KEY changed?): the authorization stays at GitHub until the user removes it.`);
    return;
  }
  const status = await revokeGitHubGrant(github, token.toString());
  // 204: revoked. 404: the token was gone already, e.g. the user removed the app at GitHub.
  if (status !== 204 && status !== 404) {
    console.error(`[madauth] GitHub did not revoke the authorization of user ${account.userId}${status ? ` (HTTP ${status})` : ''}: it stays until the user removes it.`);
  }
}
