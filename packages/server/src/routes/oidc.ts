// Sign-in with a generic OpenID Connect provider (the kind `oidc`, see providers.ts and oidc.ts) or Microsoft (the
// kind `microsoft`, see microsoft.ts): the authorization-code flow with PKCE, a nonce and a state, at
// /auth/providers/<id>/start and /callback. A provider that tells no address hands over to /address, where the
// user types one. See "Providers" in docs/server.md.
import type { Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { AppContext } from '../app.js';
import { microsoftEndpoints, microsoftProfile, verifyMicrosoftIdToken } from '../microsoft.js';
import { addressOf, discoveryCache, exchangeCode, keysCache, suggestedAddress, verifyIdToken, type OidcEndpoints, type OidcTokens } from '../oidc.js';
import { isValidEmail, normalizeEmail } from '../password.js';
import { OIDC_SCOPES, isProviderMethodKind, providerOf, type StoredProvider } from '../providers.js';
import { readToken, signToken } from '../tokens.js';
import { microsoftAccountKey, oidcAccountKey } from '../users.js';
import { localeOf } from '../webhooks.js';
import { createEmails } from './emails.js';
import { setConfirmation } from './email.js';
import { accepted, body, error, redirectTarget, signInAnswer, unavailable } from './helpers.js';
import {
  finishLink,
  pkceChallenge,
  redirectBack,
  redirectToAddress,
  redirectToConfirmation,
  resolveProviderUser,
  resolveUnconfirmedProviderUser,
  startOAuth,
  takeOAuthState,
  type OAuthProvider,
  type SignInResult,
} from './oauth.js';

/** Where a provider's routes are; its state cookie comes back to them only. */
const pathOf = (id: string) => `/auth/providers/${id}`;

/** The account an ID token is about: its key, and what the provider tells of its address and name. */
interface ProviderAccount {
  key: string;
  email?: string;
  /** Whether the provider vouches for `email`; an address it doesn't is confirmed by e-mail first. */
  verified: boolean;
  name?: string;
  /** Without an address: what the user is offered to type, see `suggestedAddress`. */
  suggestion?: string;
}

/**
 * The account the user signed in with but whose address they still type (`/address`): the provider told none. It
 * lives as long as the sign-in's state, and only goes to the provider's routes.
 */
const PENDING_COOKIE = 'madauth_pending_account';
const PENDING_TYP = 'madauth-pending-account+jwt';
const PENDING_TTL = 10 * 60;
const pendingCookie = (id: string, secure: boolean) => ({ path: pathOf(id), httpOnly: true, secure, sameSite: 'Strict' as const });
type PendingAccount = Pick<ProviderAccount, 'key' | 'name' | 'suggestion'> & { locale?: string };

export function oidcRoutes(app: Hono, ctx: AppContext): void {
  const fetchFn = ctx.config.oidcFetch ?? fetch;
  const endpointsOf = discoveryCache(fetchFn);
  const keysOf = keysCache(fetchFn);
  const callbackUrl = (id: string) => `${ctx.config.issuer}${pathOf(id)}/callback`;
  // The confirmation e-mail for an address the provider doesn't vouch for; without it, such an address is refused.
  const emails = ctx.webhook && ctx.emailVerification ? createEmails(ctx, ctx.users, ctx.webhook) : null;

  /** The OpenID Connect or Microsoft provider the route names, or null: Google's and GitHub's routes are their own. */
  const providerOfRoute = async (c: Context): Promise<StoredProvider | null> => {
    const provider = providerOf(await ctx.methods(c), c.req.param('id') ?? '');
    return provider && isProviderMethodKind(provider.kind) ? provider : null;
  };
  /** How the shared sign-in code names it. */
  const asOAuthProvider = (provider: StoredProvider): OAuthProvider => ({ method: provider.id, name: provider.name });

  /** Where the provider's sign-in is: Microsoft's endpoints are known, an OpenID Connect provider's are in its discovery document. */
  const endpointsFor = async (provider: StoredProvider): Promise<{ endpoints: OidcEndpoints } | { problem: string }> =>
    provider.kind === 'microsoft' ? { endpoints: microsoftEndpoints(provider.tenant!) } : endpointsOf(provider.issuer!);

  /** The account behind the tokens of a code exchange, checked as the provider's kind needs; null if the ID token doesn't hold. */
  const accountOf = async (provider: StoredProvider, endpoints: OidcEndpoints, tokens: OidcTokens, nonce: string): Promise<ProviderAccount | { error: string }> => {
    const keys = keysOf(endpoints.jwksUri);
    if (provider.kind === 'microsoft') {
      const claims = await verifyMicrosoftIdToken(tokens.idToken, { tenant: provider.tenant!, clientId: provider.clientId, nonce, keys });
      if (!claims) return { error: 'verification_failed' };
      return { key: microsoftAccountKey(claims.tid, claims.oid), ...microsoftProfile(claims) };
    }
    const claims = await verifyIdToken(tokens.idToken, { issuer: provider.issuer!, clientId: provider.clientId, nonce, keys });
    if (!claims) return { error: 'verification_failed' };
    const key = oidcAccountKey(provider.id, claims.sub!);
    const address = await addressOf(claims, { endpoints, accessToken: tokens.accessToken, trustEmail: !!provider.trustEmail }, fetchFn);
    // Neither the ID token nor the userinfo endpoint has an address: the user types one.
    if ('error' in address && address.error === 'email_unverified') {
      const name = typeof claims.name === 'string' && claims.name ? claims.name : undefined;
      const suggestion = suggestedAddress(claims);
      return { key, verified: false, ...(name ? { name } : {}), ...(suggestion ? { suggestion } : {}) };
    }
    if ('error' in address) return address;
    return { key, ...address };
  };

  app.get('/auth/providers/:id/start', async (c) => {
    const provider = await providerOfRoute(c);
    if (!provider) return c.notFound();
    const returnUrl = ctx.allowedUrl(c.req.query('return_to'));
    if (!returnUrl) return c.text('return_to must be an absolute URL whose origin is in ALLOWED_ORIGINS', 400);
    const back = redirectBack(c, returnUrl.href, provider.id);
    // The browser is on its way from the app: a method that is off sends it back there, with the error.
    if (!(await ctx.enabled(c, provider.id))) return back('method_disabled');
    const found = await endpointsFor(provider);
    if ('problem' in found) {
      console.error(`[madauth] The OpenID Connect provider "${provider.id}" can't be reached: ${found.problem}`);
      return back('temporarily_unavailable');
    }
    // With `link=1`, the signed-in user adds the provider to their methods.
    const oauth = await startOAuth(c, ctx, pathOf(provider.id), returnUrl);
    if ('error' in oauth) return back(oauth.error);
    const url = new URL(found.endpoints.authorizationEndpoint);
    for (const [name, value] of Object.entries({
      client_id: provider.clientId,
      redirect_uri: callbackUrl(provider.id),
      response_type: 'code',
      scope: [...OIDC_SCOPES, ...(provider.scopes ?? [])].join(' '),
      state: oauth.state,
      nonce: oauth.nonce,
      code_challenge: await pkceChallenge(oauth.verifier),
      code_challenge_method: 'S256',
    })) {
      url.searchParams.set(name, value);
    }
    return c.redirect(url.href, 302);
  });

  app.get('/auth/providers/:id/callback', async (c) => {
    const provider = await providerOfRoute(c);
    if (!provider) return c.notFound();
    const oauth = await takeOAuthState(c, ctx, pathOf(provider.id));
    if (!oauth) return c.text('Sign-in expired or was started in another browser. Please try again.', 400);
    const back = redirectBack(c, oauth.returnTo, provider.id);
    if (!(await ctx.enabled(c, provider.id))) return back('method_disabled');

    if (c.req.query('error')) return back(c.req.query('error') === 'access_denied' ? 'cancelled' : 'verification_failed');
    const code = c.req.query('code');
    if (!code || c.req.query('state') !== oauth.state) return back('verification_failed');
    const found = await endpointsFor(provider);
    if ('problem' in found) return back('temporarily_unavailable');
    const clientSecret = await ctx.clientSecret(provider);
    if (!clientSecret) return back('verification_failed');

    const tokens = await exchangeCode(found.endpoints, { clientId: provider.clientId, clientSecret }, { code, redirectUri: callbackUrl(provider.id), verifier: oauth.verifier }, fetchFn);
    if (!tokens) return back('verification_failed');
    const account = await accountOf(provider, found.endpoints, tokens, oauth.nonce);
    if ('error' in account) return back(account.error);

    // Linking takes the account by its id, whatever its address, or without one: the signed-in user is the proof.
    const linked = await finishLink(c, ctx, asOAuthProvider(provider), oauth, { key: account.key, ...(account.email ? { email: account.email } : {}) });
    if (linked) return linked;
    /** Signs the resolved user in, or goes on with their second step; or sends the browser back with the error. */
    const signIn = async (resolved: SignInResult) => {
      if (!resolved.ok) return back(resolved.error);
      const step = await ctx.secondStep(c, resolved.user, [provider.id], provider.id, account.name ? { name: account.name } : undefined);
      if ('disabled' in step) return back('method_disabled');
      // The app continues with the second step (a code, or a setup); the challenge cookie is set.
      if ('next' in step) return back(undefined, step.next, step.factors);
      return back();
    };
    const profileWith = (email: string) => ({ key: account.key, email, ...(account.name ? { name: account.name } : {}) });
    if (account.email && account.verified) return signIn(await resolveProviderUser(ctx, asOAuthProvider(provider), profileWith(account.email), oauth.locale));
    if (!account.email) {
      // A returning account needs no address: its user is known.
      const known = await ctx.users.findAccountByKey(account.key);
      const user = known && (await ctx.users.findById(known.userId));
      if (user?.emailVerified) return signIn({ ok: true, user });
    }
    if (!emails) return back('email_unverified');
    if (!account.email) {
      const pending: PendingAccount = { key: account.key, ...(account.name ? { name: account.name } : {}), ...(account.suggestion ? { suggestion: account.suggestion } : {}), ...(oauth.locale ? { locale: oauth.locale } : {}) };
      setCookie(c, PENDING_COOKIE, await signToken(ctx.keys, ctx.config.issuer, PENDING_TYP, { ...pending }, PENDING_TTL), { ...pendingCookie(provider.id, ctx.secure), maxAge: PENDING_TTL });
      return redirectToAddress(c, oauth.returnTo, provider.id);
    }
    const unconfirmed = await resolveUnconfirmedProviderUser(ctx, asOAuthProvider(provider), profileWith(account.email), oauth.locale);
    if (unconfirmed.ok !== 'confirm') return signIn(unconfirmed);
    // The address is proven by the e-mail's link or code before the account signs anyone in.
    if (!(await emails.sendLinkEmail(unconfirmed.user, 'verify', new URL(oauth.returnTo), oauth.locale))) return back('temporarily_unavailable');
    await setConfirmation(c, ctx, unconfirmed.user.id);
    return redirectToConfirmation(c, oauth.returnTo, provider.id, unconfirmed.user.email);
  });

  /** The account whose address the user types now (see {@link PENDING_COOKIE}), or null when its sign-in expired. */
  const pendingOf = async (c: Context): Promise<PendingAccount | null> => {
    const claims = await readToken<PendingAccount & Record<string, unknown>>(ctx.keys, ctx.config.issuer, PENDING_TYP, getCookie(c, PENDING_COOKIE));
    if (typeof claims?.key !== 'string') return null;
    return {
      key: claims.key,
      ...(typeof claims.name === 'string' ? { name: claims.name } : {}),
      ...(typeof claims.suggestion === 'string' ? { suggestion: claims.suggestion } : {}),
      ...(typeof claims.locale === 'string' ? { locale: claims.locale } : {}),
    };
  };
  const expired = (c: Context, provider: StoredProvider) => error(c, 400, 'challenge_expired', `The sign-in with ${provider.name} expired. Please sign in again.`);

  // What the dialog offers to type: `{ suggestion }`, the address the provider hinted at, or null.
  app.get('/auth/providers/:id/address', async (c) => {
    const provider = await providerOfRoute(c);
    if (!provider) return c.notFound();
    const pending = await pendingOf(c);
    if (!pending) return expired(c, provider);
    return c.json({ suggestion: pending.suggestion ?? null });
  });

  /**
   * The address the user typed for the pending account: `{ email, redirectTo }` → 202, and the confirmation e-mail
   * proves it, as for a sign-up with a password (the code goes to `/auth/email/verify` with the address). The answer
   * is the same for every address: the owner of one that signs in another way gets `email.send_already_registered`.
   */
  app.post('/auth/providers/:id/address', async (c) => {
    const provider = await providerOfRoute(c);
    if (!provider) return c.notFound();
    if (!(await ctx.enabled(c, provider.id))) return error(c, 403, 'method_disabled', 'This way of signing in is switched off.');
    const pending = await pendingOf(c);
    if (!pending || !emails) return expired(c, provider);
    const data = await body(c);
    const target = redirectTarget(ctx, c, data.redirectTo);
    if (target instanceof Response) return target;
    if (!isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
    const email = data.email.trim();
    const locale = localeOf(data.locale) ?? pending.locale;
    const resolved = await resolveUnconfirmedProviderUser(ctx, asOAuthProvider(provider), { key: pending.key, email, ...(pending.name ? { name: pending.name } : {}) }, locale);
    const done = (answer: Response) => {
      deleteCookie(c, PENDING_COOKIE, pendingCookie(provider.id, ctx.secure));
      return answer;
    };
    if (resolved.ok === 'confirm') {
      return (await emails.sendLinkEmail(resolved.user, 'verify', target, locale)) ? done(accepted(c)) : unavailable(c);
    }
    // The account signs its user in meanwhile (a sign-up confirmed in another tab).
    if (resolved.ok) return done(signInAnswer(c, await ctx.secondStep(c, resolved.user, [provider.id], provider.id)));
    if (resolved.error === 'other_method') {
      const owner = await ctx.users.findByEmail(normalizeEmail(email));
      if (owner && !(await emails.sendAccountEmail(owner, 'email.send_already_registered', target, locale))) return unavailable(c);
      return done(accepted(c));
    }
    if (resolved.error === 'signup_rejected') return error(c, 403, 'signup_rejected', resolved.message);
    return unavailable(c);
  });
}
