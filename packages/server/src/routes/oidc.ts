// Sign-in with a generic OpenID Connect provider (the kind `oidc`, see providers.ts and oidc.ts): the
// authorization-code flow with PKCE, a nonce and a state, at /auth/providers/<id>/start and /callback. See
// "Providers" in docs/server.md.
import type { Context, Hono } from 'hono';
import type { AppContext } from '../app.js';
import { addressOf, discoveryCache, exchangeCode, keysCache, verifyIdToken } from '../oidc.js';
import { OIDC_SCOPES, providerOf, type StoredProvider } from '../providers.js';
import { oidcAccountKey } from '../users.js';
import { createEmails } from './emails.js';
import { setConfirmation } from './email.js';
import {
  finishLink,
  pkceChallenge,
  redirectBack,
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

export function oidcRoutes(app: Hono, ctx: AppContext): void {
  const fetchFn = ctx.config.oidcFetch ?? fetch;
  const endpointsOf = discoveryCache(fetchFn);
  const keysOf = keysCache(fetchFn);
  const callbackUrl = (id: string) => `${ctx.config.issuer}${pathOf(id)}/callback`;
  // The confirmation e-mail for an address the provider doesn't vouch for; without it, such an address is refused.
  const emails = ctx.webhook && ctx.emailVerification ? createEmails(ctx, ctx.users, ctx.webhook) : null;

  /** The OpenID Connect provider the route names, or null: Google's and GitHub's routes are their own. */
  const providerOfRoute = async (c: Context): Promise<StoredProvider | null> => {
    const provider = providerOf(await ctx.methods(c), c.req.param('id') ?? '');
    return provider?.kind === 'oidc' ? provider : null;
  };
  /** How the shared sign-in code names it. */
  const asOAuthProvider = (provider: StoredProvider): OAuthProvider => ({ method: provider.id, name: provider.name });

  app.get('/auth/providers/:id/start', async (c) => {
    const provider = await providerOfRoute(c);
    if (!provider) return c.notFound();
    const returnUrl = ctx.allowedUrl(c.req.query('return_to'));
    if (!returnUrl) return c.text('return_to must be an absolute URL whose origin is in ALLOWED_ORIGINS', 400);
    const back = redirectBack(c, returnUrl.href, provider.id);
    // The browser is on its way from the app: a method that is off sends it back there, with the error.
    if (!(await ctx.enabled(c, provider.id))) return back('method_disabled');
    const found = await endpointsOf(provider.issuer!);
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
    const found = await endpointsOf(provider.issuer!);
    if ('problem' in found) return back('temporarily_unavailable');
    const clientSecret = await ctx.clientSecret(provider);
    if (!clientSecret) return back('verification_failed');

    const tokens = await exchangeCode(found.endpoints, { clientId: provider.clientId, clientSecret }, { code, redirectUri: callbackUrl(provider.id), verifier: oauth.verifier }, fetchFn);
    if (!tokens) return back('verification_failed');
    const claims = await verifyIdToken(tokens.idToken, { issuer: provider.issuer!, clientId: provider.clientId, nonce: oauth.nonce, keys: keysOf(found.endpoints.jwksUri) });
    if (!claims) return back('verification_failed');
    const address = await addressOf(claims, { endpoints: found.endpoints, accessToken: tokens.accessToken, trustEmail: !!provider.trustEmail }, fetchFn);
    if ('error' in address) return back(address.error);
    const profile = { key: oidcAccountKey(provider.id, claims.sub!), email: address.email, ...(address.name ? { name: address.name } : {}) };

    // Linking takes the account by its id, whatever its address: the signed-in user is the proof.
    const linked = await finishLink(c, ctx, asOAuthProvider(provider), oauth, profile);
    if (linked) return linked;
    /** Signs the resolved user in, or goes on with their second step; or sends the browser back with the error. */
    const signIn = async (resolved: SignInResult) => {
      if (!resolved.ok) return back(resolved.error);
      const step = await ctx.secondStep(c, resolved.user, [provider.id], provider.id, address.name ? { name: address.name } : undefined);
      if ('disabled' in step) return back('method_disabled');
      // The app continues with the second step (a code, or a setup); the challenge cookie is set.
      if ('next' in step) return back(undefined, step.next, step.factors);
      return back();
    };
    if (address.verified) return signIn(await resolveProviderUser(ctx, asOAuthProvider(provider), profile, oauth.locale));
    if (!emails) return back('email_unverified');
    const pending = await resolveUnconfirmedProviderUser(ctx, asOAuthProvider(provider), profile, oauth.locale);
    if (pending.ok !== 'confirm') return signIn(pending);
    // The address is proven by the e-mail's link or code before the account signs anyone in.
    if (!(await emails.sendLinkEmail(pending.user, 'verify', new URL(oauth.returnTo), oauth.locale))) return back('temporarily_unavailable');
    await setConfirmation(c, ctx, pending.user.id);
    return redirectToConfirmation(c, oauth.returnTo, provider.id, pending.user.email);
  });
}
