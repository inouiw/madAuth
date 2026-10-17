import type { Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { AppContext } from '../app.js';
import { verifyGoogleIdToken, type GoogleProfile } from '../google.js';
import { providerOf, type StoredProvider } from '../providers.js';
import { randomString, readToken, signToken } from '../tokens.js';
import { googleAccountKey } from '../users.js';
import { localeOf } from '../webhooks.js';
import { recentUser, signInAnswer } from './helpers.js';
import {
  finishLink,
  linkProviderAccount,
  pkceChallenge,
  redirectBack,
  resolveProviderUser,
  startOAuth,
  takeOAuthState,
  type OAuthProvider,
  type ProviderProfile,
} from './oauth.js';

const NONCE_COOKIE = 'madauth_nonce';
const NONCE_TYP = 'madauth-nonce+jwt';
const NONCE_TTL = 5 * 60;

/** The state cookie of the code flow comes back on the redirect to /auth/google/callback only. */
const COOKIE_PATH = '/auth/google';

const GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';

const GOOGLE: OAuthProvider = { method: 'google', name: 'Google' };

/** What a verified Google profile proves: a Google account is known by its `sub`, its address may change. */
const toProfile = (profile: GoogleProfile): ProviderProfile => ({ key: googleAccountKey(profile.sub), email: profile.email, name: profile.name });

/**
 * Google sign-in: FedCM / One Tap, and the server-side code flow when the Google provider has a client secret. The
 * provider is read from the store with each request; without one, the routes answer 404 as if they weren't there.
 */
export function googleRoutes(app: Hono, ctx: AppContext): void {
  const { config, keys, secure } = ctx;
  const { issuer } = config;
  const callbackUrl = `${issuer}/auth/google/callback`;
  const googleOf = async (c: Context) => providerOf(await ctx.methods(c), 'google');
  /** The Google provider, which every route below finds: the first route makes sure it exists. */
  const google = async (c: Context): Promise<StoredProvider> => (await googleOf(c))!;

  app.use(`${COOKIE_PATH}/*`, async (c, next) => {
    if (!(await googleOf(c))) return c.notFound();
    await next();
  });

  const disabled = (c: Context) =>
    c.json({ error: 'method_disabled', message: 'Google sign-in is switched off.' }, 403);

  // --- FedCM / One Tap (the ID token is issued in the browser and verified here) ---

  app.post('/auth/google/nonce', async (c) => {
    if (!(await ctx.enabled(c, 'google'))) return disabled(c);
    const nonce = randomString();
    const token = await signToken(keys, issuer, NONCE_TYP, { nonce }, NONCE_TTL);
    setCookie(c, NONCE_COOKIE, token, {
      path: COOKIE_PATH,
      httpOnly: true,
      secure,
      sameSite: 'Strict',
      maxAge: NONCE_TTL,
    });
    return c.json({ nonce });
  });

  /** The Google profile of the ID token in the request, checked against the nonce cookie; else the answer to send. */
  const verifiedCredential = async (c: Context, body: { credential?: unknown }): Promise<GoogleProfile | Response> => {
    if (typeof body.credential !== 'string' || !body.credential) {
      return c.json({ error: 'verification_failed', message: 'credential is missing' }, 400);
    }
    const nonceClaims = await readToken<{ nonce: string }>(keys, issuer, NONCE_TYP, getCookie(c, NONCE_COOKIE));
    if (!nonceClaims) {
      return c.json({ error: 'verification_failed', message: 'nonce cookie missing or expired' }, 401);
    }
    const result = await verifyGoogleIdToken(body.credential, {
      clientId: (await google(c)).clientId,
      nonce: nonceClaims.nonce,
      keys: config.jwksResolver,
    });
    if (!result.ok) {
      return c.json({ error: result.error, message: result.reason }, result.error === 'email_unverified' ? 403 : 401);
    }
    deleteCookie(c, NONCE_COOKIE, { path: COOKIE_PATH, secure });
    return result.profile;
  };

  app.post('/auth/google/verify', async (c) => {
    if (!(await ctx.enabled(c, 'google'))) return disabled(c);
    const body = await c.req.json<{ credential?: unknown; locale?: unknown }>().catch(() => ({}) as { credential?: unknown; locale?: unknown });
    const profile = await verifiedCredential(c, body);
    if (profile instanceof Response) return profile;
    const resolved = await resolveProviderUser(ctx, GOOGLE, toProfile(profile), localeOf(body.locale));
    if (!resolved.ok) {
      if (resolved.error === 'other_method') return c.json({ error: resolved.error, message: resolved.message, methods: resolved.methods }, 403);
      return c.json({ error: resolved.error, message: resolved.message }, resolved.error === 'signup_rejected' ? 403 : 503);
    }
    return signInAnswer(c, await ctx.secondStep(c, resolved.user, ['google'], 'google', profile));
  });

  // A signed-in user adds a Google account to their methods, with an ID token from One Tap / FedCM.
  app.post('/auth/google/link', async (c) => {
    if (!(await ctx.enabled(c, 'google'))) return disabled(c);
    const user = await recentUser(c, ctx);
    if (user instanceof Response) return user;
    const profile = await verifiedCredential(c, await c.req.json<{ credential?: unknown }>().catch(() => ({})));
    if (profile instanceof Response) return profile;
    const linked = await linkProviderAccount(ctx, GOOGLE, user, toProfile(profile));
    if (!linked.ok) return c.json({ error: linked.error, message: linked.message }, 409);
    return c.json({});
  });

  // --- Server-side authorization-code flow with PKCE (only with the provider's client secret) ---

  const requireCodeFlow = async (c: Context, next: () => Promise<void>) => {
    if (!(await google(c)).secret) return c.json({ error: 'not_found' }, 404);
    await next();
  };

  app.get('/auth/google/start', requireCodeFlow, async (c) => {
    const returnUrl = ctx.allowedUrl(c.req.query('return_to'));
    if (!returnUrl) return c.text('return_to must be an absolute URL whose origin is in ALLOWED_ORIGINS', 400);
    // The browser is on its way from the app: a method that is off sends it back there, with the error.
    if (!(await ctx.enabled(c, 'google'))) return redirectBack(c, returnUrl.href, 'google')('method_disabled');
    // With `link=1`, the signed-in user adds Google to their methods.
    const oauth = await startOAuth(c, ctx, COOKIE_PATH, returnUrl);
    if ('error' in oauth) return redirectBack(c, returnUrl.href, 'google')(oauth.error);

    const url = new URL(GOOGLE_AUTH_ENDPOINT);
    url.search = new URLSearchParams({
      client_id: (await google(c)).clientId,
      redirect_uri: callbackUrl,
      response_type: 'code',
      scope: 'openid email profile',
      state: oauth.state,
      nonce: oauth.nonce,
      code_challenge: await pkceChallenge(oauth.verifier),
      code_challenge_method: 'S256',
    }).toString();
    return c.redirect(url.href, 302);
  });

  app.get('/auth/google/callback', requireCodeFlow, async (c) => {
    const oauth = await takeOAuthState(c, ctx, COOKIE_PATH);
    if (!oauth) return c.text('Sign-in expired or was started in another browser. Please try again.', 400);
    const back = redirectBack(c, oauth.returnTo, 'google');
    if (!(await ctx.enabled(c, 'google'))) return back('method_disabled');

    if (c.req.query('error')) return back(c.req.query('error') === 'access_denied' ? 'cancelled' : 'verification_failed');
    const code = c.req.query('code');
    if (!code || c.req.query('state') !== oauth.state) return back('verification_failed');
    const provider = await google(c);
    const clientSecret = await ctx.clientSecret(provider);
    if (!clientSecret) return back('verification_failed');

    let idToken: unknown;
    try {
      const res = await fetch(GOOGLE_TOKEN_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: provider.clientId,
          client_secret: clientSecret,
          redirect_uri: callbackUrl,
          grant_type: 'authorization_code',
          code_verifier: oauth.verifier,
        }),
      });
      if (!res.ok) return back('verification_failed');
      ({ id_token: idToken } = (await res.json()) as { id_token?: unknown });
    } catch {
      return back('verification_failed');
    }
    if (typeof idToken !== 'string') return back('verification_failed');

    const result = await verifyGoogleIdToken(idToken, {
      clientId: provider.clientId,
      nonce: oauth.nonce,
      keys: config.jwksResolver,
    });
    if (!result.ok) return back(result.error);
    const linked = await finishLink(c, ctx, GOOGLE, oauth, toProfile(result.profile));
    if (linked) return linked;
    const resolved = await resolveProviderUser(ctx, GOOGLE, toProfile(result.profile), oauth.locale);
    if (!resolved.ok) return back(resolved.error);
    const step = await ctx.secondStep(c, resolved.user, ['google'], 'google', result.profile);
    if ('disabled' in step) return back('method_disabled');
    // The app continues with the second step (a code, or the app's setup); the challenge cookie is set.
    if ('next' in step) return back(undefined, step.next, step.factors);
    return back();
  });
}
