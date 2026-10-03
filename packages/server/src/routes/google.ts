import type { Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { base64url } from 'jose';
import type { AppContext } from '../app.js';
import type { MadauthConfig } from '../config.js';
import { verifyGoogleIdToken } from '../google.js';
import { randomString, readToken, signToken } from '../tokens.js';

const NONCE_COOKIE = 'madauth_nonce';
const NONCE_TYP = 'madauth-nonce+jwt';
const NONCE_TTL = 5 * 60;

const OAUTH_COOKIE = 'madauth_oauth';
const OAUTH_TYP = 'madauth-oauth-state+jwt';
const OAUTH_TTL = 10 * 60;

const GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';

/** Hash parameter that carries a sign-in error back to the app after the code flow. */
export const REDIRECT_ERROR_PARAM = 'madauth_error';

interface OAuthState {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url.encode(new Uint8Array(digest));
}

/** Google sign-in: FedCM / One Tap, and the server-side code flow when a client secret is configured. */
export function googleRoutes(app: Hono, ctx: AppContext, google: NonNullable<MadauthConfig['google']>): void {
  const { config, keys, secure } = ctx;
  const { issuer } = config;
  const callbackUrl = `${issuer}/auth/google/callback`;

  // --- FedCM / One Tap (the ID token is issued in the browser and verified here) ---

  app.post('/auth/google/nonce', async (c) => {
    const nonce = randomString();
    const token = await signToken(await keys, issuer, NONCE_TYP, { nonce }, NONCE_TTL);
    setCookie(c, NONCE_COOKIE, token, {
      path: '/auth/google',
      httpOnly: true,
      secure,
      sameSite: 'Strict',
      maxAge: NONCE_TTL,
    });
    return c.json({ nonce });
  });

  app.post('/auth/google/verify', async (c) => {
    const body = await c.req.json<{ credential?: unknown }>().catch(() => ({}) as { credential?: unknown });
    if (typeof body.credential !== 'string' || !body.credential) {
      return c.json({ error: 'verification_failed', message: 'credential is missing' }, 400);
    }
    const nonceClaims = await readToken<{ nonce: string }>(await keys, issuer, NONCE_TYP, getCookie(c, NONCE_COOKIE));
    if (!nonceClaims) {
      return c.json({ error: 'verification_failed', message: 'nonce cookie missing or expired' }, 401);
    }
    const result = await verifyGoogleIdToken(body.credential, {
      clientId: google.clientId,
      nonce: nonceClaims.nonce,
      keys: config.jwksResolver,
    });
    if (!result.ok) {
      return c.json({ error: result.error, message: result.reason }, result.error === 'email_unverified' ? 403 : 401);
    }
    deleteCookie(c, NONCE_COOKIE, { path: '/auth/google', secure });
    await ctx.startSession(c, result.user, ['google']);
    await ctx.emit('user.signed_in', { user: result.user, method: 'google' });
    return c.json({ user: result.user });
  });

  // --- Server-side authorization-code flow with PKCE (only with GOOGLE_CLIENT_SECRET) ---

  const requireCodeFlow = async (c: Context, next: () => Promise<void>) => {
    if (!google.clientSecret) return c.json({ error: 'not_found' }, 404);
    await next();
  };

  app.get('/auth/google/start', requireCodeFlow, async (c) => {
    const returnUrl = ctx.allowedUrl(c.req.query('return_to'));
    if (!returnUrl) return c.text('return_to must be an absolute URL whose origin is in ALLOWED_ORIGINS', 400);

    const oauth: OAuthState = {
      state: randomString(),
      nonce: randomString(),
      verifier: randomString(),
      returnTo: returnUrl.href,
    };
    const token = await signToken(await keys, issuer, OAUTH_TYP, { ...oauth }, OAUTH_TTL);
    // Lax: the cookie must come back on the top-level redirect from Google to /callback.
    setCookie(c, OAUTH_COOKIE, token, {
      path: '/auth/google',
      httpOnly: true,
      secure,
      sameSite: 'Lax',
      maxAge: OAUTH_TTL,
    });

    const url = new URL(GOOGLE_AUTH_ENDPOINT);
    url.search = new URLSearchParams({
      client_id: google.clientId,
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
    const oauth = await readToken<OAuthState & Record<string, unknown>>(await keys, issuer, OAUTH_TYP, getCookie(c, OAUTH_COOKIE));
    if (!oauth) return c.text('Sign-in expired or was started in another browser. Please try again.', 400);
    deleteCookie(c, OAUTH_COOKIE, { path: '/auth/google', secure });

    const back = (error?: string) => {
      const url = new URL(oauth.returnTo);
      if (error) url.hash = `${REDIRECT_ERROR_PARAM}=${error}`;
      return c.redirect(url.href, 302);
    };

    if (c.req.query('error')) return back(c.req.query('error') === 'access_denied' ? 'cancelled' : 'verification_failed');
    const code = c.req.query('code');
    if (!code || c.req.query('state') !== oauth.state) return back('verification_failed');

    let idToken: unknown;
    try {
      const res = await fetch(GOOGLE_TOKEN_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: google.clientId,
          client_secret: google.clientSecret!,
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
      clientId: google.clientId,
      nonce: oauth.nonce,
      keys: config.jwksResolver,
    });
    if (!result.ok) return back(result.error);
    await ctx.startSession(c, result.user, ['google']);
    await ctx.emit('user.signed_in', { user: result.user, method: 'google' });
    return back();
  });
}
