import type { Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { base64url } from 'jose';
import type { AppContext } from '../app.js';
import type { MadauthConfig } from '../config.js';
import { verifyGoogleIdToken, type GoogleProfile } from '../google.js';
import { normalizeEmail } from '../password.js';
import type { SignInMethod } from '../settings.js';
import { randomString, readToken, signToken } from '../tokens.js';
import { googleAccountKey, toMadauthUser, type StoredUser } from '../users.js';
import { localeOf } from '../webhooks.js';
import { signInAnswer } from './helpers.js';

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
/** Hash parameter that says what the sign-in still needs after the code flow: the authenticator app's code or setup. */
export const REDIRECT_NEXT_PARAM = 'madauth_next';

interface OAuthState {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  locale?: string;
}

type SignInResult =
  | { ok: true; user: StoredUser }
  | { ok: false; error: 'signup_rejected' | 'temporarily_unavailable'; message: string }
  /** The address belongs to a user who signs in another way; `methods` says how. */
  | { ok: false; error: 'other_method'; message: string; methods: SignInMethod[] };

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url.encode(new Uint8Array(digest));
}

/** Google sign-in: FedCM / One Tap, and the server-side code flow when a client secret is configured. */
export function googleRoutes(app: Hono, ctx: AppContext, google: NonNullable<MadauthConfig['google']>): void {
  const { config, keys, secure, users } = ctx;
  const { issuer } = config;
  const callbackUrl = `${issuer}/auth/google/callback`;

  /**
   * The user behind a verified Google profile. A returning Google account is known by its `sub`. A new one
   * becomes a new user after the operator's sign-up check, or takes over a user with the same address whom
   * nobody can sign in as yet (a sign-up that was never finished). It never joins a user who signs in
   * another way: that would open their account to whoever controls the Google account, past a password
   * and the authenticator app.
   */
  const resolveUser = async (profile: GoogleProfile, locale: string | undefined): Promise<SignInResult> => {
    const key = googleAccountKey(profile.sub);
    const emailNormalized = normalizeEmail(profile.email);
    const signedIn = (user: StoredUser) => ({ ok: true as const, user });

    const account = await users.findAccountByKey(key);
    if (account) {
      const user = await users.findById(account.userId);
      if (user) {
        // Google's address may change; the link to the user stays, and only the account notes the new one.
        if (account.email !== profile.email) await users.updateAccount(account.id, { email: profile.email });
        return signedIn(user);
      }
      // Left behind by a deletion that did not finish: it would hold the key forever.
      await users.deleteAccount(account.id);
    }

    // Twice at most: a user created between the lookup and the create is found the second time.
    for (let attempt = 0; attempt < 2; attempt++) {
      const existing = await users.findByEmail(emailNormalized);
      if (existing) {
        if (existing.emailVerified && (await users.hasAccounts(existing.id))) {
          const methods = await users.signInMethods(existing.id, await ctx.settings.methods());
          const how = methods.map((method) => ({ password: 'a password', totp: 'an authenticator app', google: 'Google' })[method]).join(' or ');
          return { ok: false, error: 'other_method', message: `This e-mail address signs in with ${how || 'another method'}. Use that instead of Google.`, methods };
        }
        // Google verified the address, and nobody has proven this user yet (an unconfirmed sign-up, whose
        // password goes) or nobody can sign in as them: the Google account takes the user over.
        await users.verifyByProvider(existing);
        if (!(await users.linkAccount(existing.id, { key, email: profile.email }))) {
          // The account appeared meanwhile; it belongs to whoever has it now.
          const linked = await users.findAccountByKey(key);
          const owner = linked && (await users.findById(linked.userId));
          if (!owner) return { ok: false, error: 'temporarily_unavailable', message: 'Please try again.' };
          return signedIn(owner);
        }
        return signedIn(existing);
      }
      if (attempt === 0) {
        const check = await ctx.checkSignup({ email: profile.email, name: profile.name, locale, method: 'google' });
        if (!check.ok) {
          return check.reason === 'rejected'
            ? { ok: false, error: 'signup_rejected', message: check.message }
            : { ok: false, error: 'temporarily_unavailable', message: 'Signing up is not possible right now. Please try again later.' };
        }
      }
      const user = await users.createUser({
        email: profile.email,
        emailNormalized,
        name: profile.name ?? null,
        emailVerified: true,
        account: { key, email: profile.email },
      });
      if (user) {
        await ctx.emit('user.created', { user: toMadauthUser(user), method: 'google' });
        return signedIn(user);
      }
    }
    return { ok: false, error: 'temporarily_unavailable', message: 'Please try again.' };
  };

  const disabled = (c: Context) =>
    c.json({ error: 'method_disabled', message: 'Google sign-in is switched off.' }, 403);

  // --- FedCM / One Tap (the ID token is issued in the browser and verified here) ---

  app.post('/auth/google/nonce', async (c) => {
    if (!(await ctx.enabled('google'))) return disabled(c);
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
    if (!(await ctx.enabled('google'))) return disabled(c);
    const body = await c.req.json<{ credential?: unknown; locale?: unknown }>().catch(() => ({}) as { credential?: unknown; locale?: unknown });
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
    const resolved = await resolveUser(result.profile, localeOf(body.locale));
    if (!resolved.ok) {
      if (resolved.error === 'other_method') return c.json({ error: resolved.error, message: resolved.message, methods: resolved.methods }, 403);
      return c.json({ error: resolved.error, message: resolved.message }, resolved.error === 'signup_rejected' ? 403 : 503);
    }
    return signInAnswer(c, await ctx.secondStep(c, resolved.user, ['google'], 'google', result.profile));
  });

  // --- Server-side authorization-code flow with PKCE (only with GOOGLE_CLIENT_SECRET) ---

  const requireCodeFlow = async (c: Context, next: () => Promise<void>) => {
    if (!google.clientSecret) return c.json({ error: 'not_found' }, 404);
    if (!(await ctx.enabled('google'))) return disabled(c);
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
      locale: localeOf(c.req.query('locale')),
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

    const back = (error?: string, next?: string) => {
      const url = new URL(oauth.returnTo);
      if (error) url.hash = `${REDIRECT_ERROR_PARAM}=${error}`;
      if (next) url.hash = `${REDIRECT_NEXT_PARAM}=${next}`;
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
    const resolved = await resolveUser(result.profile, typeof oauth.locale === 'string' ? oauth.locale : undefined);
    if (!resolved.ok) return back(resolved.error);
    const step = await ctx.secondStep(c, resolved.user, ['google'], 'google', result.profile);
    if ('disabled' in step) return back('method_disabled');
    // The app continues with the authenticator app's code or setup; the challenge cookie is set.
    if ('next' in step) return back(undefined, step.next);
    return back();
  });
}
