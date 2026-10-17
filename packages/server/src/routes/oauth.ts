// What the sign-ins through a provider's authorization-code (redirect) flow share: Google's code flow and
// GitHub. Between /start and /callback the sign-in's state lives in a signed cookie, the way back to the app
// carries what happened in the URL's hash, and the user behind a verified profile is resolved the same way.
import type { Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { base64url } from 'jose';
import type { AppContext } from '../app.js';
import { normalizeEmail } from '../password.js';
import { nameOfMethod } from '../providers.js';
import { signInPredicate, type SecondFactor, type SignInMethod } from '../settings.js';
import { randomString, readToken, signToken } from '../tokens.js';
import { toMadauthUser, type StoredUser } from '../users.js';
import { localeOf } from '../webhooks.js';
import type { NextStep } from './challenge.js';
import { recentSignIn } from './helpers.js';

/** Hash parameter that carries a sign-in error back to the app after the redirect flow. */
export const REDIRECT_ERROR_PARAM = 'madauth_error';
/** Hash parameter that says what the sign-in still needs after the redirect flow: the authenticator app's code or setup. */
export const REDIRECT_NEXT_PARAM = 'madauth_next';
/** Hash parameter next to it: which second factors can finish the step, comma-separated (`madauth_factors=authenticator,sms`). */
export const REDIRECT_FACTORS_PARAM = 'madauth_factors';
/**
 * Hash parameter next to the error and the next step: which method's sign-in it is (`madauth_method=github`),
 * so the app can tell the providers apart. Servers before 0.5 send none: only Google had a redirect flow.
 */
export const REDIRECT_METHOD_PARAM = 'madauth_method';
/** Hash parameter after a redirect that added the provider to the signed-in user's methods (`madauth_linked=github`). */
export const REDIRECT_LINKED_PARAM = 'madauth_linked';

const OAUTH_COOKIE = 'madauth_oauth';
const OAUTH_TYP = 'madauth-oauth-state+jwt';
const OAUTH_TTL = 10 * 60;

/** What a redirect sign-in remembers between /start and /callback. */
export interface OAuthState {
  state: string;
  /** For a provider that issues an ID token (Google); unused by the others. */
  nonce: string;
  /** The PKCE verifier; its challenge went to the provider with the authorization request. */
  verifier: string;
  /** The app page the user comes back to. */
  returnTo: string;
  locale?: string;
  /** When the flow adds the provider to a signed-in user's methods instead of signing in: the user's id. */
  link?: string;
}

/** The PKCE challenge of a verifier: its SHA-256, base64url. */
export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url.encode(new Uint8Array(digest));
}

/**
 * Starts a redirect sign-in: a fresh state, nonce and verifier, signed into the cookie that comes back on
 * the provider's redirect to the callback under `cookiePath`. `returnTo` is the app page to send the user
 * back to; the request's `locale` query is kept for the sign-up check. With `link=1` in the query, the
 * flow adds the provider to the methods of the signed-in user, who must have signed in recently: otherwise
 * the error to send the browser back with (`no_session`, `reauth_required`).
 */
export async function startOAuth(c: Context, ctx: AppContext, cookiePath: string, returnTo: URL): Promise<OAuthState | { error: string }> {
  let link: string | undefined;
  if (c.req.query('link') === '1') {
    const user = await recentSignIn(c, ctx);
    if (typeof user === 'string') return { error: user };
    link = user.id;
  }
  const oauth: OAuthState = {
    state: randomString(),
    nonce: randomString(),
    verifier: randomString(),
    returnTo: returnTo.href,
    locale: localeOf(c.req.query('locale')),
    ...(link ? { link } : {}),
  };
  const token = await signToken(ctx.keys, ctx.config.issuer, OAUTH_TYP, { ...oauth }, OAUTH_TTL);
  // Lax: the cookie must come back on the top-level redirect from the provider to /callback.
  setCookie(c, OAUTH_COOKIE, token, {
    path: cookiePath,
    httpOnly: true,
    secure: ctx.secure,
    sameSite: 'Lax',
    maxAge: OAUTH_TTL,
  });
  return oauth;
}

/**
 * The state of the sign-in this callback finishes; the cookie is used up with it. Null if there is none or it
 * has expired: the sign-in was started in another browser, or more than ten minutes ago.
 */
export async function takeOAuthState(c: Context, ctx: AppContext, cookiePath: string): Promise<OAuthState | null> {
  const oauth = await readToken<OAuthState & Record<string, unknown>>(ctx.keys, ctx.config.issuer, OAUTH_TYP, getCookie(c, OAUTH_COOKIE));
  if (!oauth) return null;
  deleteCookie(c, OAUTH_COOKIE, { path: cookiePath, secure: ctx.secure });
  // The callback has no Origin: the app it returns to is the one the sign-in is for.
  if (URL.canParse(oauth.returnTo)) appOrigins.set(c.req.raw, new URL(oauth.returnTo).origin);
  return {
    state: oauth.state,
    nonce: oauth.nonce,
    verifier: oauth.verifier,
    returnTo: oauth.returnTo,
    ...(typeof oauth.locale === 'string' ? { locale: oauth.locale } : {}),
    ...(typeof oauth.link === 'string' ? { link: oauth.link } : {}),
  };
}

const appOrigins = new WeakMap<Request, string>();

/**
 * The app a request comes from: its Origin, or, for a redirect flow's callback (which has none), the app the
 * flow returns to. Undefined when neither is known.
 */
export function appOriginOf(c: Context): string | undefined {
  return c.req.header('origin') ?? appOrigins.get(c.req.raw);
}

/**
 * The way back to the app after the callback: plain when the user is signed in (the session cookies are
 * set), with the error, or with the second step the sign-in goes on with and which second factors can
 * finish it (the challenge cookie is set). `method` names the sign-in in the hash in the last two cases.
 */
export function redirectBack(c: Context, returnTo: string, method: string): (error?: string, next?: NextStep, factors?: SecondFactor[]) => Response {
  return (error, next, factors = []) => {
    const url = new URL(returnTo);
    if (error) url.hash = `${REDIRECT_ERROR_PARAM}=${error}&${REDIRECT_METHOD_PARAM}=${method}`;
    // The step, and which second factors can finish it, so the page can offer the switch.
    if (next) url.hash = `${REDIRECT_NEXT_PARAM}=${next}${factors.length ? `&${REDIRECT_FACTORS_PARAM}=${factors.join(',')}` : ''}&${REDIRECT_METHOD_PARAM}=${method}`;
    return c.redirect(url.href, 302);
  };
}

/** A sign-in provider whose profiles {@link resolveProviderUser} resolves: its method id, and its name for messages. */
export interface OAuthProvider {
  /** Its method: madAuth's own id, or an OpenID Connect provider's id. */
  method: string;
  name: string;
}

/** What the provider proved about the account that signed in. */
export interface ProviderProfile {
  /** The account's key, by which a returning account is known: `google:<sub>` or `github:<id>`. */
  key: string;
  /** The address, verified by the provider. */
  email: string;
  name?: string;
  /** Kept on the account and renewed at every sign-in: GitHub's access token (encrypted), for revoking the grant. */
  secret?: string;
}

export type SignInResult =
  | { ok: true; user: StoredUser }
  | { ok: false; error: 'signup_rejected' | 'temporarily_unavailable'; message: string }
  /** The address belongs to a user who signs in another way; `methods` says how. */
  | { ok: false; error: 'other_method'; message: string; methods: string[] };

/** How a message names each method when it says how an address signs in. A method without a name here does not compile. */
const METHOD_NAMES = {
  google: 'Google',
  github: 'GitHub',
  password: 'a password',
  authenticator: 'an authenticator app',
  'email-link': 'an e-mail link',
  passkey: 'a passkey',
} satisfies Record<SignInMethod, string>;

/**
 * The user behind a verified provider profile. A returning account is known by its key. A new one becomes a
 * new user after the operator's sign-up check, or takes over a user with the same address whom nobody can
 * sign in as yet (a sign-up that was never finished). It never joins a user who signs in another way: that
 * would open their account to whoever controls the provider's account, past a password and the
 * authenticator app. The user adds it while signed in instead (see {@link linkProviderAccount}).
 */
export async function resolveProviderUser(
  ctx: AppContext,
  provider: OAuthProvider,
  profile: ProviderProfile,
  locale: string | undefined,
): Promise<SignInResult> {
  const { users } = ctx;
  const { key } = profile;
  const emailNormalized = normalizeEmail(profile.email);
  const signedIn = (user: StoredUser) => ({ ok: true as const, user });

  const account = await users.findAccountByKey(key);
  if (account) {
    const user = await users.findById(account.userId);
    if (user) {
      // The provider's address may change; the link to the user stays, and only the account notes the new
      // one. A secret (GitHub's token) is the latest at every sign-in.
      const patch = {
        ...(account.email !== profile.email ? { email: profile.email } : {}),
        ...(profile.secret ? { secret: profile.secret } : {}),
      };
      if (Object.keys(patch).length) await users.updateAccount(account.id, patch);
      return signedIn(user);
    }
    // Left behind by a deletion that did not finish: it would hold the key forever.
    await users.deleteAccount(account.id);
  }

  // Twice at most: a user created between the lookup and the create is found the second time.
  for (let attempt = 0; attempt < 2; attempt++) {
    const existing = await users.findByEmail(emailNormalized);
    if (existing) {
      if (existing.emailVerified && (await users.hasSignInMethod(existing.id))) {
        const now = await ctx.methods();
        const methods = await users.signInMethods(existing.id, signInPredicate(now.configured, now.settings));
        const how = methods.map((method) => nameOfMethod(METHOD_NAMES, now.providers, method)).join(' or ');
        return {
          ok: false,
          error: 'other_method',
          message: `This e-mail address signs in with ${how || 'another method'}. Use that instead of ${provider.name}.`,
          methods,
        };
      }
      // The provider verified the address, and nobody has proven this user yet (an unconfirmed sign-up, whose
      // password or e-mail link goes) or nobody can sign in as them: the provider's account takes the user over.
      // Its sign-up ends with this sign-in: one from before `user.signed_up` existed gets it too.
      const taken = await users.reopenSignUp(existing);
      await users.verifyByProvider(taken);
      if (!(await users.linkAccount(taken.id, { key, email: profile.email, secret: profile.secret }))) {
        // The account appeared meanwhile; it belongs to whoever has it now.
        const linked = await users.findAccountByKey(key);
        const owner = linked && (await users.findById(linked.userId));
        if (!owner) return { ok: false, error: 'temporarily_unavailable', message: 'Please try again.' };
        return signedIn(owner);
      }
      return signedIn({ ...taken, emailVerified: true });
    }
    if (attempt === 0) {
      const check = await ctx.checkSignup({ email: profile.email, name: profile.name, locale, method: provider.method });
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
      account: { key, email: profile.email, secret: profile.secret },
    });
    if (user) return signedIn(user);
  }
  return { ok: false, error: 'temporarily_unavailable', message: 'Please try again.' };
}

export type LinkResult = { ok: true } | { ok: false; error: 'account_taken'; message: string };

/**
 * Adds a verified provider account to the methods of `user`, who signed in recently: from then on it signs
 * them in too, whatever address it has. An account that belongs to another user stays theirs. Emits
 * `user.method_added`.
 */
export async function linkProviderAccount(ctx: AppContext, provider: OAuthProvider, user: StoredUser, profile: ProviderProfile): Promise<LinkResult> {
  const { users } = ctx;
  const taken: LinkResult = { ok: false, error: 'account_taken', message: `This ${provider.name} account signs in another user. Use another one.` };
  const existing = await users.findAccountByKey(profile.key);
  if (existing?.userId === user.id) {
    await users.updateAccount(existing.id, { email: profile.email, ...(profile.secret ? { secret: profile.secret } : {}) });
    return { ok: true };
  }
  if (existing) {
    if (await users.findById(existing.userId)) return taken;
    // Left behind by a deletion that did not finish: it would hold the key forever.
    await users.deleteAccount(existing.id);
  }
  if (!(await users.linkAccount(user.id, { key: profile.key, email: profile.email, secret: profile.secret, primary: false }))) return taken;
  await ctx.emit('user.method_added', { user: toMadauthUser(user), method: provider.method, email: profile.email });
  return { ok: true };
}

/**
 * Finishes a redirect flow that `startOAuth` began with `link=1`: adds the provider's account to the user who
 * started it, if they are still signed in at this browser (the session cookie comes along on the redirect),
 * and sends the browser back with `madauth_linked` or the error. Null for a flow that signs in.
 */
export async function finishLink(c: Context, ctx: AppContext, provider: OAuthProvider, oauth: OAuthState, profile: ProviderProfile): Promise<Response | null> {
  if (!oauth.link) return null;
  const back = redirectBack(c, oauth.returnTo, provider.method);
  const session = await ctx.currentUser(c);
  const user = session?.id === oauth.link ? await ctx.users.findById(session.id) : null;
  if (!user) return back('no_session');
  const linked = await linkProviderAccount(ctx, provider, user, profile);
  if (!linked.ok) return back(linked.error);
  const url = new URL(oauth.returnTo);
  url.hash = `${REDIRECT_LINKED_PARAM}=${provider.method}`;
  return c.redirect(url.href, 302);
}
