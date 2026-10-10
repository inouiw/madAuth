import { Hono, type Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { cors } from 'hono/cors';
import { ADMIN_ROLE, claimsFromJson, isAdmin, parseClaims, sameClaims } from './claims.js';
import type { MadauthConfig } from './config.js';
import { importSigningKeys, type SigningKeys } from './keys.js';
import { deriveCodeKey, isValidEmail, normalizeEmail } from './password.js';
import { googleRoutes } from './routes/google.js';
import { passwordRoutes } from './routes/password.js';
import { SIGN_IN_METHODS, Settings, parseMethodSettings, type SignInMethod } from './settings.js';
import { readToken, signRenewal, signSession, userFromClaims, type SessionClaims } from './tokens.js';
import { EXPIRY_COOKIE, RENEWAL_COOKIE, RENEWAL_TYP, SESSION_COOKIE, SESSION_TYP, type MadauthUser } from './user.js';
import { Users } from './users.js';
import { createWebhookClient, type WebhookClient, type WebhookType } from './webhooks.js';

/** How long madAuth waits for an event call; events never make a request fail. */
export const EVENT_TIMEOUT_MS = 5_000;
/** How long madAuth waits for the webhook to accept an e-mail or to decide on a sign-up. */
export const WEBHOOK_TIMEOUT_MS = 10_000;

export { REDIRECT_ERROR_PARAM } from './routes/google.js';

/** The answer of the operator's sign-up check. */
export type SignupCheck = { ok: true } | { ok: false; reason: 'unavailable' } | { ok: false; reason: 'rejected'; message: string };

/** What the route modules share. */
export interface AppContext {
  config: MadauthConfig;
  keys: Promise<SigningKeys>;
  /** Whether cookies get the Secure attribute (only when the issuer is https). */
  secure: boolean;
  isAllowedOrigin(origin: string | undefined): boolean;
  /** Parses an absolute URL whose origin is in ALLOWED_ORIGINS, without its hash; null otherwise. */
  allowedUrl(value: unknown): URL | null;
  /** Sets the session cookies for the user, as the routes resolved them from the store. */
  startSession(c: Context, user: MadauthUser, amr: string[], extra?: { sv?: number }): Promise<MadauthUser>;
  users: Users;
  settings: Settings;
  /** Present when WEBHOOK_URL is configured. */
  webhook?: WebhookClient;
  /** Whether a sign-in method is on: configured, and not switched off by an admin. Read from the store each time. */
  enabled(method: SignInMethod): Promise<boolean>;
  /** Asks the webhook whether someone may sign up (`signup.before`). Fails closed: without an answer, nobody signs up. */
  checkSignup(data: { email: string; name?: string; locale?: string; method: SignInMethod }): Promise<SignupCheck>;
  /** Tells the webhook that something happened. Awaited (Lambda stops after the answer), but never fails. */
  emit(type: WebhookType, data: Record<string, unknown>): Promise<void>;
}

/**
 * Creates the madAuth HTTP app. It is built on Hono's Web Standard Request/Response, so the same app runs
 * on Node (Docker), AWS Lambda and Azure Functions (see `src/entry/`).
 */
export function createApp(config: MadauthConfig): Hono {
  const { issuer, allowedOrigins, sessionTtlSeconds, renewalTtlSeconds, cookieDomain } = config;
  const keys = importSigningKeys(config.signingKey);
  // Browsers treat http://localhost as secure, but only mark cookies Secure when served over https.
  const secure = issuer.startsWith('https:');
  const isAllowedOrigin = (origin: string | undefined) => !!origin && allowedOrigins.includes(origin);
  const users = new Users(config.store, deriveCodeKey(config.signingKey.d!));
  const settings = new Settings(config.store);
  /** Whether the method is configured at all; an admin can only switch a configured method off. */
  const available = (method: SignInMethod) => (method === 'google' ? !!config.google : !!config.password);

  /**
   * Sets the cookies of a session: the session token for app backends, the renewal token for this server
   * only, and the expiry time for the web library.
   */
  const issueSession = async (c: Context, user: MadauthUser, amr: string[], extra?: { sv?: number }) => {
    const signingKeys = await keys;
    const [sessionToken, renewalToken] = await Promise.all([
      signSession(signingKeys, issuer, sessionTtlSeconds, user, amr, extra),
      signRenewal(signingKeys, issuer, renewalTtlSeconds, user, amr, extra),
    ]);
    setCookie(c, SESSION_COOKIE, sessionToken, {
      path: '/',
      domain: cookieDomain,
      httpOnly: true,
      secure,
      sameSite: 'Lax',
      maxAge: sessionTtlSeconds,
    });
    // Without a Domain, so sibling hosts that get the session cookie through COOKIE_DOMAIN never get this one.
    setCookie(c, RENEWAL_COOKIE, renewalToken, {
      path: '/auth',
      httpOnly: true,
      secure,
      sameSite: 'Lax',
      maxAge: renewalTtlSeconds,
    });
    // Kept as long as the session can be renewed: an expiry time in the past means "renew before use".
    setCookie(c, EXPIRY_COOKIE, String(Math.floor(Date.now() / 1000) + sessionTtlSeconds), {
      path: '/',
      domain: cookieDomain,
      secure,
      sameSite: 'Lax',
      maxAge: renewalTtlSeconds,
    });
  };
  const clearSession = (c: Context) => {
    deleteCookie(c, SESSION_COOKIE, { path: '/', domain: cookieDomain, secure });
    deleteCookie(c, RENEWAL_COOKIE, { path: '/auth', secure });
    deleteCookie(c, EXPIRY_COOKIE, { path: '/', domain: cookieDomain, secure });
  };

  const ctx: AppContext = {
    config,
    keys,
    secure,
    isAllowedOrigin,
    allowedUrl(value) {
      let url: URL;
      try {
        url = new URL(typeof value === 'string' ? value : '');
      } catch {
        return null;
      }
      if (!isAllowedOrigin(url.origin)) return null;
      url.hash = '';
      return url;
    },
    async startSession(c, user, amr, extra) {
      await issueSession(c, user, amr, extra);
      return user;
    },
    users,
    settings,
    webhook: config.webhook ? createWebhookClient(config.webhook, config.webhookFetch) : undefined,
    async enabled(method) {
      return available(method) && (await settings.methods())[method] !== false;
    },
    async checkSignup(data) {
      if (!this.webhook?.wants('signup.before')) return { ok: true };
      const check = await this.webhook.call('signup.before', data, WEBHOOK_TIMEOUT_MS);
      if (!check.ok) {
        console.error(`[madauth] Webhook "signup.before" failed: ${check.reason}`);
        return { ok: false, reason: 'unavailable' };
      }
      const answer = check.body as { allow?: unknown; message?: unknown } | undefined;
      if (answer?.allow === false) {
        const message = typeof answer.message === 'string' && answer.message ? answer.message : 'Sign-up is not possible with this e-mail address.';
        return { ok: false, reason: 'rejected', message };
      }
      return { ok: true };
    },
    async emit(type, data) {
      if (!this.webhook?.wants(type)) return;
      const result = await this.webhook.call(type, data, EVENT_TIMEOUT_MS);
      if (!result.ok) console.error(`[madauth] Webhook "${type}" failed: ${result.reason}`);
    },
  };

  const app = new Hono();

  app.use(
    '/auth/*',
    cors({
      origin: (origin) => (isAllowedOrigin(origin) ? origin : null),
      credentials: true,
      allowMethods: ['GET', 'POST'],
      allowHeaders: ['Content-Type'],
      maxAge: 600,
    }),
  );

  // Only the configured apps may start sign-ins or change the session.
  app.use('/auth/*', async (c, next) => {
    if (c.req.method === 'POST' && !isAllowedOrigin(c.req.header('origin'))) {
      return c.json({ error: 'forbidden_origin' }, 403);
    }
    await next();
  });

  app.get('/health', (c) => c.text('ok'));

  app.get('/.well-known/jwks.json', async (c) => {
    const { publicJwk } = await keys;
    c.header('Cache-Control', 'public, max-age=3600');
    return c.json({ keys: [publicJwk] });
  });

  // The methods that are on right now, so the web library shows exactly those.
  app.get('/auth/config', async (c) => {
    const methods = await settings.methods();
    const on = (method: SignInMethod) => available(method) && methods[method] !== false;
    return c.json({
      google: on('google') ? { clientId: config.google!.clientId, codeFlow: !!config.google!.clientSecret } : null,
      password: on('password') ? { minLength: config.password!.minLength } : null,
    });
  });

  if (config.google) googleRoutes(app, ctx, config.google);
  if (config.password && ctx.webhook) passwordRoutes(app, ctx, config.password, users, ctx.webhook);

  // --- Session ---

  /** The claims of a token in one of the request's cookies, or null if it is missing, expired or of another kind. */
  const tokenClaims = async (c: Context, cookie: string, typ: string) =>
    readToken<SessionClaims>(await keys, issuer, typ, getCookie(c, cookie));

  /**
   * The user of these claims with their claims of now, or null if the session has ended: the user is gone,
   * or a password reset incremented their session version since.
   */
  const checked = async (claims: SessionClaims): Promise<MadauthUser | null> => {
    const stored = await users.findById(claims.sub);
    if (!stored || stored.sessionVersion !== claims.sv) return null;
    const { claims: _, ...user } = userFromClaims(claims);
    const current = claimsFromJson(stored.claims);
    return Object.keys(current).length ? { ...user, claims: current } : user;
  };

  /**
   * The user of the request's session, or null if there is none or it has ended. A session token that is
   * missing, expired, past half of its lifetime or carries outdated claims is replaced on the way, if the
   * request has a valid renewal token: the user and their claims are checked again, and new cookies are set.
   */
  const currentSession = async (c: Context): Promise<MadauthUser | null> => {
    const session = await tokenClaims(c, SESSION_COOKIE, SESSION_TYP);
    // The claims are read again, so a change shows the next time the app checks the session.
    const user = session ? await checked(session) : null;
    const upToDate =
      session && user && sameClaims(user.claims, session.claims) && Date.now() / 1000 - session.iat <= sessionTtlSeconds / 2;
    if (upToDate) return user;

    const renewal = await tokenClaims(c, RENEWAL_COOKIE, RENEWAL_TYP);
    // Both tokens of one sign-in: the check of the session token holds for the renewal token as well.
    const sameSignIn =
      session && user && renewal && renewal.sub === session.sub && renewal.sv === session.sv && renewal.email === session.email;
    const renewed = sameSignIn ? user : renewal ? await checked(renewal) : null;
    if (renewal && renewed) {
      await issueSession(c, renewed, renewal.amr, { sv: renewal.sv });
      return renewed;
    }
    // Still valid, but not renewable (e.g. the renewal cookie is gone): it lasts until it expires.
    return user;
  };

  app.get('/auth/session', async (c) => {
    const user = await currentSession(c);
    if (!user) {
      // Also tells the web library that nobody is signed in any more.
      clearSession(c);
      return c.json({ error: 'no_session' }, 401);
    }
    return c.json({ user });
  });

  app.post('/auth/logout', (c) => {
    clearSession(c);
    return c.body(null, 204);
  });

  // --- Account ---

  app.post('/auth/account/delete', async (c) => {
    const user = await currentSession(c);
    if (!user) return c.json({ error: 'no_session' }, 401);
    // The user with all their sign-in methods: the session proves who they are, whichever way they signed in.
    await users.deleteById(user.id);
    clearSession(c);
    await ctx.emit('user.deleted', { user });
    return c.body(null, 204);
  });

  // --- Admin: claims and settings ---

  /** The admin's address if the request comes from one; otherwise the answer to send. */
  const admin = async (c: Context): Promise<{ email: string } | { answer: Response }> => {
    // currentSession reads the claims from the store, not from the session token: a removed admin role
    // stops counting at once.
    const user = await currentSession(c);
    if (!user) return { answer: c.json({ error: 'no_session' }, 401) };
    const email = user.email ? normalizeEmail(user.email) : undefined;
    if (!email || !isAdmin(user)) {
      const message = `Only users with the role "${ADMIN_ROLE}" can manage claims and settings.`;
      return { answer: c.json({ error: 'forbidden', message }, 403) };
    }
    return { email };
  };
  const body = async (c: Context): Promise<Record<string, unknown>> => {
    const data = await c.req.json<unknown>().catch(() => null);
    return data && typeof data === 'object' ? (data as Record<string, unknown>) : {};
  };
  const invalidEmail = (c: Context) => c.json({ error: 'invalid_email', message: 'This is not a valid e-mail address.' }, 400);
  const noUser = (c: Context) => c.json({ error: 'user_not_found', message: 'No user has this e-mail address.' }, 404);

  // POST, so the address is not part of a URL that ends up in access logs.
  app.post('/auth/admin/claims/get', async (c) => {
    const caller = await admin(c);
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    if (!isValidEmail(data.email)) return invalidEmail(c);
    const user = await users.findByEmail(normalizeEmail(data.email));
    if (!user) return noUser(c);
    return c.json({ email: user.emailNormalized, userId: user.id, claims: claimsFromJson(user.claims) });
  });

  app.post('/auth/admin/claims/set', async (c) => {
    const caller = await admin(c);
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    if (!isValidEmail(data.email)) return invalidEmail(c);
    const claims = parseClaims(data.claims);
    if (!claims) {
      return c.json(
        {
          error: 'invalid_claims',
          message:
            'claims must be a JSON object of at most 2048 characters whose keys are names (letters, digits and "_", ' +
            'starting with a letter). "roles" must be a list of names of lower-case letters, digits, "-" and "_".',
        },
        400,
      );
    }
    const user = await users.findByEmail(normalizeEmail(data.email));
    if (!user) return noUser(c);
    await users.updateUser(user.id, { claims: Object.keys(claims).length ? JSON.stringify(claims) : null });
    const email = user.emailNormalized;
    await ctx.emit('user.claims_changed', { userId: user.id, email, claims, by: caller.email });
    return c.json({ email, userId: user.id, claims });
  });

  /** The settings as the admin API answers them: for each method, whether it is configured and whether it is on. */
  const settingsAnswer = async () => {
    const methods = await settings.methods();
    return {
      methods: Object.fromEntries(
        SIGN_IN_METHODS.map((method) => [method, { available: available(method), enabled: available(method) && methods[method] !== false }]),
      ),
    };
  };

  app.post('/auth/admin/settings/get', async (c) => {
    const caller = await admin(c);
    if ('answer' in caller) return caller.answer;
    return c.json(await settingsAnswer());
  });

  app.post('/auth/admin/settings/set', async (c) => {
    const caller = await admin(c);
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    const invalid = (message: string) => c.json({ error: 'invalid_settings', message }, 400);
    const changes = parseMethodSettings(data.methods);
    if (!changes) return invalid(`methods must be an object with true or false for ${SIGN_IN_METHODS.join(' and/or ')}.`);
    const methods = { ...(await settings.methods()), ...changes };
    if (!SIGN_IN_METHODS.some((method) => available(method) && methods[method] !== false)) {
      return invalid('At least one sign-in method must stay on.');
    }
    await settings.setMethods(methods, caller.email);
    return c.json(await settingsAnswer());
  });

  return app;
}
