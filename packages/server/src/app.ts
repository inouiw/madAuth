import { Hono, type Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { cors } from 'hono/cors';
import type { MadauthConfig } from './config.js';
import { importSigningKeys, type SigningKeys } from './keys.js';
import { deriveCodeKey, isValidEmail, normalizeEmail } from './password.js';
import { ADMIN_ROLE, Roles, parseRoles, sameRoles } from './roles.js';
import { googleRoutes } from './routes/google.js';
import { passwordRoutes } from './routes/password.js';
import { readToken, signRenewal, signSession, userFromClaims, type SessionClaims } from './tokens.js';
import { EXPIRY_COOKIE, RENEWAL_COOKIE, RENEWAL_TYP, SESSION_COOKIE, SESSION_TYP, type MadauthUser } from './user.js';
import { Users } from './users.js';
import { createWebhookClient, type WebhookClient, type WebhookType } from './webhooks.js';

/** How long madAuth waits for an event call; events never make a request fail. */
export const EVENT_TIMEOUT_MS = 5_000;

export { REDIRECT_ERROR_PARAM } from './routes/google.js';

/** What the route modules share. */
export interface AppContext {
  config: MadauthConfig;
  keys: Promise<SigningKeys>;
  /** Whether cookies get the Secure attribute (only when the issuer is https). */
  secure: boolean;
  isAllowedOrigin(origin: string | undefined): boolean;
  /** Parses an absolute URL whose origin is in ALLOWED_ORIGINS, without its hash; null otherwise. */
  allowedUrl(value: unknown): URL | null;
  /** Sets the session cookie. Resolves to the user as the session holds it: with the roles of the address. */
  startSession(c: Context, user: MadauthUser, amr: string[], extra?: { sv?: number }): Promise<MadauthUser>;
  /** Present when e-mail & password sign-in is configured. */
  users?: Users;
  /** Present when WEBHOOK_URL is configured. */
  webhook?: WebhookClient;
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

  // Roles need a store, which only e-mail & password sign-in configures. They then apply to Google sign-ins too.
  const roles = config.password ? new Roles(config.password.store) : undefined;
  /** The user with the current roles of their address. */
  const withRoles = async (user: MadauthUser): Promise<MadauthUser> => {
    const { roles: _, ...rest } = user;
    const current = roles && user.email ? await roles.get(normalizeEmail(user.email)) : [];
    return current.length ? { ...rest, roles: current } : rest;
  };
  /**
   * Sets the cookies of a session: the session token for app backends, the renewal token for this server
   * only, and the expiry time for the web library.
   */
  const issueSession = async (c: Context, user: MadauthUser, amr: string[], extra?: { sv?: number }) => {
    const signingKeys = await keys;
    setCookie(c, SESSION_COOKIE, await signSession(signingKeys, issuer, sessionTtlSeconds, user, amr, extra), {
      path: '/',
      domain: cookieDomain,
      httpOnly: true,
      secure,
      sameSite: 'Lax',
      maxAge: sessionTtlSeconds,
    });
    // Without a Domain, so sibling hosts that get the session cookie through COOKIE_DOMAIN never get this one.
    setCookie(c, RENEWAL_COOKIE, await signRenewal(signingKeys, issuer, renewalTtlSeconds, user, amr, extra), {
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
      const signedIn = await withRoles(user);
      await issueSession(c, signedIn, amr, extra);
      return signedIn;
    },
    users: config.password ? new Users(config.password.store, deriveCodeKey(config.signingKey.d!)) : undefined,
    webhook: config.webhook ? createWebhookClient(config.webhook, config.webhookFetch) : undefined,
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

  app.get('/auth/config', (c) =>
    c.json({
      google: config.google ? { clientId: config.google.clientId, codeFlow: !!config.google.clientSecret } : null,
      password: config.password ? { minLength: config.password.minLength } : null,
    }),
  );

  if (config.google) googleRoutes(app, ctx, config.google);
  if (config.password && ctx.users && ctx.webhook) passwordRoutes(app, ctx, config.password, ctx.users, ctx.webhook);

  // --- Session ---

  /** The claims of a token in one of the request's cookies, or null if it is missing, expired or of another kind. */
  const tokenClaims = async (c: Context, cookie: string, typ: string) =>
    readToken<SessionClaims>(await keys, issuer, typ, getCookie(c, cookie));

  /** Users from the store: a password reset increments the session version and so ends older sessions. */
  const hasEnded = async (claims: SessionClaims) => {
    if (!claims.sub.startsWith('usr_')) return false;
    const stored = await ctx.users?.findById(claims.sub);
    return !stored || stored.sessionVersion !== claims.sv;
  };

  /**
   * Whether the session of these claims has ended, and its user with the roles of now. The roles need only
   * the address from the token, so they are read alongside the session version.
   */
  const checked = async (claims: SessionClaims): Promise<MadauthUser | null> => {
    const [ended, user] = await Promise.all([hasEnded(claims), withRoles(userFromClaims(claims))]);
    return ended ? null : user;
  };

  /**
   * The user of the request's session, or null if there is none or it has ended. A session token that is
   * missing, expired, past half of its lifetime or carries outdated roles is replaced on the way, if the
   * request has a valid renewal token: the user and their roles are checked again, and new cookies are set.
   */
  const currentSession = async (c: Context): Promise<MadauthUser | null> => {
    const session = await tokenClaims(c, SESSION_COOKIE, SESSION_TYP);
    // The roles are read again, so a change shows the next time the app checks the session.
    const user = session ? await checked(session) : null;
    const upToDate =
      session && user && sameRoles(user.roles ?? [], session.roles ?? []) && Date.now() / 1000 - session.iat <= sessionTtlSeconds / 2;
    if (upToDate) return user;

    const renewal = await tokenClaims(c, RENEWAL_COOKIE, RENEWAL_TYP);
    const renewed = renewal ? await checked(renewal) : null;
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
    // The session proves who owns the address, so its e-mail & password account goes as well when the
    // user signed in with Google. Google sign-in itself stores nothing.
    // The roles go first: once the account is gone its session no longer counts, so a failure after that
    // could not be retried.
    if (roles && user.email) await roles.remove(normalizeEmail(user.email));
    const passwordUserId = ctx.users && user.email ? await ctx.users.deleteByEmail(normalizeEmail(user.email)) : null;
    clearSession(c);
    // passwordUserId tells the receiver which e-mail & password user went, also when the session is Google's.
    await ctx.emit('user.deleted', { user, passwordUserId: passwordUserId ?? undefined });
    return c.body(null, 204);
  });

  // --- Roles (only with a store; otherwise these routes answer 404) ---

  if (roles) {
    /** The admin's address if the request comes from one; otherwise the answer to send. */
    const admin = async (c: Context): Promise<{ email: string } | { answer: Response }> => {
      // currentSession reads the roles from the store, not from the session token: a removed admin role
      // stops counting at once.
      const user = await currentSession(c);
      if (!user) return { answer: c.json({ error: 'no_session' }, 401) };
      const email = user.email ? normalizeEmail(user.email) : undefined;
      if (!email || !user.roles?.includes(ADMIN_ROLE)) {
        return { answer: c.json({ error: 'forbidden', message: `Only users with the role "${ADMIN_ROLE}" can manage roles.` }, 403) };
      }
      return { email };
    };
    const body = async (c: Context): Promise<Record<string, unknown>> => {
      const data = await c.req.json<unknown>().catch(() => null);
      return data && typeof data === 'object' ? (data as Record<string, unknown>) : {};
    };
    const invalidEmail = (c: Context) => c.json({ error: 'invalid_email', message: 'This is not a valid e-mail address.' }, 400);

    // POST, so the address is not part of a URL that ends up in access logs.
    app.post('/auth/admin/roles/get', async (c) => {
      const caller = await admin(c);
      if ('answer' in caller) return caller.answer;
      const data = await body(c);
      if (!isValidEmail(data.email)) return invalidEmail(c);
      const email = normalizeEmail(data.email);
      return c.json({ email, roles: await roles.get(email) });
    });

    app.post('/auth/admin/roles/set', async (c) => {
      const caller = await admin(c);
      if ('answer' in caller) return caller.answer;
      const data = await body(c);
      if (!isValidEmail(data.email)) return invalidEmail(c);
      const names = parseRoles(data.roles);
      if (!names) {
        return c.json(
          {
            error: 'invalid_roles',
            message: 'roles must be a list of names: lower-case letters, digits, "-" and "_", starting with a letter.',
          },
          400,
        );
      }
      const email = normalizeEmail(data.email);
      await roles.set(email, names, caller.email);
      await ctx.emit('roles.changed', { email, roles: names, by: caller.email });
      return c.json({ email, roles: names });
    });
  }

  return app;
}
