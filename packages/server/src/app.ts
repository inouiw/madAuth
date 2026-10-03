import { Hono, type Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { cors } from 'hono/cors';
import type { MadauthConfig } from './config.js';
import { importSigningKeys, type SigningKeys } from './keys.js';
import { deriveCodeKey, normalizeEmail } from './password.js';
import { googleRoutes } from './routes/google.js';
import { passwordRoutes } from './routes/password.js';
import { readToken, signSession, userFromClaims, type SessionClaims } from './tokens.js';
import { SESSION_COOKIE, SESSION_TYP, type MadauthUser } from './user.js';
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
  startSession(c: Context, user: MadauthUser, amr: string[], extra?: { sv?: number }): Promise<void>;
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
  const { issuer, allowedOrigins, sessionTtlSeconds, cookieDomain } = config;
  const keys = importSigningKeys(config.signingKey);
  // Browsers treat http://localhost as secure, but only mark cookies Secure when served over https.
  const secure = issuer.startsWith('https:');
  const isAllowedOrigin = (origin: string | undefined) => !!origin && allowedOrigins.includes(origin);

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
      const token = await signSession(await keys, issuer, sessionTtlSeconds, user, amr, extra);
      setCookie(c, SESSION_COOKIE, token, {
        path: '/',
        domain: cookieDomain,
        httpOnly: true,
        secure,
        sameSite: 'Lax',
        maxAge: sessionTtlSeconds,
      });
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

  /** The claims of the request's session, or null if there is none or it has ended. */
  const currentSession = async (c: Context) => {
    const claims = await readToken<SessionClaims>(await keys, issuer, SESSION_TYP, getCookie(c, SESSION_COOKIE));
    if (!claims) return null;
    // Users from the store: a password reset increments the session version and so ends older sessions.
    if (claims.sub.startsWith('usr_')) {
      const stored = await ctx.users?.findById(claims.sub);
      if (!stored || stored.sessionVersion !== claims.sv) return null;
    }
    return claims;
  };

  app.get('/auth/session', async (c) => {
    const claims = await currentSession(c);
    if (!claims) return c.json({ error: 'no_session' }, 401);
    const user = userFromClaims(claims);
    // Sliding session: renew once half of the lifetime has passed.
    if (Date.now() / 1000 - claims.iat > sessionTtlSeconds / 2) await ctx.startSession(c, user, claims.amr, { sv: claims.sv });
    return c.json({ user });
  });

  app.post('/auth/logout', (c) => {
    deleteCookie(c, SESSION_COOKIE, { path: '/', domain: cookieDomain, secure });
    return c.body(null, 204);
  });

  // --- Account ---

  app.post('/auth/account/delete', async (c) => {
    const claims = await currentSession(c);
    if (!claims) return c.json({ error: 'no_session' }, 401);
    // The session proves who owns the address, so its e-mail & password account goes as well when the
    // user signed in with Google. Google sign-in itself stores nothing.
    if (ctx.users && claims.email) await ctx.users.deleteByEmail(normalizeEmail(claims.email));
    deleteCookie(c, SESSION_COOKIE, { path: '/', domain: cookieDomain, secure });
    await ctx.emit('user.deleted', { user: userFromClaims(claims) });
    return c.body(null, 204);
  });

  return app;
}
