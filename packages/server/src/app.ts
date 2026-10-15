import { Hono, type Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { cors } from 'hono/cors';
import { Admins } from './admins.js';
import { ADMIN_ROLE, claimsFromJson, isAdmin, parseClaims, sameClaims } from './claims.js';
import { methodConfig, sendsVerificationEmails, type MadauthConfig } from './config.js';
import { importSigningKeys, type SigningKeys } from './keys.js';
import { deriveCodeKey, isValidEmail, normalizeEmail } from './password.js';
import { emailRoutes } from './routes/email.js';
import { emailLinkRoutes } from './routes/email-link.js';
import { deriveTokenKey } from './github.js';
import { githubRoutes, revokeGrant } from './routes/github.js';
import { googleRoutes } from './routes/google.js';
import { body, error } from './routes/helpers.js';
import { passwordRoutes } from './routes/password.js';
import { clearChallenge, setChallenge, type NextStep } from './routes/challenge.js';
import { appOriginOf } from './routes/oauth.js';
import { smsRoutes } from './routes/sms.js';
import { checkCode, totpRoutes, type TotpKeys } from './routes/totp.js';
import {
  METHODS,
  MAX_MIN_LENGTH,
  DEFAULT_PASSWORD_RULES,
  SECOND_FACTOR_POLICIES,
  Settings,
  canSignUp,
  checkMethodSettings,
  factorsOn,
  initialMethods,
  isConfigured,
  isOn,
  parseMethodSettings,
  parsePasswordRules,
  policyOf,
  signsIn,
  type MethodId,
  type MethodSettings,
  type PasswordRules,
  type SecondFactor,
  type SignInMethod,
} from './settings.js';
import { methodRoutes } from './routes/methods.js';
import { passkeyDomain, passkeyRoutes, usableOn } from './routes/passkey.js';
import { readToken, signRenewal, signSession, userFromClaims, type SessionClaims, type SessionExtra } from './tokens.js';
import { deriveTotpKey } from './totp.js';
import { EXPIRY_COOKIE, RENEWAL_COOKIE, RENEWAL_TYP, SESSION_COOKIE, SESSION_TYP, type MadauthUser } from './user.js';
import { Users, factorsAmong, methodOf, toMadauthUser, type StoredUser } from './users.js';
import { WEBHOOK_TIMEOUT_MS, createWebhookClient, type WebhookClient, type WebhookType } from './webhooks.js';

/** How long madAuth waits for an event call; events never make a request fail. */
export const EVENT_TIMEOUT_MS = 5_000;

/** `by` of the `user.claims_changed` that INITIAL_ADMIN_EMAIL causes: the variable, where an admin's change has their address. */
const INITIAL_ADMIN_EMAIL = 'INITIAL_ADMIN_EMAIL';

export { REDIRECT_ERROR_PARAM, REDIRECT_FACTORS_PARAM, REDIRECT_METHOD_PARAM, REDIRECT_NEXT_PARAM } from './routes/oauth.js';

/** The answer of the operator's sign-up check. */
export type SignupCheck = { ok: true } | { ok: false; reason: 'unavailable' } | { ok: false; reason: 'rejected'; message: string };

/**
 * What a primary sign-in method ends in: the user with their session; the next step with a second factor
 * (the challenge cookie is set; `factors` is what the user can finish with); or nothing, because the method
 * is switched off.
 */
export type SignInStep = { user: MadauthUser } | { next: NextStep; method: SignInMethod; factors: SecondFactor[] } | { disabled: true };

/** A signed-in user, and when they signed in (milliseconds since 1970; null for a session from before madAuth 0.6). */
export interface SignIn {
  user: MadauthUser;
  /** The user as stored, read with the session's check. */
  stored: StoredUser;
  signedInAt: number | null;
}

/** What the route modules share. */
export interface AppContext {
  config: MadauthConfig;
  keys: Promise<SigningKeys>;
  /** Whether cookies get the Secure attribute (only when the issuer is https). */
  secure: boolean;
  isAllowedOrigin(origin: string | undefined): boolean;
  /** Parses an absolute URL whose origin is in ALLOWED_ORIGINS, without its hash; null otherwise. */
  allowedUrl(value: unknown): URL | null;
  /**
   * Sets the session cookies for the user, as the routes resolved them from the store, and returns the user
   * with `amr`. `signIn` is how they signed in and the stored user's `signedUpAt`: the user's first session
   * sends `user.signed_up`, since a session starts only once every step the policy asks for is done.
   */
  startSession(
    c: Context,
    user: MadauthUser,
    amr: string[],
    signIn: { method: SignInMethod; signedUpAt: number | null },
    extra?: { sv?: number },
  ): Promise<MadauthUser>;
  /**
   * Finishes a primary sign-in method that succeeded: the session, or the next step with a second factor
   * as the policy of `method` and what the user has set up demand. `amr` is how the user signed in so far;
   * `profile` is what the method knows beyond the record (e.g. Google's picture). A passkey counts as a
   * factor only when it answers on the app the sign-in is for (see `appOriginOf`). Emits `user.signed_in`.
   */
  secondStep(c: Context, user: StoredUser, amr: string[], method: SignInMethod, profile?: { name?: string; picture?: string }): Promise<SignInStep>;
  /** The user of the request's session, or null if there is none or it has ended; renews it on the way like GET /auth/session. */
  currentUser(c: Context): Promise<MadauthUser | null>;
  /**
   * {@link currentUser}, with the user as stored and when they signed in (milliseconds since 1970, kept across
   * renewals; null for a session from before madAuth 0.6): from the token the user was read from, so another
   * user's token in the same request can't make the sign-in look recent.
   */
  currentSignIn(c: Context): Promise<SignIn | null>;
  users: Users;
  settings: Settings;
  /** Present when WEBHOOK_URL is configured. */
  webhook?: WebhookClient;
  /** Whether the server has what a method needs; only a configured method can be on. */
  configured(method: MethodId): boolean;
  /** Whether the webhook sends the e-mails that confirm an address, so people can sign up with one. */
  emailVerification: boolean;
  /** The sign-in methods that are on, as an admin set them: read from the store once per request. */
  methods(c: Context): Promise<MethodSettings>;
  /** Whether a method signs in: configured, listed by an admin, and allowed as a sign-in method. */
  enabled(c: Context, method: MethodId): Promise<boolean>;
  /** Asks the webhook whether someone may sign up (`user.signing_up`). Fails closed: without an answer, nobody signs up. */
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
  const codeKey = deriveCodeKey(config.signingKey.d!);
  const users = new Users(config.store, codeKey);
  const methods = methodConfig(config);
  const settings = new Settings(config.store, initialMethods(methods));
  const admins = new Admins(settings, users);
  const configured = (method: MethodId) => isConfigured(methods, method);
  const signsUp = (method: SignInMethod) => canSignUp(methods, method);
  const emailVerification = sendsVerificationEmails(config);
  const totpKeys: TotpKeys = { totpKey: deriveTotpKey(config.signingKey.d!), codeKey };
  const tokenKey = deriveTokenKey(config.signingKey.d!);

  /**
   * Sets the cookies of a session: the session token for app backends, the renewal token for this server
   * only, and the expiry time for the web library.
   */
  const issueSession = async (c: Context, user: MadauthUser, amr: string[], extra?: SessionExtra) => {
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
  /** An admin's own change that would take the role `admin` from them: another admin has to make it. */
  const ownAdminRole = (c: Context, message: string) => c.json({ error: 'own_admin_role', message }, 403);

  // --- Session ---

  /** The claims of a token in one of the request's cookies, or null if it is missing, expired or of another kind. */
  const tokenClaims = async (c: Context, cookie: string, typ: string) =>
    readToken<SessionClaims>(await keys, issuer, typ, getCookie(c, cookie));

  /**
   * The user of these claims with their claims of now, and as stored; null if the session has ended: the user
   * is gone, or a password reset incremented their session version since.
   */
  const checked = async (claims: SessionClaims): Promise<{ user: MadauthUser; stored: StoredUser } | null> => {
    const stored = await users.findById(claims.sub);
    if (!stored || stored.sessionVersion !== claims.sv) return null;
    const { claims: _, ...user } = userFromClaims(claims);
    const current = claimsFromJson(stored.claims);
    return { user: Object.keys(current).length ? { ...user, claims: current } : user, stored };
  };

  /** The checked user, with the sign-in time of the token they were read from. */
  const signInOf = (user: { user: MadauthUser; stored: StoredUser }, claims: SessionClaims): SignIn => ({
    ...user,
    signedInAt: typeof claims.auth_time === 'number' ? claims.auth_time * 1000 : null,
  });

  /**
   * The user of the request's session and when they signed in, or null if there is none or it has ended. A
   * session token that is missing, expired, past half of its lifetime or carries outdated claims is replaced on
   * the way, if the request has a valid renewal token: the user and their claims are checked again, and new
   * cookies are set.
   */
  const currentSignIn = async (c: Context): Promise<SignIn | null> => {
    const session = await tokenClaims(c, SESSION_COOKIE, SESSION_TYP);
    // The claims are read again, so a change shows the next time the app checks the session.
    const user = session ? await checked(session) : null;
    if (session && user && sameClaims(user.user.claims, session.claims) && Date.now() / 1000 - session.iat <= sessionTtlSeconds / 2) {
      return signInOf(user, session);
    }

    const renewal = await tokenClaims(c, RENEWAL_COOKIE, RENEWAL_TYP);
    // Both tokens of one sign-in: the check of the session token holds for the renewal token as well.
    const sameSignIn =
      session && user && renewal && renewal.sub === session.sub && renewal.sv === session.sv && renewal.email === session.email;
    const renewed = sameSignIn ? user : renewal ? await checked(renewal) : null;
    if (renewal && renewed) {
      // The sign-in it renews is still the one the user made: its time stays.
      await issueSession(c, renewed.user, renewal.amr, { sv: renewal.sv, auth_time: renewal.auth_time });
      return signInOf(renewed, renewal);
    }
    // Still valid, but not renewable (e.g. the renewal cookie is gone): it lasts until it expires.
    return session && user ? signInOf(user, session) : null;
  };

  /** The user of the request's session, or null; see {@link currentSignIn}. */
  const currentSession = async (c: Context): Promise<MadauthUser | null> => (await currentSignIn(c))?.user ?? null;

  // The settings of a request, read once: every route that needs them shares the read.
  const methodsOf = new WeakMap<Request, Promise<MethodSettings>>();

  /** INITIAL_ADMIN_EMAIL, for a user who starts a session: their new claims if it gave them the role now, else null. */
  const promoteInitialAdmin = async (user: MadauthUser) => {
    const value = config.initialAdminEmail;
    return value && user.email && normalizeEmail(user.email) === value ? admins.applyInitial(user.id, value) : null;
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
    async startSession(c, signedIn, amr, { method, signedUpAt }, extra) {
      // The user INITIAL_ADMIN_EMAIL names gets the role before the session, which carries it.
      const promoted = await promoteInitialAdmin(signedIn);
      const user = promoted ? { ...signedIn, claims: promoted.claims } : signedIn;
      // Only a user whose first session this is gets the write, before the cookies: if it fails, nobody is
      // signed in. The write decides, so two sign-ins at once send it once.
      const firstSession = signedUpAt === 0 && (await users.markSignedUp(user.id));
      // A sign-in that was waiting for the authenticator app is over, whichever way this session came about.
      clearChallenge(c, secure);
      await issueSession(c, user, amr, { ...extra, auth_time: Math.floor(Date.now() / 1000) });
      const result = { ...user, amr };
      // A new user is told first, already with the role; the claims change says where it came from.
      if (firstSession) await this.emit('user.signed_up', { user: result, method });
      if (promoted) await this.emit('user.claims_changed', { user: result, claims: promoted.claims, by: INITIAL_ADMIN_EMAIL });
      return result;
    },
    async secondStep(c, user, amr, method, profile) {
      const methods = await this.methods(c);
      if (!signsIn(method, configured, methods)) return { disabled: true };
      let next: NextStep | null = null;
      // The factors the user can finish with; for a setup, those the user can set up.
      let factors: SecondFactor[] = [];
      if (method === 'totp') {
        // The app itself is the method of a sign-up with it: it is set up now, or asked for if it exists already.
        const app = await users.totpAccount(user.id);
        next = app ? 'totp' : 'totp-setup';
        factors = ['totp'];
      } else {
        const policy = policyOf(method, methods);
        if (policy !== 'none') {
          // The second factors that are on, but never the method itself: a passkey is no second factor of a
          // passkey sign-in. They come in the order of SECOND_FACTORS: the client offers a switch to the others.
          const on = factorsOn(configured, methods, method);
          // A passkey answers only on the domain it was made for: one of another app's is no factor here.
          const has = factorsAmong(await users.accounts(user.id), on, usableOn(passkeyDomain(config, appOriginOf(c))));
          next = has[0] ?? (policy === 'required' ? 'totp-setup' : null);
          factors = has.length ? has : on;
        }
      }
      if (next) {
        // A sign-in that goes on with a second step ends the session there was at this browser, if any:
        // whoever was signed in is signed out until the step is done, so the setup can't be taken for theirs.
        clearSession(c);
        // Only what the session will show; the cookie is signed, not encrypted.
        const known = { ...(profile?.name ? { name: profile.name } : {}), ...(profile?.picture ? { picture: profile.picture } : {}) };
        const step = next === 'totp-setup' ? { factors: [], setup: factors } : { factors };
        await setChallenge(c, this, { sub: user.id, sv: user.sessionVersion, amr, method, next, ...step, ...(Object.keys(known).length ? { profile: known } : {}) });
        return { next, method, factors };
      }
      const result = await this.startSession(c, toMadauthUser(user, profile), amr, { method, signedUpAt: user.signedUpAt }, { sv: user.sessionVersion });
      await this.emit('user.signed_in', { user: result, method });
      return { user: result };
    },
    currentUser: currentSession,
    currentSignIn,
    users,
    settings,
    webhook: config.webhook ? createWebhookClient(config.webhook, config.webhookFetch) : undefined,
    configured,
    emailVerification,
    methods(c) {
      let reading = methodsOf.get(c.req.raw);
      if (!reading) {
        reading = settings.methods();
        methodsOf.set(c.req.raw, reading);
      }
      return reading;
    },
    async enabled(c, method) {
      // Not a method that is on only as a second factor: a sign-up with the app, e.g., can't go on then.
      return signsIn(method, configured, await this.methods(c));
    },
    async checkSignup(data) {
      if (!this.webhook?.wants('user.signing_up')) return { ok: true };
      const check = await this.webhook.call('user.signing_up', data, WEBHOOK_TIMEOUT_MS);
      if (!check.ok) {
        console.error(`[madauth] Webhook "user.signing_up" failed: ${check.reason}`);
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
      // The user in an event is the user, not their session: `amr` (how the session was authenticated) stays out.
      const user = data.user;
      const payload = user && typeof user === 'object' && 'amr' in user ? { ...data, user: { ...(user as object), amr: undefined } } : data;
      const result = await this.webhook.call(type, payload, EVENT_TIMEOUT_MS);
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
    const current = await ctx.methods(c);
    const on = (method: MethodId) => isOn(method, configured, current);
    const signIn = (method: MethodId) => signsIn(method, configured, current);
    const rules = on('password') ? await settings.passwordRules() : null;
    return c.json({
      google: on('google') ? { clientId: config.google!.clientId, codeFlow: !!config.google!.clientSecret, secondFactor: policyOf('google', current) } : null,
      github: on('github') ? { secondFactor: policyOf('github', current) } : null,
      password: rules ? { ...rules, secondFactor: policyOf('password', current) } : null,
      // The app can be set up when it is on; `signIn` says whether it signs in on its own (allowAsSignInMethod).
      totp: on('totp') ? { signIn: signIn('totp'), signUp: signIn('totp') && emailVerification } : null,
      email: { verification: emailVerification },
      emailLink: on('email-link') ? { secondFactor: policyOf('email-link', current) } : null,
      // SMS codes as a second factor: a signed-in user can add a phone, and the dialog offers it in the second step.
      sms: on('sms'),
      // Passkeys: a signed-in user can add them; `signIn` says whether they sign in on their own, `secondFactor`
      // whether such a sign-in then asks for a code. On, they are a second factor of the methods that ask for one.
      passkey: on('passkey') ? { signIn: signIn('passkey'), secondFactor: policyOf('passkey', current) } : null,
    });
  });

  if (emailVerification && ctx.webhook) emailRoutes(app, ctx, users, ctx.webhook);
  if (configured('email-link') && ctx.webhook) emailLinkRoutes(app, ctx, users, ctx.webhook);
  if (configured('sms') && ctx.webhook) smsRoutes(app, ctx, users, ctx.webhook);
  if (config.google) googleRoutes(app, ctx, config.google);
  if (config.github) githubRoutes(app, ctx, config.github, tokenKey);
  if (config.password && ctx.webhook) passwordRoutes(app, ctx, users, ctx.webhook);
  totpRoutes(app, ctx, totpKeys);
  passkeyRoutes(app, ctx);
  // GitHub's authorization goes with the account, with the token kept from its last sign-in.
  methodRoutes(app, ctx, async (account) => {
    if (config.github && account.key.startsWith('github:')) await revokeGrant(config.github, tokenKey, account);
  });

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
    clearChallenge(c, secure);
    return c.body(null, 204);
  });

  // --- Account ---

  app.post('/auth/account/delete', async (c) => {
    const user = await currentSession(c);
    if (!user) return c.json({ error: 'no_session' }, 401);
    // An admin never removes themselves, so a lone admin stays: another admin takes the role from them first.
    // Checked before the code, which a refused deletion must not use up.
    if (isAdmin(user)) {
      return ownAdminRole(c, `You have the role "${ADMIN_ROLE}", so you can't delete your account: another admin takes the role from you first.`);
    }
    const stored = await users.findById(user.id);
    // An app that is switched off server-wide protects nothing, so it is not asked for either. A phone for
    // SMS codes alone does not protect the deletion (not covered yet, see docs/sms-security.md).
    const protects = stored && isOn('totp', configured, await ctx.methods(c));
    const authenticator = protects ? await users.totpAccount(user.id) : null;
    if (stored && authenticator) {
      // Deleting the user removes their authenticator app too, so like removing it, it takes a current code.
      const data = await body(c);
      if (data.code === undefined && data.recoveryCode === undefined) {
        return error(c, 401, 'code_required', 'Enter a code from your authenticator app (or a recovery code) to delete your account.');
      }
      const via = await checkCode(c, ctx, totpKeys, stored, authenticator, data);
      if (via instanceof Response) return via;
    }
    // Read before the deletion: the web library revokes the app's access to this Google account with it.
    const googleSub = await users.googleSub(user.id);
    // GitHub's authorization goes once the user is gone, with the token kept from the last sign-in.
    const githubAccount = config.github ? await users.githubAccount(user.id) : null;
    // The user with all their sign-in methods: the session proves who they are, whichever way they signed in.
    const deleted = await users.deleteById(user.id);
    if (deleted && config.github) await revokeGrant(config.github, tokenKey, githubAccount);
    clearSession(c);
    await ctx.emit('user.deleted', { user });
    return googleSub ? c.json({ googleSub }) : c.body(null, 204);
  });

  // --- Admin: claims, settings and resetting a user's sign-in ---

  /** The admin's id and address if the request comes from one; otherwise the answer to send. */
  const admin = async (c: Context): Promise<{ id: string; email: string } | { answer: Response }> => {
    // currentSession reads the claims from the store, not from the session token: a removed admin role
    // stops counting at once.
    const user = await currentSession(c);
    if (!user) return { answer: c.json({ error: 'no_session' }, 401) };
    const email = user.email ? normalizeEmail(user.email) : undefined;
    if (!email || !isAdmin(user)) {
      const message = `Only users with the role "${ADMIN_ROLE}" can manage claims and settings.`;
      return { answer: c.json({ error: 'forbidden', message }, 403) };
    }
    return { id: user.id, email };
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
    // An admin never takes the role from themselves, so a lone admin keeps it: another admin has to.
    if (user.id === caller.id && !isAdmin({ claims })) {
      return ownAdminRole(c, `You can't take the role "${ADMIN_ROLE}" from yourself: another admin has to.`);
    }
    // Stored as JSON, and sent with the user as stored: the webhook sees what the next session sees.
    const stored = Object.keys(claims).length ? JSON.stringify(claims) : null;
    await users.updateUser(user.id, { claims: stored });
    const email = user.emailNormalized;
    await ctx.emit('user.claims_changed', { user: toMadauthUser({ ...user, claims: stored }), claims, by: caller.email });
    return c.json({ email, userId: user.id, claims });
  });

  /**
   * The settings as the admin API answers them: for each method (and `sms`), whether the server is configured
   * for it, whether it is on, whether it signs in on its own and whether it asks for a second factor; and
   * the rules for new passwords.
   */
  const settingsAnswer = (methods: MethodSettings, password: PasswordRules) => ({
    password,
    methods: Object.fromEntries(
      METHODS.map((method) => [
        method,
        {
          configured: configured(method),
          enabled: isOn(method, configured, methods),
          allowAsSignInMethod: signsIn(method, configured, methods),
          secondFactor: isOn(method, configured, methods) ? policyOf(method, methods) : 'none',
        },
      ]),
    ),
  });

  app.post('/auth/admin/settings/get', async (c) => {
    const caller = await admin(c);
    if ('answer' in caller) return caller.answer;
    const [methods, password] = await Promise.all([settings.methods(), settings.passwordRules()]);
    return c.json(settingsAnswer(methods, password));
  });

  app.post('/auth/admin/settings/set', async (c) => {
    const caller = await admin(c);
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    const invalid = (message: string) => c.json({ error: 'invalid_settings', message }, 400);
    if (data.methods === undefined && data.password === undefined) return invalid('Pass methods, password or both.');
    // Both are checked before either is written.
    const next = data.methods === undefined ? undefined : parseMethodSettings(data.methods);
    if (next === null) {
      return invalid(
        `methods must list the methods that are on (${METHODS.join(', ')}), each as { "allowAsSignInMethod": true | false, ` +
          `"secondFactor": ${SECOND_FACTOR_POLICIES.map((p) => `"${p}"`).join(' | ')} }, both given, e.g. ` +
          '{ "google": { "allowAsSignInMethod": true, "secondFactor": "none" }, "password": { "allowAsSignInMethod": true, "secondFactor": "optional" }, ' +
          '"totp": { "allowAsSignInMethod": false, "secondFactor": "none" } }. A method that is not listed is off.',
      );
    }
    const rules = data.password === undefined ? undefined : parsePasswordRules(data.password);
    if (rules === null) {
      return invalid(
        `password must be { "minLength": 1 to ${MAX_MIN_LENGTH}, "minScore": 0 to 4 }, both optional, e.g. ` +
          `{ "minLength": 10, "minScore": 3 }. What is left out takes its default (${DEFAULT_PASSWORD_RULES.minLength}, ${DEFAULT_PASSWORD_RULES.minScore}).`,
      );
    }
    const wrong = next ? checkMethodSettings(next, { configured, signsUp }) : null;
    if (wrong) return invalid(wrong);
    // Two writes: if the second fails, the first is undone, so a failed request has changed nothing.
    const previousRules = rules && next ? await settings.passwordRules() : undefined;
    const password = rules ? await settings.setPasswordRules(rules, caller.email) : await settings.passwordRules();
    if (next) {
      try {
        // The whole list is replaced.
        await settings.changeMethods(() => next, caller.email);
      } catch (e) {
        if (previousRules) await settings.setPasswordRules(previousRules, caller.email).catch(() => {});
        throw e;
      }
    }
    const methods = next ?? (await settings.methods());
    return c.json(settingsAnswer(methods, password));
  });

  // The way back for a user who lost every way in, whatever they had: they sign up again and keep their id.
  // See "Resetting a user's sign-in" in docs/server.md.
  app.post('/auth/admin/sign-in/reset', async (c) => {
    const caller = await admin(c);
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    if (!isValidEmail(data.email)) return invalidEmail(c);
    const user = await users.findByEmail(normalizeEmail(data.email));
    if (!user) return noUser(c);
    const removed = await users.resetSignIn(user.id);
    // GitHub's authorization goes with its account, as when the user removes GitHub or deletes the account.
    const github = config.github;
    if (github) await Promise.all(removed.filter((account) => methodOf(account) === 'github').map((account) => revokeGrant(github, tokenKey, account)));
    await ctx.emit('user.sign_in_reset', { user: toMadauthUser(user), by: caller.email });
    return c.json({ email: user.emailNormalized, userId: user.id });
  });

  return app;
}
