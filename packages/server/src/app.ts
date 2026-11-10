import { Hono, type Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { cors } from 'hono/cors';
import { Admins } from './admins.js';
import { ApiKeys, MADAUTH_SCOPES, ScopeCatalog, apiKeyInfo, grantedScopes, type MadauthScope } from './api-keys.js';
import { ADMIN_ROLE, claimsFromJson, isAdmin, parseClaims, sameClaims } from './claims.js';
import { methodConfig, sendsVerificationEmails, type MadauthConfig } from './config.js';
import { importAppleKey } from './apple.js';
import { Providers, importProviders, isProviderMethodKind, parseProviderFields, parseProviderKind, providerOf, type ProviderKind, type StoredProvider } from './providers.js';
import { SETUP_TOKEN_PREFIX, Setup } from './setup.js';
import { discover, keysCache } from './oidc.js';
import type { JWTVerifyGetKey } from 'jose';
import type { KeyService } from './key-service.js';
import { isValidEmail, normalizeEmail } from './password.js';
import { emailRoutes } from './routes/email.js';
import { emailLinkRoutes } from './routes/email-link.js';
import { appleRoutes, revokeAppleGrant } from './routes/apple.js';
import { githubRoutes, revokeGrant } from './routes/github.js';
import { googleRoutes } from './routes/google.js';
import { oidcRoutes } from './routes/oidc.js';
import { body, error, reauthRequired, signedInUser } from './routes/helpers.js';
import { passwordRoutes } from './routes/password.js';
import { clearChallenge, isSetupStep, setChallenge, type NextStep } from './routes/challenge.js';
import { appOriginOf } from './routes/oauth.js';
import { smsRoutes } from './routes/sms.js';
import { authenticatorRoutes, checkCode } from './routes/authenticator.js';
import {
  METHODS,
  MAX_MIN_LENGTH,
  DEFAULT_PASSWORD_RULES,
  LOGIN_URL_SETTING,
  METHODS_SETTING,
  SECOND_FACTOR_POLICIES,
  Settings,
  canSignUp,
  checkMethodSettings,
  factorsOn,
  initialMethods,
  isConfigured,
  isOn,
  parseLoginUrl,
  parseMethodSettings,
  parsePasswordRules,
  policyOf,
  signInPredicate,
  signsIn,
  type MethodId,
  type MethodSettings,
  type PasswordRules,
  type SecondFactor,
} from './settings.js';
import { methodRoutes } from './routes/methods.js';
import { apiKeyNotFound, apiKeyRoutes, invalidApiKey, keyCaller } from './routes/api-keys.js';
import { passkeyDomain, passkeyRoutes, usableOn } from './routes/passkey.js';
import { OIDC_PATH, oidcEndpoints } from './routes/oidc-endpoints.js';
import { OidcClients, clientInfo, parseClientFields } from './oidc-clients.js';
import { RSA_SIGNING_ALG } from './keys.js';
import { canSign, readToken, signRenewal, signSession, userFromClaims, type SessionClaims, type SessionExtra } from './tokens.js';
import { parseUserSearch, searchUsers } from './user-search.js';
import { EXPIRY_COOKIE, RENEWAL_COOKIE, RENEWAL_TYP, SESSION_COOKIE, SESSION_TYP, bearerTokenOf, type MadauthUser } from './user.js';
import { Users, factorsAmong, preferredFirst, toMadauthUser, type StoredAccount, type StoredUser } from './users.js';
import { WEBHOOK_TIMEOUT_MS, createWebhookClient, type WebhookClient, type WebhookType } from './webhooks.js';
import { deviceOf } from './device.js';
import { Sessions, legacySessionId, newSessionId, sessionInfo, type StoredSession } from './sessions.js';
import { sessionNotFound, sessionRoutes } from './routes/sessions.js';

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
export type SignInStep = { user: MadauthUser } | { next: NextStep; method: string; factors: SecondFactor[] } | { disabled: true };

/** A signed-in user, and when they signed in (milliseconds since 1970; null for a session from before madAuth 0.6). */
export interface SignIn {
  user: MadauthUser;
  /** The user as stored, read with the session's check. */
  stored: StoredUser;
  signedInAt: number | null;
  /** How the user signed in, as the session's token says. */
  amr: string[];
  /** The session's id; null for a session from before madAuth 0.7.5 that was not renewed since. */
  sessionId: string | null;
}

/**
 * Why a session ended, as `user.session_ended` tells it: `ended` from another session of the user's or by an admin,
 * `signed_out` at its browser, `replaced` by a new sign-in at its browser.
 */
export type SessionEndReason = 'ended' | 'signed_out' | 'replaced';

/** What a request finds the server set up for: read from the store, so a change applies on every instance at once. */
export interface MethodsNow {
  /** The methods an admin switched on, with their settings; the initial ones until an admin set them. */
  settings: MethodSettings;
  /**
   * Whether the server has what a method needs: a provider in the store (an OpenID Connect provider's method is
   * its id), or the webhook's e-mails and SMS. Only a configured method can be on.
   */
  configured: (method: string) => boolean;
  /** Whether a method creates users on this server, see `canSignUp`. */
  signsUp: (method: string) => boolean;
  /** The sign-in providers in the store. */
  providers: StoredProvider[];
}

/** What the route modules share. */
export interface AppContext {
  config: MadauthConfig;
  /** Signs the tokens, hashes the codes and encrypts the secrets: see key-service.ts. */
  keys: KeyService;
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
    signIn: { method: string; signedUpAt: number | null },
    extra: { sv: number },
  ): Promise<MadauthUser>;
  /**
   * Sets new session cookies for the same sign-in with the session version `sv`, e.g. after a change that ended
   * the user's other sessions: its time and `amr` stay, so the change doesn't count as a recent sign-in.
   */
  continueSession(c: Context, signIn: SignIn, sv: number): Promise<void>;
  /** Ends the session at this browser (its record goes, `user.session_ended` with `signed_out`), and a sign-in that waits for its second step. */
  signOut(c: Context): Promise<void>;
  /**
   * Sends `user.session_ended` for each of the user's sessions that ended, if the webhook wants it. `by` (and
   * `byApiKey`): the admin who ended them.
   */
  sessionsEnded(user: StoredUser, sessions: StoredSession[], reason: SessionEndReason, by?: { by: string; byApiKey?: { id: string; name: string } }): Promise<void>;
  /** Sends `user.signed_in` for a user who signed in, with their session's id and device when a session started. */
  signedIn(c: Context, user: MadauthUser, data: Record<string, unknown>): Promise<void>;
  /** The users' sessions, see sessions.ts. */
  sessions: Sessions;
  /**
   * Finishes a primary sign-in method that succeeded: the session, or the next step with a second factor
   * as the policy of `method` and what the user has set up demand. `amr` is how the user signed in so far;
   * `profile` is what the method knows beyond the record (e.g. Google's picture). A passkey counts as a
   * factor only when it answers on the app the sign-in is for (see `appOriginOf`). Emits `user.signed_in`.
   */
  secondStep(c: Context, user: StoredUser, amr: string[], method: string, profile?: { name?: string; picture?: string }): Promise<SignInStep>;
  /**
   * {@link secondStep} for a client that gets tokens instead of cookies (the token exchange of the OpenID Connect
   * provider): the user signed in, as returned and as stored now, or the step the sign-in needs, which only a
   * browser can take; nothing is set at this browser. Emits `user.signed_in`.
   */
  signInForTokens(
    c: Context,
    user: StoredUser,
    amr: string[],
    method: string,
    profile?: { name?: string; picture?: string },
  ): Promise<{ user: MadauthUser; stored: StoredUser } | { next: NextStep; factors: SecondFactor[] } | { disabled: true }>;
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
  /** Whether the webhook sends the e-mails that confirm an address, so people can sign up with one. */
  emailVerification: boolean;
  /**
   * The methods that are on and what the server has for each, see {@link MethodsNow}: read from the store once
   * per request `c`, or anew without one.
   */
  methods(c?: Context): Promise<MethodsNow>;
  /** A provider's client secret in plain text; null without one. Decrypted by the key service, so only read where it is used. */
  clientSecret(provider: StoredProvider): Promise<string | null>;
  /** A provider's published signing keys by its `jwks_uri`, fetched through `oidcFetch` and cached once for the server, for every route that checks its tokens. */
  providerKeys(jwksUri: string): JWTVerifyGetKey;
  /** Whether a method signs in: configured, listed by an admin, and allowed as a sign-in method. */
  enabled(c: Context, method: string): Promise<boolean>;
  /** Asks the webhook whether someone may sign up (`user.signing_up`). Fails closed: without an answer, nobody signs up. */
  checkSignup(data: { email: string; name?: string; locale?: string; method: string }): Promise<SignupCheck>;
  /** Tells the webhook that something happened. Awaited (Lambda stops after the answer), but never fails. */
  emit(type: WebhookType, data: Record<string, unknown>): Promise<void>;
}

/**
 * Creates the madAuth HTTP app. It is built on Hono's Web Standard Request/Response, so the same app runs
 * on Node (Docker), AWS Lambda and Azure Functions (see `src/entry/`).
 */
export function createApp(config: MadauthConfig): Hono {
  const { issuer, allowedOrigins, sessionTtlSeconds, renewalTtlSeconds, cookieDomain } = config;
  const keys = config.keyService;
  // Browsers treat http://localhost as secure, but only mark cookies Secure when served over https.
  const secure = issuer.startsWith('https:');
  const isAllowedOrigin = (origin: string | undefined) => !!origin && allowedOrigins.includes(origin);
  const users = new Users(config.store, keys);
  // What the configuration decides; Google and GitHub come from the providers in the store.
  const fixedMethods = methodConfig(config);
  const settings = new Settings(config.store);
  const providers = new Providers(settings, keys);
  const admins = new Admins(settings, users);
  const setup = new Setup(settings, users, keys, issuer);
  const apiKeys = new ApiKeys(config.store);
  const oidcClients = new OidcClients(config.store);
  const scopeCatalog = new ScopeCatalog(config.apiKeyScopesUrl, config.scopesFetch);
  const sessions = new Sessions(config.store, renewalTtlSeconds * 1000);
  const device = (c: Context) => deviceOf(c, config.clientIpHeader);
  const emailVerification = sendsVerificationEmails(config);

  // GOOGLE_* and GITHUB_* of madAuth before 0.7 become providers once, before the first request reads them. A
  // failed import is logged and tried again a minute later; the requests go on meanwhile, without those providers.
  let importing: Promise<void> | undefined;
  let importRetryAt = 0;
  const imported = () => {
    if (!importing && Date.now() >= importRetryAt) {
      importing = importProviders(providers, { google: config.google, github: config.github }).catch((e: unknown) => {
        console.error(`[madauth] Could not import GOOGLE_* and GITHUB_* into the providers, tried again in a minute: ${(e as Error).message}`);
        importing = undefined;
        importRetryAt = Date.now() + 60_000;
      });
    }
    return importing;
  };
  /** The methods and providers as the store has them now: two reads, at once. */
  const readMethods = async (): Promise<MethodsNow> => {
    await imported();
    const [stored, methodsValue] = await Promise.all([providers.list(), settings.get<unknown>(METHODS_SETTING)]);
    const has = {
      ...fixedMethods,
      google: providerOf({ providers: stored }, 'google'),
      github: providerOf({ providers: stored }, 'github'),
      oidc: new Set(stored.filter((provider) => isProviderMethodKind(provider.kind)).map((provider) => provider.id)),
    };
    return {
      settings: settings.methodsFrom(methodsValue, initialMethods(has)),
      configured: (method) => isConfigured(has, method),
      signsUp: (method) => canSignUp(has, method),
      providers: stored,
    };
  };

  /**
   * Sets the cookies of a session: the session token for app backends, the renewal token for this server
   * only, and the expiry time for the web library.
   */
  const issueSession = async (c: Context, user: MadauthUser, amr: string[], extra?: SessionExtra) => {
    const [sessionToken, renewalToken] = await Promise.all([
      signSession(keys, issuer, sessionTtlSeconds, user, amr, extra),
      signRenewal(keys, issuer, renewalTtlSeconds, user, amr, extra),
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
    readToken<SessionClaims>(keys, issuer, typ, getCookie(c, cookie));

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
  const signInOf = (user: { user: MadauthUser; stored: StoredUser }, claims: SessionClaims): SignIn => {
    const { sessionId: _, ...rest } = user.user;
    return {
      ...user,
      user: claims.sid ? { ...rest, sessionId: claims.sid } : rest,
      signedInAt: typeof claims.auth_time === 'number' ? claims.auth_time * 1000 : null,
      amr: claims.amr,
      sessionId: claims.sid ?? null,
    };
  };

  /**
   * Renews the record of the session a renewal token is for: resolves to its id, or null if it has ended (the record
   * is gone). A token from before madAuth 0.7.5 has no id: its first renewal makes the record, so nobody is signed out.
   */
  const renewRecord = async (c: Context, renewal: SessionClaims, stored: StoredUser): Promise<string | null> => {
    if (renewal.sid) return (await sessions.renew(renewal.sid, renewal.sub, device(c))) ? renewal.sid : null;
    const id = legacySessionId(getCookie(c, RENEWAL_COOKIE) ?? '');
    const started = await sessions.start({ id, userId: renewal.sub, sessionVersion: stored.sessionVersion, authTime: renewal.auth_time ?? null, amr: renewal.amr, device: device(c) });
    // Another renewal with the same token made it just now.
    return started || (await sessions.renew(id, renewal.sub, device(c))) ? id : null;
  };

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
      // A session that was ended has no record any more: it ends here, at its renewal.
      const sid = await renewRecord(c, renewal, renewed.stored);
      if (!sid) {
        clearSession(c);
        return null;
      }
      // The sign-in it renews is still the one the user made: its time stays.
      await issueSession(c, renewed.user, renewal.amr, { sv: renewal.sv, auth_time: renewal.auth_time, sid });
      return signInOf(renewed, { ...renewal, sid });
    }
    // Still valid, but not renewable (e.g. the renewal cookie is gone): it lasts until it expires.
    return session && user ? signInOf(user, session) : null;
  };

  /** The user of the request's session, or null; see {@link currentSignIn}. */
  const currentSession = async (c: Context): Promise<MadauthUser | null> => (await currentSignIn(c))?.user ?? null;

  // The settings of a request, read once: every route that needs them shares the read.
  const methodsOf = new WeakMap<Request, Promise<MethodsNow>>();

  /** INITIAL_ADMIN_EMAIL, for a user who starts a session: their new claims if it gave them the role now, else null. */
  const promoteInitialAdmin = async (user: MadauthUser) => {
    const value = config.initialAdminEmail;
    return value && user.email && normalizeEmail(user.email) === value ? admins.applyInitial(user.id, value) : null;
  };

  /**
   * What starting a session does besides the cookies, which `cookies` sets: the role INITIAL_ADMIN_EMAIL gives,
   * the user's first session (`user.signed_up`, sent once: the write decides), and the events after.
   */
  const establish = async (
    signedIn: MadauthUser,
    amr: string[],
    { method, signedUpAt }: { method: string; signedUpAt: number | null },
    cookies: (user: MadauthUser) => Promise<void>,
  ): Promise<MadauthUser> => {
    // The user INITIAL_ADMIN_EMAIL names gets the role before the session, which carries it.
    const promoted = await promoteInitialAdmin(signedIn);
    const user = promoted ? { ...signedIn, claims: promoted.claims } : signedIn;
    // Only a user whose first session this is gets the write, before the cookies: if it fails, nobody is
    // signed in. The write decides, so two sign-ins at once send it once.
    const firstSession = signedUpAt === 0 && (await users.markSignedUp(user.id));
    await cookies(user);
    const result = { ...user, amr };
    // A new user is told first, already with the role; the claims change says where it came from.
    if (firstSession) await ctx.emit('user.signed_up', { user: result, method });
    if (promoted) await ctx.emit('user.claims_changed', { user: result, claims: promoted.claims, by: INITIAL_ADMIN_EMAIL });
    // The first admin exists: the setup token stops working.
    if (promoted) await setup.close();
    return result;
  };

  /** The step a primary sign-in with `method` goes on with, as {@link AppContext.secondStep} decides it; `next` null for none. */
  const nextStepFor = async (c: Context, user: StoredUser, amr: string[], method: string): Promise<{ disabled: true } | { next: NextStep | null; factors: SecondFactor[] }> => {
    const now = await ctx.methods(c);
    const methods = now.settings;
    if (!signsIn(method, now.configured, methods)) return { disabled: true };
    if (method === 'authenticator') {
      // The app itself is the method of a sign-up with it: it is set up now, or asked for if it exists already.
      const app = await users.authenticatorAccount(user.id);
      return { next: app ? 'authenticator' : 'authenticator-setup', factors: ['authenticator'] };
    }
    if (method === 'passkey' && !amr.length) {
      // A sign-up with a passkey alone, whose address is confirmed: the passkey is created now, and then
      // the passkey's policy applies (see routes/passkey.ts).
      return { next: 'passkey-setup', factors: ['passkey'] };
    }
    const policy = policyOf(method, methods);
    if (policy === 'none') return { next: null, factors: [] };
    // The second factors that are on, but never the method itself: a passkey is no second factor of a
    // passkey sign-in. They come in the order of SECOND_FACTORS, the user's preferred one first: the client
    // offers a switch to the others.
    const on = factorsOn(now.configured, methods, method);
    // A passkey answers only on the domain it was made for: one of another app's is no factor here. The
    // factor the user prefers comes first, if they have it here.
    const has = preferredFirst(factorsAmong(await users.accounts(user.id), on, usableOn(passkeyDomain(config, appOriginOf(c)))), user.preferredSecondFactor);
    return { next: has[0] ?? (policy === 'required' ? 'second-factor-setup' : null), factors: has.length ? has : on };
  };

  /**
   * Ends the session this browser has, by its renewal token (or, without one, its session token): deletes its record
   * and sends `user.session_ended`. Nothing for a session that is gone, or from before madAuth 0.7.5.
   */
  const endBrowserSession = async (c: Context, reason: SessionEndReason): Promise<void> => {
    const token = (await tokenClaims(c, RENEWAL_COOKIE, RENEWAL_TYP)) ?? (await tokenClaims(c, SESSION_COOKIE, SESSION_TYP));
    const ended = token?.sid ? await sessions.end(token.sub, token.sid) : null;
    const user = ended && ctx.webhook?.wants('user.session_ended') ? await users.findById(ended.userId) : null;
    if (ended && user) await ctx.sessionsEnded(user, [ended], reason);
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
    async startSession(c, signedIn, amr, signIn, extra) {
      const sid = newSessionId();
      const result = await establish(signedIn, amr, signIn, async (user) => {
        // A sign-in that was waiting for the authenticator app is over, whichever way this session came about.
        clearChallenge(c, secure);
        // The session this browser had, if any, ends: this one replaces it.
        await endBrowserSession(c, 'replaced');
        const authTime = Math.floor(Date.now() / 1000);
        await sessions.start({ id: sid, userId: user.id, sessionVersion: extra.sv, authTime, amr, device: device(c) });
        await issueSession(c, user, amr, { ...extra, auth_time: authTime, sid });
      });
      return { ...result, sessionId: sid };
    },
    async continueSession(c, { user, amr, signedInAt, sessionId }, sv) {
      const authTime = signedInAt === null ? null : Math.floor(signedInAt / 1000);
      // The record goes on with the new session version; one that is gone (ended meanwhile) is made anew.
      const kept = sessionId !== null && (await sessions.renew(sessionId, user.id, device(c), sv));
      const sid = kept ? sessionId : newSessionId();
      if (!kept) await sessions.start({ id: sid, userId: user.id, sessionVersion: sv, authTime, amr, device: device(c) });
      await issueSession(c, user, amr, { sv, ...(authTime !== null ? { auth_time: authTime } : {}), sid });
    },
    async signOut(c) {
      await endBrowserSession(c, 'signed_out');
      clearSession(c);
      clearChallenge(c, secure);
    },
    async sessionsEnded(user, ended, reason, by) {
      if (!this.webhook?.wants('user.session_ended')) return;
      const madauthUser = toMadauthUser(user);
      await Promise.all(ended.map((session) => this.emit('user.session_ended', { user: madauthUser, session: { id: session.id }, reason, ...(by ?? {}) })));
    },
    async signedIn(c, user, data) {
      const session = user.sessionId ? { session: { id: user.sessionId, ...device(c) } } : {};
      await this.emit('user.signed_in', { user, ...data, ...session });
    },
    sessions,
    async secondStep(c, user, amr, method, profile) {
      const step = await nextStepFor(c, user, amr, method);
      if ('disabled' in step) return step;
      const { next, factors } = step;
      if (next) {
        // A sign-in that goes on with a second step ends the session there was at this browser, if any:
        // whoever was signed in is signed out until the step is done, so the setup can't be taken for theirs.
        await endBrowserSession(c, 'replaced');
        clearSession(c);
        // Only what the session will show; the cookie is signed, not encrypted.
        const known = { ...(profile?.name ? { name: profile.name } : {}), ...(profile?.picture ? { picture: profile.picture } : {}) };
        const stepClaims = isSetupStep(next) ? { factors: [], setup: factors } : { factors };
        await setChallenge(c, this, { sub: user.id, sv: user.sessionVersion, amr, method, next, ...stepClaims, ...(Object.keys(known).length ? { profile: known } : {}) });
        return { next, method, factors };
      }
      const result = await this.startSession(c, toMadauthUser(user, profile), amr, { method, signedUpAt: user.signedUpAt }, { sv: user.sessionVersion });
      await this.signedIn(c, result, { method });
      return { user: result };
    },
    async signInForTokens(c, user, amr, method, profile) {
      const step = await nextStepFor(c, user, amr, method);
      if ('disabled' in step) return step;
      if (step.next) return { next: step.next, factors: step.factors };
      // No cookies: the client gets tokens for this sign-in instead.
      const result = await establish(toMadauthUser(user, profile), amr, { method, signedUpAt: user.signedUpAt }, async () => {});
      await this.emit('user.signed_in', { user: result, method });
      // As stored now: the first admin's role may have come with this sign-in.
      return { user: result, stored: (await users.findById(user.id)) ?? user };
    },
    currentUser: currentSession,
    currentSignIn,
    users,
    settings,
    webhook: config.webhook ? createWebhookClient(config.webhook, config.webhookFetch) : undefined,
    emailVerification,
    methods(c) {
      if (!c) return readMethods();
      let reading = methodsOf.get(c.req.raw);
      if (!reading) {
        reading = readMethods();
        methodsOf.set(c.req.raw, reading);
      }
      return reading;
    },
    clientSecret: (provider) => providers.clientSecret(provider),
    providerKeys: keysCache(config.oidcFetch ?? fetch),
    async enabled(c, method) {
      // Not a method that is on only as a second factor: a sign-up with the app, e.g., can't go on then.
      const now = await this.methods(c);
      return signsIn(method, now.configured, now.settings);
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
      // The user in an event is the user, not their session: `amr` (how the session was authenticated) and the
      // session's id stay out (`user.signed_in` and `user.session_ended` name the session apart).
      const user = data.user;
      const payload =
        user && typeof user === 'object' && ('amr' in user || 'sessionId' in user) ? { ...data, user: { ...(user as object), amr: undefined, sessionId: undefined } } : data;
      const result = await this.webhook.call(type, payload, EVENT_TIMEOUT_MS);
      if (!result.ok) console.error(`[madauth] Webhook "${type}" failed: ${result.reason}`);
    },
  };

  const app = new Hono();

  const appCors = cors({
    origin: (origin) => (isAllowedOrigin(origin) ? origin : null),
    credentials: true,
    allowMethods: ['GET', 'POST'],
    allowHeaders: ['Content-Type'],
    maxAge: 600,
  });
  // The OpenID Connect endpoints serve other applications: their own servers and apps call them, from any origin,
  // without cookies (the authorization and sign-out are page visits). See routes/oidc-endpoints.ts.
  const isOidcEndpoint = (c: Context) => c.req.path.startsWith(OIDC_PATH);
  const oidcCors = cors({ origin: '*', allowMethods: ['GET', 'POST'], allowHeaders: ['Authorization', 'Content-Type'], maxAge: 600 });
  app.use('/auth/*', (c, next) => (isOidcEndpoint(c) ? oidcCors(c, next) : appCors(c, next)));

  // A provider's POST to its callback (Apple's form_post) comes from the provider's site: it checks and stores
  // nothing itself, see routes/oidc.ts.
  const isProviderCallback = (c: Context) => /^\/auth\/providers\/[^/]+\/callback$/.test(c.req.path);
  // Only the configured apps may start sign-ins or change the session. A request with an API key (any
  // `Authorization` header) comes from a program: no page makes a browser send that header to madAuth, since
  // it isn't one CORS allows, and a program has no user's cookies.
  app.use('/auth/*', async (c, next) => {
    if (c.req.method === 'POST' && !isOidcEndpoint(c) && !isProviderCallback(c) && c.req.header('authorization') === undefined && !isAllowedOrigin(c.req.header('origin'))) {
      return c.json({ error: 'forbidden_origin' }, 403);
    }
    await next();
  });

  app.get('/health', (c) => c.text('ok'));

  app.get('/.well-known/jwks.json', async (c) => {
    c.header('Cache-Control', 'public, max-age=3600');
    // Read by browser apps too, e.g. to check an ID token.
    c.header('Access-Control-Allow-Origin', '*');
    // Every key that verifies tokens: also those signed before a rotation.
    return c.json({ keys: await keys.verificationKeys() });
  });

  // The methods that are on right now, so the web library shows exactly those.
  app.get('/auth/config', async (c) => {
    const now = await ctx.methods(c);
    const current = now.settings;
    const on = (method: MethodId) => isOn(method, now.configured, current);
    const signIn = (method: MethodId) => signsIn(method, now.configured, current);
    const rules = on('password') ? await settings.passwordRules() : null;
    const google = providerOf(now, 'google');
    return c.json({
      google: on('google') && google ? { clientId: google.clientId, codeFlow: !!google.secret, secondFactor: policyOf('google', current) } : null,
      github: on('github') ? { secondFactor: policyOf('github', current) } : null,
      password: rules ? { ...rules, secondFactor: policyOf('password', current) } : null,
      // The app can be set up when it is on; `signIn` says whether it signs in on its own (allowAsSignInMethod).
      authenticator: on('authenticator') ? { signIn: signIn('authenticator'), signUp: signIn('authenticator') && emailVerification } : null,
      email: { verification: emailVerification },
      emailLink: on('email-link') ? { secondFactor: policyOf('email-link', current) } : null,
      // SMS codes as a second factor: a signed-in user can add a phone, and the dialog offers it in the second step.
      sms: on('sms'),
      // Passkeys: a signed-in user can add them; `signIn` says whether they sign in on their own, `signUp` whether
      // people can sign up with one alone, `secondFactor` whether such a sign-in then asks for a second factor.
      // On, they are a second factor of the methods that ask for one.
      passkey: on('passkey') ? { signIn: signIn('passkey'), signUp: signIn('passkey') && emailVerification, secondFactor: policyOf('passkey', current) } : null,
      // The sign-in providers that are on, with the names admins gave them: the web library shows a button for
      // each, and names those whose sign-in can ask for a second factor.
      providers: now.providers.filter((provider) => signsIn(provider.id, now.configured, current)).map(({ id, kind, name }) => ({ id, kind, name, secondFactor: policyOf(id, current) })),
    });
  });

  if (emailVerification && ctx.webhook) emailRoutes(app, ctx, users, ctx.webhook);
  if (isConfigured(fixedMethods, 'email-link') && ctx.webhook) emailLinkRoutes(app, ctx, users, ctx.webhook);
  if (isConfigured(fixedMethods, 'sms') && ctx.webhook) smsRoutes(app, ctx, users, ctx.webhook);
  // Always there: whether the store has the provider is a question of each request.
  googleRoutes(app, ctx);
  githubRoutes(app, ctx);
  appleRoutes(app, ctx);
  // After Google's and GitHub's, whose own routes answer for their ids.
  oidcRoutes(app, ctx);
  if (config.password && ctx.webhook) passwordRoutes(app, ctx, users, ctx.webhook);
  authenticatorRoutes(app, ctx);
  passkeyRoutes(app, ctx);
  apiKeyRoutes(app, ctx, apiKeys, scopeCatalog);
  oidcEndpoints(app, ctx, oidcClients);
  /**
   * The GitHub OAuth App's ID and secret, to take back a user's authorization; null without a GitHub provider, whose
   * accounts then stay authorized at GitHub until the user removes the app there.
   */
  const githubApp = async () => {
    const github = providerOf(await ctx.methods(), 'github');
    const clientSecret = github && (await ctx.clientSecret(github));
    return github && clientSecret ? { clientId: github.clientId, clientSecret } : null;
  };
  /**
   * Takes a provider's authorization back for an account that is removed, with the token kept from its last
   * sign-in: GitHub's grant, Apple's refresh token. Nothing for the other providers' accounts.
   */
  const revokeProviderGrant = async (account: StoredAccount | null): Promise<void> => {
    if (!account) return;
    if (account.key.startsWith('apple:')) return revokeAppleGrant(ctx, account, config.oidcFetch);
    const github = account.key.startsWith('github:') ? await githubApp() : null;
    if (github) await revokeGrant(github, keys, account);
  };
  // GitHub's and Apple's authorizations go with the account.
  methodRoutes(app, ctx, revokeProviderGrant);

  app.get('/auth/session', async (c) => {
    const user = await currentSession(c);
    if (!user) {
      // Also tells the web library that nobody is signed in any more.
      clearSession(c);
      return c.json({ error: 'no_session' }, 401);
    }
    return c.json({ user });
  });

  app.post('/auth/logout', async (c) => {
    await ctx.signOut(c);
    return c.body(null, 204);
  });

  sessionRoutes(app, ctx);

  // --- Account ---

  /**
   * Deletes the user with all their sign-in methods, then takes back GitHub's and Apple's authorizations with the
   * tokens kept from their last sign-ins (best effort). With `ifClaims`, only while their claims are still these.
   * False when nothing was deleted: the user is gone, or their claims changed.
   */
  const deleteUser = async (userId: string, ifClaims?: string | null): Promise<boolean> => {
    // Read before the deletion, which takes the accounts with it: those that hold a grant to give back.
    const granted = (await users.accounts(userId)).filter((account) => account.key.startsWith('github:') || account.key.startsWith('apple:'));
    const deleted = await users.deleteById(userId, ifClaims);
    if (deleted) await Promise.all(granted.map(revokeProviderGrant));
    return deleted;
  };

  app.post('/auth/account/delete', async (c) => {
    const user = await currentSession(c);
    if (!user) return c.json({ error: 'no_session' }, 401);
    // Like every sensitive change, only right after signing in: a session someone took over can't end the account.
    if (!(await signedInUser(c, ctx))?.recent) return reauthRequired(c);
    // An admin never removes themselves, so a lone admin stays: another admin takes the role from them first.
    // Checked before the code, which a refused deletion must not use up.
    if (isAdmin(user)) {
      return ownAdminRole(c, `You have the role "${ADMIN_ROLE}", so you can't delete your account: another admin takes the role from you first.`);
    }
    const stored = await users.findById(user.id);
    // An app that is switched off server-wide protects nothing, so it is not asked for either. A phone for
    // SMS codes alone does not protect the deletion (not covered yet, see docs/sms-security.md).
    const now = await ctx.methods(c);
    const protects = stored && isOn('authenticator', now.configured, now.settings);
    const authenticator = protects ? await users.authenticatorAccount(user.id) : null;
    if (stored && authenticator) {
      // Deleting the user removes their authenticator app too, so like removing it, it takes a current code.
      const data = await body(c);
      if (data.code === undefined && data.recoveryCode === undefined) {
        return error(c, 401, 'code_required', 'Enter a code from your authenticator app (or a recovery code) to delete your account.');
      }
      const via = await checkCode(c, ctx, stored, authenticator, data);
      if (via instanceof Response) return via;
    }
    // Read before the deletion: the web library revokes the app's access to this Google account with it.
    const googleSub = await users.googleSub(user.id);
    // The user with all their sign-in methods: the session proves who they are, whichever way they signed in.
    await deleteUser(user.id);
    clearSession(c);
    await ctx.emit('user.deleted', { user });
    return googleSub ? c.json({ googleSub }) : c.body(null, 204);
  });

  // --- Admin: searching users, claims, settings and resetting a user's sign-in ---

  /**
   * The admin's id and address if the request comes from one; otherwise the answer to send. A request with an
   * API key (`Authorization: Bearer`) acts as the key's user, who must be an admin, and needs the key to have
   * `scope`; `byApiKey` then names the key. Without `scope`, the route takes no keys.
   */
  const admin = async (
    c: Context,
    scope?: MadauthScope,
  ): Promise<{ id: string; email: string; byApiKey?: { id: string; name: string }; sessionId?: string | null } | { answer: Response }> => {
    if (c.req.header('authorization') !== undefined) {
      if (!scope) return { answer: c.json({ error: 'forbidden', message: "API keys can't manage API keys: sign in as an admin." }, 403) };
      const caller = await keyCaller(c, ctx, apiKeys);
      if (!caller) return { answer: invalidApiKey(c) };
      // The role and the scope are checked with the claims of now, like a session's.
      const claims = claimsFromJson(caller.user.claims);
      if (!isAdmin({ claims })) {
        return { answer: c.json({ error: 'forbidden', message: `The API key's user does not have the role "${ADMIN_ROLE}".` }, 403) };
      }
      if (!grantedScopes(caller.key, MADAUTH_SCOPES, claims).includes(scope)) {
        return { answer: c.json({ error: 'insufficient_scope', message: `The API key does not have the scope ${scope}.` }, 403) };
      }
      await apiKeys.markUsed(caller.key);
      return { id: caller.user.id, email: caller.user.emailNormalized, byApiKey: { id: caller.key.id, name: caller.key.name } };
    }
    // currentSession reads the claims from the store, not from the session token: a removed admin role
    // stops counting at once.
    const signIn = await currentSignIn(c);
    if (!signIn) return { answer: c.json({ error: 'no_session' }, 401) };
    const { user } = signIn;
    const email = user.email ? normalizeEmail(user.email) : undefined;
    if (!email || !isAdmin(user)) {
      const message = `Only users with the role "${ADMIN_ROLE}" can manage claims and settings.`;
      return { answer: c.json({ error: 'forbidden', message }, 403) };
    }
    // An admin exists, so the setup token of a deployment from before 0.7 stops working too.
    await setup.close();
    return { id: user.id, email, sessionId: signIn.sessionId };
  };

  /**
   * An admin's change (as {@link admin}): with a session, only within RECENT_SIGN_IN_MS of signing in, as every
   * sensitive change; an API key with the scope is its own proof, since a key has no sign-in.
   */
  const adminChange = async (c: Context, scope: MadauthScope): ReturnType<typeof admin> => {
    const caller = await admin(c, scope);
    if ('answer' in caller) return caller;
    if (!caller.byApiKey && !(await signedInUser(c, ctx))?.recent) return { answer: reauthRequired(c) };
    return caller;
  };

  /**
   * Who reads or changes the providers or settings: an admin as {@link admin} has it, or, while no admin exists,
   * whoever has the setup token (see setup.ts), who has no address (`by` is null). `need`: `read` as {@link admin};
   * `change` as {@link adminChange}; `session`, for the providers, a session (no API keys) with a recent sign-in.
   */
  const adminOrSetup = async (
    c: Context,
    scope: MadauthScope | undefined,
    need: 'read' | 'change' | 'session',
  ): Promise<{ by: string | null; setup: boolean; byApiKey?: { id: string; name: string } } | { answer: Response }> => {
    const bearer = bearerTokenOf(c.req.header('authorization'));
    if (bearer?.startsWith(SETUP_TOKEN_PREFIX)) {
      if (await setup.accepts(bearer)) return { by: null, setup: true };
      const message = 'This setup token is not valid, or the setup is over: an admin signs in instead.';
      return { answer: c.json({ error: 'invalid_setup_token', message }, 401) };
    }
    if (need === 'session' && bearer !== undefined) {
      return { answer: c.json({ error: 'forbidden', message: "An API key can't change the sign-in providers: an admin signs in to do it." }, 403) };
    }
    const caller = need === 'change' && scope ? await adminChange(c, scope) : await admin(c, need === 'session' ? undefined : scope);
    if ('answer' in caller) return caller;
    if (need === 'session' && !(await signedInUser(c, ctx))?.recent) return { answer: reauthRequired(c) };
    return { by: caller.email, setup: false, ...byApiKey(caller) };
  };
  /** What an event made with an API key adds: the key, next to its user's address in `by`. */
  const byApiKey = (caller: { byApiKey?: { id: string; name: string } }) => (caller.byApiKey ? { byApiKey: caller.byApiKey } : {});
  const invalidEmail = (c: Context) => c.json({ error: 'invalid_email', message: 'This is not a valid e-mail address.' }, 400);
  const noUser = (c: Context) => c.json({ error: 'user_not_found', message: 'No user has this e-mail address.' }, 404);

  // POST, like every admin route: the terms (an address, a role) are personal data, kept out of URLs and logs.
  app.post('/auth/admin/users/search', async (c) => {
    const caller = await admin(c, 'madauth:users:read');
    if ('answer' in caller) return caller.answer;
    const parsed = parseUserSearch(await body(c));
    if ('error' in parsed) return c.json(parsed, 400);
    return c.json(await searchUsers(users, parsed.search));
  });

  // POST, so the address is not part of a URL that ends up in access logs.
  app.post('/auth/admin/claims/get', async (c) => {
    const caller = await admin(c, 'madauth:claims:read');
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    if (!isValidEmail(data.email)) return invalidEmail(c);
    const user = await users.findByEmail(normalizeEmail(data.email));
    if (!user) return noUser(c);
    return c.json({ email: user.emailNormalized, userId: user.id, claims: claimsFromJson(user.claims) });
  });

  app.post('/auth/admin/claims/set', async (c) => {
    const caller = await adminChange(c, 'madauth:claims:write');
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
    await ctx.emit('user.claims_changed', { user: toMadauthUser({ ...user, claims: stored }), claims, by: caller.email, ...byApiKey(caller) });
    return c.json({ email, userId: user.id, claims });
  });

  /**
   * The settings as the admin API answers them: for each method (and `sms`), whether the server is configured
   * for it, whether it is on, whether it signs in on its own and whether it asks for a second factor; the
   * rules for new passwords; and the app's login page (null: the issuer's `/`).
   */
  const settingsAnswer = (now: MethodsNow, methods: MethodSettings, password: PasswordRules, loginUrl: string | null) => ({
    password,
    loginUrl,
    methods: Object.fromEntries(
      // madAuth's own methods, then the OpenID Connect providers' and Microsoft's by their ids.
      [...METHODS, ...now.providers.filter((provider) => isProviderMethodKind(provider.kind)).map((provider) => provider.id)].map((method) => [
        method,
        {
          configured: now.configured(method),
          enabled: isOn(method, now.configured, methods),
          allowAsSignInMethod: signsIn(method, now.configured, methods),
          secondFactor: isOn(method, now.configured, methods) ? policyOf(method, methods) : 'none',
        },
      ]),
    ),
  });

  app.post('/auth/admin/settings/get', async (c) => {
    const caller = await adminOrSetup(c, 'madauth:settings:read', 'read');
    if ('answer' in caller) return caller.answer;
    const [now, password, loginUrl] = await Promise.all([ctx.methods(c), settings.passwordRules(), settings.loginUrl()]);
    return c.json(settingsAnswer(now, now.settings, password, loginUrl));
  });

  app.post('/auth/admin/settings/set', async (c) => {
    const caller = await adminOrSetup(c, 'madauth:settings:write', 'change');
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    const invalid = (message: string) => c.json({ error: 'invalid_settings', message }, 400);
    if (data.methods === undefined && data.password === undefined && data.loginUrl === undefined) return invalid('Pass methods, password, loginUrl or several of them.');
    // Both are checked before either is written.
    const next = data.methods === undefined ? undefined : parseMethodSettings(data.methods);
    if (next === null) {
      return invalid(
        `methods must list the methods that are on (${METHODS.join(', ')}), each as { "allowAsSignInMethod": true | false, ` +
          `"secondFactor": ${SECOND_FACTOR_POLICIES.map((p) => `"${p}"`).join(' | ')} }, both given, e.g. ` +
          '{ "google": { "allowAsSignInMethod": true, "secondFactor": "none" }, "password": { "allowAsSignInMethod": true, "secondFactor": "optional" }, ' +
          '"authenticator": { "allowAsSignInMethod": false, "secondFactor": "none" } }. A method that is not listed is off.',
      );
    }
    const rules = data.password === undefined ? undefined : parsePasswordRules(data.password);
    if (rules === null) {
      return invalid(
        `password must be { "minLength": 1 to ${MAX_MIN_LENGTH}, "minScore": 0 to 4 }, both optional, e.g. ` +
          `{ "minLength": 10, "minScore": 3 }. What is left out takes its default (${DEFAULT_PASSWORD_RULES.minLength}, ${DEFAULT_PASSWORD_RULES.minScore}).`,
      );
    }
    const loginUrl = data.loginUrl === undefined || data.loginUrl === null ? data.loginUrl : parseLoginUrl(data.loginUrl, allowedOrigins);
    if (loginUrl === null && data.loginUrl !== null) {
      return invalid(`loginUrl must be a path on the issuer's origin (e.g. "/login"), an absolute URL on one of ALLOWED_ORIGINS, or null for "/".`);
    }
    const now = await ctx.methods(c);
    const wrong = next ? checkMethodSettings(next, now) : null;
    if (wrong) return invalid(wrong);
    const [previousRules, previousLoginUrl] = await Promise.all([settings.passwordRules(), settings.loginUrl()]);
    // Each write with its undo: if a later one fails, the earlier ones are undone, so a failed request has changed nothing.
    const writes = [
      ...(rules ? [{ write: () => settings.setPasswordRules(rules, caller.by), undo: () => settings.setPasswordRules(previousRules, caller.by) }] : []),
      ...(loginUrl !== undefined ? [{ write: () => settings.set(LOGIN_URL_SETTING, loginUrl, caller.by), undo: () => settings.set(LOGIN_URL_SETTING, previousLoginUrl, caller.by) }] : []),
      // The whole list is replaced.
      ...(next ? [{ write: () => settings.changeMethods(() => next, caller.by), undo: async () => {} }] : []),
    ];
    for (const [i, step] of writes.entries()) {
      try {
        await step.write();
      } catch (e) {
        for (const done of writes.slice(0, i).reverse()) await done.undo().catch(() => {});
        throw e;
      }
    }
    return c.json(settingsAnswer(now, next ?? now.settings, rules ?? previousRules, loginUrl === undefined ? previousLoginUrl : loginUrl));
  });

  // One method's entry, changed in the stored list itself: what another admin changes meanwhile stays.
  app.post('/auth/admin/settings/method', async (c) => {
    const caller = await adminOrSetup(c, 'madauth:settings:write', 'change');
    if ('answer' in caller) return caller.answer;
    const { method, setting } = await body(c);
    const invalid = (message: string) => c.json({ error: 'invalid_settings', message }, 400);
    const parsed = typeof method === 'string' && setting !== null ? parseMethodSettings({ [method]: setting }) : null;
    if (typeof method !== 'string' || (setting !== null && parsed === null)) {
      return invalid(
        `Pass a method's id and its setting, { "method": "gitlab", "setting": { "allowAsSignInMethod": true | false, "secondFactor": ${SECOND_FACTOR_POLICIES.map((p) => `"${p}"`).join(' | ')} } }, or "setting": null to switch it off.`,
      );
    }
    const now = await ctx.methods(c);
    // Checked against the list as stored at the moment of the write, which the retries of a concurrent change read anew.
    let wrong: string | null = null;
    const changed = await settings.changeMethods(
      (current) => {
        const next = { ...Object.fromEntries(Object.entries(current).filter(([id]) => id !== method)), ...(parsed ?? {}) };
        wrong = checkMethodSettings(next, now);
        return wrong ? null : next;
      },
      caller.by,
      now.settings,
    );
    if (!changed) return invalid(wrong ?? 'The settings could not be changed.');
    const [password, loginUrl] = await Promise.all([settings.passwordRules(), settings.loginUrl()]);
    return c.json(settingsAnswer(now, changed, password, loginUrl));
  });

  // --- Admin: the sign-in providers (see providers.ts) ---

  /** A provider as the admin API answers it: never its secret, only whether it has one. */
  const providerInfo = (provider: StoredProvider) => ({
    id: provider.id,
    kind: provider.kind,
    name: provider.name,
    clientId: provider.clientId,
    hasClientSecret: !!provider.secret,
    // What the provider's console must list as the redirect URI (Google) or callback URL (GitHub).
    callbackUrl: `${issuer}/auth/providers/${provider.id}/callback`,
    createdAt: provider.createdAt,
    updatedAt: provider.updatedAt,
    ...(provider.kind === 'oidc' ? { issuer: provider.issuer, scopes: provider.scopes, trustEmail: provider.trustEmail } : {}),
    ...(provider.kind === 'microsoft' ? { tenant: provider.tenant } : {}),
    ...(provider.kind === 'apple' ? { teamId: provider.teamId, keyId: provider.keyId, bundleIds: provider.bundleIds ?? [] } : {}),
  });
  /** Apple's secret is a key file: one that isn't the ES256 key Apple gives would only fail at the first sign-in. */
  const checkAppleKey = async (c: Context, kind: ProviderKind, fields: { clientSecret?: string | null }): Promise<Response | null> => {
    if (kind !== 'apple' || !fields.clientSecret || (await importAppleKey(fields.clientSecret))) return null;
    return c.json({ error: 'invalid_provider', message: 'clientSecret is not the private key Apple gives for Sign in with Apple (an EC P-256 key in a .p8 file): paste the whole file.' }, 400);
  };
  /** Who made a change, as a `provider.*` event tells it. */
  const changedBy = (caller: { by: string | null; setup: boolean }) => ({ by: caller.by, ...(caller.setup ? { bySetupToken: true } : {}) });
  const providerNotFound = (c: Context) => c.json({ error: 'provider_not_found', message: 'There is no provider with this id.' }, 404);

  app.post('/auth/admin/providers/list', async (c) => {
    const caller = await adminOrSetup(c, 'madauth:providers:read', 'read');
    if ('answer' in caller) return caller.answer;
    // `callbackBase`: a new provider's callback URL is `<callbackBase><id>/callback`, which the admin registers
    // at the provider before adding it.
    return c.json({ providers: (await ctx.methods(c)).providers.map(providerInfo), callbackBase: `${issuer}/auth/providers/` });
  });

  app.post('/auth/admin/providers/add', async (c) => {
    const caller = await adminOrSetup(c, undefined, 'session');
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    const named = parseProviderKind(data);
    if ('error' in named) return c.json(named, 400);
    const { kind, id } = named;
    const fields = parseProviderFields(kind, data, true);
    if ('error' in fields) return c.json(fields, 400);
    const wrongKey = await checkAppleKey(c, kind, fields);
    if (wrongKey) return wrongKey;
    // An issuer that doesn't answer as an OpenID Connect provider would only fail at the first sign-in.
    const found = fields.issuer ? await discover(fields.issuer, config.oidcFetch) : null;
    if (found && 'problem' in found) return c.json({ error: 'invalid_provider', message: `The issuer is no OpenID Connect provider madAuth can use: ${found.problem}.` }, 400);
    // Until an admin saved the methods, every configured one counts as on: they are saved as they are now
    // first, so the new provider stays off until it is switched on.
    if ((await settings.get(METHODS_SETTING)) === undefined) await settings.changeMethods((current) => current, caller.by, (await ctx.methods(c)).settings);
    const added = await providers.add(kind, id, fields, caller.by);
    if ('error' in added && added.error === 'issuer_bound') {
      return c.json({ error: 'invalid_provider', message: `The id "${id}" belongs to the issuer "${added.issuer}", whose users' accounts it has: give this provider another id.` }, 400);
    }
    if ('error' in added) return c.json({ error: added.error, message: `There is a provider "${id}" already: change it with providers/update.` }, 409);
    await ctx.emit('provider.added', { provider: providerInfo(added.provider), ...changedBy(caller) });
    return c.json({ provider: providerInfo(added.provider) });
  });

  app.post('/auth/admin/providers/update', async (c) => {
    const caller = await adminOrSetup(c, undefined, 'session');
    if ('answer' in caller) return caller.answer;
    const { id, ...data } = await body(c);
    const current = (await ctx.methods(c)).providers.find((provider) => provider.id === id);
    if (!current) return providerNotFound(c);
    if (data.kind !== undefined && data.kind !== current.kind) return c.json({ error: 'invalid_provider', message: "A provider's kind can't change: add a new one." }, 400);
    const fields = parseProviderFields(current.kind, data, false);
    if ('error' in fields) return c.json(fields, 400);
    const wrongKey = await checkAppleKey(c, current.kind, fields);
    if (wrongKey) return wrongKey;
    const updated = await providers.update(current.id, fields, caller.by);
    if ('error' in updated) return providerNotFound(c);
    await ctx.emit('provider.changed', { provider: providerInfo(updated.provider), ...changedBy(caller) });
    return c.json({ provider: providerInfo(updated.provider) });
  });

  // Its users' accounts stay, so adding the provider again brings their sign-ins back.
  app.post('/auth/admin/providers/remove', async (c) => {
    const { id, dryRun } = await body(c);
    if (dryRun !== undefined && typeof dryRun !== 'boolean') return c.json({ error: 'invalid_options', message: 'dryRun must be true or false.' }, 400);
    // A dry run only counts, so reading the providers is enough for it; removing takes a fresh sign-in.
    const caller = dryRun ? await adminOrSetup(c, 'madauth:providers:read', 'read') : await adminOrSetup(c, undefined, 'session');
    if ('answer' in caller) return caller.answer;
    const now = await ctx.methods(c);
    const provider = typeof id === 'string' ? now.providers.find((p) => p.id === id) : undefined;
    if (!provider) return providerNotFound(c);
    // Counted before, while the provider still counts: the users who sign in with nothing else that is on.
    const signsIn = signInPredicate(now.configured, now.settings);
    const stranded = await users.countSigningInOnlyWith(provider.id, (method) => method !== provider.id && signsIn(method));
    if (dryRun) return c.json({ provider: providerInfo(provider), usersWithoutSignIn: stranded, dryRun: true });
    const removed = await providers.remove(provider.id, caller.by);
    if ('error' in removed) return providerNotFound(c);
    // Out of the settings too, so a provider added again with the id stays off until it is switched on.
    await settings.changeMethods(
      (methods) => (methods[provider.id] ? Object.fromEntries(Object.entries(methods).filter(([method]) => method !== provider.id)) : null),
      caller.by,
    );
    await ctx.emit('provider.removed', { provider: providerInfo(removed.provider), ...changedBy(caller) });
    return c.json({ provider: providerInfo(removed.provider), usersWithoutSignIn: stranded });
  });

  // --- Admin: the applications that sign in with madAuth as their OpenID Connect provider (see oidc-clients.ts) ---

  /**
   * An admin's change (as {@link admin}) that only a session makes, with a recent sign-in: one whose answer shows a
   * secret. `byKey` is the answer to a request with an API key.
   */
  const adminSessionChange = async (c: Context, byKey: string): ReturnType<typeof admin> => {
    if (c.req.header('authorization') !== undefined) return { answer: c.json({ error: 'forbidden', message: byKey }, 403) };
    const caller = await admin(c);
    if ('answer' in caller) return caller;
    if (!(await signedInUser(c, ctx))?.recent) return { answer: reauthRequired(c) };
    return caller;
  };
  const clientsByKey = "An API key can't change the applications that sign in with madAuth: an admin signs in to do it.";
  const clientNotFound = (c: Context) => c.json({ error: 'client_not_found', message: 'There is no application with this client ID.' }, 404);
  const invalidClient = (c: Context, message: string) => c.json({ error: 'invalid_client', message }, 400);
  const noRsaKey = 'idTokenAlg RS256 needs an RS256 key in the key service: add one to MADAUTH_SIGNING_KEY, or run kms-setup --rs256 (see "RS256 ID tokens" in docs/server.md).';

  app.post('/auth/admin/clients/list', async (c) => {
    const caller = await admin(c, 'madauth:clients:read');
    if ('answer' in caller) return caller.answer;
    return c.json({ clients: (await oidcClients.list()).map(clientInfo) });
  });

  // The secret shows only in this answer: madAuth keeps its SHA-256.
  app.post('/auth/admin/clients/add', async (c) => {
    const caller = await adminSessionChange(c, clientsByKey);
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    if (data.public !== undefined && typeof data.public !== 'boolean') return invalidClient(c, 'public must be true or false.');
    const fields = parseClientFields(data, true);
    if ('error' in fields) return c.json(fields, 400);
    if (fields.idTokenAlg === RSA_SIGNING_ALG && !(await canSign(keys, RSA_SIGNING_ALG))) return invalidClient(c, noRsaKey);
    // A new client's fields always have a name and redirect URIs.
    const added = await oidcClients.add({ ...fields, name: fields.name!, redirectUris: fields.redirectUris! }, data.public === true, caller.email);
    return c.json({ client: clientInfo(added.client), ...(added.secret ? { clientSecret: added.secret } : {}) });
  });

  // `newSecret: true` replaces a confidential client's secret: the old one stops working at once.
  app.post('/auth/admin/clients/update', async (c) => {
    const caller = await adminSessionChange(c, clientsByKey);
    if ('answer' in caller) return caller.answer;
    const { id, newSecret, ...data } = await body(c);
    if (newSecret !== undefined && typeof newSecret !== 'boolean') return invalidClient(c, 'newSecret must be true or false.');
    if (data.public !== undefined) return invalidClient(c, 'Whether a client is public can\'t change: add a new one.');
    const fields = parseClientFields(data, false);
    if ('error' in fields) return c.json(fields, 400);
    if (fields.idTokenAlg === RSA_SIGNING_ALG && !(await canSign(keys, RSA_SIGNING_ALG))) return invalidClient(c, noRsaKey);
    const updated = typeof id === 'string' ? await oidcClients.update(id, fields, newSecret === true, caller.email) : null;
    if (!updated) return clientNotFound(c);
    return c.json({ client: clientInfo(updated.client), ...(updated.secret ? { clientSecret: updated.secret } : {}) });
  });

  // Its refresh tokens end with it; access tokens it has work until they expire (15 minutes).
  app.post('/auth/admin/clients/remove', async (c) => {
    const caller = await adminSessionChange(c, clientsByKey);
    if ('answer' in caller) return caller.answer;
    const { id } = await body(c);
    const removed = typeof id === 'string' ? await oidcClients.remove(id) : null;
    if (!removed) return clientNotFound(c);
    return c.json({ client: clientInfo(removed) });
  });

  // The way back for a user who lost every way in, whatever they had: they sign up again and keep their id.
  // See "Resetting a user's sign-in" in docs/server.md.
  app.post('/auth/admin/sign-in/reset', async (c) => {
    const caller = await adminChange(c, 'madauth:sign-in:reset');
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    if (!isValidEmail(data.email)) return invalidEmail(c);
    const user = await users.findByEmail(normalizeEmail(data.email));
    if (!user) return noUser(c);
    const removed = await users.resetSignIn(user.id);
    // GitHub's and Apple's authorizations go with their accounts, as when the user removes them or deletes the account.
    await Promise.all(removed.map(revokeProviderGrant));
    await ctx.emit('user.sign_in_reset', { user: toMadauthUser(user), by: caller.email, ...byApiKey(caller) });
    return c.json({ email: user.emailNormalized, userId: user.id });
  });

  // Deleting a user for good, as if they never signed up, e.g. a test account or on request.
  // See "Deleting a user" in docs/server.md.
  app.post('/auth/admin/users/delete', async (c) => {
    const caller = await adminChange(c, 'madauth:users:delete');
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    if (!isValidEmail(data.email)) return invalidEmail(c);
    const user = await users.findByEmail(normalizeEmail(data.email));
    if (!user) return noUser(c);
    // No admin is deleted through the admin API: an admin never removes themselves, and a key with the scope
    // can't remove the admins. Another admin takes the role first (claims/set).
    if (user.id === caller.id) {
      return ownAdminRole(c, `You have the role "${ADMIN_ROLE}", so you can't delete yourself: another admin takes the role from you first.`);
    }
    if (isAdmin({ claims: claimsFromJson(user.claims) })) {
      return c.json({ error: 'forbidden', message: `The user has the role "${ADMIN_ROLE}": take it from them first.` }, 403);
    }
    // Only with the claims just checked: a user who got the role meanwhile stays.
    if (!(await deleteUser(user.id, user.claims ?? null))) {
      // Gone: another request deleted the user and sent the event.
      if (!(await users.findById(user.id))) return noUser(c);
      return c.json({ error: 'forbidden', message: "The user's claims changed meanwhile: check them and try again." }, 403);
    }
    await ctx.emit('user.deleted', { user: toMadauthUser(user), by: caller.email, ...byApiKey(caller) });
    return c.json({ email: user.emailNormalized, userId: user.id });
  });

  // A user's API keys, e.g. to revoke one that leaked. Only with a session: a key never manages keys.
  app.post('/auth/admin/api-keys/list', async (c) => {
    const caller = await admin(c);
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    if (!isValidEmail(data.email)) return invalidEmail(c);
    const user = await users.findByEmail(normalizeEmail(data.email));
    if (!user) return noUser(c);
    return c.json({ email: user.emailNormalized, userId: user.id, apiKeys: (await apiKeys.list(user.id)).map(apiKeyInfo) });
  });

  app.post('/auth/admin/api-keys/revoke', async (c) => {
    const caller = await admin(c);
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    if (!isValidEmail(data.email)) return invalidEmail(c);
    const user = await users.findByEmail(normalizeEmail(data.email));
    if (!user) return noUser(c);
    const key = typeof data.id === 'string' ? await apiKeys.revoke(user.id, data.id) : null;
    if (!key) return apiKeyNotFound(c);
    await ctx.emit('user.api_key_revoked', { user: toMadauthUser(user), apiKey: { id: key.id, name: key.name }, by: caller.email });
    return c.json({ email: user.emailNormalized, userId: user.id });
  });

  // A user's sessions, by the user's id (e.g. from users/search). See "Ending a user's sessions" in docs/server.md.
  const userById = async (c: Context, userId: unknown): Promise<StoredUser | Response> => {
    const user = typeof userId === 'string' && userId ? await users.findById(userId) : null;
    return user ?? c.json({ error: 'user_not_found', message: 'No user has this id.' }, 404);
  };

  app.post('/auth/admin/sessions/list', async (c) => {
    const caller = await admin(c, 'madauth:sessions:read');
    if ('answer' in caller) return caller.answer;
    const user = await userById(c, (await body(c)).userId);
    if (user instanceof Response) return user;
    const list = await sessions.list(user.id, user.sessionVersion);
    return c.json({ email: user.emailNormalized, userId: user.id, sessions: list.map((session) => sessionInfo(session, caller.sessionId ?? null)) });
  });

  // `id: "all"` ends every session of the user. Each ends at its next renewal, within SESSION_TTL.
  app.post('/auth/admin/sessions/end', async (c) => {
    const caller = await adminChange(c, 'madauth:sessions:end');
    if ('answer' in caller) return caller.answer;
    const data = await body(c);
    if (typeof data.id !== 'string' || !data.id) return c.json({ error: 'invalid_options', message: 'Pass the id of a session, or "all".' }, 400);
    const user = await userById(c, data.userId);
    if (user instanceof Response) return user;
    const one = data.id === 'all' ? null : await sessions.end(user.id, data.id);
    if (data.id !== 'all' && !one) return sessionNotFound(c);
    const ended = one ? [one] : await sessions.endAll(user.id, user.sessionVersion);
    await ctx.sessionsEnded(user, ended, 'ended', { by: caller.email, ...byApiKey(caller) });
    return c.json({ email: user.emailNormalized, userId: user.id, ended: ended.length });
  });

  return app;
}
