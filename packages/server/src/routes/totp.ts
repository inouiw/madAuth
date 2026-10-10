// The authenticator app (TOTP): setting it up, signing in with it on its own (the e-mail address and a code),
// and the second step of the other methods. The security rules are described in docs/totp-security.md.
import type { Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { JWTPayload } from 'jose';
import type { AppContext } from '../app.js';
import { isValidEmail, normalizeEmail } from '../password.js';
import { METHODS_WITH_SECOND_FACTOR, authenticatorOn, isOn, policyOf, type SignInMethod } from '../settings.js';
import { readToken, signToken } from '../tokens.js';
import {
  TOTP_WINDOW,
  base32Encode,
  decryptSecret,
  encryptSecret,
  generateRecoveryCodes,
  generateTotpSecret,
  hashRecoveryCode,
  normalizeRecoveryCode,
  otpauthUri,
  verifyTotp,
} from '../totp.js';
import { toMadauthUser, totpAccountKey, type StoredAccount, type StoredUser } from '../users.js';
import { localeOf } from '../webhooks.js';
import { MAIL_INTERVAL_MS, createEmails } from './emails.js';
import { accepted, body, error, nameOf, noSession, redirectTarget, unavailable, type Body } from './helpers.js';
import { countSignInAttempt } from './lockout.js';

/** The cookie that carries a sign-in from its first step to the code (or the setup) of the authenticator app. */
export const CHALLENGE_COOKIE = 'madauth_challenge';
export const CHALLENGE_TYP = 'madauth-challenge+jwt';
/** How long the second step may take. */
export const CHALLENGE_TTL = 10 * 60;

const SETUP_COOKIE = 'madauth_totp_setup';
const SETUP_TYP = 'madauth-totp-setup+jwt';
/** How long scanning the QR code and entering the first code may take. */
const SETUP_TTL = 10 * 60;

/** Both cookies are only sent to these routes. */
const COOKIE_PATH = '/auth/totp';

/** What a sign-in still needs after its primary method succeeded: a code from the app, or setting one up. */
export type NextStep = 'totp' | 'totp-setup';

/** The challenge cookie: who passed the first step, how (`amr`, empty for a sign-up with the app), and what comes next. */
export interface Challenge {
  sub: string;
  sv: number;
  amr: string[];
  method: SignInMethod;
  next: NextStep;
}

type ChallengeClaims = Challenge & JWTPayload;
/** The setup cookie: whose setup it is, and the secret as it will be stored (encrypted). */
interface SetupClaims extends JWTPayload {
  sub: string;
  secret: string;
}

/** The keys of the authenticator app: one encrypts the secrets, the other (the e-mail codes' key) hashes the recovery codes. */
export interface TotpKeys {
  totpKey: Buffer;
  codeKey: Buffer;
}

const cookieOptions = (secure: boolean) => ({ path: COOKIE_PATH, httpOnly: true, secure, sameSite: 'Strict' as const });

/** Sets the challenge cookie: the sign-in goes on with the authenticator app within CHALLENGE_TTL. */
export async function setChallenge(c: Context, ctx: AppContext, challenge: Challenge): Promise<void> {
  const token = await signToken(await ctx.keys, ctx.config.issuer, CHALLENGE_TYP, { ...challenge }, CHALLENGE_TTL);
  setCookie(c, CHALLENGE_COOKIE, token, { ...cookieOptions(ctx.secure), maxAge: CHALLENGE_TTL });
}

/** The request's challenge for this step, or null if there is none, it expired, or it waits for another step. */
async function readChallenge(c: Context, ctx: AppContext, next: NextStep): Promise<ChallengeClaims | null> {
  const claims = await readToken<ChallengeClaims>(await ctx.keys, ctx.config.issuer, CHALLENGE_TYP, getCookie(c, CHALLENGE_COOKIE));
  return claims && claims.next === next && typeof claims.sub === 'string' && Array.isArray(claims.amr) ? claims : null;
}

/** How a code was given: from the app, or one of the recovery codes. */
export type CodeVia = 'totp' | 'recovery_code';

/**
 * Checks the code in the request (`code` from the app, or `recoveryCode`) against the user's authenticator
 * account, counting the attempt first (see routes/lockout.ts). Resolves to how it was given, or to the
 * answer to send: `wrong()` for a wrong, used or missing code, 429 when the account is locked.
 */
export async function checkCode(
  c: Context,
  ctx: AppContext,
  keys: TotpKeys,
  user: StoredUser,
  account: StoredAccount,
  data: Body,
  wrong: () => Response = () => error(c, 401, 'code_invalid', 'The code is wrong or was already used.'),
): Promise<CodeVia | Response> {
  const { users } = ctx;
  const refused = await countSignInAttempt(c, users, account);
  if (refused) return refused;

  if (typeof data.recoveryCode === 'string') {
    const code = normalizeRecoveryCode(data.recoveryCode);
    if (!code || !(await users.consumeRecoveryCode(user.id, hashRecoveryCode(keys.codeKey, code)))) return wrong();
    await users.updateAccount(account.id, { failedAttempts: 0, lockedUntil: 0 });
    const remaining = await users.countRecoveryCodes(user.id);
    await ctx.emit('totp.recovery_code_used', { user: toMadauthUser(user), remaining });
    return 'recovery_code';
  }

  if (typeof data.code !== 'string' || !account.secret) return wrong();
  const secret = decryptSecret(keys.totpKey, account.secret);
  if (!secret) {
    console.error(`[madauth] The authenticator secret of user ${user.id} can't be read: was MADAUTH_SIGNING_KEY changed?`);
    return wrong();
  }
  const step = verifyTotp(secret, data.code, Date.now(), TOTP_WINDOW);
  // A code works once: it must be later than the last accepted one, and the write decides between
  // requests sent at the same time.
  if (step === null || step <= (account.lastUsedStep ?? 0) || !(await users.useTotpStep(account, step))) return wrong();
  return 'totp';
}

export function totpRoutes(app: Hono, ctx: AppContext, keys: TotpKeys): void {
  const { config, secure, users } = ctx;
  const { issuer } = config;
  const cookie = cookieOptions(secure);
  const methodsNow = () => ctx.settings.methods();

  // Every route: an admin switched the authenticator app off, on its own and as a second factor.
  app.use(`${COOKIE_PATH}/*`, async (c, next) => {
    if (!authenticatorOn(ctx.configured, await methodsNow())) {
      return error(c, 403, 'method_disabled', 'The authenticator app is switched off.');
    }
    await next();
  });

  /** Whether the app signs in on its own (the e-mail address and a code), as opposed to a second step only. */
  const standalone = async () => isOn('totp', ctx.configured, await methodsNow());
  const notStandalone = (c: Context) => error(c, 403, 'method_disabled', 'Signing in with the authenticator app alone is switched off.');

  /** The stored user of the request's session, or null. */
  const signedIn = async (c: Context): Promise<StoredUser | null> => {
    const user = await ctx.currentUser(c);
    return user ? users.findById(user.id) : null;
  };

  /**
   * Who sets the app up: the signed-in user, or the one whose sign-in waits for the setup (the challenge).
   * A challenge from before a password reset no longer counts.
   */
  const whoSetsUp = async (c: Context): Promise<{ user: StoredUser; challenge: ChallengeClaims | null } | null> => {
    const user = await signedIn(c);
    if (user) return { user, challenge: null };
    const challenge = await readChallenge(c, ctx, 'totp-setup');
    const waiting = challenge ? await users.findById(challenge.sub) : null;
    return challenge && waiting && waiting.sessionVersion === challenge.sv ? { user: waiting, challenge } : null;
  };

  /** The name the app shows next to the account: TOTP_ISSUER, or the host of the app that asked. */
  const issuerLabel = (c: Context): string => {
    if (config.totpIssuer) return config.totpIssuer;
    const origin = c.req.header('origin');
    return URL.canParse(origin ?? '') ? new URL(origin!).hostname : new URL(issuer).hostname;
  };

  /** Finishes a sign-in whose second step is done: the session, with the app in `amr`. */
  const finishSignIn = async (c: Context, user: StoredUser, challenge: ChallengeClaims, via: CodeVia) => {
    deleteCookie(c, CHALLENGE_COOKIE, cookie);
    const result = await ctx.startSession(c, toMadauthUser(user), [...challenge.amr, 'otp'], { sv: user.sessionVersion });
    // For a sign-up with the app, the app is the method itself, not a second factor.
    await ctx.emit('user.signed_in', { user: result, method: challenge.method, ...(challenge.amr.length ? { secondFactor: via } : {}) });
    return result;
  };

  app.post(`${COOKIE_PATH}/setup`, async (c) => {
    const who = await whoSetsUp(c);
    if (!who) return noSession(c);
    const secret = generateTotpSecret();
    const token = await signToken(await ctx.keys, issuer, SETUP_TYP, { sub: who.user.id, secret: encryptSecret(keys.totpKey, secret) }, SETUP_TTL);
    setCookie(c, SETUP_COOKIE, token, { ...cookie, maxAge: SETUP_TTL });
    // Nothing is stored until the first code proves that the app has the secret.
    return c.json({ secret: base32Encode(secret), uri: otpauthUri({ issuer: issuerLabel(c), account: who.user.email, secret }) });
  });

  app.post(`${COOKIE_PATH}/confirm`, async (c) => {
    const who = await whoSetsUp(c);
    if (!who) return noSession(c);
    const { user, challenge } = who;
    const data = await body(c);
    const setup = await readToken<SetupClaims>(await ctx.keys, issuer, SETUP_TYP, getCookie(c, SETUP_COOKIE));
    const secret = setup && setup.sub === user.id && typeof setup.secret === 'string' ? decryptSecret(keys.totpKey, setup.secret) : null;
    if (!setup || !secret) return error(c, 400, 'setup_expired', 'The setup has expired or was started in another browser. Please start again.');
    const step = typeof data.code === 'string' ? verifyTotp(secret, data.code, Date.now(), TOTP_WINDOW) : null;
    // The setup cookie stays, so a mistyped code can be tried again.
    if (step === null) return error(c, 400, 'code_invalid', 'The code is wrong. Enter the current code from the app.');

    // A new app replaces an earlier one, and starts without failed attempts; the code just used can't sign in.
    const patch = { secret: setup.secret, failedAttempts: 0, lockedUntil: 0, lastUsedStep: step };
    const existing = await users.totpAccount(user.id);
    if (!existing || !(await users.updateAccount(existing.id, patch))) {
      if (!(await users.linkAccount(user.id, { key: totpAccountKey(user.id), ...patch }))) {
        // Set up in two places at once: the other one just won, and this app replaces it.
        const other = await users.totpAccount(user.id);
        if (other) await users.updateAccount(other.id, patch);
      }
    }
    const recoveryCodes = generateRecoveryCodes();
    await users.replaceRecoveryCodes(
      user.id,
      recoveryCodes.map((code) => hashRecoveryCode(keys.codeKey, normalizeRecoveryCode(code)!)),
    );
    deleteCookie(c, SETUP_COOKIE, cookie);
    await ctx.emit('totp.enabled', { user: toMadauthUser(user) });
    if (!challenge) return c.json({ recoveryCodes });
    const result = await finishSignIn(c, user, challenge, 'totp');
    return c.json({ user: result, recoveryCodes });
  });

  app.post(`${COOKIE_PATH}/verify`, async (c) => {
    const expired = () => error(c, 401, 'challenge_expired', 'The sign-in has expired. Please sign in again.');
    const challenge = await readChallenge(c, ctx, 'totp');
    if (!challenge) return expired();
    const user = await users.findById(challenge.sub);
    // The user is gone, a password reset ended their sessions meanwhile, or the app was removed.
    const account = user && user.sessionVersion === challenge.sv ? await users.totpAccount(user.id) : null;
    if (!user || !account) return expired();
    const via = await checkCode(c, ctx, keys, user, account, await body(c));
    if (via instanceof Response) return via;
    return c.json({ user: await finishSignIn(c, user, challenge, via) });
  });

  app.post(`${COOKIE_PATH}/signin`, async (c) => {
    if (!(await standalone())) return notStandalone(c);
    const data = await body(c);
    const wrong = () => error(c, 401, 'invalid_credentials', 'E-mail or code is wrong.');
    if (!isValidEmail(data.email)) return wrong();
    const user = await users.findByEmail(normalizeEmail(data.email));
    const account = user ? await users.totpAccount(user.id) : null;
    // An unknown address, one without an app, one nobody confirmed, or a wrong code: all the same answer.
    if (!user || !user.emailVerified || !account?.secret) return wrong();
    const via = await checkCode(c, ctx, keys, user, account, data, wrong);
    if (via instanceof Response) return via;
    const result = await ctx.startSession(c, toMadauthUser(user), ['otp'], { sv: user.sessionVersion });
    await ctx.emit('user.signed_in', { user: result, method: 'totp' });
    return c.json({ user: result });
  });

  app.post(`${COOKIE_PATH}/remove`, async (c) => {
    const user = await signedIn(c);
    if (!user) return noSession(c);
    const methods = await methodsNow();
    const required = METHODS_WITH_SECOND_FACTOR.filter((method) => isOn(method, ctx.configured, methods) && policyOf(method, methods) === 'required');
    if (required.length) {
      const names = required.map((method) => (method === 'google' ? 'Google' : 'e-mail & password'));
      return error(c, 403, 'required_by_policy', `Signing in with ${names.join(' and ')} requires the authenticator app, so it can't be removed.`);
    }
    const account = await users.totpAccount(user.id);
    if (!account) return c.json({});
    // Removing the app takes a current code: a stolen session alone can't switch the protection off.
    const via = await checkCode(c, ctx, keys, user, account, await body(c));
    if (via instanceof Response) return via;
    await users.unlinkAccount(totpAccountKey(user.id));
    await users.clearRecoveryCodes(user.id);
    await ctx.emit('totp.disabled', { user: toMadauthUser(user) });
    return c.json({});
  });

  app.post(`${COOKIE_PATH}/recovery-codes`, async (c) => {
    const user = await signedIn(c);
    if (!user) return noSession(c);
    const account = await users.totpAccount(user.id);
    if (!account) return error(c, 400, 'no_authenticator', 'No authenticator app is set up.');
    const via = await checkCode(c, ctx, keys, user, account, await body(c));
    if (via instanceof Response) return via;
    const recoveryCodes = generateRecoveryCodes();
    await users.replaceRecoveryCodes(
      user.id,
      recoveryCodes.map((code) => hashRecoveryCode(keys.codeKey, normalizeRecoveryCode(code)!)),
    );
    return c.json({ recoveryCodes });
  });

  app.get(`${COOKIE_PATH}/status`, async (c) => {
    const user = await signedIn(c);
    if (!user) return noSession(c);
    const account = await users.totpAccount(user.id);
    return c.json({ enabled: !!account, recoveryCodesLeft: account ? await users.countRecoveryCodes(user.id) : 0 });
  });

  // --- Sign-up with the app alone: the address is confirmed by e-mail, then the app is set up ---

  if (ctx.webhook && ctx.emailVerification) {
    const emails = createEmails(ctx, users, ctx.webhook);

    app.post(`${COOKIE_PATH}/signup`, async (c) => {
      if (!(await standalone())) return notStandalone(c);
      const data = await body(c);
      const target = redirectTarget(ctx, c, data.redirectTo);
      if (target instanceof Response) return target;
      if (!isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
      const name = nameOf(data.name);
      const email = data.email.trim();
      const locale = localeOf(data.locale);

      const check = await ctx.checkSignup({ email, name: name ?? undefined, locale, method: 'totp' });
      if (!check.ok) return check.reason === 'rejected' ? error(c, 403, 'signup_rejected', check.message) : unavailable(c);

      const existing = await users.findByEmail(normalizeEmail(email));
      if (existing?.emailVerified && (await users.hasAccounts(existing.id))) {
        return (await emails.sendAccountEmail(existing, 'email.already_registered', target, locale)) ? accepted(c) : unavailable(c);
      }
      if (existing) {
        // Nobody has proven this address yet, or nobody can sign in with it: the sign-up starts afresh.
        if (Date.now() - existing.lastMailAt < MAIL_INTERVAL_MS) return accepted(c);
        await users.updateUser(existing.id, { name });
        return (await emails.sendLinkEmail({ ...existing, name }, 'verify', target, locale)) ? accepted(c) : unavailable(c);
      }

      // Without an account: the app is set up once the address is confirmed.
      const user = await users.createUser({ email, emailNormalized: normalizeEmail(email), name, emailVerified: false });
      if (!user) return accepted(c);
      await ctx.emit('user.created', { user: toMadauthUser(user), method: 'totp' });
      return (await emails.sendLinkEmail(user, 'verify', target, locale)) ? accepted(c) : unavailable(c);
    });
  }
}
