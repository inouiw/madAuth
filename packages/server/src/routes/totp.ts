// The authenticator app (TOTP): setting it up, signing in with it on its own (the e-mail address and a code),
// and the second step of the other methods. The security rules are described in docs/totp-security.md.
import type { Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { JWTPayload } from 'jose';
import type { AppContext } from '../app.js';
import { isValidEmail, normalizeEmail } from '../password.js';
import { isMethodId, isOn, signsIn } from '../settings.js';
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
import { newId, toMadauthUser, totpAccountKey, type StoredAccount, type StoredUser } from '../users.js';
import { localeOf } from '../webhooks.js';
import { finishSignIn, methodOff, methodStillOn, pendingOrSignedIn, readChallenge, requiredByPolicy } from './challenge.js';
import { MAIL_INTERVAL_MS, createEmails } from './emails.js';
import { accepted, body, error, nameOf, noSession, originHost, redirectTarget, unavailable, type Body } from './helpers.js';
import { countSignInAttempt } from './lockout.js';

export { CHALLENGE_COOKIE, CHALLENGE_TTL, CHALLENGE_TYP, clearChallenge, setChallenge, type Challenge, type NextStep } from './challenge.js';

const SETUP_COOKIE = 'madauth_totp_setup';
const SETUP_TYP = 'madauth-totp-setup+jwt';
/** How long scanning the QR code and entering the first code may take. */
const SETUP_TTL = 10 * 60;

/** The routes, and where the setup cookie is sent. */
const COOKIE_PATH = '/auth/totp';

/**
 * The setup cookie: whose setup it is (`sub`), its id, the secret as it will be stored (encrypted), the id of
 * the setup the account had when this one started (`replaces`; absent without an account, null for one
 * without a setup id), and, when it replaces an app, when the current app agreed (a code): the approval
 * holds for SETUP_TTL, also for a setup started again.
 */
interface SetupClaims extends JWTPayload {
  sub: string;
  setup: string;
  secret: string;
  replaces?: string | null;
  approved?: number;
}

/** The keys of the authenticator app: one encrypts the secrets, the other (the e-mail codes' key) hashes the recovery codes. */
export interface TotpKeys {
  totpKey: Buffer;
  codeKey: Buffer;
}

const cookieOptions = (secure: boolean) => ({ path: COOKIE_PATH, httpOnly: true, secure, sameSite: 'Strict' as const });

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
    if (!code || !(await users.consumeRecoveryCode(account, hashRecoveryCode(keys.codeKey, code)))) return wrong();
    await users.updateAccount(account.id, { failedAttempts: 0, lockedUntil: 0 });
    const remaining = await users.countRecoveryCodes(account);
    await ctx.emit('user.recovery_code_used', { user: toMadauthUser(user), remaining });
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
  const methodsNow = (c: Context) => ctx.methods(c);

  // Every route: an admin switched the authenticator app off, on its own and as a second factor.
  app.use(`${COOKIE_PATH}/*`, async (c, next) => {
    if (!isOn('totp', ctx.configured, await methodsNow(c))) {
      return error(c, 403, 'method_disabled', 'The authenticator app is switched off.');
    }
    await next();
  });

  /** Whether the app signs in on its own (the e-mail address and a code), as opposed to a second step only. */
  const standalone = async (c: Context) => signsIn('totp', ctx.configured, await methodsNow(c));
  const notStandalone = (c: Context) => error(c, 403, 'method_disabled', 'Signing in with the authenticator app alone is switched off.');

  /** The stored user of the request's session, or null. */
  const signedIn = async (c: Context): Promise<StoredUser | null> => {
    const user = await ctx.currentUser(c);
    return user ? users.findById(user.id) : null;
  };

  /** Who sets the app up: the user whose sign-in waits for the setup, else the signed-in user (see challenge.ts). */
  const whoSetsUp = (c: Context) => pendingOrSignedIn(c, ctx, 'totp');

  /** New recovery codes, with what is stored for them. */
  const newRecoveryCodes = () => {
    const recoveryCodes = generateRecoveryCodes();
    return { recoveryCodes, hashes: recoveryCodes.map((code) => hashRecoveryCode(keys.codeKey, normalizeRecoveryCode(code)!)) };
  };

  /** The name the app shows next to the account: TOTP_ISSUER, or the host of the app that asked. */
  const issuerLabel = (c: Context): string => config.totpIssuer || originHost(ctx, c);

  app.post(`${COOKIE_PATH}/setup`, async (c) => {
    const who = await whoSetsUp(c);
    if (!who) return noSession(c);
    if (who.challenge && !(await methodStillOn(c, ctx, who.challenge))) return methodOff(c);
    // Replacing an app takes a current code from it (or a recovery code), like removing it: a stolen
    // session alone must not swap the app and the recovery codes for the thief's. The approval holds for
    // SETUP_TTL in the setup cookie, so starting again (or a closed dialog) costs no second code.
    const existing = await users.totpAccount(who.user.id);
    let approved: number | undefined;
    if (existing) {
      const previous = await readToken<SetupClaims>(await ctx.keys, issuer, SETUP_TYP, getCookie(c, SETUP_COOKIE));
      const holds = previous?.sub === who.user.id && typeof previous.approved === 'number' && Date.now() - previous.approved < SETUP_TTL * 1000;
      if (holds) {
        approved = previous.approved;
      } else {
        const data = await body(c);
        if (data.code === undefined && data.recoveryCode === undefined) {
          return error(c, 401, 'code_required', 'Enter a code from your current authenticator app (or a recovery code) to replace it.');
        }
        const via = await checkCode(c, ctx, keys, who.user, existing, data);
        if (via instanceof Response) return via;
        approved = Date.now();
      }
    }
    const secret = generateTotpSecret();
    const claims = {
      sub: who.user.id,
      setup: newId('tsu'),
      secret: encryptSecret(keys.totpKey, secret),
      ...(existing ? { replaces: existing.setupId } : {}),
      ...(approved ? { approved } : {}),
    };
    const token = await signToken(await ctx.keys, issuer, SETUP_TYP, claims, SETUP_TTL);
    setCookie(c, SETUP_COOKIE, token, { ...cookie, maxAge: SETUP_TTL });
    // Nothing is stored until the first code proves that the app has the secret.
    return c.json({ secret: base32Encode(secret), uri: otpauthUri({ issuer: issuerLabel(c), account: who.user.email, secret }) });
  });

  app.post(`${COOKIE_PATH}/confirm`, async (c) => {
    const who = await whoSetsUp(c);
    if (!who) return noSession(c);
    const { challenge } = who;
    let { user } = who;
    if (challenge && !(await methodStillOn(c, ctx, challenge))) return methodOff(c);
    const data = await body(c);
    const setup = await readToken<SetupClaims>(await ctx.keys, issuer, SETUP_TYP, getCookie(c, SETUP_COOKIE));
    const secret =
      setup && setup.sub === user.id && typeof setup.secret === 'string' && typeof setup.setup === 'string' ? decryptSecret(keys.totpKey, setup.secret) : null;
    if (!setup || !secret) return error(c, 400, 'setup_expired', 'The setup has expired or was started in another browser. Please start again.');
    const step = typeof data.code === 'string' ? verifyTotp(secret, data.code, Date.now(), TOTP_WINDOW) : null;
    // The setup cookie stays, so a mistyped code can be tried again.
    if (step === null) return error(c, 400, 'code_invalid', 'The code is wrong. Enter the current code from the app.');

    // The app and its recovery codes always belong together: the codes are written first, under this
    // setup's id, and the secret only if the account still has the setup it had when this one started.
    // Of two setups confirmed at once, exactly one wins; the other drops its codes and starts again. A new
    // app starts without failed attempts, and the code just used can't sign in.
    // A sign-up with the app sets up the account the user signs up with; every other setup adds the app to a
    // user who has a method already. If a sign-up got another method meanwhile, the sign-up's app is refused.
    const signUp = challenge?.method === 'totp';
    // The challenge of a sign-up with the app comes from a used confirmation link. A password sign-up for the
    // address meanwhile took the confirmation back until its own e-mail is used; nobody has, so the app wins
    // and the password goes, as for any unconfirmed sign-up.
    // Read again: a password confirmed by its own e-mail meanwhile stays.
    const fresh = signUp && !user.emailVerified ? await users.findById(user.id) : null;
    if (fresh && !fresh.emailVerified) {
      await users.verifyByProvider(fresh);
      user = { ...user, emailVerified: true, wrongCodes: 0 };
    }
    const { recoveryCodes, hashes } = newRecoveryCodes();
    await users.addRecoveryCodes(user.id, setup.setup, hashes);
    const patch = { secret: setup.secret, setupId: setup.setup, failedAttempts: 0, lockedUntil: 0, lastUsedStep: step };
    const replaced = setup.replaces === undefined ? null : await users.totpApp(user.id);
    const current = replaced?.account ?? null;
    const written =
      setup.replaces === undefined
        ? !!(await users.linkAccount(user.id, { key: totpAccountKey(user.id), primary: signUp, ...patch }))
        : !!current && (await users.confirmTotpSetup(current.id, setup.replaces, patch));
    if (!written) {
      await users.clearRecoveryCodes(user.id, { only: setup.setup });
      deleteCookie(c, SETUP_COOKIE, cookie);
      return error(c, 400, 'setup_expired', 'Your authenticator app was set up or removed elsewhere meanwhile. Please start again.');
    }
    await users.clearRecoveryCodes(user.id, { except: setup.setup });
    deleteCookie(c, SETUP_COOKIE, cookie);
    // A new or replaced app is told; the app a user signed up with is part of their sign-up (`user.signed_up`).
    const secondFactor = replaced ? !replaced.signedUpWith : !signUp;
    if (secondFactor) await ctx.emit('user.second_factor_enabled', { user: toMadauthUser(user), method: 'totp' });
    if (!challenge) return c.json({ recoveryCodes });
    const result = await finishSignIn(c, ctx, user, challenge, 'otp', 'totp');
    return c.json({ user: result, recoveryCodes });
  });

  app.post(`${COOKIE_PATH}/verify`, async (c) => {
    const expired = () => error(c, 401, 'challenge_expired', 'The sign-in has expired. Please sign in again.');
    const challenge = await readChallenge(c, ctx, 'totp');
    if (!challenge) return expired();
    if (!(await methodStillOn(c, ctx, challenge))) return methodOff(c);
    const user = await users.findById(challenge.sub);
    // The user is gone, a password reset ended their sessions meanwhile, or the app was removed.
    const account = user && user.sessionVersion === challenge.sv ? await users.totpAccount(user.id) : null;
    if (!user || !account) return expired();
    const via = await checkCode(c, ctx, keys, user, account, await body(c));
    if (via instanceof Response) return via;
    return c.json({ user: await finishSignIn(c, ctx, user, challenge, 'otp', via) });
  });

  app.post(`${COOKIE_PATH}/signin`, async (c) => {
    if (!(await standalone(c))) return notStandalone(c);
    const data = await body(c);
    const wrong = () => error(c, 401, 'invalid_credentials', 'E-mail or code is wrong.');
    if (!isValidEmail(data.email)) return wrong();
    const user = await users.findByEmail(normalizeEmail(data.email));
    const account = user ? await users.totpAccount(user.id) : null;
    // An unknown address, one without an app, one nobody confirmed, or a wrong code: all the same answer. With
    // the app allowed as a sign-in method, every user who has one signs in with it alone: the admin's decision.
    if (!user || !user.emailVerified || !account?.secret) return wrong();
    const via = await checkCode(c, ctx, keys, user, account, data, wrong);
    if (via instanceof Response) return via;
    const result = await ctx.startSession(c, toMadauthUser(user), ['otp'], { method: 'totp', signedUpAt: user.signedUpAt }, { sv: user.sessionVersion });
    await ctx.emit('user.signed_in', { user: result, method: 'totp' });
    return c.json({ user: result });
  });

  app.post(`${COOKIE_PATH}/remove`, async (c) => {
    const user = await signedIn(c);
    if (!user) return noSession(c);
    const methods = await methodsNow(c);
    // Another second factor (a passkey, a phone) satisfies the policy as well: with one, the app may go.
    const required = await requiredByPolicy(c, ctx, user.id, 'totp', 'the authenticator app');
    if (required) return required;
    const account = await users.totpAccount(user.id);
    if (!account) return c.json({});
    // Without the app, nobody could sign in as the user: it is the last of their methods that signs in.
    if (await users.isLastWayIn(user.id, (m) => isMethodId(m) && signsIn(m, ctx.configured, methods), (a) => a.id === account.id)) {
      return error(c, 403, 'only_method', 'The authenticator app is the only way you sign in, so it can\'t be removed. Add another way to sign in first, or delete your account.');
    }
    // Removing the app takes a current code: a stolen session alone can't switch the protection off.
    const via = await checkCode(c, ctx, keys, user, account, await body(c));
    if (via instanceof Response) return via;
    await users.removeTotp(user.id);
    await ctx.emit('user.second_factor_disabled', { user: toMadauthUser(user), method: 'totp' });
    return c.json({});
  });

  app.post(`${COOKIE_PATH}/recovery-codes`, async (c) => {
    const user = await signedIn(c);
    if (!user) return noSession(c);
    const account = await users.totpAccount(user.id);
    if (!account) return error(c, 400, 'no_authenticator', 'No authenticator app is set up.');
    const via = await checkCode(c, ctx, keys, user, account, await body(c));
    if (via instanceof Response) return via;
    const { recoveryCodes, hashes } = newRecoveryCodes();
    await users.replaceRecoveryCodes(account, hashes);
    return c.json({ recoveryCodes });
  });

  app.get(`${COOKIE_PATH}/status`, async (c) => {
    const user = await signedIn(c);
    if (!user) return noSession(c);
    const account = await users.totpAccount(user.id);
    return c.json({ enabled: !!account, recoveryCodesLeft: account ? await users.countRecoveryCodes(account) : 0 });
  });

  // --- Sign-up with the app alone: the address is confirmed by e-mail, then the app is set up ---

  if (ctx.webhook && ctx.emailVerification) {
    const emails = createEmails(ctx, users, ctx.webhook);

    app.post(`${COOKIE_PATH}/signup`, async (c) => {
      if (!(await standalone(c))) return notStandalone(c);
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
      if (existing?.emailVerified && (await users.hasSignInMethod(existing.id))) {
        return (await emails.sendAccountEmail(existing, 'email.send_already_registered', target, locale)) ? accepted(c) : unavailable(c);
      }
      if (existing) {
        // Nobody has proven this address yet, or nobody can sign in with it: the sign-up starts afresh. A
        // password or an e-mail link an earlier, unconfirmed sign-up set (perhaps by someone else) goes with it.
        if (Date.now() - existing.lastMailAt < MAIL_INTERVAL_MS) return accepted(c);
        if (!existing.emailVerified) await users.dropUnprovenAccounts(existing.id);
        await users.reopenSignUp(existing);
        await users.updateUser(existing.id, { name });
        return (await emails.sendLinkEmail({ ...existing, name }, 'verify', target, locale)) ? accepted(c) : unavailable(c);
      }

      // Without an account: the app is set up once the address is confirmed.
      const user = await users.createUser({ email, emailNormalized: normalizeEmail(email), name, emailVerified: false });
      if (!user) return accepted(c);
      return (await emails.sendLinkEmail(user, 'verify', target, locale)) ? accepted(c) : unavailable(c);
    });
  }
}
