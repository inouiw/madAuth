// SMS codes as a second factor: a signed-in user adds a phone number and confirms it with a code; from then
// on the sign-in methods whose policy asks for a second factor can ask for a code sent to it, next to the
// authenticator app. The security rules are described in docs/sms-security.md.
import type { Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { JWTPayload } from 'jose';
import type { AppContext } from '../app.js';
import { METHODS_WITH_SECOND_FACTOR, isOn, policyOf } from '../settings.js';
import { readToken, signToken } from '../tokens.js';
import { smsAccountKey, toMadauthUser, type StoredAccount, type StoredUser, type Users } from '../users.js';
import { WEBHOOK_TIMEOUT_MS, localeOf, type WebhookClient } from '../webhooks.js';
import { finishSignIn, methodOff, methodStillOn, pendingOrSignedIn, readChallenge, type ChallengeClaims } from './challenge.js';
import { MAIL_INTERVAL_MS as SMS_INTERVAL_MS } from './emails.js';
import { body, error, noSession, originHost, smsUnavailable, type Body } from './helpers.js';
import { countSignInAttempt } from './lockout.js';

/** How long a code sent by SMS works. */
export const SMS_TTL_MS = 10 * 60 * 1000;

const SETUP_COOKIE = 'madauth_sms_setup';
const SETUP_TYP = 'madauth-sms-setup+jwt';
/** How long entering the code that confirms a new number may take. */
const SETUP_TTL = 10 * 60;

/** The routes, and where the setup cookie is sent. */
const ROUTE_PATH = '/auth/sms';

/** What an SMS is for: confirming a new number, the second step of a sign-in, or approving a change to the number. */
export type SmsPurpose = 'setup' | 'signin' | 'approve';

/**
 * The setup cookie: whose setup it is, the number being confirmed, and, when it replaces a number, when the
 * current number agreed (a code sent to it): the approval holds for SETUP_TTL, also for a setup started again.
 */
interface SetupClaims extends JWTPayload {
  sub: string;
  phone: string;
  approved?: number;
}

/** A phone number in E.164 form (`+41791234567`), from what was typed; null if it is not one. */
export function normalizePhone(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const digits = value.replace(/[\s().-]/g, '');
  return /^\+[1-9]\d{6,14}$/.test(digits) ? digits : null;
}

/** The number as it is shown: the beginning and the last two digits, e.g. `+41 ••••••• 67`. */
export function maskPhone(phone: string): string {
  return `${phone.slice(0, 3)} ${'•'.repeat(Math.max(0, phone.length - 5))} ${phone.slice(-2)}`;
}

export function smsRoutes(app: Hono, ctx: AppContext, users: Users, webhook: WebhookClient): void {
  const { config, secure } = ctx;
  const cookie = { path: ROUTE_PATH, httpOnly: true, secure, sameSite: 'Strict' as const };

  // Every route: an admin switched SMS codes off.
  app.use(`${ROUTE_PATH}/*`, async (c, next) => {
    if (!isOn('sms', ctx.configured, await ctx.methods(c))) return error(c, 403, 'method_disabled', 'SMS codes are switched off.');
    await next();
  });

  const expired = (c: Context) => error(c, 401, 'challenge_expired', 'The sign-in has expired. Please sign in again.');
  const tooSoon = (c: Context) =>
    error(c, 429, 'too_soon', 'A code was sent to your phone less than a minute ago: enter that one, or wait a minute for a new one.');

  /** Issues a code and hands the SMS to the webhook. Resolves to false if the webhook did not take it over. */
  const sendCode = async (c: Context, user: StoredUser, phone: string, purpose: SmsPurpose, locale: string | undefined): Promise<boolean> => {
    const { code } = await users.issueVerification(user.id, 'sms', SMS_TTL_MS);
    const data = { to: phone, code, purpose, expiresAt: Date.now() + SMS_TTL_MS, site: originHost(ctx, c), locale, user: { id: user.id, name: user.name ?? undefined } };
    const result = await webhook.call('sms.code', data, WEBHOOK_TIMEOUT_MS);
    if (!result.ok) {
      console.error(`[madauth] Webhook "sms.code" for user ${user.id} failed: ${result.reason}`);
      return false;
    }
    // Only now: after a failure the user can try again right away.
    await users.updateUser(user.id, { lastSmsAt: Date.now() });
    return true;
  };

  /** At most one SMS per minute, counted apart from the e-mails: the link of a sign-in and the SMS of its second step may follow each other at once. */
  const sentRecently = (user: StoredUser) => Date.now() - (user.lastSmsAt ?? 0) < SMS_INTERVAL_MS;

  /**
   * Checks the code in the request against the user's current SMS code, counting the attempt on their sms
   * account first (see routes/lockout.ts) when they have one. Resolves to null when it is right, else to
   * the answer to send.
   */
  const checkCode = async (c: Context, user: StoredUser, account: StoredAccount | null, data: Body): Promise<Response | null> => {
    if (account) {
      const refused = await countSignInAttempt(c, users, account);
      if (refused) return refused;
    }
    const code = typeof data.code === 'string' ? data.code.replace(/\s/g, '') : '';
    const { userId } = code ? await users.consumeCode(user, 'sms', code) : { userId: null };
    if (!userId) return error(c, 401, 'code_invalid', 'The code is wrong or has expired.');
    if (account) await users.updateAccount(account.id, { failedAttempts: 0, lockedUntil: 0 });
    return null;
  };

  /**
   * Who sets a phone up: the user whose sign-in waits for a second factor (the challenge), else the signed-in
   * user. A sign-up with the app alone has no first factor yet: it sets the app up, not a phone, so SMS
   * codes are never the only factor.
   */
  const whoSetsUp = async (c: Context): Promise<{ user: StoredUser; challenge: ChallengeClaims | null } | { answer: Response }> => {
    const who = await pendingOrSignedIn(c, ctx);
    if (!who || (who.challenge && !who.challenge.amr.length)) return { answer: noSession(c) };
    if (who.challenge && !(await methodStillOn(c, ctx, who.challenge))) return { answer: methodOff(c) };
    return who;
  };

  app.post(`${ROUTE_PATH}/setup`, async (c) => {
    const who = await whoSetsUp(c);
    if ('answer' in who) return who.answer;
    const { user } = who;
    const data = await body(c);
    const phone = normalizePhone(data.phone);
    if (!phone) return error(c, 400, 'invalid_phone', 'Enter a mobile number with the country code, e.g. +41 79 123 45 67.');
    // Replacing a number takes a code sent to the current one (see `send`), like removing it: a stolen
    // session alone must not swap the number for the thief's. The approval holds for SETUP_TTL in the setup
    // cookie, so a code sent again (or a mistyped number) costs no second approval.
    const existing = await users.smsAccount(user.id);
    let approved: number | undefined;
    if (existing) {
      const previous = await readToken<SetupClaims>(await ctx.keys, config.issuer, SETUP_TYP, getCookie(c, SETUP_COOKIE));
      const holds = previous?.sub === user.id && typeof previous.approved === 'number' && Date.now() - previous.approved < SETUP_TTL * 1000;
      if (holds) {
        approved = previous.approved;
      } else {
        if (data.code === undefined) return error(c, 401, 'code_required', 'Enter the code we sent to your current number to replace it.');
        const wrong = await checkCode(c, user, existing, data);
        if (wrong) return wrong;
        approved = Date.now();
      }
    }
    // The code to the current number was just sent: the one to the new number may follow at once.
    if (approved !== Date.now() && sentRecently(user)) return tooSoon(c);
    if (!(await sendCode(c, user, phone, 'setup', localeOf(data.locale)))) return smsUnavailable(c);
    const token = await signToken(await ctx.keys, config.issuer, SETUP_TYP, { sub: user.id, phone, ...(approved ? { approved } : {}) }, SETUP_TTL);
    setCookie(c, SETUP_COOKIE, token, { ...cookie, maxAge: SETUP_TTL });
    // Nothing is stored until the code proves that the number receives the SMS.
    return c.json({ phone: maskPhone(phone) }, 202);
  });

  app.post(`${ROUTE_PATH}/confirm`, async (c) => {
    const who = await whoSetsUp(c);
    if ('answer' in who) return who.answer;
    const { user, challenge } = who;
    const setup = await readToken<SetupClaims>(await ctx.keys, config.issuer, SETUP_TYP, getCookie(c, SETUP_COOKIE));
    if (!setup || setup.sub !== user.id || typeof setup.phone !== 'string') {
      return error(c, 400, 'setup_expired', 'The setup has expired or was started in another browser. Please start again.');
    }
    const existing = await users.smsAccount(user.id);
    // The setup cookie stays, so a mistyped code can be tried again; the code's attempts are limited.
    const wrong = await checkCode(c, user, existing, await body(c));
    if (wrong) return wrong;
    const written = existing
      ? await users.updateAccount(existing.id, { phone: setup.phone, failedAttempts: 0, lockedUntil: 0 })
      : !!(await users.linkAccount(user.id, { key: smsAccountKey(user.id), phone: setup.phone }));
    deleteCookie(c, SETUP_COOKIE, cookie);
    if (!written) return error(c, 400, 'setup_expired', 'Your phone number was changed elsewhere meanwhile. Please start again.');
    await ctx.emit('sms.enabled', { user: toMadauthUser(user), phone: setup.phone });
    if (!challenge) return c.json({});
    return c.json({ user: await finishSignIn(c, ctx, user, challenge, 'sms', 'sms') });
  });

  app.post(`${ROUTE_PATH}/send`, async (c) => {
    const data = await body(c);
    // The second step of a sign-in, or the signed-in user approving a change to their number.
    const challenge = await readChallenge(c, ctx, 'sms');
    let user: StoredUser | null;
    if (challenge) {
      if (!(await methodStillOn(c, ctx, challenge))) return methodOff(c);
      const waiting = await users.findById(challenge.sub);
      user = waiting && waiting.sessionVersion === challenge.sv ? waiting : null;
      if (!user) return expired(c);
    } else {
      const session = await ctx.currentUser(c);
      user = session ? await users.findById(session.id) : null;
      if (!user) return noSession(c);
    }
    const account = await users.smsAccount(user.id);
    if (!account?.phone) return challenge ? expired(c) : error(c, 400, 'no_phone', 'No phone number is set up.');
    if (sentRecently(user)) return tooSoon(c);
    if (!(await sendCode(c, user, account.phone, challenge ? 'signin' : 'approve', localeOf(data.locale)))) return smsUnavailable(c);
    return c.json({ phone: maskPhone(account.phone) }, 202);
  });

  app.post(`${ROUTE_PATH}/verify`, async (c) => {
    const challenge = await readChallenge(c, ctx, 'sms');
    if (!challenge) return expired(c);
    if (!(await methodStillOn(c, ctx, challenge))) return methodOff(c);
    const user = await users.findById(challenge.sub);
    // The user is gone, a password reset ended their sessions meanwhile, or the number was removed.
    const account = user && user.sessionVersion === challenge.sv ? await users.smsAccount(user.id) : null;
    if (!user || !account) return expired(c);
    const wrong = await checkCode(c, user, account, await body(c));
    if (wrong) return wrong;
    return c.json({ user: await finishSignIn(c, ctx, user, challenge, 'sms', 'sms') });
  });

  app.post(`${ROUTE_PATH}/remove`, async (c) => {
    const session = await ctx.currentUser(c);
    const user = session ? await users.findById(session.id) : null;
    if (!user) return noSession(c);
    const account = await users.smsAccount(user.id);
    if (!account) return error(c, 400, 'no_phone', 'No phone number is set up.');
    // With a policy that requires a second factor, the phone can only go while the app stays.
    const methods = await ctx.methods(c);
    const required = METHODS_WITH_SECOND_FACTOR.some((method) => isOn(method, ctx.configured, methods) && policyOf(method, methods) === 'required');
    if (required && !(await users.totpAccount(user.id))) {
      return error(c, 403, 'required_by_policy', "Signing in requires a second factor, so the phone number can't be removed without an authenticator app.");
    }
    // Removing the number takes a code sent to it (see `send`): a stolen session alone can't switch the protection off.
    const wrong = await checkCode(c, user, account, await body(c));
    if (wrong) return wrong;
    await users.removeSms(user.id);
    await ctx.emit('sms.disabled', { user: toMadauthUser(user) });
    return c.json({});
  });

  app.get(`${ROUTE_PATH}/status`, async (c) => {
    const session = await ctx.currentUser(c);
    if (!session) return noSession(c);
    const account = await users.smsAccount(session.id);
    return c.json({ enabled: !!account?.phone, phone: account?.phone ? maskPhone(account.phone) : null });
  });
}
