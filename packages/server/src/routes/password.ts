// E-mail & password sign-in. The security rules are described in docs/password-security.md.
import type { Context, Hono } from 'hono';
import type { AppContext } from '../app.js';
import type { MadauthConfig } from '../config.js';
import { alreadyRegisteredMail, resetPasswordMail, verifyEmailMail, type Mail } from '../mail.js';
import {
  MAX_PASSWORD_LENGTH,
  checkPasswordPolicy,
  hashPassword,
  isValidEmail,
  normalizeEmail,
  verifyAgainstDummy,
  verifyPassword,
} from '../password.js';
import type { MadauthUser } from '../user.js';
import type { StoredUser, Users, VerificationPurpose } from '../users.js';

/** Failed sign-ins allowed before each further attempt has to wait. */
export const FREE_ATTEMPTS = 5;
/** Longest wait after failed sign-ins. */
export const MAX_LOCK_MS = 15 * 60 * 1000;
/** At most one e-mail per account in this time, so nobody can flood an inbox through madAuth. */
export const MAIL_INTERVAL_MS = 60 * 1000;
export const VERIFY_TTL_MS = 24 * 60 * 60 * 1000;
export const RESET_TTL_MS = 30 * 60 * 1000;

/** Hash parameters that carry e-mail link tokens to the app (`<redirectTo>#madauth_verify=<token>`). */
export const VERIFY_LINK_PARAM = 'madauth_verify';
export const RESET_LINK_PARAM = 'madauth_reset';

const MAX_NAME_LENGTH = 100;

type Body = Record<string, unknown>;

function toMadauthUser(user: StoredUser): MadauthUser {
  const result: MadauthUser = { id: user.id, email: user.email };
  if (user.name) result.name = user.name;
  return result;
}

export function passwordRoutes(app: Hono, ctx: AppContext, password: NonNullable<MadauthConfig['password']>, users: Users): void {
  const { minLength, mailer } = password;

  const body = async (c: Context): Promise<Body> => {
    const data = await c.req.json<unknown>().catch(() => null);
    return data && typeof data === 'object' ? (data as Body) : {};
  };

  const error = (c: Context, status: 400 | 401 | 403 | 429, code: string, message: string) => c.json({ error: code, message }, status);

  /** Every accepted request for an e-mail answers the same way, whether or not a mail was sent. */
  const accepted = (c: Context) => c.json({}, 202);

  const redirectTarget = (c: Context, value: unknown): URL | Response => {
    const url = ctx.allowedUrl(value);
    return url ?? error(c, 400, 'invalid_options', 'redirectTo must be an absolute URL whose origin is in ALLOWED_ORIGINS.');
  };

  /** Sends a mail unless the account got one less than a minute ago. */
  const sendMail = async (user: StoredUser, mail: Mail): Promise<void> => {
    if (Date.now() - user.lastMailAt < MAIL_INTERVAL_MS) return;
    await users.updateUser(user.id, { lastMailAt: Date.now() });
    try {
      await mailer.send(mail);
    } catch (e) {
      // The answer must not depend on the account, so the failure is only logged.
      console.error(`[madauth] Could not send "${mail.subject}" to ${mail.to}:`, e);
    }
  };

  const sendLinkMail = async (user: StoredUser, purpose: VerificationPurpose, target: URL): Promise<void> => {
    if (Date.now() - user.lastMailAt < MAIL_INTERVAL_MS) return;
    const { token, code } = await users.issueVerification(user.id, purpose, purpose === 'verify' ? VERIFY_TTL_MS : RESET_TTL_MS);
    const link = new URL(target);
    link.hash = `${purpose === 'verify' ? VERIFY_LINK_PARAM : RESET_LINK_PARAM}=${token}`;
    const build = purpose === 'verify' ? verifyEmailMail : resetPasswordMail;
    await sendMail(user, build(user.email, target.host, link.href, code));
  };

  /** Resolves the user from `{ token }` (an e-mail link) or `{ email, code }`; null if invalid, expired or used. */
  const consume = async (data: Body, purpose: VerificationPurpose): Promise<{ userId: string | null; via: 'link' | 'code' }> => {
    if (typeof data.token === 'string' && data.token) {
      return { userId: await users.consumeLinkToken(data.token, purpose), via: 'link' };
    }
    if (isValidEmail(data.email) && typeof data.code === 'string') {
      const user = await users.findByEmail(normalizeEmail(data.email));
      const code = data.code.replace(/\s/g, '');
      return { userId: user ? await users.consumeCode(user.id, purpose, code) : null, via: 'code' };
    }
    return { userId: null, via: 'code' };
  };

  const invalidVerification = (c: Context, via: 'link' | 'code') =>
    via === 'link'
      ? error(c, 400, 'link_invalid', 'The link is invalid, expired or was already used.')
      : error(c, 400, 'code_invalid', 'The code is wrong or expired.');

  app.post('/auth/password/signin', async (c) => {
    const data = await body(c);
    const wrong = () => error(c, 401, 'invalid_credentials', 'E-mail or password is wrong.');
    const pw = typeof data.password === 'string' ? data.password : '';
    // Absurdly long input is rejected before hashing, so it can't be used to tie up the CPU.
    if (!isValidEmail(data.email) || !pw || pw.length > MAX_PASSWORD_LENGTH * 4) return wrong();

    const user = await users.findByEmail(normalizeEmail(data.email));
    const account = user ? await users.passwordAccount(user.id) : null;
    if (!user || !account?.secret) {
      // Takes as long as a real check, so the answer time doesn't reveal whether the account exists.
      await verifyAgainstDummy(pw);
      return wrong();
    }

    const now = Date.now();
    if (account.lockedUntil > now) {
      const seconds = Math.ceil((account.lockedUntil - now) / 1000);
      return error(c, 429, 'too_many_attempts', `Too many failed attempts. Try again in ${seconds} seconds.`);
    }

    const { ok, needsRehash } = await verifyPassword(pw, account.secret);
    if (!ok) {
      const failed = account.failedAttempts + 1;
      const lockedUntil = failed >= FREE_ATTEMPTS ? now + Math.min(2 ** (failed - FREE_ATTEMPTS) * 1000, MAX_LOCK_MS) : 0;
      await users.updateAccount(account.id, { failedAttempts: failed, lockedUntil });
      return wrong();
    }
    await users.updateAccount(account.id, {
      failedAttempts: 0,
      lockedUntil: 0,
      ...(needsRehash ? { secret: await hashPassword(pw) } : {}),
    });

    if (!user.emailVerified) {
      return error(c, 403, 'email_unverified', 'Please confirm your e-mail address first. We can send the e-mail again.');
    }
    const result = toMadauthUser(user);
    await ctx.startSession(c, result, ['pwd'], { sv: user.sessionVersion });
    return c.json({ user: result });
  });

  app.post('/auth/password/signup', async (c) => {
    const data = await body(c);
    const target = redirectTarget(c, data.redirectTo);
    if (target instanceof Response) return target;
    if (!isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
    const policy = checkPasswordPolicy(data.password, minLength);
    if (policy) return error(c, 400, 'weak_password', policy);
    const name = typeof data.name === 'string' && data.name.trim() ? data.name.trim().slice(0, MAX_NAME_LENGTH) : null;
    const email = data.email.trim();

    // Hash before looking the address up, so new and existing addresses take the same time.
    const passwordHash = await hashPassword(data.password as string);
    const existing = await users.findByEmail(normalizeEmail(email));

    if (existing?.emailVerified) {
      await sendMail(existing, alreadyRegisteredMail(existing.email, target.host, target.href));
      return accepted(c);
    }
    if (existing) {
      // Nobody has confirmed this address yet, so the latest sign-up sets the password; only its e-mail works.
      if (Date.now() - existing.lastMailAt < MAIL_INTERVAL_MS) return accepted(c);
      const account = await users.passwordAccount(existing.id);
      if (account) await users.updateAccount(account.id, { secret: passwordHash, failedAttempts: 0, lockedUntil: 0 });
      await users.updateUser(existing.id, { name });
      await sendLinkMail(existing, 'verify', target);
      return accepted(c);
    }

    const user = await users.createPasswordUser({
      email,
      emailNormalized: normalizeEmail(email),
      name,
      passwordHash,
      emailVerified: false,
    });
    if (user) await sendLinkMail(user, 'verify', target);
    return accepted(c);
  });

  app.post('/auth/password/send-verification', async (c) => {
    const data = await body(c);
    const target = redirectTarget(c, data.redirectTo);
    if (target instanceof Response) return target;
    if (!isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
    const user = await users.findByEmail(normalizeEmail(data.email));
    if (user && !user.emailVerified && (await users.passwordAccount(user.id))) await sendLinkMail(user, 'verify', target);
    return accepted(c);
  });

  app.post('/auth/password/verify-email', async (c) => {
    const { userId, via } = await consume(await body(c), 'verify');
    const user = userId ? await users.findById(userId) : null;
    if (!user) return invalidVerification(c, via);
    await users.updateUser(user.id, { emailVerified: true });
    const result = toMadauthUser(user);
    await ctx.startSession(c, result, ['pwd'], { sv: user.sessionVersion });
    return c.json({ user: result });
  });

  app.post('/auth/password/send-reset', async (c) => {
    const data = await body(c);
    const target = redirectTarget(c, data.redirectTo);
    if (target instanceof Response) return target;
    if (!isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
    const user = await users.findByEmail(normalizeEmail(data.email));
    if (user && (await users.passwordAccount(user.id))) await sendLinkMail(user, 'reset', target);
    return accepted(c);
  });

  app.post('/auth/password/reset', async (c) => {
    const data = await body(c);
    // Checked first, so a weak password doesn't use up the link.
    const policy = checkPasswordPolicy(data.password, minLength);
    if (policy) return error(c, 400, 'weak_password', policy);
    const { userId, via } = await consume(data, 'reset');
    const user = userId ? await users.findById(userId) : null;
    const account = user ? await users.passwordAccount(user.id) : null;
    if (!user || !account) return invalidVerification(c, via);

    await users.updateAccount(account.id, { secret: await hashPassword(data.password as string), failedAttempts: 0, lockedUntil: 0 });
    // The reset proves access to the inbox, and the new session version ends all older sessions.
    const sessionVersion = user.sessionVersion + 1;
    await users.updateUser(user.id, { emailVerified: true, sessionVersion });
    const result = toMadauthUser(user);
    await ctx.startSession(c, result, ['pwd'], { sv: sessionVersion });
    return c.json({ user: result });
  });
}
