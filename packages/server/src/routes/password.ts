// E-mail & password sign-in. The security rules are described in docs/password-security.md.
import type { Context, Hono } from 'hono';
import type { AppContext } from '../app.js';
import type { MadauthConfig } from '../config.js';
import {
  MAX_PASSWORD_LENGTH,
  checkPasswordPolicy,
  hashPassword,
  isValidEmail,
  normalizeEmail,
  verifyAgainstDummy,
  verifyPassword,
} from '../password.js';
import { passwordAccountKey, toMadauthUser, type CodeResult, type StoredUser, type Users, type VerificationPurpose } from '../users.js';
import { WEBHOOK_TIMEOUT_MS, localeOf, type WebhookClient, type WebhookType } from '../webhooks.js';

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

export function passwordRoutes(
  app: Hono,
  ctx: AppContext,
  password: NonNullable<MadauthConfig['password']>,
  users: Users,
  webhook: WebhookClient,
): void {
  const { minLength } = password;

  const disabled = (c: Context) => c.json({ error: 'method_disabled', message: 'E-mail & password sign-in is switched off.' }, 403);
  // Every route of the method: an admin switched it off for sign-ups and sign-ins alike.
  app.use('/auth/password/*', async (c, next) => {
    if (!(await ctx.enabled('password'))) return disabled(c);
    await next();
  });

  const body = async (c: Context): Promise<Body> => {
    const data = await c.req.json<unknown>().catch(() => null);
    return data && typeof data === 'object' ? (data as Body) : {};
  };

  const error = (c: Context, status: 400 | 401 | 403 | 429 | 503, code: string, message: string) =>
    c.json({ error: code, message }, status);

  /** The webhook did not take over an e-mail or did not answer the sign-up check. */
  const unavailable = (c: Context) =>
    error(c, 503, 'temporarily_unavailable', 'E-mails can not be sent right now. Please try again later.');

  /** Every accepted request for an e-mail answers the same way, whether or not a mail was sent. */
  const accepted = (c: Context) => c.json({}, 202);

  const redirectTarget = (c: Context, value: unknown): URL | Response => {
    const url = ctx.allowedUrl(value);
    return url ?? error(c, 400, 'invalid_options', 'redirectTo must be an absolute URL whose origin is in ALLOWED_ORIGINS.');
  };

  /**
   * Hands an e-mail to the webhook, at most one per account and minute (within that minute nothing is sent,
   * and the answer is the same). Resolves to false if the webhook did not take it over.
   */
  const sendEmail = async (user: StoredUser, type: WebhookType, data: Record<string, unknown>): Promise<boolean> => {
    if (Date.now() - user.lastMailAt < MAIL_INTERVAL_MS) return true;
    const result = await webhook.call(type, { to: user.email, user: { id: user.id, name: user.name ?? undefined }, ...data }, WEBHOOK_TIMEOUT_MS);
    if (!result.ok) {
      console.error(`[madauth] Webhook "${type}" for ${user.email} failed: ${result.reason}`);
      return false;
    }
    // Only now: after a failure the user can try again right away.
    await users.updateUser(user.id, { lastMailAt: Date.now() });
    return true;
  };

  const sendLinkEmail = async (user: StoredUser, purpose: VerificationPurpose, target: URL, locale?: string): Promise<boolean> => {
    if (Date.now() - user.lastMailAt < MAIL_INTERVAL_MS) return true;
    const ttl = purpose === 'verify' ? VERIFY_TTL_MS : RESET_TTL_MS;
    const { token, code } = await users.issueVerification(user.id, purpose, ttl);
    const link = new URL(target);
    link.hash = `${purpose === 'verify' ? VERIFY_LINK_PARAM : RESET_LINK_PARAM}=${token}`;
    return sendEmail(user, purpose === 'verify' ? 'email.verify' : 'email.reset', {
      link: link.href,
      code,
      expiresAt: Date.now() + ttl,
      site: target.host,
      locale,
    });
  };

  type Consumed = Partial<CodeResult> & { userId: string | null; via: 'link' | 'code' };

  /** Resolves the user from `{ token }` (an e-mail link) or `{ email, code }`; null if invalid, expired or used. */
  const consume = async (data: Body, purpose: VerificationPurpose): Promise<Consumed> => {
    if (typeof data.token === 'string' && data.token) {
      return { userId: await users.consumeLinkToken(data.token, purpose), via: 'link' };
    }
    if (isValidEmail(data.email) && typeof data.code === 'string') {
      const user = await users.findByEmail(normalizeEmail(data.email));
      if (!user) return { userId: null, via: 'code' };
      return { ...(await users.consumeCode(user, purpose, data.code.replace(/\s/g, ''))), via: 'code' };
    }
    return { userId: null, via: 'code' };
  };

  const invalidVerification = (c: Context, { via, locked }: Consumed) => {
    if (locked) {
      return error(c, 429, 'codes_locked', 'Too many wrong codes. Please ask for a new e-mail and use the link in it.');
    }
    return via === 'link'
      ? error(c, 400, 'link_invalid', 'The link is invalid, expired or was already used.')
      : error(c, 400, 'code_invalid', 'The code is wrong or expired.');
  };

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

    // The attempt is counted before the slow password check, and only if no other request counted one
    // meanwhile. So requests sent at the same time can't all get past the lock.
    const failed = account.failedAttempts + 1;
    const lockedUntil = failed >= FREE_ATTEMPTS ? now + Math.min(2 ** (failed - FREE_ATTEMPTS) * 1000, MAX_LOCK_MS) : 0;
    if (!(await users.countAttempt(account, { failedAttempts: failed, lockedUntil }))) {
      return error(c, 429, 'too_many_attempts', 'Too many attempts at once. Please try again.');
    }

    const { ok, needsRehash } = await verifyPassword(pw, account.secret);
    if (!ok) return wrong();
    await users.updateAccount(account.id, {
      failedAttempts: 0,
      lockedUntil: 0,
      ...(needsRehash ? { secret: await hashPassword(pw) } : {}),
    });

    if (!user.emailVerified) {
      return error(c, 403, 'email_unverified', 'Please confirm your e-mail address first. We can send the e-mail again.');
    }
    const result = await ctx.startSession(c, toMadauthUser(user), ['pwd'], { sv: user.sessionVersion });
    await ctx.emit('user.signed_in', { user: result, method: 'password' });
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
    const locale = localeOf(data.locale);

    // The operator's check comes first and fails closed: without an answer, nobody signs up.
    const check = await ctx.checkSignup({ email, name: name ?? undefined, locale, method: 'password' });
    if (!check.ok) return check.reason === 'rejected' ? error(c, 403, 'signup_rejected', check.message) : unavailable(c);

    // Hash before looking the address up, so new and existing addresses take the same time.
    const passwordHash = await hashPassword(data.password as string);
    const existing = await users.findByEmail(normalizeEmail(email));

    if (existing?.emailVerified) {
      // The note to the owner is optional; the answer is the same either way.
      if (!webhook.wants('email.already_registered')) return accepted(c);
      const sent = await sendEmail(existing, 'email.already_registered', { link: target.href, site: target.host, locale });
      return sent ? accepted(c) : unavailable(c);
    }
    if (existing) {
      // Nobody has confirmed this address yet, so the latest sign-up sets the password; only its e-mail works.
      if (Date.now() - existing.lastMailAt < MAIL_INTERVAL_MS) return accepted(c);
      const account = await users.passwordAccount(existing.id);
      if (account) await users.updateAccount(account.id, { secret: passwordHash, failedAttempts: 0, lockedUntil: 0 });
      else await users.linkAccount(existing.id, { key: passwordAccountKey(existing.id), secret: passwordHash });
      await users.updateUser(existing.id, { name });
      return (await sendLinkEmail({ ...existing, name }, 'verify', target, locale)) ? accepted(c) : unavailable(c);
    }

    const user = await users.createUser({
      email,
      emailNormalized: normalizeEmail(email),
      name,
      emailVerified: false,
      account: (userId) => ({ key: passwordAccountKey(userId), secret: passwordHash }),
    });
    if (!user) return accepted(c);
    await ctx.emit('user.created', { user: toMadauthUser(user), method: 'password' });
    // If this fails, signing up again is allowed: the account is not confirmed yet.
    return (await sendLinkEmail(user, 'verify', target, locale)) ? accepted(c) : unavailable(c);
  });

  app.post('/auth/password/send-verification', async (c) => {
    const data = await body(c);
    const target = redirectTarget(c, data.redirectTo);
    if (target instanceof Response) return target;
    if (!isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
    const user = await users.findByEmail(normalizeEmail(data.email));
    if (user && !user.emailVerified && (await users.passwordAccount(user.id))) {
      if (!(await sendLinkEmail(user, 'verify', target, localeOf(data.locale)))) return unavailable(c);
    }
    return accepted(c);
  });

  app.post('/auth/password/verify-email', async (c) => {
    const consumed = await consume(await body(c), 'verify');
    const { userId, via } = consumed;
    const user = userId ? await users.findById(userId) : null;
    if (!user) return invalidVerification(c, consumed);
    // Using a link or a code proves access to the inbox, so wrong codes are counted from zero again.
    await users.updateUser(user.id, { emailVerified: true, wrongCodes: 0 });
    const result = await ctx.startSession(c, toMadauthUser(user), ['pwd'], { sv: user.sessionVersion });
    await ctx.emit('email.verified', { user: result, via });
    await ctx.emit('user.signed_in', { user: result, method: 'password' });
    return c.json({ user: result });
  });

  app.post('/auth/password/send-reset', async (c) => {
    const data = await body(c);
    const target = redirectTarget(c, data.redirectTo);
    if (target instanceof Response) return target;
    if (!isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
    const user = await users.findByEmail(normalizeEmail(data.email));
    // A confirmed user without a password (signed up with Google) sets one this way: the e-mail proves the inbox.
    if (user && (user.emailVerified || (await users.passwordAccount(user.id)))) {
      if (!(await sendLinkEmail(user, 'reset', target, localeOf(data.locale)))) return unavailable(c);
    }
    return accepted(c);
  });

  app.post('/auth/password/reset', async (c) => {
    const data = await body(c);
    // Checked first, so a weak password doesn't use up the link.
    const policy = checkPasswordPolicy(data.password, minLength);
    if (policy) return error(c, 400, 'weak_password', policy);
    const consumed = await consume(data, 'reset');
    const user = consumed.userId ? await users.findById(consumed.userId) : null;
    if (!user) return invalidVerification(c, consumed);

    const secret = await hashPassword(data.password as string);
    const account = await users.passwordAccount(user.id);
    if (account) await users.updateAccount(account.id, { secret, failedAttempts: 0, lockedUntil: 0 });
    else await users.linkAccount(user.id, { key: passwordAccountKey(user.id), secret });
    // The reset proves access to the inbox, and the new session version ends all older sessions.
    const sessionVersion = user.sessionVersion + 1;
    await users.updateUser(user.id, { emailVerified: true, sessionVersion, wrongCodes: 0 });
    // An unused confirmation link would otherwise still sign in.
    await users.clearVerifications(user.id);
    const result = await ctx.startSession(c, toMadauthUser(user), ['pwd'], { sv: sessionVersion });
    await ctx.emit('email.password_reset', { user: result });
    await ctx.emit('user.signed_in', { user: result, method: 'password' });
    return c.json({ user: result });
  });
}
