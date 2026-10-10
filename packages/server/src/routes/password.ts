// E-mail & password sign-in. The security rules are described in docs/password-security.md.
import type { Hono } from 'hono';
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
import { passwordAccountKey, toMadauthUser, type Users } from '../users.js';
import { localeOf, type WebhookClient } from '../webhooks.js';
import { MAIL_INTERVAL_MS, createEmails } from './emails.js';
import { accepted, body, error, nameOf, redirectTarget, signInAnswer, unavailable } from './helpers.js';
import { countSignInAttempt } from './lockout.js';

export { MAIL_INTERVAL_MS, RESET_LINK_PARAM, RESET_TTL_MS, VERIFY_LINK_PARAM, VERIFY_TTL_MS } from './emails.js';
export { FREE_ATTEMPTS, MAX_LOCK_MS } from './lockout.js';

export function passwordRoutes(
  app: Hono,
  ctx: AppContext,
  password: NonNullable<MadauthConfig['password']>,
  users: Users,
  webhook: WebhookClient,
): void {
  const { minLength } = password;
  const emails = createEmails(ctx, users, webhook);

  // Every route of the method: an admin switched it off for sign-ups and sign-ins alike.
  app.use('/auth/password/*', async (c, next) => {
    if (!(await ctx.enabled('password'))) return error(c, 403, 'method_disabled', 'E-mail & password sign-in is switched off.');
    await next();
  });

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

    // Counted before the slow password check; see routes/lockout.ts.
    const refused = await countSignInAttempt(c, users, account);
    if (refused) return refused;

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
    return signInAnswer(c, await ctx.secondStep(c, user, ['pwd'], 'password'));
  });

  app.post('/auth/password/signup', async (c) => {
    const data = await body(c);
    const target = redirectTarget(ctx, c, data.redirectTo);
    if (target instanceof Response) return target;
    if (!isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
    const policy = checkPasswordPolicy(data.password, minLength);
    if (policy) return error(c, 400, 'weak_password', policy);
    const name = nameOf(data.name);
    const email = data.email.trim();
    const locale = localeOf(data.locale);

    // The operator's check comes first and fails closed: without an answer, nobody signs up.
    const check = await ctx.checkSignup({ email, name: name ?? undefined, locale, method: 'password' });
    if (!check.ok) return check.reason === 'rejected' ? error(c, 403, 'signup_rejected', check.message) : unavailable(c);

    // Hash before looking the address up, so new and existing addresses take the same time.
    const passwordHash = await hashPassword(data.password as string);
    const existing = await users.findByEmail(normalizeEmail(email));

    if (existing?.emailVerified && (await users.hasAccounts(existing.id))) {
      return (await emails.sendAccountEmail(existing, 'email.already_registered', target, locale)) ? accepted(c) : unavailable(c);
    }
    if (existing) {
      // Nobody has proven this address yet (or nobody can sign in with it): the latest sign-up sets the
      // password, and only its e-mail works.
      if (Date.now() - existing.lastMailAt < MAIL_INTERVAL_MS) return accepted(c);
      const account = await users.passwordAccount(existing.id);
      if (account) await users.updateAccount(account.id, { secret: passwordHash, failedAttempts: 0, lockedUntil: 0 });
      else await users.linkAccount(existing.id, { key: passwordAccountKey(existing.id), secret: passwordHash });
      await users.updateUser(existing.id, { name });
      return (await emails.sendLinkEmail({ ...existing, name }, 'verify', target, locale)) ? accepted(c) : unavailable(c);
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
    return (await emails.sendLinkEmail(user, 'verify', target, locale)) ? accepted(c) : unavailable(c);
  });

  app.post('/auth/password/send-reset', async (c) => {
    const data = await body(c);
    const target = redirectTarget(ctx, c, data.redirectTo);
    if (target instanceof Response) return target;
    if (!isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
    const user = await users.findByEmail(normalizeEmail(data.email));
    const locale = localeOf(data.locale);
    // Only a password can be reset; the answer is the same either way, so nothing is revealed.
    if (user && (await users.passwordAccount(user.id))) {
      if (!(await emails.sendLinkEmail(user, 'reset', target, locale))) return unavailable(c);
    } else if (user) {
      // A user who signs in with Google alone has nothing to reset (Firebase Auth and Auth0 send nothing).
      // Rather than leave them waiting for an e-mail, the inbox's owner is told how they sign in.
      if (!(await emails.sendAccountEmail(user, 'email.no_password', target, locale))) return unavailable(c);
    }
    return accepted(c);
  });

  app.post('/auth/password/reset', async (c) => {
    const data = await body(c);
    // Checked first, so a weak password doesn't use up the link.
    const policy = checkPasswordPolicy(data.password, minLength);
    if (policy) return error(c, 400, 'weak_password', policy);
    const consumed = await emails.consume(data, 'reset');
    const user = consumed.userId ? await users.findById(consumed.userId) : null;
    const account = user ? await users.passwordAccount(user.id) : null;
    // A reset never adds a password: without one (dropped by a Google sign-in meanwhile) there is nothing to reset.
    if (!user || !account) return emails.invalidVerification(c, consumed);

    const secret = await hashPassword(data.password as string);
    // The password may have gone while hashing (a Google sign-in dropping an unproven one): then nothing was reset.
    if (!(await users.updateAccount(account.id, { secret, failedAttempts: 0, lockedUntil: 0 }))) return emails.invalidVerification(c, consumed);
    // The reset proves access to the inbox, and the new session version ends all older sessions.
    const sessionVersion = user.sessionVersion + 1;
    await users.updateUser(user.id, { emailVerified: true, sessionVersion, wrongCodes: 0 });
    // An unused confirmation link would otherwise still sign in.
    await users.clearVerifications(user.id);
    const reset = { ...user, emailVerified: true, sessionVersion, wrongCodes: 0 };
    await ctx.emit('email.password_reset', { user: toMadauthUser(reset) });
    // The authenticator app, if the policy asks for it, is still needed: the inbox alone does not sign in.
    return signInAnswer(c, await ctx.secondStep(c, reset, ['pwd'], 'password'));
  });
}
