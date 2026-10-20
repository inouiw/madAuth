// E-mail & password sign-in. The security rules are described in docs/password-security.md.
import type { Context, Hono } from 'hono';
import type { AppContext } from '../app.js';
import {
  MAX_PASSWORD_LENGTH,
  checkPasswordPolicy,
  hashPassword,
  isValidEmail,
  normalizeEmail,
  verifyAgainstDummy,
  verifyPassword,
  type PasswordProblem,
} from '../password.js';
import { passwordAccountKey, toMadauthUser, type Users } from '../users.js';
import { localeOf, type WebhookClient } from '../webhooks.js';
import { MAIL_INTERVAL_MS, createEmails } from './emails.js';
import { accepted, body, error, nameOf, noSession, recentUser, redirectTarget, signInAnswer, unavailable } from './helpers.js';
import { countSignInAttempt } from './lockout.js';

export { MAIL_INTERVAL_MS, RESET_LINK_PARAM, RESET_TTL_MS, VERIFY_LINK_PARAM, VERIFY_TTL_MS } from './emails.js';
export { FREE_ATTEMPTS, MAX_LOCK_MS } from './lockout.js';

/** A new password breaks the rules: the message, and what the dialog needs to say it in the user's language. */
function weakPassword(c: Context, problem: PasswordProblem): Response {
  const { message, ...details } = problem;
  return c.json({ error: 'weak_password', message, ...details }, 400);
}

export function passwordRoutes(app: Hono, ctx: AppContext, users: Users, webhook: WebhookClient): void {
  /**
   * Why a new password breaks the rules an admin set, as the answer; null if it doesn't. `userInputs` are the
   * user's address and name: a password made of them is easy to guess.
   */
  const refused = async (c: Context, password: unknown, userInputs: (string | null | undefined)[]) => {
    const words = userInputs.filter((word): word is string => !!word);
    const problem = await checkPasswordPolicy(password, await ctx.settings.passwordRules(), words);
    return problem ? weakPassword(c, problem) : null;
  };
  const emails = createEmails(ctx, users, webhook);

  // Every route of the method: an admin switched it off for sign-ups and sign-ins alike.
  app.use('/auth/password/*', async (c, next) => {
    if (!(await ctx.enabled(c, 'password'))) return error(c, 403, 'method_disabled', 'E-mail & password sign-in is switched off.');
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
    const name = nameOf(data.name);
    const email = data.email.trim();
    const weak = await refused(c, data.password, [email, name]);
    if (weak) return weak;
    const locale = localeOf(data.locale);

    // The operator's check comes first and fails closed: without an answer, nobody signs up.
    const check = await ctx.checkSignup({ email, name: name ?? undefined, locale, method: 'password' });
    if (!check.ok) return check.reason === 'rejected' ? error(c, 403, 'signup_rejected', check.message) : unavailable(c);

    // Hash before looking the address up, so new and existing addresses take the same time.
    const passwordHash = await hashPassword(data.password as string);
    const existing = await users.findByEmail(normalizeEmail(email));

    if (existing?.emailVerified && (await users.hasSignInMethod(existing.id))) {
      return (await emails.sendAccountEmail(existing, 'email.send_already_registered', target, locale)) ? accepted(c) : unavailable(c);
    }
    if (existing) {
      // Nobody has proven this address yet (or nobody can sign in with it): the latest sign-up sets the
      // password, and only its e-mail works. An e-mail link an unfinished sign-up asked for goes with it.
      if (Date.now() - existing.lastMailAt < MAIL_INTERVAL_MS) return accepted(c);
      if (!existing.emailVerified) await users.dropUnprovenAccounts(existing.id, 'password');
      // A confirmed address without a sign-in method (an unfinished sign-up with the app, an interrupted one
      // with Google) is confirmed again for the password: whoever sent it hasn't proven the inbox. Until then,
      // an app sign-up or a Google sign-in drops the password, as for any unconfirmed sign-up.
      if (existing.emailVerified) await users.updateUser(existing.id, { emailVerified: false });
      const account = await users.passwordAccount(existing.id);
      if (account) await users.updateAccount(account.id, { secret: passwordHash, failedAttempts: 0, lockedUntil: 0 });
      // Another sign-up gave the user a sign-in method meanwhile: theirs stands, and no e-mail goes out for a
      // password that was never stored. The answer is the same.
      else if (!(await users.linkAccount(existing.id, { key: passwordAccountKey(existing.id), secret: passwordHash }))) {
        // The confirmation comes back only for a method that won without a password (an app sign-up whose
        // address was confirmed): a password another sign-up linked meanwhile still waits for its own e-mail.
        if (existing.emailVerified && !(await users.passwordAccount(existing.id))) await users.updateUser(existing.id, { emailVerified: true });
        return accepted(c);
      }
      await users.reopenSignUp(existing);
      await users.updateUser(existing.id, { name, signUpMethod: 'password' });
      return (await emails.sendLinkEmail({ ...existing, name }, 'verify', target, locale)) ? accepted(c) : unavailable(c);
    }

    const user = await users.createUser({
      email,
      emailNormalized: normalizeEmail(email),
      name,
      emailVerified: false,
      account: (userId) => ({ key: passwordAccountKey(userId), secret: passwordHash }),
      signUpMethod: 'password',
    });
    if (!user) return accepted(c);
    // If this fails, signing up again is allowed: the account is not confirmed yet.
    return (await emails.sendLinkEmail(user, 'verify', target, locale)) ? accepted(c) : unavailable(c);
  });

  // A signed-in user without a password adds one: from then on it signs them in too.
  app.post('/auth/password/add', async (c) => {
    const user = await recentUser(c, ctx);
    if (user instanceof Response) return user;
    const data = await body(c);
    const weak = await refused(c, data.password, [user.email, user.name]);
    if (weak) return weak;
    const taken = () => error(c, 409, 'already_added', 'You have a password already. Change it instead.');
    if (await users.passwordAccount(user.id)) return taken();
    const secret = await hashPassword(data.password as string);
    if (!(await users.linkAccount(user.id, { key: passwordAccountKey(user.id), secret, primary: false }))) return taken();
    await ctx.emit('user.method_added', { user: toMadauthUser(user), method: 'password' });
    return c.json({});
  });

  // A signed-in user with a password changes it. The current password proves who they are, so it takes no recent
  // sign-in; it is counted like a sign-in, against guessing. The user's other sessions end, this one goes on.
  app.post('/auth/password/change', async (c) => {
    const signedIn = await ctx.currentSignIn(c);
    if (!signedIn) return noSession(c);
    const { stored: user } = signedIn;
    const data = await body(c);
    // Checked first, so fixing a weak password doesn't count as another attempt.
    const weak = await refused(c, data.password, [user.email, user.name]);
    if (weak) return weak;
    const wrong = () => error(c, 401, 'invalid_credentials', 'The current password is wrong.');
    const current = typeof data.current === 'string' ? data.current : '';
    if (!current || current.length > MAX_PASSWORD_LENGTH * 4) return wrong();
    const gone = () => error(c, 404, 'method_not_found', 'You have no password. Add one instead.');
    const account = await users.passwordAccount(user.id);
    if (!account?.secret) return gone();

    const locked = await countSignInAttempt(c, users, account);
    if (locked) return locked;
    if (!(await verifyPassword(current, account.secret)).ok) return wrong();

    const secret = await hashPassword(data.password as string);
    // The password may have gone meanwhile (removed in another tab): then nothing was changed.
    if (!(await users.updateAccount(account.id, { secret, failedAttempts: 0, lockedUntil: 0 }))) return gone();
    // The new session version ends every other session; this one goes on with it, as the same sign-in.
    const sessionVersion = user.sessionVersion + 1;
    await users.updateUser(user.id, { sessionVersion });
    await ctx.continueSession(c, signedIn, sessionVersion);
    await ctx.emit('user.password_changed', { user: toMadauthUser({ ...user, sessionVersion }) });
    return c.json({});
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
      if (!(await emails.sendAccountEmail(user, 'email.send_password_reset_no_password', target, locale))) return unavailable(c);
    }
    return accepted(c);
  });

  app.post('/auth/password/reset', async (c) => {
    const data = await body(c);
    // Checked first, so a weak password doesn't use up the link. The user's words are only what the page knows
    // too (the address typed with the code), so the strength meter and this check agree.
    const weak = await refused(c, data.password, [isValidEmail(data.email) ? data.email.trim() : null]);
    if (weak) return weak;
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
    // A reset can finish an unconfirmed sign-up: one from before `user.signed_up` existed gets it too.
    const reset = { ...(user.emailVerified ? user : await users.reopenSignUp(user)), emailVerified: true, sessionVersion, wrongCodes: 0 };
    await ctx.emit('user.password_reset', { user: toMadauthUser(reset) });
    // The authenticator app, if the policy asks for it, is still needed: the inbox alone does not sign in.
    return signInAnswer(c, await ctx.secondStep(c, reset, ['pwd'], 'password'));
  });
}
