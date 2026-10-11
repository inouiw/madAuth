// Passwordless sign-in with an e-mail link: the address, then the link or the code from the e-mail. A new
// address is signed up on first use. The security rules are described in docs/email-link-security.md.
import type { Hono } from 'hono';
import type { AppContext } from '../app.js';
import { isValidEmail, normalizeEmail } from '../password.js';
import { emailLinkAccountKey, toMadauthUser, type StoredUser, type Users } from '../users.js';
import { localeOf, type WebhookClient } from '../webhooks.js';
import { MAIL_INTERVAL_MS, createEmails } from './emails.js';
import { accepted, body, error, redirectTarget, signInAnswer, unavailable } from './helpers.js';

export function emailLinkRoutes(app: Hono, ctx: AppContext, users: Users, webhook: WebhookClient): void {
  const emails = createEmails(ctx, users, webhook);

  // Every route: an admin switched the e-mail link off. A link or code is refused before it is used up, so
  // it still works once the method is on again.
  app.use('/auth/email-link/*', async (c, next) => {
    if (!(await ctx.enabled(c, 'email-link'))) {
      return error(c, 403, 'method_disabled', 'Signing in with an e-mail link is switched off.');
    }
    await next();
  });

  app.post('/auth/email-link/send', async (c) => {
    const data = await body(c);
    const target = redirectTarget(ctx, c, data.redirectTo);
    if (target instanceof Response) return target;
    if (!isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
    const email = data.email.trim();
    const locale = localeOf(data.locale);
    const send = async (user: StoredUser) => ((await emails.sendLinkEmail(user, 'signin', target, locale)) ? accepted(c) : unavailable(c));

    const existing = await users.findByEmail(normalizeEmail(email));
    // A user who signs in this way gets their link. The answer is the same for every address.
    if (existing && (await users.emailLinkAccount(existing.id))) return send(existing);
    // A method signs in only users who have it: an address that signs in another way is told so instead
    // (if the receiver sends that e-mail).
    if (existing?.emailVerified && (await users.hasSignInMethod(existing.id))) {
      return (await emails.sendAccountEmail(existing, 'email.send_already_registered', target, locale)) ? accepted(c) : unavailable(c);
    }

    // A new address, or a sign-up nobody finished: the first link signs the user up. The operator's check
    // comes first and fails closed: without an answer, nobody signs up.
    const check = await ctx.checkSignup({ email, locale, method: 'email-link' });
    if (!check.ok) return check.reason === 'rejected' ? error(c, 403, 'signup_rejected', check.message) : unavailable(c);

    if (existing) {
      if (Date.now() - existing.lastMailAt < MAIL_INTERVAL_MS) return accepted(c);
      // A password an earlier, unconfirmed sign-up set (perhaps by someone else) goes with it.
      if (!existing.emailVerified) await users.dropUnprovenAccounts(existing.id, 'email-link');
      // Another sign-up gave the user a sign-in method meanwhile: theirs stands, and no link is sent for a
      // method the user doesn't have. The answer is the same.
      if (!(await users.linkAccount(existing.id, { key: emailLinkAccountKey(existing.id) }))) return accepted(c);
      return send(await users.reopenSignUp(existing));
    }
    const user = await users.createUser({
      email,
      emailNormalized: normalizeEmail(email),
      name: null,
      emailVerified: false,
      account: (userId) => ({ key: emailLinkAccountKey(userId) }),
    });
    // Created by another request meanwhile: the same answer, and the next request finds the user.
    if (!user) return accepted(c);
    return send(user);
  });

  app.post('/auth/email-link/verify', async (c) => {
    const consumed = await emails.consume(await body(c), 'signin');
    const found = consumed.userId ? await users.findById(consumed.userId) : null;
    if (!found || !(await users.emailLinkAccount(found.id))) return emails.invalidVerification(c, consumed);
    // The first link finishes a sign-up: one from before `user.signed_up` existed gets it too.
    const user = found.emailVerified ? found : await users.reopenSignUp(found);
    if (!user.emailVerified) {
      // The link proves access to the inbox, and nobody had proven the address before: a password an
      // unconfirmed sign-up set meanwhile (perhaps by someone else) goes, with its links and codes.
      await users.verifyByProvider(user, 'email-link');
      await ctx.emit('user.email_verified', { user: toMadauthUser({ ...user, emailVerified: true }), method: 'email-link', via: consumed.via });
    } else {
      // Using a link or a code proves access to the inbox, so wrong codes are counted from zero again.
      await users.updateUser(user.id, { wrongCodes: 0 });
    }
    const verified = { ...user, emailVerified: true, wrongCodes: 0 };
    // The authenticator app, if the policy asks for it, is still needed: the inbox alone does not sign in.
    return signInAnswer(c, await ctx.secondStep(c, verified, ['email'], 'email-link'));
  });
}
