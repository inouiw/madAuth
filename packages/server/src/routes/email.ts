// Confirming an e-mail address with the link or the code from the confirmation e-mail. Shared by the
// methods that sign people up with an address: e-mail & password, and the authenticator app.
import type { Context, Hono } from 'hono';
import type { AppContext } from '../app.js';
import { isValidEmail, normalizeEmail } from '../password.js';
import { toMadauthUser, type Users } from '../users.js';
import { localeOf, type WebhookClient } from '../webhooks.js';
import { createEmails } from './emails.js';
import { accepted, body, error, redirectTarget, signInAnswer, unavailable } from './helpers.js';

export function emailRoutes(app: Hono, ctx: AppContext, users: Users, webhook: WebhookClient): void {
  const emails = createEmails(ctx, users, webhook);

  /** The method a user signs up with: a password if they set one, else the authenticator app. */
  const signUpMethod = async (userId: string) => ((await users.passwordAccount(userId)) ? ('password' as const) : ('totp' as const));

  app.post('/auth/email/send-verification', async (c) => {
    const data = await body(c);
    const target = redirectTarget(ctx, c, data.redirectTo);
    if (target instanceof Response) return target;
    if (!isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
    const user = await users.findByEmail(normalizeEmail(data.email));
    // Only for an address nobody confirmed yet, and only if its method is on; the answer is the same either way.
    if (user && !user.emailVerified && (await ctx.enabled(c, await signUpMethod(user.id)))) {
      if (!(await emails.sendLinkEmail(user, 'verify', target, localeOf(data.locale)))) return unavailable(c);
    }
    return accepted(c);
  });

  const disabled = (c: Context) => error(c, 403, 'method_disabled', 'This way of signing in is switched off.');

  app.post('/auth/email/verify', async (c) => {
    const data = await body(c);
    // A link or code whose method is off is refused before it is used up, so it still works once the
    // method is on again. For a code, this tells whoever sends it that the address has a pending sign-up
    // with that method, but only while the method is off (see docs/password-security.md).
    const waiting =
      typeof data.token === 'string' && data.token
        ? await users.peekLinkToken(data.token, 'verify')
        : isValidEmail(data.email)
          ? ((await users.findByEmail(normalizeEmail(data.email)))?.id ?? null)
          : null;
    if (waiting && !(await ctx.enabled(c, await signUpMethod(waiting)))) return disabled(c);
    const consumed = await emails.consume(data, 'verify');
    const { userId, via } = consumed;
    const user = userId ? await users.findById(userId) : null;
    if (!user) return emails.invalidVerification(c, consumed);
    const method = await signUpMethod(user.id);
    if (!(await ctx.enabled(c, method))) return disabled(c);
    // The address is proven for this sign-up: the e-mail link account another unfinished sign-up set with it
    // (perhaps by someone else) goes; a password of this sign-up stays.
    if (!user.emailVerified) await users.dropUnprovenAccounts(user.id, method === 'password' ? 'password' : undefined);
    // Using a link or a code proves access to the inbox, so wrong codes are counted from zero again.
    await users.updateUser(user.id, { emailVerified: true, wrongCodes: 0 });
    const verified = { ...user, emailVerified: true, wrongCodes: 0 };
    await ctx.emit('user.email_verified', { user: toMadauthUser(verified), method, via });
    // A password user is signed in (or asked for their code); a sign-up with the authenticator app sets it up now.
    return signInAnswer(c, await ctx.secondStep(c, verified, method === 'password' ? ['pwd'] : [], method));
  });
}
