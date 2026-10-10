// Confirming an e-mail address with the link or the code from the confirmation e-mail. Shared by the
// methods that sign people up with an address: e-mail & password, and the authenticator app.
import type { Hono } from 'hono';
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
    if (user && !user.emailVerified && (await ctx.enabled(await signUpMethod(user.id)))) {
      if (!(await emails.sendLinkEmail(user, 'verify', target, localeOf(data.locale)))) return unavailable(c);
    }
    return accepted(c);
  });

  app.post('/auth/email/verify', async (c) => {
    const consumed = await emails.consume(await body(c), 'verify');
    const { userId, via } = consumed;
    const user = userId ? await users.findById(userId) : null;
    if (!user) return emails.invalidVerification(c, consumed);
    const method = await signUpMethod(user.id);
    if (!(await ctx.enabled(method))) return error(c, 403, 'method_disabled', 'This way of signing in is switched off.');
    // Using a link or a code proves access to the inbox, so wrong codes are counted from zero again.
    await users.updateUser(user.id, { emailVerified: true, wrongCodes: 0 });
    const verified = { ...user, emailVerified: true, wrongCodes: 0 };
    await ctx.emit('email.verified', { user: toMadauthUser(verified), via });
    // A password user is signed in (or asked for their code); a sign-up with the authenticator app sets it up now.
    return signInAnswer(c, await ctx.secondStep(c, verified, method === 'password' ? ['pwd'] : [], method));
  });
}
