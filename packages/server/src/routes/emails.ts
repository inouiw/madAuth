// The e-mails of the sign-in methods that use an address: confirmation links and codes, password resets,
// and the notes to an address's owner. Shared by the e-mail, password and authenticator routes.
import type { Context } from 'hono';
import type { AppContext } from '../app.js';
import { isValidEmail, normalizeEmail } from '../password.js';
import type { CodeResult, StoredUser, Users, VerificationPurpose } from '../users.js';
import { WEBHOOK_TIMEOUT_MS, type WebhookClient, type WebhookType } from '../webhooks.js';
import { error, type Body } from './helpers.js';

/** At most one e-mail per account in this time, so nobody can flood an inbox through madAuth. */
export const MAIL_INTERVAL_MS = 60 * 1000;
export const VERIFY_TTL_MS = 24 * 60 * 60 * 1000;
export const RESET_TTL_MS = 30 * 60 * 1000;

/** Hash parameters that carry e-mail link tokens to the app (`<redirectTo>#madauth_verify=<token>`). */
export const VERIFY_LINK_PARAM = 'madauth_verify';
export const RESET_LINK_PARAM = 'madauth_reset';

/** What a link or code resolved to: the user, or why not. */
export type Consumed = Partial<CodeResult> & { userId: string | null; via: 'link' | 'code' };

export interface Emails {
  /**
   * Hands an e-mail to the webhook, at most one per account and minute (within that minute nothing is sent,
   * and the answer is the same). Resolves to false if the webhook did not take it over.
   */
  sendEmail(user: StoredUser, type: WebhookType, data: Record<string, unknown>): Promise<boolean>;
  /** Issues a verification or reset and sends its link and code. */
  sendLinkEmail(user: StoredUser, purpose: VerificationPurpose, target: URL, locale?: string): Promise<boolean>;
  /**
   * Tells the owner of an address about the account it has and how it signs in: after a sign-up with it
   * (`email.already_registered`) or a "forgot password" for a user without a password (`email.no_password`).
   * Both are optional for the receiver: without the type in its list nothing is sent, and the answer is
   * the same. Resolves to false if the webhook did not take the e-mail over.
   */
  sendAccountEmail(user: StoredUser, type: 'email.already_registered' | 'email.no_password', target: URL, locale?: string): Promise<boolean>;
  /** Resolves the user from `{ token }` (an e-mail link) or `{ email, code }`; null if invalid, expired or used. */
  consume(data: Body, purpose: VerificationPurpose): Promise<Consumed>;
  /** The answer when a link or code did not resolve to a user. */
  invalidVerification(c: Context, consumed: Consumed): Response;
}

export function createEmails(ctx: AppContext, users: Users, webhook: WebhookClient): Emails {
  const sendEmail: Emails['sendEmail'] = async (user, type, data) => {
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

  return {
    sendEmail,

    async sendLinkEmail(user, purpose, target, locale) {
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
    },

    async sendAccountEmail(user, type, target, locale) {
      if (!webhook.wants(type)) return true;
      const methods = await users.signInMethods(user.id, await ctx.settings.methods());
      return sendEmail(user, type, { link: target.href, site: target.host, locale, methods });
    },

    async consume(data, purpose) {
      if (typeof data.token === 'string' && data.token) {
        return { userId: await users.consumeLinkToken(data.token, purpose), via: 'link' };
      }
      if (isValidEmail(data.email) && typeof data.code === 'string') {
        const user = await users.findByEmail(normalizeEmail(data.email));
        if (!user) return { userId: null, via: 'code' };
        return { ...(await users.consumeCode(user, purpose, data.code.replace(/\s/g, ''))), via: 'code' };
      }
      return { userId: null, via: 'code' };
    },

    invalidVerification(c, { via, locked }) {
      if (locked) {
        return error(c, 429, 'codes_locked', 'Too many wrong codes. Please ask for a new e-mail and use the link in it.');
      }
      return via === 'link'
        ? error(c, 400, 'link_invalid', 'The link is invalid, expired or was already used.')
        : error(c, 400, 'code_invalid', 'The code is wrong or expired.');
    },
  };
}
