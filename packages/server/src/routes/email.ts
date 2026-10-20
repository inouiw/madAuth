// Confirming an e-mail address with the link or the code from the confirmation e-mail. Shared by the
// methods that sign people up with an address: e-mail & password, the authenticator app, passkeys, and an
// OpenID Connect provider whose address isn't verified.
import type { Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { AppContext } from '../app.js';
import { isValidEmail, normalizeEmail } from '../password.js';
import { isProviderId } from '../providers.js';
import { FORMER_AUTHENTICATOR_ID } from '../settings.js';
import { readToken, signToken } from '../tokens.js';
import { isSignUpMethod, toMadauthUser, type SignUpMethod, type StoredUser, type Users } from '../users.js';
import { localeOf, type WebhookClient } from '../webhooks.js';
import { MAIL_INTERVAL_MS, VERIFY_TTL_MS, createEmails, type Emails } from './emails.js';
import { accepted, body, error, nameOf, redirectTarget, signInAnswer, unavailable } from './helpers.js';

/**
 * The method the user's pending sign-up confirms the address for, as the sign-up recorded it (`totp`, the
 * app's id before it was named `authenticator`, is read as `authenticator`): one of {@link SignUpMethod}, or
 * an OpenID Connect provider's id. A password sign-up whose password went meanwhile (an e-mail link sign-up
 * took the address over) counts as unrecorded, as does a record from before schema version 9: then, as
 * before, a password if the user has one, else the authenticator app.
 */
export async function signUpMethodOf(users: Users, user: StoredUser): Promise<string> {
  const stored = user.signUpMethod === FORMER_AUTHENTICATOR_ID ? 'authenticator' : user.signUpMethod;
  if (isProviderId(stored)) return stored;
  const recorded = isSignUpMethod(stored) ? stored : null;
  if (recorded && recorded !== 'password') return recorded;
  return (await users.passwordAccount(user.id)) ? 'password' : 'authenticator';
}

/**
 * A sign-up with a method that is set up once the address is confirmed: the authenticator app, or a passkey.
 * `{ email, name?, redirectTo, locale? }` → 202 and the confirmation e-mail. The operator's check comes first;
 * the owner of an address that signs in already gets `email.send_already_registered` instead; a sign-up
 * nobody finished starts afresh, and the latest one wins. The answer is the same for every address.
 */
export async function signUpThenSetUp(c: Context, ctx: AppContext, emails: Emails, method: Exclude<SignUpMethod, 'password'>): Promise<Response> {
  const { users } = ctx;
  const data = await body(c);
  const target = redirectTarget(ctx, c, data.redirectTo);
  if (target instanceof Response) return target;
  if (!isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
  const name = nameOf(data.name);
  const email = data.email.trim();
  const locale = localeOf(data.locale);

  const check = await ctx.checkSignup({ email, name: name ?? undefined, locale, method });
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
    // A confirmed address without a sign-in method (a sign-up whose setup was abandoned) is confirmed again,
    // as for a password: whoever sent this hasn't proven the inbox. "Send the e-mail again" works then too.
    await users.updateUser(existing.id, { name, signUpMethod: method, emailVerified: false });
    return (await emails.sendLinkEmail({ ...existing, name }, 'verify', target, locale)) ? accepted(c) : unavailable(c);
  }

  // Without an account: the method is set up once the address is confirmed.
  const user = await users.createUser({ email, emailNormalized: normalizeEmail(email), name, emailVerified: false, signUpMethod: method });
  if (!user) return accepted(c);
  return (await emails.sendLinkEmail(user, 'verify', target, locale)) ? accepted(c) : unavailable(c);
}

/**
 * The user of a sign-up whose method is set up now (the app, a passkey): the challenge comes from a used
 * confirmation link. A password sign-up for the address meanwhile took the confirmation back until its own
 * e-mail is used; nobody has, so this sign-up wins and the password goes, as for any unconfirmed sign-up.
 * Read again: a password confirmed by its own e-mail meanwhile stays, and is the user's method.
 */
export async function reclaimConfirmation(users: Users, user: StoredUser): Promise<StoredUser> {
  if (user.emailVerified) return user;
  const fresh = await users.findById(user.id);
  if (!fresh || fresh.emailVerified) return user;
  await users.verifyByProvider(fresh);
  return { ...user, emailVerified: true, wrongCodes: 0 };
}

/**
 * A sign-up through a provider whose address isn't verified waits for its confirmation e-mail (see
 * `resolveUnconfirmedProviderUser`). The page never had the address, so this cookie says whose sign-up it is:
 * the code is sent without one, and "send it again" too. It lives as long as the e-mail's link, and only
 * goes to /auth/email.
 */
const CONFIRMATION_COOKIE = 'madauth_confirmation';
const CONFIRMATION_TYP = 'madauth-confirmation+jwt';
const confirmationCookie = (secure: boolean) => ({ path: '/auth/email', httpOnly: true, secure, sameSite: 'Strict' as const });

export async function setConfirmation(c: Context, ctx: AppContext, userId: string): Promise<void> {
  const ttl = VERIFY_TTL_MS / 1000;
  setCookie(c, CONFIRMATION_COOKIE, await signToken(ctx.keys, ctx.config.issuer, CONFIRMATION_TYP, { sub: userId }, ttl), { ...confirmationCookie(ctx.secure), maxAge: ttl });
}

/** The user whose sign-up the request's confirmation cookie names, or null. */
async function confirmationOf(c: Context, ctx: AppContext): Promise<StoredUser | null> {
  const claims = await readToken(ctx.keys, ctx.config.issuer, CONFIRMATION_TYP, getCookie(c, CONFIRMATION_COOKIE));
  return typeof claims?.sub === 'string' ? ctx.users.findById(claims.sub) : null;
}

export function emailRoutes(app: Hono, ctx: AppContext, users: Users, webhook: WebhookClient): void {
  const emails = createEmails(ctx, users, webhook);

  app.post('/auth/email/send-verification', async (c) => {
    const data = await body(c);
    const target = redirectTarget(ctx, c, data.redirectTo);
    if (target instanceof Response) return target;
    // Without an address: the sign-up through a provider that the confirmation cookie names.
    const pending = data.email === undefined ? await confirmationOf(c, ctx) : null;
    if (!pending && !isValidEmail(data.email)) return error(c, 400, 'invalid_email', 'This is not a valid e-mail address.');
    const user = pending ?? (await users.findByEmail(normalizeEmail(data.email as string)));
    // Only for an address nobody confirmed yet, and only if its method is on; the answer is the same either way.
    if (user && !user.emailVerified && (await ctx.enabled(c, await signUpMethodOf(users, user)))) {
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
    const token = typeof data.token === 'string' && data.token ? data.token : null;
    const peeked = token ? await users.peekLinkToken(token, 'verify') : null;
    // A code without an address: the sign-up through a provider that the confirmation cookie names.
    const pending = !token && data.email === undefined ? await confirmationOf(c, ctx) : null;
    const waiting = token
      ? peeked
        ? await users.findById(peeked)
        : null
      : pending ?? (isValidEmail(data.email) ? await users.findByEmail(normalizeEmail(data.email)) : null);
    if (waiting && !(await ctx.enabled(c, await signUpMethodOf(users, waiting)))) return disabled(c);
    const consumed =
      pending && typeof data.code === 'string'
        ? { ...(await users.consumeCode(pending, 'verify', data.code.replace(/\s/g, ''))), via: 'code' as const }
        : await emails.consume(data, 'verify');
    const { userId, via } = consumed;
    const user = userId ? await users.findById(userId) : null;
    if (!user) return emails.invalidVerification(c, consumed);
    const method = await signUpMethodOf(users, user);
    if (!(await ctx.enabled(c, method))) return disabled(c);
    // The address is proven for this sign-up: what another unfinished sign-up set with it (perhaps someone
    // else's) goes; this sign-up's own password or provider account stays.
    if (!user.emailVerified) await users.dropUnprovenAccounts(user.id, method);
    deleteCookie(c, CONFIRMATION_COOKIE, confirmationCookie(ctx.secure));
    // Using a link or a code proves access to the inbox, so wrong codes are counted from zero again.
    await users.updateUser(user.id, { emailVerified: true, wrongCodes: 0 });
    // Confirming finishes a sign-up: one from before `user.signed_up` existed gets it too.
    const verified = { ...(user.emailVerified ? user : await users.reopenSignUp(user)), emailVerified: true, wrongCodes: 0 };
    await ctx.emit('user.email_verified', { user: toMadauthUser(verified), method, via });
    // A password user is signed in (or asked for their code), as is one of a provider, by its id; a sign-up
    // with the app or a passkey sets it up now.
    const amr = method === 'password' ? ['pwd'] : isProviderId(method) ? [method] : [];
    return signInAnswer(c, await ctx.secondStep(c, verified, amr, method));
  });
}
