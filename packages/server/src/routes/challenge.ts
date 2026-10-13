// The challenge cookie: carries a sign-in from its first step to its second (a passkey, a code from the
// authenticator app, a code by SMS, or setting one of them up). Shared by the passkey, totp and sms routes.
import type { Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { JWTPayload } from 'jose';
import type { AppContext } from '../app.js';
import { factorsOn, requiringSecondFactor, signsIn, type MethodWithSecondFactor, type SecondFactor, type SignInMethod } from '../settings.js';
import { readToken, signToken } from '../tokens.js';
import { factorsAmong, toMadauthUser, type StoredAccount, type StoredUser } from '../users.js';
import type { MadauthUser } from '../user.js';
import { error } from './helpers.js';

/** The cookie that carries a sign-in from its first step to its second. */
export const CHALLENGE_COOKIE = 'madauth_challenge';
export const CHALLENGE_TYP = 'madauth-challenge+jwt';
/** How long the second step may take. */
export const CHALLENGE_TTL = 10 * 60;

/** The cookie is sent to every /auth route: the app's and the SMS's. */
const COOKIE_PATH = '/auth';
/** Where madAuth 0.4 set it: deleted there as well, so a cookie from before an upgrade doesn't linger. */
const LEGACY_COOKIE_PATH = '/auth/totp';

/** A second factor: a passkey, a code from the authenticator app, or one sent by SMS. */
export type Factor = SecondFactor;

/**
 * What a sign-in still needs after its first step succeeded: a passkey, a code from the app, a code by SMS,
 * or setting a second factor up (`totp-setup`, named after the only one there was at first: the challenge's
 * `setup` says which can be set up).
 */
export type NextStep = 'passkey' | 'totp' | 'totp-setup' | 'sms';

/** How the second step was passed, for `user.signed_in`. */
export type SecondFactorVia = 'passkey' | 'totp' | 'recovery_code' | 'sms';

/**
 * The challenge cookie: who passed the first step, how (`amr`, empty for a sign-up with the app), what comes
 * next, which factors the user can finish with, which they can set up when the setup is next (absent in
 * cookies from before madAuth 0.6: the app or a phone), and what the method knows beyond the record (Google's
 * name and picture), for the session.
 */
export interface Challenge {
  sub: string;
  sv: number;
  amr: string[];
  method: SignInMethod;
  next: NextStep;
  factors: Factor[];
  setup?: Factor[];
  profile?: { name?: string; picture?: string };
}

export type ChallengeClaims = Challenge & JWTPayload;

const cookieOptions = (secure: boolean) => ({ path: COOKIE_PATH, httpOnly: true, secure, sameSite: 'Strict' as const });

/** Sets the challenge cookie: the sign-in goes on with its second step within CHALLENGE_TTL. */
export async function setChallenge(c: Context, ctx: AppContext, challenge: Challenge): Promise<void> {
  const token = await signToken(await ctx.keys, ctx.config.issuer, CHALLENGE_TYP, { ...challenge }, CHALLENGE_TTL);
  setCookie(c, CHALLENGE_COOKIE, token, { ...cookieOptions(ctx.secure), maxAge: CHALLENGE_TTL });
}

/** Ends the challenge, if any: a session was started, or the user signed out. */
export function clearChallenge(c: Context, secure: boolean): void {
  deleteCookie(c, CHALLENGE_COOKIE, cookieOptions(secure));
  deleteCookie(c, CHALLENGE_COOKIE, { ...cookieOptions(secure), path: LEGACY_COOKIE_PATH });
}

/**
 * The request's challenge for this step, or null if there is none, it expired, or it waits for another
 * step: a factor (`passkey`, `totp`, `sms`) needs to be among the challenge's, so a user who has several can
 * switch; the setup needs `next` to be it.
 */
export async function readChallenge(c: Context, ctx: AppContext, step: NextStep): Promise<ChallengeClaims | null> {
  const claims = await readToken<ChallengeClaims>(await ctx.keys, ctx.config.issuer, CHALLENGE_TYP, getCookie(c, CHALLENGE_COOKIE));
  if (!claims || typeof claims.sub !== 'string' || !Array.isArray(claims.amr)) return null;
  const factors = Array.isArray(claims.factors) ? claims.factors : [];
  const fits = step === 'totp-setup' ? claims.next === 'totp-setup' : factors.includes(step);
  return fits ? claims : null;
}

/** A challenge finishes only if the method it belongs to still signs in: an admin may have switched it off meanwhile. */
export const methodStillOn = async (c: Context, ctx: AppContext, challenge: Challenge): Promise<boolean> =>
  signsIn(challenge.method, ctx.configured, await ctx.methods(c));

export const methodOff = (c: Context): Response => error(c, 403, 'method_disabled', 'This way of signing in is switched off.');

/** The sign-in that waits for the setup of `factor`, with its user; null if there is none (any more). */
export async function pendingSetup(c: Context, ctx: AppContext, factor: Factor): Promise<{ user: StoredUser; challenge: ChallengeClaims } | null> {
  const pending = await readChallenge(c, ctx, 'totp-setup');
  // A cookie from before madAuth 0.6 names no factors: the app or a phone could be set up then.
  const challenge = pending && (Array.isArray(pending.setup) ? pending.setup.includes(factor) : factor !== 'passkey') ? pending : null;
  const waiting = challenge ? await ctx.users.findById(challenge.sub) : null;
  return challenge && waiting && waiting.sessionVersion === challenge.sv ? { user: waiting, challenge } : null;
}

/**
 * Who sets a second factor up: the user whose sign-in waits for the setup of `factor` (the challenge, the
 * latest sign-in at this browser), else the signed-in user. Starting a session ends the challenge, so an
 * abandoned one can't outlive a later sign-in. A challenge from before a password reset no longer counts.
 */
export async function pendingOrSignedIn(
  c: Context,
  ctx: AppContext,
  factor: Factor,
): Promise<{ user: StoredUser; challenge: ChallengeClaims | null } | null> {
  const pending = await pendingSetup(c, ctx, factor);
  if (pending) return pending;
  const session = await ctx.currentUser(c);
  const user = session ? await ctx.users.findById(session.id) : null;
  return user ? { user, challenge: null } : null;
}

/** Finishes a sign-in whose second step is done: the session, with the factor in `amr`. */
export async function finishSignIn(
  c: Context,
  ctx: AppContext,
  user: StoredUser,
  challenge: ChallengeClaims,
  amr: 'otp' | 'sms' | 'passkey',
  via: SecondFactorVia,
): Promise<MadauthUser> {
  const result = await ctx.startSession(c, toMadauthUser(user, challenge.profile), [...challenge.amr, amr], { method: challenge.method, signedUpAt: user.signedUpAt }, { sv: user.sessionVersion });
  // For a sign-up with the app, the app is the method itself, not a second factor.
  await ctx.emit('user.signed_in', { user: result, method: challenge.method, ...(challenge.amr.length ? { secondFactor: via } : {}) });
  return result;
}

/** How a message names the methods whose policy can require a second factor. A method without a name here does not compile. */
const POLICY_NAMES = {
  google: 'Google',
  github: 'GitHub',
  password: 'e-mail & password',
  'email-link': 'the e-mail link',
  passkey: 'a passkey',
} satisfies Record<MethodWithSecondFactor, string>;

/**
 * Why the signed-in user can't do without `factor` (all their passkeys; with `keepsOne`, one of several), as
 * the answer to send; null if they can. Each method whose policy is `required` needs a second factor the user
 * keeps, which is on and isn't the method itself (a passkey is no second factor of a passkey sign-in); the
 * passkeys' own policy doesn't count once the last passkey goes. `accounts` are the user's, if read already.
 * `what` names the factor in the message.
 */
export async function requiredByPolicy(
  c: Context,
  ctx: AppContext,
  userId: string,
  factor: Factor,
  what: string,
  options: { keepsOne?: boolean; accounts?: StoredAccount[] } = {},
): Promise<Response | null> {
  const { keepsOne = false } = options;
  const methods = await ctx.methods(c);
  const required = requiringSecondFactor(ctx.configured, methods);
  if (!required.length) return null;
  const on = factorsOn(ctx.configured, methods);
  const has = options.accounts ? factorsAmong(options.accounts, on) : await ctx.users.secondFactors(userId, on);
  const left = keepsOne ? has : has.filter((f) => f !== factor);
  const lacking = required.filter((method) => (keepsOne || method !== factor) && !left.some((f) => f !== method));
  if (!lacking.length) return null;
  const names = lacking.map((method) => POLICY_NAMES[method]).join(' and ');
  return error(c, 403, 'required_by_policy', `Signing in with ${names} requires a second factor, so ${what} can't be removed. Set up another second factor first, or delete your account.`);
}
