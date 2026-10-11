// The challenge cookie: carries a sign-in from its first step to its second (a code from the authenticator
// app, a code by SMS, or the app's setup). Shared by the totp and sms routes.
import type { Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { JWTPayload } from 'jose';
import type { AppContext } from '../app.js';
import { isOn, type SignInMethod } from '../settings.js';
import { readToken, signToken } from '../tokens.js';
import { toMadauthUser, type StoredUser } from '../users.js';
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

/** A second factor: a code from the authenticator app, or one sent by SMS. */
export type Factor = 'totp' | 'sms';

/**
 * What a sign-in still needs after its primary method succeeded: a code from the app, a code by SMS, or
 * setting the app up (or, when SMS codes are on, adding a phone instead).
 */
export type NextStep = 'totp' | 'totp-setup' | 'sms';

/** How the second step was passed, for `user.signed_in`. */
export type SecondFactorVia = 'totp' | 'recovery_code' | 'sms';

/**
 * The challenge cookie: who passed the first step, how (`amr`, empty for a sign-up with the app), what comes
 * next, which factors the user can finish with, and what the method knows beyond the record (Google's name
 * and picture), for the session.
 */
export interface Challenge {
  sub: string;
  sv: number;
  amr: string[];
  method: SignInMethod;
  next: NextStep;
  factors: Factor[];
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
 * step: a code (`totp`, `sms`) needs the factor among the challenge's, so a user who has both can switch;
 * the setup needs `next` to be it.
 */
export async function readChallenge(c: Context, ctx: AppContext, step: NextStep): Promise<ChallengeClaims | null> {
  const claims = await readToken<ChallengeClaims>(await ctx.keys, ctx.config.issuer, CHALLENGE_TYP, getCookie(c, CHALLENGE_COOKIE));
  if (!claims || typeof claims.sub !== 'string' || !Array.isArray(claims.amr)) return null;
  const factors = Array.isArray(claims.factors) ? claims.factors : [];
  const fits = step === 'totp-setup' ? claims.next === 'totp-setup' : factors.includes(step);
  return fits ? claims : null;
}

/** A challenge finishes only if the method it belongs to is still on: an admin may have switched it off meanwhile. */
export const methodStillOn = async (c: Context, ctx: AppContext, challenge: Challenge): Promise<boolean> =>
  isOn(challenge.method, ctx.configured, await ctx.methods(c));

export const methodOff = (c: Context): Response => error(c, 403, 'method_disabled', 'This way of signing in is switched off.');

/**
 * Who sets a second factor up: the user whose sign-in waits for the setup (the challenge, the latest sign-in
 * at this browser), else the signed-in user. Starting a session ends the challenge, so an abandoned one
 * can't outlive a later sign-in. A challenge from before a password reset no longer counts.
 */
export async function pendingOrSignedIn(c: Context, ctx: AppContext): Promise<{ user: StoredUser; challenge: ChallengeClaims | null } | null> {
  const challenge = await readChallenge(c, ctx, 'totp-setup');
  const waiting = challenge ? await ctx.users.findById(challenge.sub) : null;
  if (challenge && waiting && waiting.sessionVersion === challenge.sv) return { user: waiting, challenge };
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
  amr: 'otp' | 'sms',
  via: SecondFactorVia,
): Promise<MadauthUser> {
  const result = await ctx.startSession(c, toMadauthUser(user, challenge.profile), [...challenge.amr, amr], { method: challenge.method, signedUpAt: user.signedUpAt }, { sv: user.sessionVersion });
  // For a sign-up with the app, the app is the method itself, not a second factor.
  await ctx.emit('user.signed_in', { user: result, method: challenge.method, ...(challenge.amr.length ? { secondFactor: via } : {}) });
  return result;
}
