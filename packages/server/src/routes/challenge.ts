// The challenge cookie: carries a sign-in from its first step to its second (a passkey, a code from the
// authenticator app, a code by SMS, or setting one of them up). Shared by the passkey, authenticator and sms routes.
import type { Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { JWTPayload } from 'jose';
import type { AppContext } from '../app.js';
import type { SecondFactor, SignInMethod } from '../settings.js';
import { readToken, signToken } from '../tokens.js';
import { toMadauthUser, type StoredUser } from '../users.js';
import type { MadauthUser } from '../user.js';
import { error, noSession, reauthRequired, signedInUser } from './helpers.js';

/** The cookie that carries a sign-in from its first step to its second. */
export const CHALLENGE_COOKIE = 'madauth_challenge';
export const CHALLENGE_TYP = 'madauth-challenge+jwt';
/** How long the second step may take. */
export const CHALLENGE_TTL = 10 * 60;

/** The cookie is sent to every /auth route: the app's and the SMS's. */
const COOKIE_PATH = '/auth';
/** Where madAuth 0.4 set it: deleted there as well, so a cookie from before an upgrade doesn't linger. */
const LEGACY_COOKIE_PATH = '/auth/totp';

/**
 * What a sign-in still needs after its first step succeeded: a passkey, a code from the app, a code by SMS,
 * or a setup, of which the challenge's `setup` names what can be set up. `second-factor-setup`: a policy
 * requires a second factor the user doesn't have, and they choose one. `<method>-setup`: a sign-up creates
 * that method now (`authenticator-setup`: the sign-up with the app alone, after the address is confirmed).
 */
export type NextStep = 'passkey' | 'authenticator' | 'sms' | 'second-factor-setup' | 'authenticator-setup';

/** The steps that set something up rather than check it: the challenge's `setup` says what. */
const SETUP_STEPS: readonly NextStep[] = ['second-factor-setup', 'authenticator-setup'];
export const isSetupStep = (step: unknown): boolean => SETUP_STEPS.includes(step as NextStep);

/** How the second step was passed, for `user.signed_in`. */
export type SecondFactorVia = 'passkey' | 'authenticator' | 'recovery_code' | 'sms';

/**
 * The challenge cookie: who passed the first step, how (`amr`, empty for a sign-up with the app), what comes
 * next, which factors the user can finish with, which they can set up when the setup is next, and what the
 * method knows beyond the record (Google's name and picture), for the session.
 */
export interface Challenge {
  sub: string;
  sv: number;
  amr: string[];
  method: SignInMethod;
  next: NextStep;
  factors: SecondFactor[];
  setup?: SecondFactor[];
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
 * step: a factor (`passkey`, `authenticator`, `sms`) needs to be among the challenge's, so a user who has
 * several can switch; `setup` needs `next` to be a setup step.
 */
export async function readChallenge(c: Context, ctx: AppContext, step: SecondFactor | 'setup'): Promise<ChallengeClaims | null> {
  const claims = await readToken<ChallengeClaims>(await ctx.keys, ctx.config.issuer, CHALLENGE_TYP, getCookie(c, CHALLENGE_COOKIE));
  if (!claims || typeof claims.sub !== 'string' || !Array.isArray(claims.amr)) return null;
  const factors = Array.isArray(claims.factors) ? claims.factors : [];
  const fits = step === 'setup' ? isSetupStep(claims.next) : factors.includes(step);
  return fits ? claims : null;
}

/** A challenge finishes only if the method it belongs to still signs in: an admin may have switched it off meanwhile. */
export const methodStillOn = (c: Context, ctx: AppContext, challenge: Challenge): Promise<boolean> => ctx.enabled(c, challenge.method);

export const methodOff = (c: Context): Response => error(c, 403, 'method_disabled', 'This way of signing in is switched off.');

/** The sign-in that waits for the setup of `factor`, with its user; null if there is none (any more). */
export async function pendingSetup(c: Context, ctx: AppContext, factor: SecondFactor): Promise<{ user: StoredUser; challenge: ChallengeClaims } | null> {
  const pending = await readChallenge(c, ctx, 'setup');
  const challenge = pending && Array.isArray(pending.setup) && pending.setup.includes(factor) ? pending : null;
  const waiting = challenge ? await ctx.users.findById(challenge.sub) : null;
  return challenge && waiting && waiting.sessionVersion === challenge.sv ? { user: waiting, challenge } : null;
}

/**
 * Who sets `factor` up: the user whose sign-in waits for its setup (the challenge, the latest sign-in at
 * this browser), else the signed-in user; otherwise the answer to send. Starting a session ends the
 * challenge, so an abandoned one can't outlive a later sign-in, and one from before a password reset no
 * longer counts. A sign-up with the app has no first factor yet: it sets the app up, nothing else. A
 * signed-in user for whom `recent` holds (a factor that is a way in of its own) must have signed in within
 * the last ten minutes (`reauth_required`).
 */
export async function whoSetsUp(
  c: Context,
  ctx: AppContext,
  factor: SecondFactor,
  recent: (user: StoredUser) => Promise<boolean> = async () => false,
): Promise<{ user: StoredUser; challenge: ChallengeClaims | null } | Response> {
  const pending = await pendingSetup(c, ctx, factor);
  if (pending) {
    if (!pending.challenge.amr.length && factor !== 'authenticator') return noSession(c);
    return (await methodStillOn(c, ctx, pending.challenge)) ? pending : methodOff(c);
  }
  const signedIn = await signedInUser(c, ctx);
  if (!signedIn) return noSession(c);
  if (!signedIn.recent && (await recent(signedIn.user))) return reauthRequired(c);
  return { user: signedIn.user, challenge: null };
}

/**
 * The sign-in that waits for its second step with `factor`, with its user; otherwise the answer to send:
 * `challenge_expired` (none, too old, the user gone or a password reset since), `method_disabled` (an admin
 * switched the method off meanwhile).
 */
export async function pendingFactor(c: Context, ctx: AppContext, factor: SecondFactor): Promise<{ challenge: ChallengeClaims; user: StoredUser } | Response> {
  const expired = () => error(c, 401, 'challenge_expired', 'The sign-in has expired. Please sign in again.');
  const challenge = await readChallenge(c, ctx, factor);
  if (!challenge) return expired();
  if (!(await methodStillOn(c, ctx, challenge))) return methodOff(c);
  const user = await ctx.users.findById(challenge.sub);
  return user && user.sessionVersion === challenge.sv ? { challenge, user } : expired();
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
