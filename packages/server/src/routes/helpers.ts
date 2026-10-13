// Small helpers the route modules share: reading the body, the shape of errors, and common answers.
import type { Context } from 'hono';
import type { AppContext, SignInStep } from '../app.js';
import type { StoredUser } from '../users.js';

export type Body = Record<string, unknown>;

/** The request's JSON body as an object; empty if it is none. */
export async function body(c: Context): Promise<Body> {
  const data = await c.req.json<unknown>().catch(() => null);
  return data && typeof data === 'object' ? (data as Body) : {};
}

export function error(c: Context, status: 400 | 401 | 403 | 404 | 409 | 429 | 503, code: string, message: string): Response {
  return c.json({ error: code, message }, status);
}

/** The webhook did not take over an e-mail or did not answer the sign-up check. */
export const unavailable = (c: Context): Response =>
  error(c, 503, 'temporarily_unavailable', 'E-mails can not be sent right now. Please try again later.');

/** The webhook did not take over an SMS. */
export const smsUnavailable = (c: Context): Response =>
  error(c, 503, 'temporarily_unavailable', 'The SMS can not be sent right now. Please try again later.');

/** The host of the app that made the request (its Origin), else the server's: what a message names as the site. */
export function originHost(ctx: AppContext, c: Context): string {
  const origin = c.req.header('origin');
  return URL.canParse(origin ?? '') ? new URL(origin!).hostname : new URL(ctx.config.issuer).hostname;
}

/** Every accepted request for an e-mail answers the same way, whether or not a mail was sent. */
export const accepted = (c: Context): Response => c.json({}, 202);

export const noSession = (c: Context): Response => error(c, 401, 'no_session', 'Please sign in first.');

/**
 * How recently the user must have signed in to change how they sign in: add or remove a method. A session
 * that someone took over can then not give its thief a way in of their own.
 */
export const RECENT_SIGN_IN_MS = 10 * 60 * 1000;

/** The signed-in user as stored, and whether they signed in within RECENT_SIGN_IN_MS (renewals don't count); null without a session. */
export async function signedInUser(c: Context, ctx: AppContext): Promise<{ user: StoredUser; recent: boolean } | null> {
  const signIn = await ctx.currentSignIn(c);
  if (!signIn) return null;
  const user = await ctx.users.findById(signIn.user.id);
  const { signedInAt } = signIn;
  return user ? { user, recent: signedInAt !== null && Date.now() - signedInAt <= RECENT_SIGN_IN_MS } : null;
}

/** The signed-in user if they signed in recently, else why not: for the routes that change how a user signs in. */
export async function recentSignIn(c: Context, ctx: AppContext): Promise<StoredUser | 'no_session' | 'reauth_required'> {
  const signedIn = await signedInUser(c, ctx);
  return !signedIn ? 'no_session' : signedIn.recent ? signedIn.user : 'reauth_required';
}

/** {@link recentSignIn} with the answer to send when not. */
export async function recentUser(c: Context, ctx: AppContext): Promise<StoredUser | Response> {
  const result = await recentSignIn(c, ctx);
  if (result === 'no_session') return noSession(c);
  return result === 'reauth_required' ? reauthRequired(c) : result;
}

/** The answer when a change to how the user signs in needs a recent sign-in. */
export const reauthRequired = (c: Context): Response =>
  error(c, 401, 'reauth_required', 'For your security, sign in again to change how you sign in.');

export function redirectTarget(ctx: AppContext, c: Context, value: unknown): URL | Response {
  const url = ctx.allowedUrl(value);
  return url ?? error(c, 400, 'invalid_options', 'redirectTo must be an absolute URL whose origin is in ALLOWED_ORIGINS.');
}

const MAX_NAME_LENGTH = 100;

/** A name as given, e.g. at sign-up: trimmed and cut to `maxLength`, or null if there is none. */
export function nameOf(value: unknown, maxLength = MAX_NAME_LENGTH): string | null {
  return typeof value === 'string' && value.trim() ? value.trim().slice(0, maxLength) : null;
}

/**
 * The answer after a primary sign-in method succeeded: the user with their session, or what the sign-in
 * still needs (a 401 whose error names the next step; the challenge cookie is set already).
 */
export function signInAnswer(c: Context, step: SignInStep): Response {
  if ('disabled' in step) return error(c, 403, 'method_disabled', 'This way of signing in is switched off.');
  if ('next' in step) {
    // `method` says which sign-in goes on, for a client that learns of the step later (e.g. after a redirect);
    // `factors` which second factors the user can finish it with, so the client can offer a switch.
    const rest = { method: step.method, factors: step.factors };
    if (step.next === 'totp') return c.json({ error: 'totp_required', message: 'Enter the code from your authenticator app to finish signing in.', ...rest }, 401);
    if (step.next === 'sms') return c.json({ error: 'sms_required', message: 'Enter the code we sent to your phone to finish signing in.', ...rest }, 401);
    if (step.next === 'passkey') return c.json({ error: 'passkey_required', message: 'Confirm with your passkey to finish signing in.', ...rest }, 401);
    // `factors` are the second factors the user can set up here.
    return c.json({ error: 'totp_setup_required', message: 'Set up a second factor to finish signing in.', ...rest }, 401);
  }
  return c.json({ user: step.user });
}
