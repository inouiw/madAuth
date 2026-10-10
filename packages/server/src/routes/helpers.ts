// Small helpers the route modules share: reading the body, the shape of errors, and common answers.
import type { Context } from 'hono';
import type { AppContext, SignInStep } from '../app.js';

export type Body = Record<string, unknown>;

/** The request's JSON body as an object; empty if it is none. */
export async function body(c: Context): Promise<Body> {
  const data = await c.req.json<unknown>().catch(() => null);
  return data && typeof data === 'object' ? (data as Body) : {};
}

export function error(c: Context, status: 400 | 401 | 403 | 404 | 429 | 503, code: string, message: string): Response {
  return c.json({ error: code, message }, status);
}

/** The webhook did not take over an e-mail or did not answer the sign-up check. */
export const unavailable = (c: Context): Response =>
  error(c, 503, 'temporarily_unavailable', 'E-mails can not be sent right now. Please try again later.');

/** Every accepted request for an e-mail answers the same way, whether or not a mail was sent. */
export const accepted = (c: Context): Response => c.json({}, 202);

export const noSession = (c: Context): Response => error(c, 401, 'no_session', 'Please sign in first.');

export function redirectTarget(ctx: AppContext, c: Context, value: unknown): URL | Response {
  const url = ctx.allowedUrl(value);
  return url ?? error(c, 400, 'invalid_options', 'redirectTo must be an absolute URL whose origin is in ALLOWED_ORIGINS.');
}

const MAX_NAME_LENGTH = 100;

/** A name as given at sign-up: trimmed and cut, or null if there is none. */
export function nameOf(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim().slice(0, MAX_NAME_LENGTH) : null;
}

/**
 * The answer after a primary sign-in method succeeded: the user with their session, or what the sign-in
 * still needs (a 401 whose error names the next step; the challenge cookie is set already).
 */
export function signInAnswer(c: Context, step: SignInStep): Response {
  if ('disabled' in step) return error(c, 403, 'method_disabled', 'This way of signing in is switched off.');
  if ('next' in step) {
    return step.next === 'totp'
      ? error(c, 401, 'totp_required', 'Enter the code from your authenticator app to finish signing in.')
      : error(c, 401, 'totp_setup_required', 'Set up an authenticator app to finish signing in.');
  }
  return c.json({ user: step.user });
}
