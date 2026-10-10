/** The signed-in user as returned to apps. */
export interface MadauthUser {
  /** Stable id (`usr_…`), the same whichever way the user signs in. */
  id: string;
  email?: string;
  name?: string;
  picture?: string;
  /** What admins attached to the user, e.g. `{ roles: ['admin'] }`. Absent without claims. */
  claims?: Record<string, unknown>;
}

/** Name of the cookie that holds the madAuth session JWT. */
export const SESSION_COOKIE = 'madauth_session';

/** JWT `typ` header of madAuth session tokens, so other madAuth tokens can't be used as a session. */
export const SESSION_TYP = 'madauth-session+jwt';

/**
 * Name of the cookie that holds the renewal token: it gets a new session when the old one has expired.
 * It is only sent to the madAuth server (Path=/auth, no Domain), never to app backends.
 */
export const RENEWAL_COOKIE = 'madauth_renewal';

/** JWT `typ` header of renewal tokens. Backends verify sessions by their `typ`, so they never accept one. */
export const RENEWAL_TYP = 'madauth-renewal+jwt';

/**
 * Name of the cookie that tells the web library when the session expires (seconds since 1970) and, by
 * being there, that it can be renewed. Scripts can read it; it holds no secret.
 */
export const EXPIRY_COOKIE = 'madauth_session_expires';
