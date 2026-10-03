/** The signed-in user as returned to apps. */
export interface MadauthUser {
  /** Stable id, e.g. `google:<sub>`. */
  id: string;
  email?: string;
  name?: string;
  picture?: string;
  /** The roles of the user's e-mail address, e.g. `['admin']`. Absent without roles. */
  roles?: string[];
}

/** Name of the cookie that holds the madAuth session JWT. */
export const SESSION_COOKIE = 'madauth_session';

/** JWT `typ` header of madAuth session tokens, so other madAuth tokens can't be used as a session. */
export const SESSION_TYP = 'madauth-session+jwt';
