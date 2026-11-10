import { ok, type Result } from '../result.js';
import { serverCalls, type Core } from './core.js';

/** A session of a user at a browser, as the server recorded it at its last renewal. */
export interface SessionInfo {
  /** Its id (`ses_…`), which {@link SessionsApi.end} takes; the `user.session_ended` webhook names it. */
  id: string;
  /** Whether it is the session of this browser. */
  current: boolean;
  /** e.g. `Firefox`; null when the server doesn't know the browser. */
  browser: string | null;
  /** e.g. `macOS`; null when the server doesn't know the system. */
  os: string | null;
  /** The browser's IP address; null when the server can't tell it. */
  ip: string | null;
  /** When the user signed in, in milliseconds since 1970; null for a session from before madAuth 0.6. */
  signedInAt: number | null;
  /** How the user signed in (RFC 8176), e.g. `['pwd', 'otp']`. */
  amr: string[];
  /** When the server recorded it: the sign-in, or the first renewal of a session from before madAuth 0.7.5. */
  createdAt: number;
  /** When it was last renewed: the user was active at most the session lifetime (8 hours by default) after it. */
  lastActiveAt: number;
  /** When it ends unless it is renewed. */
  expiresAt: number;
}

/**
 * The signed-in user's sessions: where they are signed in, and ending a session. An ended session stops at its
 * next renewal, so within the session lifetime (8 hours by default); its session token works at your backend until
 * then, unless the backend keeps a list of ended sessions from the `user.session_ended` webhook.
 * `Madauth.showManageSignInMethodsDialog()` shows them under "Sessions".
 */
export interface SessionsApi {
  /** The user's sessions, the current one first, then by the latest activity. Fails with `no_session`. */
  list(): Promise<Result<{ sessions: SessionInfo[] }>>;
  /**
   * Ends a session; ending the current one signs this browser out. Only within two minutes of signing in, else it
   * fails with `reauth_required`. Fails with `session_not_found` (gone already) or `no_session`.
   */
  end(id: string): Promise<Result>;
  /** Ends every session but the current one; `ended` says how many. Needs a recent sign-in like {@link end}. */
  endOthers(): Promise<Result<{ ended: number }>>;
}

export function createSessionsApi(core: Core): SessionsApi {
  const call = serverCalls(core);

  return {
    async list() {
      const result = await call<{ sessions: SessionInfo[] }>('/auth/sessions', { method: 'GET', session: true });
      return result.isSuccess ? ok({ sessions: result.sessions }) : result;
    },
    async end(id) {
      const result = await call('/auth/sessions/end', { body: { id }, session: true });
      return result.isSuccess ? ok() : result;
    },
    async endOthers() {
      const result = await call<{ ended: number }>('/auth/sessions/end-others', { body: {}, session: true });
      return result.isSuccess ? ok({ ended: result.ended }) : result;
    },
  };
}
