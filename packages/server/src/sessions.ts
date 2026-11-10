// The sessions of the users: a record per session at a browser, which users and admins list and end. A session's
// tokens carry its id (`sid`); a renewal finds the record or ends the session. Ending it deletes the record, so it
// stops at its next renewal, within SESSION_TTL: the session token itself is checked by backends without madAuth.
import { createHash } from 'node:crypto';
import type { Device } from './device.js';
import type { Row, StoreAdapter } from './store/schema.js';
import { randomString } from './tokens.js';

/** A session as stored, see the `session` model in store/schema.ts. */
export interface StoredSession {
  id: string;
  userId: string;
  sessionVersion: number;
  /** Seconds since 1970; null for a session from before madAuth 0.6. */
  authTime: number | null;
  /** Separated by spaces. */
  amr: string;
  ip: string | null;
  browser: string | null;
  os: string | null;
  createdAt: number;
  renewedAt: number;
  expiresAt: number;
}

/** A session as its user and the admins see it. */
export interface SessionInfo {
  /** Its id (`ses_…`), which ending it takes and `user.session_ended` names. */
  id: string;
  /** Whether it is the session of the request that asked. */
  current: boolean;
  browser: string | null;
  os: string | null;
  ip: string | null;
  /** When the user signed in, in milliseconds since 1970; null for a session from before madAuth 0.6. */
  signedInAt: number | null;
  /** How the user signed in (RFC 8176), e.g. `['pwd', 'otp']`. */
  amr: string[];
  /** When the record was made: the sign-in, or the first renewal of a session from before madAuth 0.7.5. */
  createdAt: number;
  /** When the session was last renewed: the user was active within SESSION_TTL of it. */
  lastActiveAt: number;
  /** When it ends unless it is renewed. */
  expiresAt: number;
}

/** The start of every session id. */
export const SESSION_ID_PREFIX = 'ses_';

/** A new session id: `ses_` and 16 random bytes. */
export const newSessionId = (): string => `${SESSION_ID_PREFIX}${randomString(16)}`;

/**
 * The id of a session from before madAuth 0.7.5, whose renewal token has no `sid`: the same for every renewal with
 * that token, so two renewals at once make one record.
 */
export const legacySessionId = (renewalToken: string): string =>
  `${SESSION_ID_PREFIX}${createHash('sha256').update(renewalToken).digest('base64url').slice(0, 22)}`;

/** How often an instance at most deletes the expired sessions of every user (with a store that has `deleteExpired`). */
export const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;

export const sessionInfo = (session: StoredSession, currentId: string | null): SessionInfo => ({
  id: session.id,
  current: session.id === currentId,
  browser: session.browser,
  os: session.os,
  ip: session.ip,
  signedInAt: session.authTime === null ? null : session.authTime * 1000,
  amr: session.amr.split(' ').filter(Boolean),
  createdAt: session.createdAt,
  lastActiveAt: session.renewedAt,
  expiresAt: session.expiresAt,
});

/** A new session of a user: who, with which session version, and how and when they signed in. */
export interface NewSession {
  id: string;
  userId: string;
  sessionVersion: number;
  authTime: number | null;
  amr: string[];
  device: Device;
}

export class Sessions {
  private cleanedAt = 0;

  constructor(
    private readonly store: StoreAdapter,
    private readonly renewalTtlMs: number,
  ) {}

  /**
   * Records a new session. Resolves to false if one with this id exists already (only a legacy id repeats).
   * Deletes the user's sessions that ended meanwhile, and now and then those of every user that expired.
   */
  async start(session: NewSession): Promise<boolean> {
    const now = Date.now();
    const record: StoredSession = {
      id: session.id,
      userId: session.userId,
      sessionVersion: session.sessionVersion,
      authTime: session.authTime,
      amr: session.amr.join(' '),
      ...session.device,
      createdAt: now,
      renewedAt: now,
      expiresAt: now + this.renewalTtlMs,
    };
    const created = await this.store.create('session', record as unknown as Row);
    await Promise.all([this.dropEnded(session.userId, session.sessionVersion), this.cleanUp(now)]);
    return created;
  }

  /**
   * Renews a session of the user: moves its expiry on and records the device anew. Resolves to false if it is gone,
   * i.e. it has ended. `sessionVersion` replaces the stored one, after a change that keeps this session.
   */
  async renew(id: string, userId: string, device: Device, sessionVersion?: number): Promise<boolean> {
    const now = Date.now();
    const patch = { ...device, renewedAt: now, expiresAt: now + this.renewalTtlMs, ...(sessionVersion === undefined ? {} : { sessionVersion }) };
    return (await this.store.update('session', { id, userId }, patch)) === 1;
  }

  /** The user's sessions that are still going (with their session version of now), the newest activity first. */
  async list(userId: string, sessionVersion: number): Promise<StoredSession[]> {
    const all = (await this.store.findMany('session', { userId })) as unknown as StoredSession[];
    const now = Date.now();
    return all.filter((session) => isGoing(session, sessionVersion, now)).sort((a, b) => b.renewedAt - a.renewedAt);
  }

  /** Ends a session of the user: resolves to it if this request deleted it, null if it was gone. */
  async end(userId: string, id: string): Promise<StoredSession | null> {
    const session = (await this.store.findOne('session', { id, userId })) as unknown as StoredSession | null;
    return session && (await this.store.delete('session', { id, userId })) === 1 ? session : null;
  }

  /** Ends every session of the user but `except`: resolves to those this request deleted that were still going. */
  async endAll(userId: string, sessionVersion: number | null, except?: string | null): Promise<StoredSession[]> {
    const all = (await this.store.findMany('session', { userId })) as unknown as StoredSession[];
    const now = Date.now();
    const ended = await Promise.all(
      all
        .filter((session) => session.id !== except)
        .map(async (session) => ((await this.store.delete('session', { id: session.id })) === 1 && (sessionVersion === null || isGoing(session, sessionVersion, now)) ? [session] : [])),
    );
    return ended.flat();
  }

  /** Deletes the user's sessions that ended without being deleted: expired, or from before their session version. */
  private async dropEnded(userId: string, sessionVersion: number): Promise<void> {
    const all = (await this.store.findMany('session', { userId })) as unknown as StoredSession[];
    const now = Date.now();
    await Promise.all(all.filter((session) => !isGoing(session, sessionVersion, now)).map((session) => this.store.delete('session', { id: session.id })));
  }

  /** At most once per CLEANUP_INTERVAL_MS per instance: the expired sessions of every user, with a store that can. */
  private async cleanUp(now: number): Promise<void> {
    if (!this.store.deleteExpired || now - this.cleanedAt < CLEANUP_INTERVAL_MS) return;
    this.cleanedAt = now;
    await this.store.deleteExpired('session', now).catch((e: unknown) => {
      console.error(`[madauth] Could not delete the expired sessions, tried again in an hour: ${(e as Error).message}`);
    });
  }
}

/** Whether a session still goes: not expired, and of the user's session version of now. */
const isGoing = (session: StoredSession, sessionVersion: number, now: number): boolean => session.expiresAt > now && session.sessionVersion === sessionVersion;
