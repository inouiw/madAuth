// Everything madAuth stores, written once on top of the StoreAdapter. Routes never call the adapter directly.
import { randomBytes } from 'node:crypto';
import { generateCode, generateLinkToken, hashCode, hashLinkToken, safeEqual } from './password.js';
import type { Row, StoreAdapter } from './store/schema.js';

export interface StoredUser {
  id: string;
  email: string;
  emailNormalized: string;
  emailVerified: boolean;
  name: string | null;
  sessionVersion: number;
  lastMailAt: number;
  createdAt: number;
}

export interface StoredAccount {
  id: string;
  userId: string;
  key: string;
  secret: string | null;
  failedAttempts: number;
  lockedUntil: number;
  createdAt: number;
}

interface StoredVerification {
  id: string;
  userId: string;
  purpose: VerificationPurpose;
  codeHash: string;
  attempts: number;
  expiresAt: number;
}

export type VerificationPurpose = 'verify' | 'reset';

/** Wrong codes allowed per e-mail before the code (and its link) stop working. */
export const MAX_CODE_ATTEMPTS = 5;

const newId = (prefix: string) => `${prefix}_${randomBytes(16).toString('base64url')}`;

export function passwordAccountKey(userId: string): string {
  return `password:${userId}`;
}

export class Users {
  /** `codeKey` keys the e-mail codes (see deriveCodeKey); only needed to issue and check them. */
  constructor(
    private readonly store: StoreAdapter,
    private readonly codeKey?: Buffer,
  ) {}

  private get key(): Buffer {
    if (!this.codeKey) throw new Error('Users needs a code key to issue or check e-mail codes.');
    return this.codeKey;
  }

  async findByEmail(emailNormalized: string): Promise<StoredUser | null> {
    return (await this.store.findOne('user', { emailNormalized })) as StoredUser | null;
  }

  async findById(id: string): Promise<StoredUser | null> {
    return (await this.store.findOne('user', { id })) as StoredUser | null;
  }

  async passwordAccount(userId: string): Promise<StoredAccount | null> {
    return (await this.store.findOne('account', { key: passwordAccountKey(userId) })) as StoredAccount | null;
  }

  /** Creates a user with a password. Resolves to null if the e-mail address is taken. */
  async createPasswordUser(data: {
    email: string;
    emailNormalized: string;
    name: string | null;
    passwordHash: string;
    emailVerified: boolean;
  }): Promise<StoredUser | null> {
    const now = Date.now();
    const user: StoredUser = {
      id: newId('usr'),
      email: data.email,
      emailNormalized: data.emailNormalized,
      emailVerified: data.emailVerified,
      name: data.name,
      sessionVersion: 0,
      lastMailAt: 0,
      createdAt: now,
    };
    if (!(await this.store.create('user', user as unknown as Row))) return null;
    const account: StoredAccount = {
      id: newId('acc'),
      userId: user.id,
      key: passwordAccountKey(user.id),
      secret: data.passwordHash,
      failedAttempts: 0,
      lockedUntil: 0,
      createdAt: now,
    };
    if (!(await this.store.create('account', account as unknown as Row))) {
      await this.store.delete('user', { id: user.id });
      return null;
    }
    return user;
  }

  /**
   * Deletes the user with this e-mail address and everything stored for them. Resolves to false if there
   * is no such user (any more).
   */
  async deleteByEmail(emailNormalized: string): Promise<boolean> {
    const user = await this.findByEmail(emailNormalized);
    if (!user) return false;
    // The user record goes first: from then on nobody can sign in, and a sign-up with the address starts afresh.
    if ((await this.store.delete('user', { id: user.id })) !== 1) return false;
    // The user is gone now, so the deletion has to finish: a retry would find no session and send no event.
    // Records left behind belong to a user ID that no longer exists and are never read again.
    try {
      await this.store.delete('account', { userId: user.id });
      await this.store.delete('verification', { userId: user.id });
    } catch (e) {
      console.error(`[madauth] Deleted user ${user.id}, but not all of their records: ${(e as Error).message}`);
    }
    return true;
  }

  async updateUser(id: string, patch: Partial<Omit<StoredUser, 'id'>>): Promise<void> {
    await this.store.update('user', { id }, patch as Row);
  }

  async updateAccount(id: string, patch: Partial<Omit<StoredAccount, 'id'>>): Promise<void> {
    await this.store.update('account', { id }, patch as Row);
  }

  /**
   * Counts a sign-in attempt: writes `patch` only if the account's `failedAttempts` is still the value that
   * was read. Resolves to false if another request counted an attempt meanwhile.
   */
  async countAttempt(account: StoredAccount, patch: Pick<StoredAccount, 'failedAttempts' | 'lockedUntil'>): Promise<boolean> {
    const changed = await this.store.update('account', { id: account.id, failedAttempts: account.failedAttempts }, patch);
    return changed === 1;
  }

  /** Deletes the user's pending verifications and password resets; their links and codes stop working. */
  async clearVerifications(userId: string): Promise<void> {
    await this.store.delete('verification', { userId });
  }

  /**
   * Starts a verification or password reset: replaces the user's earlier one for the same purpose and
   * returns the link token and the code for the e-mail. Only their hashes are stored.
   */
  async issueVerification(userId: string, purpose: VerificationPurpose, ttlMs: number): Promise<{ token: string; code: string }> {
    await this.store.delete('verification', { userId, purpose });
    const token = generateLinkToken();
    const code = generateCode();
    const record: StoredVerification = {
      id: hashLinkToken(token),
      userId,
      purpose,
      codeHash: hashCode(this.key, code),
      attempts: 0,
      expiresAt: Date.now() + ttlMs,
    };
    await this.store.create('verification', record as unknown as Row);
    return { token, code };
  }

  /** Uses up the verification a link token belongs to. Resolves to its user ID, or null if invalid, expired or used. */
  async consumeLinkToken(token: string, purpose: VerificationPurpose): Promise<string | null> {
    const id = hashLinkToken(token);
    const record = (await this.store.findOne('verification', { id, purpose })) as StoredVerification | null;
    return record ? this.consume(record) : null;
  }

  /** Uses up the user's verification if `code` matches. Too many wrong codes delete it. */
  async consumeCode(userId: string, purpose: VerificationPurpose, code: string): Promise<string | null> {
    const record = (await this.store.findOne('verification', { userId, purpose })) as StoredVerification | null;
    if (!record) return null;
    // The attempt is counted before the code is compared, and only if no other request counted one
    // meanwhile. So requests sent at the same time can't try more codes than allowed.
    const attempts = record.attempts + 1;
    if ((await this.store.update('verification', { id: record.id, attempts: record.attempts }, { attempts })) !== 1) return null;
    if (!safeEqual(hashCode(this.key, code), record.codeHash)) {
      if (attempts >= MAX_CODE_ATTEMPTS) await this.store.delete('verification', { id: record.id });
      return null;
    }
    return this.consume(record);
  }

  private async consume(record: StoredVerification): Promise<string | null> {
    // The delete count decides, so two requests with the same link or code can't both succeed.
    const deleted = await this.store.delete('verification', { id: record.id });
    if (deleted !== 1 || record.expiresAt <= Date.now()) return null;
    return record.userId;
  }
}
