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
  constructor(
    private readonly store: StoreAdapter,
    private readonly codeKey: Buffer,
  ) {}

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

  async updateUser(id: string, patch: Partial<Omit<StoredUser, 'id'>>): Promise<void> {
    await this.store.update('user', { id }, patch as Row);
  }

  async updateAccount(id: string, patch: Partial<Omit<StoredAccount, 'id'>>): Promise<void> {
    await this.store.update('account', { id }, patch as Row);
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
      codeHash: hashCode(this.codeKey, code),
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
    if (!safeEqual(hashCode(this.codeKey, code), record.codeHash)) {
      if (record.attempts + 1 >= MAX_CODE_ATTEMPTS) {
        await this.store.delete('verification', { id: record.id });
      } else {
        await this.store.update('verification', { id: record.id }, { attempts: record.attempts + 1 });
      }
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
