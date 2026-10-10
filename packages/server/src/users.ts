// Everything madAuth stores, written once on top of the StoreAdapter. Routes never call the adapter directly.
import { randomBytes } from 'node:crypto';
import { claimsFromJson } from './claims.js';
import { generateCode, generateLinkToken, hashCode, hashLinkToken, safeEqual } from './password.js';
import type { Row, StoreAdapter } from './store/schema.js';
import type { MadauthUser } from './user.js';

export interface StoredUser {
  id: string;
  email: string;
  emailNormalized: string;
  emailVerified: boolean;
  name: string | null;
  sessionVersion: number;
  lastMailAt: number;
  /** Wrong e-mail codes in a row. Empty in records that a store keeps from before schema version 2. */
  wrongCodes: number | null;
  /** The user's claims as JSON. Empty without claims, and in records from before schema version 4. */
  claims: string | null;
  createdAt: number;
}

export interface StoredAccount {
  id: string;
  userId: string;
  /** `password:<userId>` or `google:<sub>`. */
  key: string;
  secret: string | null;
  failedAttempts: number;
  lockedUntil: number;
  /** The address the provider reported at the last sign-in. Empty for password accounts and before schema version 4. */
  email: string | null;
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
/**
 * Wrong codes in a row allowed per user, counted across e-mails. After that the user's codes stop working
 * until one of their e-mail links is used. Without this limit, asking for a new e-mail every minute would
 * buy five new guesses each time.
 */
export const MAX_WRONG_CODES = 10;

/** `userId` is null if the code was wrong, expired or used; `locked` if the user's codes no longer work at all. */
export interface CodeResult {
  userId: string | null;
  locked: boolean;
}

const newId = (prefix: string) => `${prefix}_${randomBytes(16).toString('base64url')}`;

export function passwordAccountKey(userId: string): string {
  return `password:${userId}`;
}

export function googleAccountKey(sub: string): string {
  return `google:${sub}`;
}

/**
 * The user as apps see them. `profile` is what the sign-in method knows beyond the record, e.g. Google's
 * picture; the stored name wins over the provider's.
 */
export function toMadauthUser(user: StoredUser, profile: { name?: string; picture?: string } = {}): MadauthUser {
  const result: MadauthUser = { id: user.id, email: user.email };
  const name = user.name ?? profile.name;
  if (name) result.name = name;
  if (profile.picture) result.picture = profile.picture;
  const claims = claimsFromJson(user.claims);
  if (Object.keys(claims).length) result.claims = claims;
  return result;
}

/** A new account's sign-in method: its key, and its secret (the password hash) or the provider's address. */
export interface NewAccount {
  key: string;
  secret?: string;
  email?: string;
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
    return this.findAccountByKey(passwordAccountKey(userId));
  }

  async findAccountByKey(key: string): Promise<StoredAccount | null> {
    return (await this.store.findOne('account', { key })) as StoredAccount | null;
  }

  /**
   * Creates a user with their first account. Resolves to null if the e-mail address or the account key is
   * taken. `account.key` is `password:<userId>` for a password (its hash as `secret`), or e.g. `google:<sub>`.
   */
  async createUser(data: {
    email: string;
    emailNormalized: string;
    name: string | null;
    emailVerified: boolean;
    account: NewAccount | ((userId: string) => NewAccount);
  }): Promise<StoredUser | null> {
    const user: StoredUser = {
      id: newId('usr'),
      email: data.email,
      emailNormalized: data.emailNormalized,
      emailVerified: data.emailVerified,
      name: data.name,
      sessionVersion: 0,
      lastMailAt: 0,
      wrongCodes: 0,
      claims: null,
      createdAt: Date.now(),
    };
    if (!(await this.store.create('user', user as unknown as Row))) return null;
    const account = typeof data.account === 'function' ? data.account(user.id) : data.account;
    if (!(await this.linkAccount(user.id, account))) {
      await this.store.delete('user', { id: user.id });
      return null;
    }
    return user;
  }

  /**
   * A provider verified the user's address: an unconfirmed password sign-up with it, whose password nobody
   * has proven, is dropped (the account and its pending links and codes), and the user counts as verified.
   */
  async verifyByProvider(user: StoredUser): Promise<void> {
    if (user.emailVerified) return;
    await this.store.delete('account', { key: passwordAccountKey(user.id) });
    await this.clearVerifications(user.id);
    await this.updateUser(user.id, { emailVerified: true, wrongCodes: 0 });
  }

  /** Removes an account record, e.g. one left behind by a deletion that did not finish. */
  async deleteAccount(id: string): Promise<void> {
    await this.store.delete('account', { id });
  }

  /** Adds a sign-in method to a user. Resolves to null if the account key is taken. */
  async linkAccount(userId: string, account: NewAccount): Promise<StoredAccount | null> {
    const record: StoredAccount = {
      id: newId('acc'),
      userId,
      key: account.key,
      secret: account.secret ?? null,
      failedAttempts: 0,
      lockedUntil: 0,
      email: account.email ?? null,
      createdAt: Date.now(),
    };
    return (await this.store.create('account', record as unknown as Row)) ? record : null;
  }

  /**
   * Deletes the user and everything stored for them. Resolves to false if there is no such user (any more).
   */
  async deleteById(id: string): Promise<boolean> {
    const user = await this.findById(id);
    if (!user) return false;
    // The user record goes first: from then on nobody can sign in, and a sign-up with the address starts afresh.
    if ((await this.store.delete('user', { id: user.id })) !== 1) return false;
    // The user is gone now, so the deletion has to finish: a retry would find no session and send no event.
    // Records left behind belong to a user ID that no longer exists; a Google sign-in that meets such an
    // account removes it.
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

  /**
   * Uses up the user's verification if `code` matches. Too many wrong codes delete it, and after
   * MAX_WRONG_CODES wrong codes in a row the user's codes stop working until an e-mail link is used.
   */
  async consumeCode(user: StoredUser, purpose: VerificationPurpose, code: string): Promise<CodeResult> {
    // A locked user's verification is left alone, so the link in the e-mail keeps working.
    if ((user.wrongCodes ?? 0) >= MAX_WRONG_CODES) return { userId: null, locked: true };
    const record = (await this.store.findOne('verification', { userId: user.id, purpose })) as StoredVerification | null;
    if (!record) return { userId: null, locked: false };
    // The attempt is counted before the code is compared, and only if no other request counted one
    // meanwhile. So requests sent at the same time can't try more codes than allowed.
    const attempts = record.attempts + 1;
    if ((await this.store.update('verification', { id: record.id, attempts: record.attempts }, { attempts })) !== 1) {
      return { userId: null, locked: false };
    }
    // The code is also counted as wrong for the user before it is compared, so codes for confirming and
    // for resetting tried at the same time can't get past the limit either. A right code sets it back.
    const wrongCodes = await this.countWrongCode(user);
    if (wrongCodes === null) return { userId: null, locked: false };
    if (wrongCodes > MAX_WRONG_CODES) return { userId: null, locked: true };
    if (!safeEqual(hashCode(this.key, code), record.codeHash)) {
      if (attempts >= MAX_CODE_ATTEMPTS) await this.store.delete('verification', { id: record.id });
      return { userId: null, locked: wrongCodes >= MAX_WRONG_CODES };
    }
    return { userId: await this.consume(record), locked: false };
  }

  /** Counts a code for the user and resolves to the new count; null if other requests kept changing it. */
  private async countWrongCode(user: StoredUser): Promise<number | null> {
    let current: StoredUser | null = user;
    for (let attempt = 0; attempt < 3 && current; attempt++) {
      const wrongCodes = (current.wrongCodes ?? 0) + 1;
      if ((await this.store.update('user', { id: user.id, wrongCodes: current.wrongCodes ?? null }, { wrongCodes })) === 1) {
        return wrongCodes;
      }
      current = await this.findById(user.id);
    }
    return null;
  }

  private async consume(record: StoredVerification): Promise<string | null> {
    // The delete count decides, so two requests with the same link or code can't both succeed.
    const deleted = await this.store.delete('verification', { id: record.id });
    if (deleted !== 1 || record.expiresAt <= Date.now()) return null;
    return record.userId;
  }
}
