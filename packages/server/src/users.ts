// Everything madAuth stores, written once on top of the StoreAdapter. Routes never call the adapter directly.
import { randomBytes } from 'node:crypto';
import { claimsFromJson } from './claims.js';
import { generateCode, generateLinkToken, hashCode, hashLinkToken, safeEqual } from './password.js';
import { SIGN_IN_METHODS, type MethodSettings, type SignInMethod } from './settings.js';
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
  /** `password:<userId>`, `google:<sub>` or `totp:<userId>`. */
  key: string;
  /** The password hash, or the encrypted secret of the authenticator app. Empty for Google. */
  secret: string | null;
  failedAttempts: number;
  lockedUntil: number;
  /** The address the provider reported at the last sign-in. Empty for password accounts and before schema version 4. */
  email: string | null;
  /** The time step of the last authenticator code that was accepted (totp accounts). Empty in records from before schema version 5. */
  lastUsedStep: number | null;
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

export function totpAccountKey(userId: string): string {
  return `totp:${userId}`;
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

/** A new account's sign-in method: its key, and its secret (the password hash or the encrypted authenticator secret) or the provider's address. */
export interface NewAccount {
  key: string;
  secret?: string;
  email?: string;
  /** For an authenticator app: the time step of the code that proved the setup, so that code can't sign in. */
  lastUsedStep?: number;
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

  /** The user's authenticator app, if they set one up. */
  async totpAccount(userId: string): Promise<StoredAccount | null> {
    return this.findAccountByKey(totpAccountKey(userId));
  }

  /** Whether the user has any way to sign in; a sign-up with the authenticator app has none until it is set up. */
  async hasAccounts(userId: string): Promise<boolean> {
    return (await this.store.findMany('account', { userId }, { limit: 1 })).length > 0;
  }

  /**
   * The ways the user can sign in, from their accounts: e.g. `['google']` for a user without a password.
   * The authenticator app counts only when it signs in on its own (`methods` lists it); as a second
   * factor it is a step of another method, not a way in.
   */
  async signInMethods(userId: string, methods: MethodSettings): Promise<SignInMethod[]> {
    const accounts = await this.store.findMany('account', { userId });
    const keys = accounts.map((account) => String(account.key).split(':')[0]);
    return SIGN_IN_METHODS.filter((method) => keys.includes(method) && (method !== 'totp' || methods.totp !== undefined));
  }

  async findAccountByKey(key: string): Promise<StoredAccount | null> {
    return (await this.store.findOne('account', { key })) as StoredAccount | null;
  }

  /**
   * Creates a user, with their first account if given. Resolves to null if the e-mail address or the
   * account key is taken. `account.key` is `password:<userId>` for a password (its hash as `secret`), or
   * e.g. `google:<sub>`. A sign-up with the authenticator app creates the user without an account: the app
   * is set up once the address is confirmed.
   */
  async createUser(data: {
    email: string;
    emailNormalized: string;
    name: string | null;
    emailVerified: boolean;
    account?: NewAccount | ((userId: string) => NewAccount);
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
    if (!data.account) return user;
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

  /** Removes a sign-in method by its key. Resolves to false if there was none. */
  async unlinkAccount(key: string): Promise<boolean> {
    return (await this.store.delete('account', { key })) === 1;
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
      lastUsedStep: account.lastUsedStep ?? 0,
      createdAt: Date.now(),
    };
    return (await this.store.create('account', record as unknown as Row)) ? record : null;
  }

  /**
   * Marks the time step of an accepted authenticator code as used and resets the failed attempts, only if
   * no other request accepted a code meanwhile: the write count decides, so the same code sent twice signs
   * in once.
   */
  async useTotpStep(account: StoredAccount, step: number): Promise<boolean> {
    const changed = await this.store.update(
      'account',
      { id: account.id, lastUsedStep: account.lastUsedStep ?? null },
      { lastUsedStep: step, failedAttempts: 0, lockedUntil: 0 },
    );
    return changed === 1;
  }

  /** Replaces the user's recovery codes with new ones, given as their hashes. */
  async replaceRecoveryCodes(userId: string, hashes: string[]): Promise<void> {
    await this.store.delete('recoveryCode', { userId });
    const createdAt = Date.now();
    for (const id of hashes) await this.store.create('recoveryCode', { id, userId, createdAt });
  }

  /** Uses up the user's recovery code with this hash. Resolves to false if it is not theirs or was used already. */
  async consumeRecoveryCode(userId: string, hash: string): Promise<boolean> {
    const record = await this.store.findOne('recoveryCode', { id: hash });
    if (!record || record.userId !== userId) return false;
    // The delete count decides, so the same code sent twice is accepted once.
    return (await this.store.delete('recoveryCode', { id: hash })) === 1;
  }

  async countRecoveryCodes(userId: string): Promise<number> {
    return (await this.store.findMany('recoveryCode', { userId })).length;
  }

  async clearRecoveryCodes(userId: string): Promise<void> {
    await this.store.delete('recoveryCode', { userId });
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
      await this.store.delete('recoveryCode', { userId: user.id });
    } catch (e) {
      console.error(`[madauth] Deleted user ${user.id}, but not all of their records: ${(e as Error).message}`);
    }
    return true;
  }

  async updateUser(id: string, patch: Partial<Omit<StoredUser, 'id'>>): Promise<void> {
    await this.store.update('user', { id }, patch as Row);
  }

  /** Changes an account. Resolves to false if it is gone meanwhile. */
  async updateAccount(id: string, patch: Partial<Omit<StoredAccount, 'id'>>): Promise<boolean> {
    return (await this.store.update('account', { id }, patch as Row)) === 1;
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
