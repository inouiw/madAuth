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
  /** When the last SMS was sent. Empty in records from before schema version 6. */
  lastSmsAt: number | null;
  /** Wrong e-mail codes in a row. Empty in records that a store keeps from before schema version 2. */
  wrongCodes: number | null;
  /** The user's claims as JSON. Empty without claims, and in records from before schema version 4. */
  claims: string | null;
  createdAt: number;
}

export interface StoredAccount {
  id: string;
  userId: string;
  /** `password:<userId>`, `google:<sub>`, `github:<id>`, `totp:<userId>`, `email-link:<userId>` or `sms:<userId>`. */
  key: string;
  /** The password hash, the encrypted secret of the authenticator app, or GitHub's encrypted access token. Empty for Google. */
  secret: string | null;
  failedAttempts: number;
  lockedUntil: number;
  /** The address the provider reported at the last sign-in. Empty for password accounts and before schema version 4. */
  email: string | null;
  /** The time step of the last authenticator code that was accepted (totp accounts). Empty in records from before schema version 5. */
  lastUsedStep: number | null;
  /** The setup the authenticator secret came from; its recovery codes carry the same id. Empty for other accounts. */
  setupId: string | null;
  /** The phone number of an sms account (E.164). Empty for other accounts, and in records from before schema version 6. */
  phone: string | null;
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

/**
 * What a link and code are for: confirming an address, resetting the password, signing in (the e-mail link),
 * or an SMS code (no link is sent for it).
 */
export type VerificationPurpose = 'verify' | 'reset' | 'signin' | 'sms';

/** The methods an unconfirmed sign-up can set an account for before the address is proven, see {@link Users.dropUnprovenAccounts}. */
export type UnprovenMethod = 'password' | 'email-link';

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

/** A new random id with a type prefix, e.g. `usr_…`. */
export const newId = (prefix: string): string => `${prefix}_${randomBytes(16).toString('base64url')}`;

export function passwordAccountKey(userId: string): string {
  return `password:${userId}`;
}

export function googleAccountKey(sub: string): string {
  return `google:${sub}`;
}

/** `id` is GitHub's numeric user id: unlike the login, it never changes. */
export function githubAccountKey(id: string): string {
  return `github:${id}`;
}

export function totpAccountKey(userId: string): string {
  return `totp:${userId}`;
}

/** The account of a user who signs in with the e-mail link; it has no secret, the inbox is the key. */
export function emailLinkAccountKey(userId: string): string {
  return `email-link:${userId}`;
}

/** The account that holds the user's phone number for SMS codes as a second factor. */
export function smsAccountKey(userId: string): string {
  return `sms:${userId}`;
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
  /** For an authenticator app: the setup the secret came from. */
  setupId?: string;
  /** For SMS codes: the phone number (E.164). */
  phone?: string;
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

  /** The user's e-mail link account, if they sign in that way. */
  async emailLinkAccount(userId: string): Promise<StoredAccount | null> {
    return this.findAccountByKey(emailLinkAccountKey(userId));
  }

  /** The user's phone number for SMS codes, if they added one. */
  async smsAccount(userId: string): Promise<StoredAccount | null> {
    return this.findAccountByKey(smsAccountKey(userId));
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

  /** The `sub` of the user's linked Google account, if they have one. */
  async googleSub(userId: string): Promise<string | null> {
    const accounts = await this.store.findMany('account', { userId });
    const key = accounts.map((account) => String(account.key)).find((k) => k.startsWith('google:'));
    return key ? key.slice('google:'.length) : null;
  }

  /** The user's GitHub account, if linked: its key holds GitHub's user id, its secret the encrypted access token of the last sign-in. */
  async githubAccount(userId: string): Promise<StoredAccount | null> {
    const accounts = (await this.store.findMany('account', { userId })) as unknown as StoredAccount[];
    return accounts.find((account) => account.key.startsWith('github:')) ?? null;
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
      lastSmsAt: 0,
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
   * Removes what an unconfirmed sign-up set without proving it: the password, and the e-mail link account of
   * a first link nobody used. Only `except`'s own account stays: the method that proves the address, or
   * signs it up anew, is the one the user ends up with.
   */
  async dropUnprovenAccounts(userId: string, except?: UnprovenMethod): Promise<void> {
    const keys: Record<UnprovenMethod, string> = { password: passwordAccountKey(userId), 'email-link': emailLinkAccountKey(userId) };
    for (const [method, key] of Object.entries(keys)) {
      if (method !== except) await this.store.delete('account', { key });
    }
  }

  /**
   * A provider verified the user's address: an unconfirmed sign-up with it, whose password or e-mail link
   * nobody has proven, is dropped (its accounts, except `proven`'s own, and its pending links and codes),
   * and the user counts as verified.
   */
  async verifyByProvider(user: StoredUser, proven?: UnprovenMethod): Promise<void> {
    if (user.emailVerified) return;
    await this.dropUnprovenAccounts(user.id, proven);
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

  /** Removes the user's authenticator app and recovery codes. Resolves to false if they had no app. */
  async removeTotp(userId: string): Promise<boolean> {
    const removed = await this.unlinkAccount(totpAccountKey(userId));
    await this.clearRecoveryCodes(userId);
    return removed;
  }

  /** Removes the user's phone number for SMS codes. Resolves to false if they had none. */
  async removeSms(userId: string): Promise<boolean> {
    return this.unlinkAccount(smsAccountKey(userId));
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
      setupId: account.setupId ?? null,
      phone: account.phone ?? null,
      createdAt: Date.now(),
    };
    return (await this.store.create('account', record as unknown as Row)) ? record : null;
  }

  /**
   * Writes the secret of a confirmed setup over the authenticator account, only if the account still has the
   * setup it had when this setup started (`replaces`): the write count decides, so of two setups confirmed
   * at once exactly one wins, and the other is told to start again.
   */
  async confirmTotpSetup(accountId: string, replaces: string | null, patch: Pick<StoredAccount, 'secret' | 'setupId' | 'failedAttempts' | 'lockedUntil' | 'lastUsedStep'>): Promise<boolean> {
    return (await this.store.update('account', { id: accountId, setupId: replaces }, patch)) === 1;
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
  /** Stores the recovery codes of a setup (their hashes), next to whatever codes the user has. */
  async addRecoveryCodes(userId: string, setupId: string, hashes: string[]): Promise<void> {
    const createdAt = Date.now();
    for (const id of hashes) await this.store.create('recoveryCode', { id, userId, setupId, createdAt });
  }

  /** New recovery codes for the user's current app: the codes they had before stop working. */
  async replaceRecoveryCodes(account: StoredAccount, hashes: string[]): Promise<void> {
    const before = await this.store.findMany('recoveryCode', { userId: account.userId });
    await this.addRecoveryCodes(account.userId, account.setupId ?? '', hashes);
    for (const old of before) await this.store.delete('recoveryCode', { id: old.id });
  }

  /**
   * Uses up the recovery code with this hash for the user's authenticator account. Resolves to false if it
   * is not theirs, belongs to another setup than the account's, or was used already.
   */
  async consumeRecoveryCode(account: StoredAccount, hash: string): Promise<boolean> {
    const record = await this.store.findOne('recoveryCode', { id: hash });
    if (!record || record.userId !== account.userId || record.setupId !== (account.setupId ?? '')) return false;
    // The delete count decides, so the same code sent twice is accepted once.
    return (await this.store.delete('recoveryCode', { id: hash })) === 1;
  }

  /** How many recovery codes of the account's setup are left. */
  async countRecoveryCodes(account: StoredAccount): Promise<number> {
    const codes = await this.store.findMany('recoveryCode', { userId: account.userId });
    return codes.filter((code) => code.setupId === (account.setupId ?? '')).length;
  }

  /** Deletes the user's recovery codes: all of them, or only those of one setup, or all but one setup's. */
  async clearRecoveryCodes(userId: string, which: { only?: string; except?: string } = {}): Promise<void> {
    if (which.only === undefined && which.except === undefined) {
      await this.store.delete('recoveryCode', { userId });
      return;
    }
    for (const code of await this.store.findMany('recoveryCode', { userId })) {
      const match = which.only !== undefined ? code.setupId === which.only : code.setupId !== which.except;
      if (match) await this.store.delete('recoveryCode', { id: code.id });
    }
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
   * Starts a verification, password reset or e-mail link sign-in: replaces the user's earlier one for the same purpose and
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

  /** The user ID a link token belongs to, without using the verification up; null if invalid, expired or used. */
  async peekLinkToken(token: string, purpose: VerificationPurpose): Promise<string | null> {
    const record = (await this.store.findOne('verification', { id: hashLinkToken(token), purpose })) as StoredVerification | null;
    return record && record.expiresAt > Date.now() ? record.userId : null;
  }

  /** Uses up the verification a link token belongs to. Resolves to its user ID, or null if invalid, expired or used. */
  async consumeLinkToken(token: string, purpose: VerificationPurpose): Promise<string | null> {
    const id = hashLinkToken(token);
    const record = (await this.store.findOne('verification', { id, purpose })) as StoredVerification | null;
    return record ? this.consume(record) : null;
  }

  /**
   * Uses up the user's verification if `code` matches. Too many wrong codes delete it, and after
   * MAX_WRONG_CODES wrong e-mail codes in a row the user's codes stop working until an e-mail link is used.
   * SMS codes are not counted that way: that lock is only lifted by an e-mail link or a password reset, which
   * a Google user with a phone never has. Their record's attempts, one SMS per minute and the lock on the
   * sms account (routes/lockout.ts) are their limits.
   */
  async consumeCode(user: StoredUser, purpose: VerificationPurpose, code: string): Promise<CodeResult> {
    const counted = purpose !== 'sms';
    // A locked user's verification is left alone, so the link in the e-mail keeps working.
    if (counted && (user.wrongCodes ?? 0) >= MAX_WRONG_CODES) return { userId: null, locked: true };
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
    let wrongCodes = 0;
    if (counted) {
      const count = await this.countWrongCode(user);
      if (count === null) return { userId: null, locked: false };
      if (count > MAX_WRONG_CODES) return { userId: null, locked: true };
      wrongCodes = count;
    }
    if (!safeEqual(hashCode(this.key, code), record.codeHash)) {
      if (attempts >= MAX_CODE_ATTEMPTS) await this.store.delete('verification', { id: record.id });
      return { userId: null, locked: counted && wrongCodes >= MAX_WRONG_CODES };
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
