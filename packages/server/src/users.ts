// Everything madAuth stores, written once on top of the StoreAdapter. Routes never call the adapter directly.
import { createHash, randomBytes } from 'node:crypto';
import { claimsFromJson, type Claims } from './claims.js';
import { generateCode, generateLinkToken, hashCode, hashLinkToken, safeEqual } from './password.js';
import { ALWAYS_SIGN_IN, SIGN_IN_METHODS, type SecondFactor, type SignInMethod } from './settings.js';
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
  /**
   * When the user's first session started, so `user.signed_up` is sent once: 0 until then. Empty in records
   * from before schema version 7, whose sign-up counts as complete.
   */
  signedUpAt: number | null;
  createdAt: number;
}

export interface StoredAccount {
  id: string;
  userId: string;
  /** `password:<userId>`, `google:<sub>`, `github:<id>`, `totp:<userId>`, `email-link:<userId>`, `sms:<userId>` or `passkey:<hash>`. */
  key: string;
  /**
   * The password hash, the encrypted secret of the authenticator app, GitHub's encrypted access token, or a
   * passkey's public key (COSE, base64url). Empty for Google.
   */
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
  /**
   * The user's id on the account they signed up with, null on the accounts they added since and on SMS. Unique,
   * so of two sign-ups for one address that race, one wins. Null in records from before schema version 7 as
   * well: see {@link isPrimary}.
   */
  primaryUserId: string | null;
  /**
   * True for an account that was only a second factor when it was made (SMS codes, an authenticator app set up
   * as the step of another method), false for the others. Null in records from before schema version 7.
   */
  secondFactor: boolean | null;
  /** A passkey's name. Empty for other accounts, and in records from before schema version 8. */
  name: string | null;
  /** A passkey's credential id (base64url). Empty for other accounts. */
  credentialId: string | null;
  /** A passkey's signature counter at its last use. */
  signCount: number | null;
  /** A passkey's transports, comma-separated (`internal,hybrid`), as the browser reported them. */
  transports: string | null;
  /** When a passkey last signed in, or 0. */
  lastUsedAt: number | null;
  /** The domain a passkey belongs to; it answers only there. */
  rpId: string | null;
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
 * or an SMS code (no link is sent for it). `passkey` notes an answer of a passkey that was accepted, so it
 * counts once (see {@link Users.useCeremony}).
 */
export type VerificationPurpose = 'verify' | 'reset' | 'signin' | 'sms' | 'passkey';

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

/** How often a write that compares what it read is tried again when another request changed it in between. */
const MAX_TRIES = 3;

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
 * The account of a passkey. The credential id can be up to 1023 bytes, more than a key column of every
 * database holds, so the key has its SHA-256 instead; the id itself is in `credentialId`.
 */
export function passkeyAccountKey(credentialId: string): string {
  return `passkey:${createHash('sha256').update(credentialId).digest('base64url')}`;
}

/** The method of an account: the start of its key, e.g. `password` or `sms`. */
export const methodOf = (account: Pick<StoredAccount, 'key'>): string => String(account.key).split(':')[0];

/** The methods whose accounts a sign-up makes; the authenticator app makes one only for a sign-up with it. */
const isAlwaysPrimary = (method: string) => (ALWAYS_SIGN_IN as readonly string[]).includes(method);

/**
 * Whether an account is the one its user signed up with; `accounts` are all of the user's. Records since
 * schema version 7 say so. Older ones don't: password, Google and the e-mail link always are, SMS never is,
 * and the authenticator app is when the user has none of the others (they signed up with it).
 */
export function isPrimary(account: StoredAccount, accounts: StoredAccount[]): boolean {
  if (account.primaryUserId) return true;
  if (account.secondFactor === true) return false;
  const method = methodOf(account);
  if (method !== 'totp') return isAlwaysPrimary(method);
  return !accounts.some((other) => isAlwaysPrimary(methodOf(other)));
}

/**
 * Which of the second factors in `on` the accounts (all of one user's) hold, in the order of `on`.
 * `passkeyUsable` leaves out passkeys that can't answer where the user is (another domain's).
 */
export function factorsAmong(accounts: StoredAccount[], on: readonly SecondFactor[], passkeyUsable: (account: StoredAccount) => boolean = () => true): SecondFactor[] {
  const has: Record<SecondFactor, boolean> = {
    passkey: accounts.some((account) => account.key.startsWith('passkey:') && passkeyUsable(account)),
    totp: accounts.some((account) => methodOf(account) === 'totp'),
    sms: accounts.some((account) => methodOf(account) === 'sms' && !!account.phone),
  };
  return on.filter((factor) => has[factor]);
}

/**
 * Whether the accounts `without` picks are the last way in among `accounts` (all of one user's): the user
 * signs in now with one whose method `signsIn`, and wouldn't without them. A user who can't sign in now
 * anyway (an admin switched their methods off) is not locked out by it.
 */
export function lastWayIn(accounts: StoredAccount[], signsIn: (method: string) => boolean, without: (account: StoredAccount) => boolean): boolean {
  const ways = accounts.filter((account) => signsIn(methodOf(account)));
  return ways.length > 0 && ways.every(without);
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
  /** For a passkey: its name, credential id, signature counter, transports and domain. */
  passkey?: { name: string; credentialId: string; signCount: number; transports: string | null; rpId: string };
  /**
   * Whether the account is the one the user signs up with. By default it is for a password, Google, GitHub
   * and the e-mail link; the authenticator app is one only for a sign-up with it, SMS and passkeys never. An
   * account a signed-in user adds is not.
   */
  primary?: boolean;
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

  /**
   * The user's accounts: their sign-in methods and their second factors. Read once, for the checks that take
   * them ({@link factorsAmong}, {@link lastWayIn}).
   */
  async accounts(userId: string): Promise<StoredAccount[]> {
    return (await this.store.findMany('account', { userId })) as unknown as StoredAccount[];
  }

  /** Puts back an account that was removed: a removal that turned out to leave the user without a way in. */
  async restoreAccount(account: StoredAccount): Promise<void> {
    await this.store.create('account', account as unknown as Row);
  }

  /** The user's passkeys, oldest first. */
  async passkeys(userId: string): Promise<StoredAccount[]> {
    const accounts = await this.accounts(userId);
    return accounts.filter((account) => account.key.startsWith('passkey:')).sort((a, b) => a.createdAt - b.createdAt);
  }

  /** The passkey with this credential id, if it is stored. */
  async passkeyByCredential(credentialId: string): Promise<StoredAccount | null> {
    return this.findAccountByKey(passkeyAccountKey(credentialId));
  }

  /**
   * Notes that a passkey of the user answered the ceremony with this challenge, so the same answer counts
   * once: resolves to false if it was noted before (the create decides between two requests). Only accepted
   * answers are noted, so nobody fills the store without a passkey; the user's notes of ceremonies that have
   * expired (`expiresAt`) go meanwhile.
   */
  async useCeremony(userId: string, challenge: string, expiresAt: number): Promise<boolean> {
    const now = Date.now();
    const id = `passkey:${createHash('sha256').update(challenge).digest('base64url')}`;
    // The create alone decides a replay, so the expired notes go alongside it.
    const expired = (await this.store.findMany('verification', { userId, purpose: 'passkey' })).filter((old) => Number(old.expiresAt) <= now);
    const [created] = await Promise.all([
      this.store.create('verification', { id, userId, purpose: 'passkey', codeHash: '', attempts: 0, expiresAt }),
      ...expired.map((old) => this.store.delete('verification', { id: old.id })),
    ]);
    return created;
  }

  /**
   * The user's authenticator app, if they set one up, and whether they signed up with it (as opposed to
   * adding it later). One read: the app and the user's other accounts together.
   */
  async totpApp(userId: string): Promise<{ account: StoredAccount; signedUpWith: boolean } | null> {
    const accounts = await this.accounts(userId);
    const account = accounts.find((a) => a.key === totpAccountKey(userId));
    return account ? { account, signedUpWith: isPrimary(account, accounts) } : null;
  }

  /**
   * Whether the user's sign-up got as far as a way in: they have an account other than a phone for SMS codes.
   * A sign-up with the authenticator app has none until the app is set up.
   */
  async hasSignInMethod(userId: string): Promise<boolean> {
    return (await this.accounts(userId)).some((account) => methodOf(account) !== 'sms');
  }

  /**
   * How the user signs in, e.g. `['google', 'passkey']`: the methods they have that sign in on their own now
   * (`signsIn`: on, configured, and allowed as a sign-in method); empty while nobody can.
   */
  async signInMethods(userId: string, signsIn: (method: string) => boolean): Promise<SignInMethod[]> {
    const has = (await this.accounts(userId)).map(methodOf);
    return SIGN_IN_METHODS.filter((m) => has.includes(m) && signsIn(m));
  }

  /**
   * Notes that the user's first session started: their sign-up is complete. Resolves to true only for the
   * request that wrote it, so `user.signed_up` is sent once; false for a later session, and for a user from
   * before schema version 7.
   */
  async markSignedUp(userId: string): Promise<boolean> {
    return (await this.store.update('user', { id: userId, signedUpAt: 0 }, { signedUpAt: Date.now() })) === 1;
  }

  /**
   * For a user whose sign-up is not complete (no confirmed address, or no sign-in method) and who is about to
   * finish it or sign up again: one from before schema version 7 says nothing (`signedUpAt` empty, which
   * counts as complete), so it is set to 0 and `user.signed_up` comes at their first session like for anyone.
   */
  async reopenSignUp<T extends StoredUser>(user: T): Promise<T> {
    if (user.signedUpAt !== null && user.signedUpAt !== undefined) return user;
    await this.store.update('user', { id: user.id, signedUpAt: null }, { signedUpAt: 0 });
    return { ...user, signedUpAt: 0 };
  }

  /** The `sub` of the user's linked Google account, if they have one. */
  async googleSub(userId: string): Promise<string | null> {
    const accounts = await this.store.findMany('account', { userId });
    const key = accounts.map((account) => String(account.key)).find((k) => k.startsWith('google:'));
    return key ? key.slice('google:'.length) : null;
  }

  /** The user's GitHub account, if linked: its key holds GitHub's user id, its secret the encrypted access token of the last sign-in. */
  async githubAccount(userId: string): Promise<StoredAccount | null> {
    const accounts = await this.accounts(userId);
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
      signedUpAt: 0,
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

  /**
   * Resets the sign-in of a user who lost every way in: removes all their accounts (sign-in methods and
   * second factors) with the recovery codes, ends their sessions and the sign-ins that wait for a second step
   * (a new session version), deletes their pending links and codes, counts wrong codes from zero, and marks
   * the address unconfirmed, so their next sign-up proves the inbox again. The user keeps their id, address,
   * name, claims and `signedUpAt`. Resolves to the accounts that were removed, e.g. for GitHub's token.
   */
  async resetSignIn(userId: string): Promise<StoredAccount[]> {
    // The sessions end first, so none of them adds a method meanwhile. A sign-in that found one of the accounts
    // before they went (or a password reset under way) may still start a session with that version: the
    // second raise ends it. Each raise counts from the user as stored then, not as the request read them.
    await this.endSignIns(userId);
    const removed = await this.deleteAccounts(userId);
    await this.endSignIns(userId);
    await this.clearVerifications(userId);
    await this.clearRecoveryCodes(userId);
    return removed;
  }

  /** Raises the session version and marks the address unconfirmed, with wrong codes counted from zero. */
  private async endSignIns(userId: string): Promise<void> {
    const user = await this.findById(userId);
    if (user) await this.updateUser(userId, { emailVerified: false, sessionVersion: user.sessionVersion + 1, wrongCodes: 0 });
  }

  /**
   * Deletes the user's accounts until none is left, as another request may add one meanwhile. Resolves to the
   * accounts this deleted (not those another request deleted at the same time).
   */
  private async deleteAccounts(userId: string, rounds = 3): Promise<StoredAccount[]> {
    const accounts = rounds > 0 ? await this.accounts(userId) : [];
    if (!accounts.length) return [];
    const deleted = await Promise.all(accounts.map(async (account) => ((await this.store.delete('account', { id: account.id })) === 1 ? [account] : [])));
    return [...deleted.flat(), ...(await this.deleteAccounts(userId, rounds - 1))];
  }

  /**
   * Adds a sign-in method or a second factor to a user. Resolves to null if the account key is taken, or if
   * it is `primary` and the user signed up with another account already.
   */
  async linkAccount(userId: string, account: NewAccount): Promise<StoredAccount | null> {
    const primary = account.primary ?? isAlwaysPrimary(methodOf(account));
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
      primaryUserId: primary ? userId : null,
      secondFactor: !primary,
      name: account.passkey?.name ?? null,
      credentialId: account.passkey?.credentialId ?? null,
      signCount: account.passkey?.signCount ?? null,
      transports: account.passkey?.transports ?? null,
      lastUsedAt: account.passkey ? 0 : null,
      rpId: account.passkey?.rpId ?? null,
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

  /**
   * Changes the user's claims: `apply` gets them as stored and returns the new ones (in canonical form, see
   * `parseClaims`). The write lands only if nobody changed them since they were read; otherwise `apply` runs
   * again with the newer ones. Resolves to the user as written, or null if they are gone or kept changing.
   */
  async changeClaims(user: StoredUser, apply: (claims: Claims) => Claims): Promise<StoredUser | null> {
    let current: StoredUser | null = user;
    for (let attempt = 0; attempt < MAX_TRIES && current; attempt++) {
      const next = apply(claimsFromJson(current.claims));
      const claims = Object.keys(next).length ? JSON.stringify(next) : null;
      if ((await this.store.update('user', { id: current.id, claims: current.claims ?? null }, { claims })) === 1) return { ...current, claims };
      current = await this.findById(user.id);
    }
    return null;
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
    // The notes of accepted passkey answers stay: without them, such an answer could be used again.
    const records = await this.store.findMany('verification', { userId });
    await Promise.all(records.filter((record) => record.purpose !== 'passkey').map((record) => this.store.delete('verification', { id: record.id })));
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
    for (let attempt = 0; attempt < MAX_TRIES && current; attempt++) {
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
