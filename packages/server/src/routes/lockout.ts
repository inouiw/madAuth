// The lock against guessing a secret, shared by the methods that check one: a password, or a code from
// the authenticator app. See "Brute force" in docs/password-security.md and docs/totp-security.md.
import type { Context } from 'hono';
import type { StoredAccount, Users } from '../users.js';

/** Failed sign-ins allowed before each further attempt has to wait. */
export const FREE_ATTEMPTS = 5;
/** Longest wait after failed sign-ins. */
export const MAX_LOCK_MS = 15 * 60 * 1000;

/**
 * Counts a sign-in attempt on the account before its secret is checked. Resolves to the answer to send
 * if the account is locked, or if another request counted an attempt meanwhile (so requests sent at the
 * same time can't all get past the lock); to null if the check may go on. A successful check resets the
 * count afterwards.
 */
export async function countSignInAttempt(c: Context, users: Users, account: StoredAccount, now = Date.now()): Promise<Response | null> {
  const tooMany = (message: string) => c.json({ error: 'too_many_attempts', message }, 429);
  if (account.lockedUntil > now) {
    const seconds = Math.ceil((account.lockedUntil - now) / 1000);
    return tooMany(`Too many failed attempts. Try again in ${seconds} seconds.`);
  }
  const failed = account.failedAttempts + 1;
  const lockedUntil = failed >= FREE_ATTEMPTS ? now + Math.min(2 ** (failed - FREE_ATTEMPTS) * 1000, MAX_LOCK_MS) : 0;
  if (!(await users.countAttempt(account, { failedAttempts: failed, lockedUntil }))) {
    return tooMany('Too many attempts at once. Please try again.');
  }
  return null;
}
