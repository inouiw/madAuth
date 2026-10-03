// Password hashing and the checks around it. See docs/password-security.md.
import { createHash, createHmac, hkdfSync, randomBytes, randomInt, scrypt, timingSafeEqual } from 'node:crypto';

/**
 * scrypt cost: N = 2^15, r = 8, p = 3. One of OWASP's equivalent recommendations; it needs 32 MiB per hash
 * instead of 128 MiB for N = 2^17, so a few concurrent sign-ins can't exhaust a small container's memory.
 */
export const HASH_PARAMS = { logN: 15, r: 8, p: 3 } as const;
const KEY_LENGTH = 64;
const SALT_LENGTH = 16;

export const MAX_PASSWORD_LENGTH = 256;
const MAX_EMAIL_LENGTH = 254;

type HashParams = { logN: number; r: number; p: number };

function derive(password: string, salt: Buffer, { logN, r, p }: HashParams): Promise<Buffer> {
  const N = 2 ** logN;
  return new Promise((resolve, reject) =>
    scrypt(password.normalize('NFC'), salt, KEY_LENGTH, { N, r, p, maxmem: 256 * N * r + 1024 * 1024 }, (err, key) =>
      err ? reject(err) : resolve(key),
    ),
  );
}

/** Hashes a password as `scrypt$<log2 N>$<r>$<p>$<salt>$<hash>` (base64url), so the cost can be raised later. */
export async function hashPassword(password: string, params: HashParams = HASH_PARAMS): Promise<string> {
  const salt = randomBytes(SALT_LENGTH);
  const key = await derive(password, salt, params);
  return ['scrypt', params.logN, params.r, params.p, salt.toString('base64url'), key.toString('base64url')].join('$');
}

/**
 * Checks a password against a stored hash in constant time. `needsRehash` is true when the hash uses
 * older cost parameters and should be replaced with {@link hashPassword} after a successful sign-in.
 */
export async function verifyPassword(password: string, stored: string): Promise<{ ok: boolean; needsRehash: boolean }> {
  const [scheme, logN, r, p, salt, hash] = stored.split('$');
  const params = { logN: Number(logN), r: Number(r), p: Number(p) };
  if (scheme !== 'scrypt' || !salt || !hash || !Object.values(params).every((n) => Number.isInteger(n) && n > 0)) {
    return { ok: false, needsRehash: false };
  }
  const expected = Buffer.from(hash, 'base64url');
  const key = await derive(password, Buffer.from(salt, 'base64url'), params);
  const ok = key.length === expected.length && timingSafeEqual(key, expected);
  const needsRehash = params.logN !== HASH_PARAMS.logN || params.r !== HASH_PARAMS.r || params.p !== HASH_PARAMS.p;
  return { ok, needsRehash };
}

let dummyHash: Promise<string> | undefined;

/**
 * Spends the same time as checking a real password. Used for unknown e-mail addresses, so the response
 * time does not reveal whether an account exists.
 */
export async function verifyAgainstDummy(password: string): Promise<void> {
  dummyHash ??= hashPassword(randomBytes(16).toString('hex'));
  await verifyPassword(password, await dummyHash);
}

/** Returns why a password is not acceptable, or null. Length only, as NIST SP 800-63B recommends. */
export function checkPasswordPolicy(password: unknown, minLength: number): string | null {
  if (typeof password !== 'string') return 'password is missing';
  const length = [...password].length;
  if (length < minLength) return `The password must have at least ${minLength} characters.`;
  if (length > MAX_PASSWORD_LENGTH) return `The password must have at most ${MAX_PASSWORD_LENGTH} characters.`;
  return null;
}

/** The form of an e-mail address used to look it up: trimmed and lower-cased. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** A plausible e-mail address: something@domain.tld, no spaces, at most 254 characters. */
export function isValidEmail(email: unknown): email is string {
  return typeof email === 'string' && email.trim().length <= MAX_EMAIL_LENGTH && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

/** A random token for e-mail links (32 bytes, base64url). */
export function generateLinkToken(): string {
  return randomBytes(32).toString('base64url');
}

/** What is stored for a link token: its SHA-256, so a database leak reveals no usable links. */
export function hashLinkToken(token: string): string {
  return createHash('sha256').update(token).digest('base64url');
}

/** A random 6-digit code for e-mails, e.g. "042917". */
export function generateCode(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, '0');
}

/**
 * The key for {@link hashCode}, derived from the signing key. A 6-digit code has only a million values,
 * so a plain hash could be reversed from a leaked database; a keyed HMAC can't without the signing key.
 */
export function deriveCodeKey(signingKeyD: string): Buffer {
  return Buffer.from(hkdfSync('sha256', Buffer.from(signingKeyD, 'base64url'), '', 'madauth e-mail code', 32));
}

export function hashCode(key: Buffer, code: string): string {
  return createHmac('sha256', key).update(code).digest('base64url');
}

/** Compares two strings in constant time. */
export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
