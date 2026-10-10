// Authenticator app codes (TOTP, RFC 6238), how their secrets are kept, and recovery codes. See docs/totp-security.md.
import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, randomInt } from 'node:crypto';
import { hashCode, safeEqual } from './password.js';

/** How long one code is valid, as authenticator apps expect. */
export const TOTP_STEP_SECONDS = 30;
export const TOTP_DIGITS = 6;
/** Steps before and after the current one whose codes are accepted too: the phone's clock drifts, and typing takes time. */
export const TOTP_WINDOW = 1;
/** Recovery codes a user gets when the authenticator is set up. */
export const RECOVERY_CODES = 10;

/** 160 bits, what RFC 4226 recommends for HMAC-SHA1. */
const SECRET_BYTES = 20;
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
/** Lower-case base32 without 0, 1 and 8, so a code read from paper is not mistyped. */
const RECOVERY_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const RECOVERY_CODE_LENGTH = 10;
const ENCRYPTION_VERSION = 'v1';
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** RFC 4648 base32 without padding, the form authenticator apps take a key in. */
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = ((value << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

/** Decodes base32 as a person may type it: any case, with spaces or padding. Null if it holds other characters. */
export function base32Decode(text: string): Buffer | null {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of text.toUpperCase().replace(/[\s=]/g, '')) {
    const index = BASE32.indexOf(char);
    if (index < 0) return null;
    value = ((value << 5) | index) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** An HOTP code (RFC 4226): HMAC-SHA1 of the counter, truncated to `digits` digits. */
export function hotp(secret: Uint8Array, counter: number, digits = TOTP_DIGITS): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', secret).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return (binary % 10 ** digits).toString().padStart(digits, '0');
}

/** The time step a moment belongs to: the counter of its TOTP code. */
export function stepOf(nowMs: number): number {
  return Math.floor(nowMs / 1000 / TOTP_STEP_SECONDS);
}

/** The code an authenticator app shows during a time step (RFC 6238). */
export function totp(secret: Uint8Array, step: number, digits = TOTP_DIGITS): string {
  return hotp(secret, step, digits);
}

/**
 * The time step whose code `code` is, within `window` steps of now, or null if it is none of them. Spaces
 * in the code are ignored. Every candidate is compared, so the time taken does not say which one matched.
 */
export function verifyTotp(secret: Uint8Array, code: string, nowMs: number, window = TOTP_WINDOW): number | null {
  const given = code.replace(/\s/g, '');
  if (!new RegExp(`^\\d{${TOTP_DIGITS}}$`).test(given)) return null;
  const now = stepOf(nowMs);
  let found: number | null = null;
  for (let step = now - window; step <= now + window; step++) {
    if (safeEqual(totp(secret, step), given) && found === null) found = step;
  }
  return found;
}

export function generateTotpSecret(): Buffer {
  return randomBytes(SECRET_BYTES);
}

/** The `otpauth://` URI an authenticator app scans as a QR code: the key, and the names it shows next to the code. */
export function otpauthUri(options: { issuer: string; account: string; secret: Uint8Array }): string {
  const issuer = encodeURIComponent(options.issuer);
  const account = encodeURIComponent(options.account);
  const secret = base32Encode(options.secret);
  return `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_STEP_SECONDS}`;
}

/**
 * The key that encrypts the secrets at rest, derived from the signing key like the key for e-mail codes.
 * A secret must be readable to check codes, so a leaked database alone must not give it away.
 */
export function deriveTotpKey(signingKeyD: string): Buffer {
  return Buffer.from(hkdfSync('sha256', Buffer.from(signingKeyD, 'base64url'), '', 'madauth totp secret', 32));
}

/** Encrypts a secret for the store: `v1.<iv>.<ciphertext>.<tag>` in base64url, AES-256-GCM with a random IV. */
export function encryptSecret(key: Buffer, secret: Uint8Array): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(secret), cipher.final()]);
  const parts = [iv, encrypted, cipher.getAuthTag()].map((part) => part.toString('base64url'));
  return [ENCRYPTION_VERSION, ...parts].join('.');
}

/** The secret from {@link encryptSecret}, or null if the value is malformed, tampered with, or from another key. */
export function decryptSecret(key: Buffer, stored: string): Buffer | null {
  const [version, iv, encrypted, tag, ...rest] = stored.split('.');
  if (version !== ENCRYPTION_VERSION || !iv || !encrypted || !tag || rest.length) return null;
  const ivBytes = Buffer.from(iv, 'base64url');
  const tagBytes = Buffer.from(tag, 'base64url');
  if (ivBytes.length !== IV_BYTES || tagBytes.length !== TAG_BYTES) return null;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, ivBytes);
    decipher.setAuthTag(tagBytes);
    return Buffer.concat([decipher.update(Buffer.from(encrypted, 'base64url')), decipher.final()]);
  } catch {
    return null;
  }
}

/** New recovery codes, e.g. `k7mxq-2bz4p`: ten characters of 32 each, in two groups. */
export function generateRecoveryCodes(): string[] {
  const codes = new Set<string>();
  while (codes.size < RECOVERY_CODES) {
    let code = '';
    for (let i = 0; i < RECOVERY_CODE_LENGTH; i++) code += RECOVERY_ALPHABET[randomInt(RECOVERY_ALPHABET.length)];
    codes.add(`${code.slice(0, 5)}-${code.slice(5)}`);
  }
  return [...codes];
}

/** A recovery code as a person typed it, in the form that is hashed: lower-case, without dashes or spaces. Null if it can't be one. */
export function normalizeRecoveryCode(text: unknown): string | null {
  if (typeof text !== 'string') return null;
  const code = text.toLowerCase().replace(/[\s-]/g, '');
  return code.length === RECOVERY_CODE_LENGTH && [...code].every((char) => RECOVERY_ALPHABET.includes(char)) ? code : null;
}

/** What is stored for a recovery code: a keyed hash, like the e-mail codes, so a leaked database gives no usable code. */
export function hashRecoveryCode(codeKey: Buffer, code: string): string {
  return hashCode(codeKey, `recovery:${code}`);
}
