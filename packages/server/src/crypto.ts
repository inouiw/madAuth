// Keys derived from the signing key, and AES-256-GCM at rest, for what the server must be able to read again:
// the secrets of authenticator apps (totp.ts) and the access tokens of providers (github.ts). Each use derives
// a key of its own, so the two stay apart and a leaked database alone gives neither away.
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

const ENCRYPTION_VERSION = 'v1';
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** A 256-bit key for one purpose, named by `info`, derived from the signing key's private scalar. */
export function deriveKey(signingKeyD: string, info: string): Buffer {
  return Buffer.from(hkdfSync('sha256', Buffer.from(signingKeyD, 'base64url'), '', info, 32));
}

/** Encrypts a secret for the store: `v1.<iv>.<ciphertext>.<tag>` in base64url, AES-256-GCM with a random IV. */
export function encrypt(key: Buffer, secret: Uint8Array): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(secret), cipher.final()]);
  const parts = [iv, encrypted, cipher.getAuthTag()].map((part) => part.toString('base64url'));
  return [ENCRYPTION_VERSION, ...parts].join('.');
}

/** The secret from {@link encrypt}, or null if the value is malformed, tampered with, or from another key. */
export function decrypt(key: Buffer, stored: string): Buffer | null {
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
