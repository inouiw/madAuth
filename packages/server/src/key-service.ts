// The key service: everything madAuth does with its keys goes through it. It signs the tokens, hashes the codes
// (HMAC) and encrypts the secrets it must read again, each with keys of its own. A key service can keep its keys
// out of the process (e.g. AWS KMS); the local one below holds them, from MADAUTH_SIGNING_KEY. Each operation has a
// list of keys: the newest signs, hashes and encrypts, and every listed one still verifies, finds and decrypts,
// so keys can be rotated. See "Signing key" in docs/server.md.
import { createHmac, createSecretKey, type KeyObject } from 'node:crypto';
import { calculateJwkThumbprint, importJWK, type JWK } from 'jose';
import { decrypt, deriveKey, encrypt } from './crypto.js';
import { SIGNING_ALG, assertPrivateSigningJwk, signingJwkProblem } from './keys.js';

/** What a value is encrypted for: each purpose has keys of its own, so one kind can never be read as another. */
export type EncryptionPurpose = 'authenticator-secret' | 'provider-token';

export interface KeyService {
  /**
   * The public keys that verify madAuth's tokens (ES256, each with its `kid`), the one that signs now first.
   * They are published at /.well-known/jwks.json, so backends verify tokens of every listed key.
   */
  verificationKeys(): Promise<JWK[]>;
  /** Signs a JWS signing input (`header.payload`) with the key `kid`: ES256, the signature as JWS has it (r and s, 64 bytes). */
  sign(kid: string, data: Uint8Array): Promise<Uint8Array>;
  /**
   * Keyed hashes (HMAC-SHA256) of `data`, one per hash key, the newest first. The first is stored; a stored
   * hash is found as any of them, so what was hashed before a rotation is still found.
   */
  mac(data: Uint8Array): Promise<Uint8Array[]>;
  /** Encrypts `plaintext` for `purpose` with the newest key. */
  encrypt(purpose: EncryptionPurpose, plaintext: Uint8Array): Promise<string>;
  /**
   * Decrypts what {@link encrypt} made, with any listed key; null if none opens it (another purpose, tampered
   * with, or a key that is gone). `current` is false when an older key made it: encrypt it again.
   */
  decrypt(purpose: EncryptionPurpose, value: string): Promise<{ plaintext: Uint8Array; current: boolean } | null>;
}

/**
 * The labels the local keys of each purpose are derived with. They are those of madAuth before the key service,
 * so what was stored then is read as it is; another label would derive another key.
 */
const ENCRYPTION_LABELS: Record<EncryptionPurpose, string> = {
  'authenticator-secret': 'madauth totp secret',
  'provider-token': 'madauth provider token',
};
const MAC_LABEL = 'madauth e-mail code';

/** One local key: an ES256 key pair, and the hash and encryption keys derived from its private scalar. */
interface LocalKey {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
  macKey: KeyObject;
  encryptionKeys: Record<EncryptionPurpose, Buffer>;
}

async function localKey(jwk: JWK): Promise<LocalKey> {
  assertPrivateSigningJwk(jwk);
  const { d, ...pub } = jwk;
  const kid = jwk.kid ?? (await calculateJwkThumbprint(pub));
  return {
    kid,
    privateKey: (await importJWK({ ...jwk, alg: SIGNING_ALG }, SIGNING_ALG, { extractable: false })) as CryptoKey,
    publicJwk: { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y, alg: SIGNING_ALG, use: 'sig', kid },
    macKey: createSecretKey(deriveKey(d!, MAC_LABEL)),
    encryptionKeys: {
      'authenticator-secret': deriveKey(d!, ENCRYPTION_LABELS['authenticator-secret']),
      'provider-token': deriveKey(d!, ENCRYPTION_LABELS['provider-token']),
    },
  };
}

/**
 * A key service that holds its keys in the process: private ES256 JWKs, the newest first (MADAUTH_SIGNING_KEY).
 * Each one brings its own hash and encryption keys, derived from it as madAuth always did, so a deployment that
 * adds a key keeps reading what the older ones wrote. Whoever reads the process's memory reads these keys.
 */
export async function createLocalKeyService(jwks: JWK[]): Promise<KeyService> {
  if (!jwks.length) throw new Error('createLocalKeyService needs at least one key.');
  const keys = await Promise.all(jwks.map(localKey));
  const verificationKeys = keys.map((key) => key.publicJwk);
  const [newest] = keys;

  return {
    verificationKeys: async () => verificationKeys,
    async sign(kid, data) {
      const key = keys.find((k) => k.kid === kid);
      if (!key) throw new Error(`No signing key ${kid}.`);
      // WebCrypto's ECDSA signature is r and s, as JWS wants it.
      return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, new Uint8Array(data)));
    },
    mac: async (data) => keys.map((key) => new Uint8Array(createHmac('sha256', key.macKey).update(data).digest())),
    encrypt: async (purpose, plaintext) => encrypt(newest!.encryptionKeys[purpose], plaintext),
    async decrypt(purpose, value) {
      // AES-GCM opens a value only with its own key.
      for (const [index, key] of keys.entries()) {
        const plaintext = decrypt(key.encryptionKeys[purpose], value);
        if (plaintext) return { plaintext: new Uint8Array(plaintext), current: index === 0 };
      }
      return null;
    },
  };
}

const parseJson = (value: string): unknown => {
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
};

/**
 * The keys of MADAUTH_SIGNING_KEY: one private JWK, or a JWK set (`{ "keys": [newest, …, oldest] }`); or why
 * it is not that, to complete "MADAUTH_SIGNING_KEY …".
 */
export async function parseSigningKeys(value: string): Promise<{ keys: JWK[] } | { problem: string }> {
  const parsed = parseJson(value);
  if (parsed === undefined) return { problem: 'is not valid JSON' };
  const set = parsed && typeof parsed === 'object' && 'keys' in parsed ? (parsed as { keys: unknown }).keys : undefined;
  const list: unknown[] = set === undefined ? [parsed] : Array.isArray(set) ? set : [];
  if (!list.length) return { problem: 'must be a private JWK, or a set of them: { "keys": [newest, …, oldest] }' };
  const problems = list.map(signingJwkProblem);
  const wrong = problems.findIndex((problem) => problem !== null);
  if (wrong >= 0) return { problem: list.length > 1 ? `has a key (number ${wrong + 1}) that ${problems[wrong]}` : problems[wrong]! };
  const keys = list as JWK[];
  const kids = await Promise.all(keys.map((jwk) => jwk.kid ?? calculateJwkThumbprint({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y })));
  return new Set(kids).size === kids.length ? { keys } : { problem: 'has the same key twice (or two keys with the same kid)' };
}
