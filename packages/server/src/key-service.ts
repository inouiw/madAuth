// The key service: everything madAuth does with its keys goes through it. It signs the tokens, hashes the codes
// (HMAC) and encrypts the secrets it must read again, each with keys of its own. A key service can keep its keys
// out of the process (e.g. AWS KMS); the local one below holds them, from MADAUTH_SIGNING_KEY. Each operation has a
// list of keys: the newest signs, hashes and encrypts, and every listed one still verifies, finds and decrypts,
// so keys can be rotated. Besides the ES256 keys, a deployment may have RS256 keys, for the ID tokens of OpenID
// Connect clients that can't verify ES256; they only sign. See "Signing key" in docs/server.md.
import { createHmac, createSecretKey, type KeyObject } from 'node:crypto';
import { calculateJwkThumbprint, importJWK, type JWK } from 'jose';
import { decrypt, deriveKey, encrypt } from './crypto.js';
import { RSA_SIGNING_ALG, SIGNING_ALG, algOf, assertPrivateSigningJwk, publicSigningJwk, signingJwkProblem, thumbprintMembers, type SigningAlg } from './keys.js';

/** What a value is encrypted for: each purpose has keys of its own, so one kind can never be read as another. */
export type EncryptionPurpose = 'authenticator-secret' | 'provider-token' | 'provider-secret';

export interface KeyService {
  /**
   * The public keys that verify madAuth's tokens, each with its `alg` and `kid`: the ES256 keys first, the one
   * that signs now before the others, then the RS256 keys the same way, if the deployment has any. They are
   * published at /.well-known/jwks.json, so backends verify tokens of every listed key.
   */
  verificationKeys(): Promise<JWK[]>;
  /**
   * Signs a JWS signing input (`header.payload`) with the key `kid`, with its algorithm: the signature as JWS has
   * it (ES256: r and s, 64 bytes; RS256: the PKCS #1 v1.5 signature).
   */
  sign(kid: string, data: Uint8Array): Promise<Uint8Array>;
  /** The keyed hash (HMAC-SHA256) of `data` with the newest hash key: what is stored. */
  mac(data: Uint8Array): Promise<Uint8Array>;
  /**
   * The keyed hashes of `data` with every hash key, the newest first: a stored hash is found as any of them, so
   * what was hashed before a rotation is still found.
   */
  macs(data: Uint8Array): Promise<Uint8Array[]>;
  /** Encrypts `plaintext` for `purpose` with the newest key. */
  encrypt(purpose: EncryptionPurpose, plaintext: Uint8Array): Promise<string>;
  /**
   * Decrypts what {@link encrypt} made, with any listed key; null if none opens it (another purpose, tampered
   * with, or a key that is gone). `current` is false when an older key made it: encrypt it again.
   */
  decrypt(purpose: EncryptionPurpose, value: string): Promise<{ plaintext: Uint8Array; current: boolean } | null>;
}

/**
 * The labels the local keys of each purpose are derived with. The first two are those of madAuth before the key
 * service, so what was stored then is read as it is; another label would derive another key. `provider-secret`
 * is the client secrets of the sign-in providers (providers.ts); `provider-token`, a user's token at a provider.
 */
const ENCRYPTION_LABELS: Record<EncryptionPurpose, string> = {
  'authenticator-secret': 'madauth totp secret',
  'provider-token': 'madauth provider token',
  'provider-secret': 'madauth provider client secret',
};
const MAC_LABEL = 'madauth e-mail code';

/** One local ES256 key: the key pair, and the hash and encryption keys derived from its private scalar. */
interface LocalKey {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
  macKey: KeyObject;
  encryptionKeys: Record<EncryptionPurpose, Buffer>;
}

/** One local RS256 key: it only signs. */
interface LocalRsaKey {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
}

const hmac = (key: LocalKey, data: Uint8Array) => new Uint8Array(createHmac('sha256', key.macKey).update(data).digest());

/** The kid of a private JWK: its own, or its thumbprint. */
const kidOf = async (jwk: JWK): Promise<string> => jwk.kid ?? calculateJwkThumbprint(thumbprintMembers(jwk));

const importPrivate = async (jwk: JWK, alg: SigningAlg): Promise<CryptoKey> => (await importJWK({ ...jwk, alg }, alg, { extractable: false })) as CryptoKey;

async function localKey(jwk: JWK): Promise<LocalKey> {
  const kid = await kidOf(jwk);
  const { d } = jwk;
  return {
    kid,
    privateKey: await importPrivate(jwk, SIGNING_ALG),
    publicJwk: publicSigningJwk(jwk, kid),
    macKey: createSecretKey(deriveKey(d!, MAC_LABEL)),
    encryptionKeys: {
      'authenticator-secret': deriveKey(d!, ENCRYPTION_LABELS['authenticator-secret']),
      'provider-token': deriveKey(d!, ENCRYPTION_LABELS['provider-token']),
      'provider-secret': deriveKey(d!, ENCRYPTION_LABELS['provider-secret']),
    },
  };
}

async function localRsaKey(jwk: JWK): Promise<LocalRsaKey> {
  const kid = await kidOf(jwk);
  return { kid, privateKey: await importPrivate(jwk, RSA_SIGNING_ALG), publicJwk: publicSigningJwk(jwk, kid) };
}

/**
 * A key service that holds its keys in the process: private JWKs, the newest first (MADAUTH_SIGNING_KEY). The
 * ES256 keys (at least one) sign madAuth's tokens, and each brings its own hash and encryption keys, derived from
 * it as madAuth always did, so a deployment that adds a key keeps reading what the older ones wrote. RS256 keys,
 * if any, sign the ID tokens of the clients that ask for RS256. Whoever reads the process's memory reads these keys.
 */
export async function createLocalKeyService(jwks: JWK[]): Promise<KeyService> {
  for (const jwk of jwks) assertPrivateSigningJwk(jwk);
  const keys = await Promise.all(jwks.filter((jwk) => algOf(jwk) === SIGNING_ALG).map(localKey));
  const rsaKeys = await Promise.all(jwks.filter((jwk) => algOf(jwk) === RSA_SIGNING_ALG).map(localRsaKey));
  if (!keys.length) throw new Error('createLocalKeyService needs at least one ES256 key.');
  const verificationKeys = [...keys, ...rsaKeys].map((key) => key.publicJwk);
  const [newest] = keys;

  return {
    verificationKeys: async () => verificationKeys,
    async sign(kid, data) {
      const key = keys.find((k) => k.kid === kid);
      // WebCrypto's ECDSA signature is r and s, as JWS wants it.
      if (key) return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, new Uint8Array(data)));
      const rsaKey = rsaKeys.find((k) => k.kid === kid);
      if (!rsaKey) throw new Error(`No signing key ${kid}.`);
      return new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, rsaKey.privateKey, new Uint8Array(data)));
    },
    mac: async (data) => hmac(newest!, data),
    macs: async (data) => keys.map((key) => hmac(key, data)),
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
 * The keys of MADAUTH_SIGNING_KEY: one private JWK, or a JWK set (`{ "keys": [newest, …, oldest] }`) of ES256
 * keys and, if the deployment needs them, RS256 keys, each kind the newest first; or why it is not that, to
 * complete "MADAUTH_SIGNING_KEY …".
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
  if (!keys.some((jwk) => algOf(jwk) === SIGNING_ALG)) return { problem: 'has no EC P-256 key: madAuth signs its own tokens with ES256, RSA keys only sign ID tokens' };
  const kids = await Promise.all(keys.map(kidOf));
  return new Set(kids).size === kids.length ? { keys } : { problem: 'has the same key twice (or two keys with the same kid)' };
}
