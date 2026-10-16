// The AWS KMS key service (MADAUTH_KEY_SERVICE=aws-kms): madAuth signs, hashes and encrypts with keys that never
// leave KMS. It finds its keys by itself, under aliases named after the deployment (its MADAUTH_ISSUER):
//
//   alias/madauth/<deployment>/signing              the key that signs now
//   alias/madauth/<deployment>/signing/<time>       every signing key, by when it was made: all of them verify
//   alias/madauth/<deployment>/mac (and /mac/<time>) the same for the keys that hash the codes
//   alias/madauth/<deployment>/encryption           the key that encrypts the secrets; KMS rotates it in place
//
// The deployment creates the keys and a rotator with a role of its own rotates them (kms-rotation.ts); the server
// only uses them, and may use only keys with its deployment's aliases, which it can't create. See "AWS KMS" in
// docs/server.md.
import { createHash, createPublicKey } from 'node:crypto';
import { calculateJwkThumbprint, type JWK } from 'jose';
import type { EncryptionPurpose, KeyService } from './key-service.js';
import { SIGNING_ALG } from './keys.js';

/** The KMS operations madAuth uses; {@link kmsFromSdk} makes them from the AWS SDK, tests from a stand-in. */
export interface Kms {
  /** Every alias of the account and region, with the key it points to. */
  aliases(): Promise<{ name: string; keyId: string }[]>;
  /** The public key (DER, SubjectPublicKeyInfo) of an asymmetric key; null if the key is disabled or going. */
  publicKey(keyId: string): Promise<Uint8Array | null>;
  /** ECDSA with SHA-256 of `message`; the signature in DER. */
  sign(keyId: string, message: Uint8Array): Promise<Uint8Array>;
  /** HMAC-SHA256 of `message`. */
  mac(keyId: string, message: Uint8Array): Promise<Uint8Array>;
  encrypt(keyId: string, plaintext: Uint8Array, context: Record<string, string>): Promise<Uint8Array>;
  /** Null if the ciphertext isn't one of this key, or was made for another context. */
  decrypt(keyId: string, ciphertext: Uint8Array, context: Record<string, string>): Promise<Uint8Array | null>;
  // For setting up and rotating the keys (kms-rotation.ts), never called by the server:
  createKey(kind: KmsKeyKind, description: string): Promise<string>;
  createAlias(name: string, keyId: string): Promise<void>;
  updateAlias(name: string, keyId: string): Promise<void>;
  /** Whether the key can be used: enabled, not disabled or going. */
  enabled(keyId: string): Promise<boolean>;
  disableKey(keyId: string): Promise<void>;
}

/** The three kinds of keys: ES256 signing, HMAC, and symmetric encryption that KMS rotates by itself. */
export type KmsKeyKind = 'signing' | 'mac' | 'encryption';

/** The name of a deployment in the aliases: its MADAUTH_ISSUER's host, in the characters an alias allows. */
export function deploymentOf(issuer: string): string {
  return new URL(issuer).host.replace(/[^a-zA-Z0-9_-]/g, '-');
}

export const aliasPrefix = (deployment: string) => `alias/madauth/${deployment}`;

/** A key of one purpose: its id in KMS, and when it was made (from its generation alias). */
export interface Generation {
  keyId: string;
  /** Milliseconds since 1970. */
  madeAt: number;
  alias: string;
}

/** A generation alias's time, `20261017T120000Z`, from and to milliseconds. */
export const generationName = (ms: number) => new Date(ms).toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
const generationTime = (name: string): number | null => {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(name);
  return m ? Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!) : null;
};

/** The deployment's keys as its aliases say: per purpose the current key and every generation, oldest first. */
export interface KmsKeys {
  signing: { current: string | undefined; generations: Generation[] };
  mac: { current: string | undefined; generations: Generation[] };
  encryption: string | undefined;
}

export async function deploymentKeys(kms: Kms, deployment: string): Promise<KmsKeys> {
  const prefix = aliasPrefix(deployment);
  const aliases = (await kms.aliases()).filter((alias) => alias.name.startsWith(`${prefix}/`));
  const of = (purpose: 'signing' | 'mac') => ({
    current: aliases.find((alias) => alias.name === `${prefix}/${purpose}`)?.keyId,
    generations: aliases
      .flatMap((alias) => {
        const time = alias.name.startsWith(`${prefix}/${purpose}/`) ? generationTime(alias.name.slice(`${prefix}/${purpose}/`.length)) : null;
        return time === null ? [] : [{ keyId: alias.keyId, madeAt: time, alias: alias.name }];
      })
      .sort((a, b) => a.madeAt - b.madeAt),
  });
  return { signing: of('signing'), mac: of('mac'), encryption: aliases.find((alias) => alias.name === `${prefix}/encryption`)?.keyId };
}

/** An ECDSA signature in DER (SEQUENCE of the INTEGERs r and s) as JWS has it: r and s, 32 bytes each. */
export function derToJose(der: Uint8Array): Uint8Array {
  // SEQUENCE, its length (one byte for P-256), then INTEGER r and INTEGER s.
  let offset = 2;
  const integer = () => {
    const length = der[offset + 1]!;
    const value = der.subarray(offset + 2, offset + 2 + length);
    offset += 2 + length;
    // A leading 0 keeps a high bit from making the number negative; a short one is padded.
    const trimmed = value[0] === 0 ? value.subarray(1) : value;
    const padded = new Uint8Array(32);
    padded.set(trimmed, 32 - trimmed.length);
    return padded;
  };
  const r = integer();
  const s = integer();
  const jose = new Uint8Array(64);
  jose.set(r, 0);
  jose.set(s, 32);
  return jose;
}

/** A public key from KMS (DER, SubjectPublicKeyInfo) as a JWK, with its thumbprint as `kid`. */
async function publicJwk(spki: Uint8Array): Promise<JWK> {
  const { kty, crv, x, y } = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' }).export({ format: 'jwk' }) as JWK;
  const jwk = { kty, crv, x, y };
  return { ...jwk, alg: SIGNING_ALG, use: 'sig', kid: await calculateJwkThumbprint(jwk) };
}

/** Messages KMS signs as they are; a longer one is hashed here and sent as its digest. */
const MAX_RAW_MESSAGE = 4096;

/** How the stored values encrypted by KMS start, to tell them from the local key service's (`v1.`). */
const KMS_VALUE = 'kms1.';

/** How often madAuth reads its keys again, so a rotation reaches every running instance. */
const REFRESH_MS = 5 * 60 * 1000;

interface State {
  verificationKeys: JWK[];
  /** By kid: the KMS key that signs with it. */
  signers: Map<string, string>;
  macKeys: string[];
  encryptionKey: string;
}

/**
 * The key service of a deployment's keys in KMS, or why there is none (e.g. the keys are missing). Reads them
 * when it starts and every five minutes after, keeping what it had when a read fails.
 */
export async function createAwsKmsKeyService(kms: Kms, deployment: string): Promise<{ keyService: KeyService } | { problem: string }> {
  /** The keys as KMS has them now, or why they can't be used. */
  const load = async (): Promise<State | string> => {
    const keys = await deploymentKeys(kms, deployment);
    const { signing, mac, encryption } = keys;
    if (!signing.current || !mac.current || !encryption) {
      return `the KMS keys of ${aliasPrefix(deployment)} are missing: create them with the AWS template (deploy/aws) or with npx @madauth/server kms-setup`;
    }
    // The signing key of now first, then the others, newest first; a disabled one verifies nothing any more.
    const order = [signing.current, ...signing.generations.map((g) => g.keyId).reverse().filter((id) => id !== signing.current)];
    const published = await Promise.all(order.map(async (keyId) => ({ keyId, spki: await kms.publicKey(keyId) })));
    const usable = published.filter((key): key is { keyId: string; spki: Uint8Array } => key.spki !== null);
    if (usable[0]?.keyId !== signing.current) return `the signing key behind ${aliasPrefix(deployment)}/signing is disabled`;
    const jwks = await Promise.all(usable.map(async (key) => ({ keyId: key.keyId, jwk: await publicJwk(key.spki) })));
    const macKeys = [mac.current, ...mac.generations.map((g) => g.keyId).reverse().filter((id) => id !== mac.current)];
    return {
      verificationKeys: jwks.map((key) => key.jwk),
      signers: new Map(jwks.map((key) => [key.jwk.kid!, key.keyId])),
      macKeys,
      encryptionKey: encryption,
    };
  };

  const first = await load();
  if (typeof first === 'string') return { problem: first };
  let state = first;
  let loadedAt = Date.now();
  let reading: Promise<void> | undefined;
  const keep = (why: string) => console.error(`[madauth] Could not read the KMS keys again, so the ones read before stay: ${why}`);
  const current = async (): Promise<State> => {
    if (Date.now() - loadedAt >= REFRESH_MS) {
      reading ??= load()
        .then(
          (next) => {
            if (typeof next === 'string') return keep(next);
            // The same list as before keeps its identity: tokens.ts builds its key set once per list.
            const same = JSON.stringify(next.verificationKeys) === JSON.stringify(state.verificationKeys);
            state = same ? { ...next, verificationKeys: state.verificationKeys } : next;
          },
          (e: Error) => keep(e.message),
        )
        .finally(() => {
          loadedAt = Date.now();
          reading = undefined;
        });
      await reading;
    }
    return state;
  };
  const context = (purpose: EncryptionPurpose) => ({ madauth: deployment, purpose });

  const keyService: KeyService = {
    verificationKeys: async () => (await current()).verificationKeys,
    async sign(kid, data) {
      const keyId = (await current()).signers.get(kid);
      if (!keyId) throw new Error(`No KMS signing key has the kid ${kid}.`);
      const message = data.length <= MAX_RAW_MESSAGE ? data : createHash('sha256').update(data).digest();
      return derToJose(await kms.sign(keyId, message));
    },
    mac: async (data) => kms.mac((await current()).macKeys[0]!, data),
    macs: async (data) => Promise.all((await current()).macKeys.map((keyId) => kms.mac(keyId, data))),
    encrypt: async (purpose, plaintext) =>
      KMS_VALUE + Buffer.from(await kms.encrypt((await current()).encryptionKey, plaintext, context(purpose))).toString('base64url'),
    async decrypt(purpose, value) {
      // A clean cut: what the local key service stored can't be read here.
      if (!value.startsWith(KMS_VALUE)) return null;
      const plaintext = await kms.decrypt((await current()).encryptionKey, Buffer.from(value.slice(KMS_VALUE.length), 'base64url'), context(purpose));
      // KMS rotates the encryption key in place and decrypts with the material that made a value.
      return plaintext ? { plaintext, current: true } : null;
    },
  };
  return { keyService };
}

/** The key specs and usages of the three kinds, as KMS names them. */
const KEY_SPECS: Record<KmsKeyKind, { KeySpec: 'ECC_NIST_P256' | 'HMAC_256' | 'SYMMETRIC_DEFAULT'; KeyUsage: 'SIGN_VERIFY' | 'GENERATE_VERIFY_MAC' | 'ENCRYPT_DECRYPT' }> = {
  signing: { KeySpec: 'ECC_NIST_P256', KeyUsage: 'SIGN_VERIFY' },
  mac: { KeySpec: 'HMAC_256', KeyUsage: 'GENERATE_VERIFY_MAC' },
  encryption: { KeySpec: 'SYMMETRIC_DEFAULT', KeyUsage: 'ENCRYPT_DECRYPT' },
};

/** The errors that mean "not this key" or "can't be used", rather than KMS being unreachable. */
const NOT_USABLE = ['DisabledException', 'KMSInvalidStateException', 'NotFoundException'];
const NOT_ITS_CIPHERTEXT = ['InvalidCiphertextException', 'IncorrectKeyException'];

/**
 * The KMS operations through the AWS SDK (`@aws-sdk/client-kms`, which AWS Lambda's Node.js runtimes contain), with
 * the default credentials and region of the environment. Null if the SDK isn't installed.
 */
export async function kmsFromSdk(): Promise<Kms | null> {
  const sdk = await import('@aws-sdk/client-kms').catch(() => null);
  if (!sdk) return null;
  const client = new sdk.KMSClient({});
  /** What a call answers, or its error when it is one of `expected`; other errors are thrown on. */
  const unless = async <T>(call: Promise<T>, expected: string[]): Promise<T | null> => {
    const result = await call.catch((e: Error) => e);
    if (!(result instanceof Error)) return result;
    if (expected.includes(result.name)) return null;
    throw result;
  };
  return {
    async aliases() {
      const all: { name: string; keyId: string }[] = [];
      let marker: string | undefined;
      do {
        const page = await client.send(new sdk.ListAliasesCommand({ Limit: 100, Marker: marker }));
        for (const { AliasName, TargetKeyId } of page.Aliases ?? []) if (AliasName && TargetKeyId) all.push({ name: AliasName, keyId: TargetKeyId });
        marker = page.Truncated ? page.NextMarker : undefined;
      } while (marker);
      return all;
    },
    publicKey: async (keyId) => (await unless(client.send(new sdk.GetPublicKeyCommand({ KeyId: keyId })), NOT_USABLE))?.PublicKey ?? null,
    async sign(keyId, message) {
      const raw = message.length <= MAX_RAW_MESSAGE;
      const answer = await client.send(new sdk.SignCommand({ KeyId: keyId, Message: message, MessageType: raw ? 'RAW' : 'DIGEST', SigningAlgorithm: 'ECDSA_SHA_256' }));
      return answer.Signature!;
    },
    mac: async (keyId, message) => (await client.send(new sdk.GenerateMacCommand({ KeyId: keyId, Message: message, MacAlgorithm: 'HMAC_SHA_256' }))).Mac!,
    encrypt: async (keyId, plaintext, context) =>
      (await client.send(new sdk.EncryptCommand({ KeyId: keyId, Plaintext: plaintext, EncryptionContext: context }))).CiphertextBlob!,
    decrypt: async (keyId, ciphertext, context) =>
      (await unless(client.send(new sdk.DecryptCommand({ KeyId: keyId, CiphertextBlob: ciphertext, EncryptionContext: context })), NOT_ITS_CIPHERTEXT))?.Plaintext ?? null,
    async createKey(kind, description) {
      const answer = await client.send(new sdk.CreateKeyCommand({ ...KEY_SPECS[kind], Description: description }));
      const keyId = answer.KeyMetadata!.KeyId!;
      // The encryption key gets new material every year by itself; KMS keeps the old to decrypt.
      if (kind === 'encryption') await client.send(new sdk.EnableKeyRotationCommand({ KeyId: keyId }));
      return keyId;
    },
    async createAlias(name, keyId) {
      await client.send(new sdk.CreateAliasCommand({ AliasName: name, TargetKeyId: keyId }));
    },
    async updateAlias(name, keyId) {
      await client.send(new sdk.UpdateAliasCommand({ AliasName: name, TargetKeyId: keyId }));
    },
    enabled: async (keyId) => (await client.send(new sdk.DescribeKeyCommand({ KeyId: keyId }))).KeyMetadata?.KeyState === 'Enabled',
    async disableKey(keyId) {
      await client.send(new sdk.DisableKeyCommand({ KeyId: keyId }));
    },
  };
}
