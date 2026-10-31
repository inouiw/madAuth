// The AWS KMS key service (MADAUTH_KEY_SERVICE=aws-kms): madAuth signs, hashes and encrypts with keys that never
// leave KMS. It finds its keys by itself, under aliases named after the deployment (its MADAUTH_ISSUER):
//
//   alias/madauth/<deployment>/signing              the ES256 key that signs now
//   alias/madauth/<deployment>/signing/<time>       every signing key, by when it was made: all of them verify
//   alias/madauth/<deployment>/signing-rsa (and /signing-rsa/<time>)
//                                                   the same for the RS256 keys, if the deployment has them: they
//                                                   sign the ID tokens of the clients that ask for RS256
//   alias/madauth/<deployment>/mac (and /mac/<time>) the same for the keys that hash the codes
//   alias/madauth/<deployment>/encryption           the key that encrypts the secrets; KMS rotates it in place
//
// The deployment creates the keys and a rotator with a role of its own rotates them (kms-rotation.ts); the server
// only uses them, and may use only keys with its deployment's aliases, which it can't create. See "AWS KMS" in
// docs/server.md.
import { createHash, createPublicKey } from 'node:crypto';
import { calculateJwkThumbprint, type JWK } from 'jose';
import type { EncryptionPurpose, KeyService } from './key-service.js';
import { RSA_SIGNING_ALG, SIGNING_ALG, publicSigningJwk, thumbprintMembers, type SigningAlg } from './keys.js';

/** The KMS operations madAuth uses; {@link kmsFromSdk} makes them from the AWS SDK, tests from a stand-in. */
export interface Kms {
  /** Every alias of the account and region, with the key it points to. */
  aliases(): Promise<{ name: string; keyId: string }[]>;
  /** The public key (DER, SubjectPublicKeyInfo) of an asymmetric key; null if the key is disabled or going. */
  publicKey(keyId: string): Promise<Uint8Array | null>;
  /** The signature of `message`, of any length, as KMS makes it: ECDSA with SHA-256 in DER for ES256, RSASSA-PKCS1-v1_5 with SHA-256 for RS256. */
  sign(keyId: string, message: Uint8Array, alg: SigningAlg): Promise<Uint8Array>;
  /** HMAC-SHA256 of `message`. */
  mac(keyId: string, message: Uint8Array): Promise<Uint8Array>;
  encrypt(keyId: string, plaintext: Uint8Array, context: Record<string, string>): Promise<Uint8Array>;
  /** Null if the ciphertext isn't one of this key, or was made for another context. */
  decrypt(keyId: string, ciphertext: Uint8Array, context: Record<string, string>): Promise<Uint8Array | null>;
  // For setting up and rotating the keys (kms-rotation.ts), never called by the server:
  createKey(kind: KmsKeyKind, description: string): Promise<string>;
  createAlias(name: string, keyId: string): Promise<void>;
  updateAlias(name: string, keyId: string): Promise<void>;
  deleteAlias(name: string): Promise<void>;
  /** Whether the key can be used: enabled, not disabled or going. */
  enabled(keyId: string): Promise<boolean>;
  disableKey(keyId: string): Promise<void>;
}

/** The kinds of keys: ES256 signing, RS256 signing (optional), HMAC, and symmetric encryption that KMS rotates by itself. */
export type KmsKeyKind = 'signing' | 'signing-rsa' | 'mac' | 'encryption';

/** The kinds that get a successor at a rotation: all but the encryption key, which KMS rotates in place. */
export type RotatedKind = Exclude<KmsKeyKind, 'encryption'>;

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
  /** The RS256 keys: none unless the deployment was set up with them. */
  'signing-rsa': { current: string | undefined; generations: Generation[] };
  mac: { current: string | undefined; generations: Generation[] };
  encryption: string | undefined;
}

export async function deploymentKeys(kms: Kms, deployment: string): Promise<KmsKeys> {
  const prefix = aliasPrefix(deployment);
  const aliases = (await kms.aliases()).filter((alias) => alias.name.startsWith(`${prefix}/`));
  const of = (purpose: RotatedKind) => ({
    current: aliases.find((alias) => alias.name === `${prefix}/${purpose}`)?.keyId,
    generations: aliases
      .flatMap((alias) => {
        const time = alias.name.startsWith(`${prefix}/${purpose}/`) ? generationTime(alias.name.slice(`${prefix}/${purpose}/`.length)) : null;
        return time === null ? [] : [{ keyId: alias.keyId, madeAt: time, alias: alias.name }];
      })
      .sort((a, b) => a.madeAt - b.madeAt),
  });
  return { signing: of('signing'), 'signing-rsa': of('signing-rsa'), mac: of('mac'), encryption: aliases.find((alias) => alias.name === `${prefix}/encryption`)?.keyId };
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
  const jwk = thumbprintMembers(createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' }).export({ format: 'jwk' }) as JWK);
  return publicSigningJwk(jwk, await calculateJwkThumbprint(jwk));
}

/** The longest message KMS signs as it is; a longer one is hashed here and sent as its digest. */
const MAX_RAW_MESSAGE = 4096;

/** How the stored values encrypted by KMS start, to tell them from the local key service's (`v1.`). */
const KMS_VALUE = 'kms1.';

/** How often madAuth reads its keys again, so a rotation reaches every running instance. */
const REFRESH_MS = 5 * 60 * 1000;

interface State {
  verificationKeys: JWK[];
  /** By kid: the KMS key that signs with it, and how. */
  signers: Map<string, { keyId: string; alg: SigningAlg }>;
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
    const rsaKeys = keys['signing-rsa'];
    if (!signing.current || !mac.current || !encryption) {
      return `the KMS keys of ${aliasPrefix(deployment)} are missing: create them with the AWS template (deploy/aws) or with npx @madauth/server kms-setup`;
    }
    /** The public keys of one signing kind: the key of now first, then the others, newest first; a disabled one verifies nothing any more. */
    const publish = async (kind: 'signing' | 'signing-rsa', alg: SigningAlg) => {
      const { current, generations } = keys[kind];
      if (!current) return [];
      const order = [current, ...generations.map((g) => g.keyId).reverse().filter((id) => id !== current)];
      const published = await Promise.all(order.map(async (keyId) => ({ keyId, spki: await kms.publicKey(keyId) })));
      const usable = published.filter((key): key is { keyId: string; spki: Uint8Array } => key.spki !== null);
      if (usable[0]?.keyId !== current) return `the ${kind === 'signing' ? 'signing' : 'RS256 signing'} key behind ${aliasPrefix(deployment)}/${kind} is disabled`;
      return Promise.all(usable.map(async (key) => ({ keyId: key.keyId, alg, jwk: await publicJwk(key.spki) })));
    };
    const ec = await publish('signing', SIGNING_ALG);
    if (typeof ec === 'string') return ec;
    const rsa = rsaKeys.current ? await publish('signing-rsa', RSA_SIGNING_ALG) : [];
    // RS256 is optional: without its key the server runs on, and the clients set to RS256 get server_error.
    if (typeof rsa === 'string') console.error(`[madauth] ${rsa}: no RS256 ID tokens until it is enabled again or the alias removed.`);
    const jwks = [...ec, ...(typeof rsa === 'string' ? [] : rsa)];
    const macKeys = [mac.current, ...mac.generations.map((g) => g.keyId).reverse().filter((id) => id !== mac.current)];
    return {
      verificationKeys: jwks.map((key) => key.jwk),
      signers: new Map(jwks.map((key) => [key.jwk.kid!, { keyId: key.keyId, alg: key.alg }])),
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
      const signer = (await current()).signers.get(kid);
      if (!signer) throw new Error(`No KMS signing key has the kid ${kid}.`);
      const signature = await kms.sign(signer.keyId, data, signer.alg);
      // An RSA signature is as JWS wants it; ECDSA's comes in DER.
      return signer.alg === RSA_SIGNING_ALG ? signature : derToJose(signature);
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

/** The key specs and usages of the kinds, as KMS names them. */
const KEY_SPECS: Record<KmsKeyKind, { KeySpec: 'ECC_NIST_P256' | 'RSA_2048' | 'HMAC_256' | 'SYMMETRIC_DEFAULT'; KeyUsage: 'SIGN_VERIFY' | 'GENERATE_VERIFY_MAC' | 'ENCRYPT_DECRYPT' }> = {
  signing: { KeySpec: 'ECC_NIST_P256', KeyUsage: 'SIGN_VERIFY' },
  'signing-rsa': { KeySpec: 'RSA_2048', KeyUsage: 'SIGN_VERIFY' },
  mac: { KeySpec: 'HMAC_256', KeyUsage: 'GENERATE_VERIFY_MAC' },
  encryption: { KeySpec: 'SYMMETRIC_DEFAULT', KeyUsage: 'ENCRYPT_DECRYPT' },
};

/** The errors that mean "not this key" or "can't be used", rather than KMS being unreachable. */
const NOT_USABLE = ['DisabledException', 'KMSInvalidStateException', 'NotFoundException'];
const NOT_ITS_CIPHERTEXT = ['InvalidCiphertextException', 'IncorrectKeyException'];

/**
 * The KMS operations through the AWS SDK (`@aws-sdk/client-kms`, which AWS Lambda's Node.js runtimes contain), with
 * the default credentials and region of the environment; or, if the SDK can't be loaded, why.
 */
export async function kmsFromSdk(): Promise<{ kms: Kms } | { problem: string }> {
  const sdk = await import('@aws-sdk/client-kms').catch((e: Error) => e);
  if (sdk instanceof Error) return { problem: `the AWS SDK could not be loaded: npm install @aws-sdk/client-kms (${sdk.message})` };
  const client = new sdk.KMSClient({});
  /** What a call answers, or its error when it is one of `expected`; other errors are thrown on. */
  const unless = async <T>(call: Promise<T>, expected: string[]): Promise<T | null> => {
    const result = await call.catch((e: Error) => e);
    if (!(result instanceof Error)) return result;
    if (expected.includes(result.name)) return null;
    throw result;
  };
  const kms: Kms = {
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
    async sign(keyId, message, alg) {
      const raw = message.length <= MAX_RAW_MESSAGE;
      const answer = await client.send(
        new sdk.SignCommand({
          KeyId: keyId,
          Message: raw ? message : createHash('sha256').update(message).digest(),
          MessageType: raw ? 'RAW' : 'DIGEST',
          SigningAlgorithm: alg === RSA_SIGNING_ALG ? 'RSASSA_PKCS1_V1_5_SHA_256' : 'ECDSA_SHA_256',
        }),
      );
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
    async deleteAlias(name) {
      await client.send(new sdk.DeleteAliasCommand({ AliasName: name }));
    },
    enabled: async (keyId) => (await client.send(new sdk.DescribeKeyCommand({ KeyId: keyId }))).KeyMetadata?.KeyState === 'Enabled',
    async disableKey(keyId) {
      await client.send(new sdk.DisableKeyCommand({ KeyId: keyId }));
    },
  };
  return { kms };
}
