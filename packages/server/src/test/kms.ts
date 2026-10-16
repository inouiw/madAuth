// A stand-in for AWS KMS in tests: the operations of `Kms` (aws-kms.ts) on keys held here, with what KMS answers:
// DER signatures, SubjectPublicKeyInfo public keys, ciphertexts bound to their encryption context.
import { createCipheriv, createDecipheriv, createHmac, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import type { Kms, KmsKeyKind } from '../aws-kms.js';

interface FakeKey {
  kind: KmsKeyKind;
  enabled: boolean;
  privateKey?: KeyObject;
  publicKey?: KeyObject;
  secret?: Buffer;
}

export function fakeKms() {
  const keys = new Map<string, FakeKey>();
  const aliases = new Map<string, string>();
  const calls: string[] = [];
  let next = 1;
  const usable = (keyId: string, kind: KmsKeyKind) => {
    const key = keys.get(keyId);
    if (!key || key.kind !== kind) throw Object.assign(new Error(`No ${kind} key ${keyId}`), { name: 'NotFoundException' });
    if (!key.enabled) throw Object.assign(new Error(`${keyId} is disabled`), { name: 'DisabledException' });
    return key;
  };
  const contextOf = (context: Record<string, string>) => JSON.stringify(Object.entries(context).sort());

  const kms: Kms = {
    aliases: async () => [...aliases].map(([name, keyId]) => ({ name, keyId })),
    async publicKey(keyId) {
      calls.push(`publicKey ${keyId}`);
      const key = keys.get(keyId);
      return key?.enabled && key.publicKey ? new Uint8Array(key.publicKey.export({ format: 'der', type: 'spki' })) : null;
    },
    async sign(keyId, message) {
      calls.push(`sign ${keyId}`);
      return new Uint8Array(sign('sha256', message, usable(keyId, 'signing').privateKey!));
    },
    async mac(keyId, message) {
      calls.push(`mac ${keyId}`);
      return new Uint8Array(createHmac('sha256', usable(keyId, 'mac').secret!).update(message).digest());
    },
    async encrypt(keyId, plaintext, context) {
      calls.push(`encrypt ${keyId}`);
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', usable(keyId, 'encryption').secret!, iv);
      cipher.setAAD(Buffer.from(contextOf(context)));
      const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      return new Uint8Array(Buffer.concat([Buffer.from(keyId.padEnd(16)), iv, cipher.getAuthTag(), body]));
    },
    async decrypt(keyId, ciphertext, context) {
      calls.push(`decrypt ${keyId}`);
      const blob = Buffer.from(ciphertext);
      if (blob.subarray(0, 16).toString().trim() !== keyId) return null;
      const decipher = createDecipheriv('aes-256-gcm', usable(keyId, 'encryption').secret!, blob.subarray(16, 28));
      decipher.setAAD(Buffer.from(contextOf(context)));
      decipher.setAuthTag(blob.subarray(28, 44));
      const opened = (() => {
        try {
          return Buffer.concat([decipher.update(blob.subarray(44)), decipher.final()]);
        } catch {
          return null;
        }
      })();
      return opened ? new Uint8Array(opened) : null;
    },
    async createKey(kind) {
      const keyId = `key-${next++}`;
      calls.push(`createKey ${kind} ${keyId}`);
      const pair = kind === 'signing' ? generateKeyPairSync('ec', { namedCurve: 'P-256' }) : undefined;
      keys.set(keyId, { kind, enabled: true, privateKey: pair?.privateKey, publicKey: pair?.publicKey, secret: kind === 'signing' ? undefined : randomBytes(32) });
      return keyId;
    },
    async createAlias(name, keyId) {
      if (aliases.has(name)) throw Object.assign(new Error(`${name} exists`), { name: 'AlreadyExistsException' });
      aliases.set(name, keyId);
    },
    async updateAlias(name, keyId) {
      aliases.set(name, keyId);
    },
    enabled: async (keyId) => !!keys.get(keyId)?.enabled,
    async disableKey(keyId) {
      calls.push(`disableKey ${keyId}`);
      keys.get(keyId)!.enabled = false;
    },
  };
  return { kms, keys, aliases, calls };
}
