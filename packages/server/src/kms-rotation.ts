// Setting up and rotating a deployment's KMS keys (aws-kms.ts). Never the server's work: `npx @madauth/server
// kms-setup` and `kms-rotate` do it with an admin's credentials, the AWS template's rotator with a role of its own.
// Whatever can create a key the server trusts can forge sessions, so the server's role can't. See "AWS KMS" in
// docs/server.md.
import { aliasPrefix, deploymentKeys, generationName, type Kms, type KmsKeyKind } from './aws-kms.js';

const DAY_MS = 24 * 60 * 60 * 1000;

export interface RotationOptions {
  /** How old the signing and hash keys get before a new one is made. Default: a year. */
  everyMs?: number;
  /**
   * How long a new key is published before it is used: backends may cache the list of signing keys for an
   * hour, and would refuse what a key signs before they know it. Default: 2 hours.
   */
  publishMs?: number;
  /**
   * How long an old signing key keeps verifying after the next one began to sign: as long as the sessions it
   * signed can be renewed, SESSION_RENEWAL_TTL, with a margin for the time between rotation runs. Default: 32 days.
   */
  retireAfterMs?: number;
}

const description = (deployment: string, kind: KmsKeyKind) => `madAuth ${kind} key of ${deployment}`;

/**
 * Creates the keys a deployment lacks, each under its aliases (aws-kms.ts); does nothing for the ones it has.
 * Resolves to what was done, for people to read.
 */
export async function setUpKmsKeys(kms: Kms, deployment: string, now = Date.now()): Promise<string[]> {
  const prefix = aliasPrefix(deployment);
  const keys = await deploymentKeys(kms, deployment);
  const done: string[] = [];
  for (const kind of ['signing', 'mac'] as const) {
    if (keys[kind].current) continue;
    const keyId = await kms.createKey(kind, description(deployment, kind));
    await kms.createAlias(`${prefix}/${kind}/${generationName(now)}`, keyId);
    await kms.createAlias(`${prefix}/${kind}`, keyId);
    done.push(`Created the ${kind} key ${keyId} (${prefix}/${kind}).`);
  }
  if (!keys.encryption) {
    const keyId = await kms.createKey('encryption', description(deployment, 'encryption'));
    await kms.createAlias(`${prefix}/encryption`, keyId);
    done.push(`Created the encryption key ${keyId} (${prefix}/encryption); KMS rotates it every year by itself.`);
  }
  return done;
}

/**
 * One run of the rotation, for the signing and the hash key; run it at least daily. A key older than `everyMs`
 * gets a successor, which is published first and used from a run at least `publishMs` later. An old signing key
 * is disabled once its sessions have expired; old hash keys stay, since recovery codes hashed with them may be
 * kept for years. KMS rotates the encryption key in place. Resolves to what was done, for people to read.
 */
export async function rotateKmsKeys(kms: Kms, deployment: string, now = Date.now(), options: RotationOptions = {}): Promise<string[]> {
  const { everyMs = 365 * DAY_MS, publishMs = 2 * 60 * 60 * 1000, retireAfterMs = 32 * DAY_MS } = options;
  const prefix = aliasPrefix(deployment);
  const keys = await deploymentKeys(kms, deployment);
  const done: string[] = [];
  for (const kind of ['signing', 'mac'] as const) {
    const { current, generations } = keys[kind];
    const newest = generations.at(-1);
    if (!current || !newest) {
      done.push(`There is no ${kind} key with its aliases under ${prefix}: run kms-setup first.`);
      continue;
    }
    if (newest.keyId !== current && now - newest.madeAt >= publishMs) {
      await kms.updateAlias(`${prefix}/${kind}`, newest.keyId);
      done.push(`The ${kind} key ${newest.keyId} is used from now on.`);
    } else if (newest.keyId === current && now - newest.madeAt >= everyMs) {
      const keyId = await kms.createKey(kind, description(deployment, kind));
      await kms.createAlias(`${prefix}/${kind}/${generationName(now)}`, keyId);
      done.push(`Created the ${kind} key ${keyId}: it is used from a run in ${Math.round(publishMs / 3600_000)} hours.`);
    }
    if (kind !== 'signing') continue;
    // A signing key retires once the key after it has signed for `retireAfterMs`: it began no sooner than
    // `publishMs` after it was made.
    for (const [index, generation] of generations.entries()) {
      const next = generations[index + 1];
      if (!next || generation.keyId === current || now - (next.madeAt + publishMs) < retireAfterMs) continue;
      if (!(await kms.enabled(generation.keyId))) continue;
      await kms.disableKey(generation.keyId);
      done.push(`Disabled the signing key ${generation.keyId}: the sessions it signed have expired.`);
    }
  }
  return done;
}

/**
 * The IAM statements the server's role needs: use the keys of its deployment, which it finds by their aliases,
 * and nothing else. It can't create keys or aliases, so it can't make a key trusted.
 */
export function serverKmsPolicy(deployment: string): object[] {
  return [
    {
      Effect: 'Allow',
      Action: ['kms:GetPublicKey', 'kms:Sign', 'kms:GenerateMac', 'kms:Encrypt', 'kms:Decrypt'],
      Resource: '*',
      Condition: { 'ForAnyValue:StringLike': { 'kms:ResourceAliases': `${aliasPrefix(deployment)}/*` } },
    },
    { Effect: 'Allow', Action: 'kms:ListAliases', Resource: '*' },
  ];
}
