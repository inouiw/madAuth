// Setting up and rotating a deployment's KMS keys (aws-kms.ts). Never the server's work: `npx @madauth/server
// kms-setup` and `kms-rotate` do it with an admin's credentials, the AWS template's rotator with a role of its own.
// Whatever can create a key the server trusts can forge sessions, so the server's role can't. See "AWS KMS" in
// docs/server.md.
import { aliasPrefix, deploymentKeys, generationName, type Kms, type KmsKeyKind, type RotatedKind } from './aws-kms.js';

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
  /**
   * How long an old webhook key stays published after the next one began to sign. A receiver checks a call within
   * minutes (WEBHOOK_TOLERANCE_SECONDS), so a day is ample. Default: 1 day.
   */
  retireWebhookAfterMs?: number;
}

const description = (deployment: string, kind: KmsKeyKind) => `madAuth ${kind} key of ${deployment}`;

export interface SetupOptions {
  /**
   * Also an RS256 signing key (`signing-rsa`), for the ID tokens of OpenID Connect clients that can't verify
   * ES256. Default: false; a deployment that has one keeps it either way.
   */
  rs256?: boolean;
  /**
   * Also an Ed25519 key (`webhook`) that signs the webhook calls (`v1a`), which receivers check with its public key
   * alone. Default: true; false for a deployment whose receiver checks only WEBHOOK_SECRET or AWS IAM. A deployment
   * that has one keeps it either way.
   */
  webhook?: boolean;
}

/** The kinds a deployment rotates: the RS256 and webhook keys only once it has them (or is set up with them). */
const rotatedKinds = (keys: Awaited<ReturnType<typeof deploymentKeys>>, options: SetupOptions = {}): RotatedKind[] => {
  const has = (kind: 'signing-rsa' | 'webhook') => !!keys[kind].current || keys[kind].generations.length > 0;
  return [
    'signing',
    ...(options.rs256 || has('signing-rsa') ? (['signing-rsa'] as const) : []),
    'mac',
    ...(options.webhook || has('webhook') ? (['webhook'] as const) : []),
  ];
};

/**
 * Creates the keys a deployment lacks, each under its aliases (aws-kms.ts); does nothing for the ones it has. A key
 * that has its generation alias but not the current one (a setup that stopped half-way) becomes current instead
 * of getting a second key. Resolves to what was done, for people to read.
 */
export async function setUpKmsKeys(kms: Kms, deployment: string, now = Date.now(), options: SetupOptions = {}): Promise<string[]> {
  const prefix = aliasPrefix(deployment);
  const keys = await deploymentKeys(kms, deployment);
  const done: string[] = [];
  for (const kind of rotatedKinds(keys, { rs256: options.rs256, webhook: options.webhook ?? true })) {
    if (keys[kind].current) continue;
    const newest = keys[kind].generations.at(-1);
    if (newest) {
      await kms.createAlias(`${prefix}/${kind}`, newest.keyId);
      done.push(`The ${kind} key ${newest.keyId} (${newest.alias}) is used from now on.`);
      continue;
    }
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
 * One run of the rotation, for the signing, hash and webhook keys; run it at least daily. A key older than `everyMs`
 * gets a successor, which is published first and used from a run at least `publishMs` later. An old signing key
 * is disabled once its sessions have expired, an old webhook key a day after its successor began to sign, and its
 * generation alias removed, so the server stops reading it; old hash keys stay, since recovery codes hashed with
 * them may be kept for years. KMS rotates the encryption key in place. Resolves to what was done and what is
 * missing, for people to read.
 */
export async function rotateKmsKeys(
  kms: Kms,
  deployment: string,
  now = Date.now(),
  options: RotationOptions = {},
): Promise<{ done: string[]; problems: string[] }> {
  const { everyMs = 365 * DAY_MS, publishMs = 2 * 60 * 60 * 1000, retireAfterMs = 32 * DAY_MS, retireWebhookAfterMs = DAY_MS } = options;
  const prefix = aliasPrefix(deployment);
  const keys = await deploymentKeys(kms, deployment);
  const done: string[] = [];
  const problems: string[] = [];
  for (const kind of rotatedKinds(keys)) {
    const { current, generations } = keys[kind];
    const newest = generations.at(-1);
    if (!current || !newest) {
      problems.push(`There is no ${kind} key with its aliases under ${prefix}: run kms-setup${kind === 'signing-rsa' ? ' --rs256' : ''} first.`);
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
    if (kind === 'mac') continue;
    // A signing key retires once the key after it has signed for `retireAfterMs` (a webhook key `retireWebhookAfterMs`):
    // it began no sooner than `publishMs` after it was made.
    const retiresAfter = kind === 'webhook' ? retireWebhookAfterMs : retireAfterMs;
    const signed = { signing: 'sessions it signed have expired', 'signing-rsa': 'tokens it signed have expired', webhook: 'calls it signed are checked' }[kind];
    for (const [index, generation] of generations.entries()) {
      const next = generations[index + 1];
      if (!next || generation.keyId === current || now - (next.madeAt + publishMs) < retiresAfter) continue;
      // Disabled first: if removing the alias fails, the next run removes it.
      if (await kms.enabled(generation.keyId)) await kms.disableKey(generation.keyId);
      await kms.deleteAlias(generation.alias);
      done.push(`Disabled the ${kind} key ${generation.keyId} and removed ${generation.alias}: the ${signed}.`);
    }
  }
  return { done, problems };
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
