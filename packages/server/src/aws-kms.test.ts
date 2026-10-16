// The AWS KMS key service, and setting up and rotating its keys. Behaviour described in "AWS KMS" in
// docs/server.md; update the doc when changing it.
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { aliasPrefix, createAwsKmsKeyService, deploymentOf, derToJose } from './aws-kms.js';
import { rotateKmsKeys, serverKmsPolicy, setUpKmsKeys } from './kms-rotation.js';
import { ISSUER, cookies, passwordApp, post, signUpVerified } from './test/helpers.js';
import { fakeKms } from './test/kms.js';
import { readToken, signToken } from './tokens.js';
import type { KeyService } from './key-service.js';

const DEPLOYMENT = 'auth-example-com';
const START = Date.UTC(2026, 9, 17, 12, 0, 0);
const HOUR = 3600_000;
const DAY = 24 * HOUR;

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

async function keyServiceOf(kms: ReturnType<typeof fakeKms>['kms']): Promise<KeyService> {
  const made = await createAwsKmsKeyService(kms, DEPLOYMENT);
  if ('problem' in made) throw new Error(made.problem);
  return made.keyService;
}

describe('the AWS KMS key service', () => {
  it('KM1: names the deployment after its issuer, and finds no keys before they are set up', async () => {
    expect(deploymentOf('https://auth.example.com')).toBe(DEPLOYMENT);
    expect(deploymentOf('http://localhost:8787')).toBe('localhost-8787');
    expect(await createAwsKmsKeyService(fakeKms().kms, DEPLOYMENT)).toEqual({
      problem: `the KMS keys of ${aliasPrefix(DEPLOYMENT)} are missing: create them with the AWS template (deploy/aws) or with npx @madauth/server kms-setup`,
    });
  });

  it('KM2: signs with the KMS key as JWS has it, publishes its public key, and verifies its tokens', async () => {
    const { kms } = fakeKms();
    await setUpKmsKeys(kms, DEPLOYMENT, START);
    const keys = await keyServiceOf(kms);

    const [published] = await keys.verificationKeys();
    expect(published).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig', kid: expect.any(String) });
    expect(published).not.toHaveProperty('d');
    const token = await signToken(keys, ISSUER, 'madauth-test+jwt', { sub: 'usr_1' }, 60);
    expect(decodeProtectedHeader(token).kid).toBe(published!.kid);
    // A backend verifies with the published key alone.
    expect((await jwtVerify(token, createLocalJWKSet({ keys: [published!] }))).payload.sub).toBe('usr_1');
    expect(await readToken(keys, ISSUER, 'madauth-test+jwt', token)).toMatchObject({ sub: 'usr_1' });
    // A token longer than KMS signs as it is verifies too.
    const long = await signToken(keys, ISSUER, 'madauth-test+jwt', { sub: 'usr_1', pad: 'x'.repeat(5000) }, 60);
    expect((await jwtVerify(long, createLocalJWKSet({ keys: [published!] }))).payload.sub).toBe('usr_1');
  });

  it('KM3: hashes with the KMS hash key and encrypts bound to the purpose; values of the local key service read as nothing', async () => {
    const { kms } = fakeKms();
    await setUpKmsKeys(kms, DEPLOYMENT, START);
    const keys = await keyServiceOf(kms);

    const hash = await keys.mac(new TextEncoder().encode('123456'));
    expect(hash).toHaveLength(32);
    expect(await keys.macs(new TextEncoder().encode('123456'))).toEqual([hash]);

    const stored = await keys.encrypt('authenticator-secret', Buffer.from('a secret'));
    expect(stored).toMatch(/^kms1\./);
    expect(await keys.decrypt('authenticator-secret', stored)).toEqual({ plaintext: new Uint8Array(Buffer.from('a secret')), current: true });
    expect(await keys.decrypt('provider-token', stored)).toBeNull();
    // The clean cut: what the local key service stored is not read.
    expect(await keys.decrypt('authenticator-secret', 'v1.aaaa.bbbb.cccc')).toBeNull();
  });

  it('KM4: turns the DER signature of KMS into r and s, padding short numbers and dropping the sign byte', () => {
    const r = new Uint8Array(32).fill(1);
    r[0] = 0x80; // a high bit: DER puts a 0 in front
    const s = new Uint8Array(31).fill(2); // a short number: padded on the left
    const der = new Uint8Array([0x30, 2 + 33 + 2 + 31, 0x02, 33, 0, ...r, 0x02, 31, ...s]);
    const jose = derToJose(der);
    expect(jose).toHaveLength(64);
    expect([...jose.subarray(0, 32)]).toEqual([...r]);
    expect([...jose.subarray(32)]).toEqual([0, ...s]);
  });

  it('KM5: a madAuth server on KMS signs in, with a session it signs and codes it hashes', async () => {
    const { kms } = fakeKms();
    await setUpKmsKeys(kms, DEPLOYMENT, START);
    const made = passwordApp({ keyService: await keyServiceOf(kms) });
    const session = await signUpVerified(made.app, made.hook);

    const checked = await made.app.request('/auth/session', { headers: { Cookie: `madauth_session=${session}` } });
    expect(checked.status).toBe(200);
    const jwks = (await (await made.app.request('/.well-known/jwks.json')).json()) as { keys: { kid: string }[] };
    expect(decodeProtectedHeader(session).kid).toBe(jwks.keys[0]!.kid);
    const signedIn = await post(made.app, '/auth/password/signin', { email: 'grace@example.com', password: 'correct horse battery' });
    expect(cookies(signedIn).madauth_session).toBeDefined();
  });
});

describe('setting up and rotating the KMS keys', () => {
  it('KR1: kms-setup creates the three keys under their aliases once', async () => {
    const { kms, aliases } = fakeKms();
    const prefix = aliasPrefix(DEPLOYMENT);

    expect(await setUpKmsKeys(kms, DEPLOYMENT, START)).toHaveLength(3);
    expect([...aliases.keys()].sort()).toEqual([
      `${prefix}/encryption`,
      `${prefix}/mac`,
      `${prefix}/mac/20261017T120000Z`,
      `${prefix}/signing`,
      `${prefix}/signing/20261017T120000Z`,
    ]);
    expect(await setUpKmsKeys(kms, DEPLOYMENT, START + DAY)).toEqual([]);

    // A setup that stopped before the current alias makes its key current, without a second one.
    const signing = aliases.get(`${prefix}/signing`)!;
    aliases.delete(`${prefix}/signing`);
    expect(await setUpKmsKeys(kms, DEPLOYMENT, START + DAY)).toEqual([`The signing key ${signing} (${prefix}/signing/20261017T120000Z) is used from now on.`]);
    expect(aliases.get(`${prefix}/signing`)).toBe(signing);
    expect([...aliases.keys()].filter((name) => name.startsWith(`${prefix}/signing/`))).toHaveLength(1);
  });

  it('KR2: a key a year old gets a successor that is published first and used two hours later', async () => {
    const { kms, aliases } = fakeKms();
    const prefix = aliasPrefix(DEPLOYMENT);
    await setUpKmsKeys(kms, DEPLOYMENT, START);
    const first = aliases.get(`${prefix}/signing`)!;

    expect((await rotateKmsKeys(kms, DEPLOYMENT, START + 364 * DAY)).done).toEqual([]);
    const { done: created } = await rotateKmsKeys(kms, DEPLOYMENT, START + 365 * DAY);
    expect(created).toEqual([expect.stringMatching(/^Created the signing key/), expect.stringMatching(/^Created the mac key/)]);
    // Published, not yet signing: the key service lists it after the one that signs.
    expect(aliases.get(`${prefix}/signing`)).toBe(first);
    const keys = await keyServiceOf(kms);
    expect(await keys.verificationKeys()).toHaveLength(2);
    const before = await signToken(keys, ISSUER, 'madauth-test+jwt', { sub: 'usr_1' }, 60);

    expect((await rotateKmsKeys(kms, DEPLOYMENT, START + 365 * DAY + HOUR)).done).toEqual([]);
    expect(await rotateKmsKeys(kms, DEPLOYMENT, START + 365 * DAY + 2 * HOUR)).toEqual({
      done: [expect.stringMatching(/^The signing key key-\d+ is used from now on/), expect.stringMatching(/^The mac key key-\d+ is used from now on/)],
      problems: [],
    });
    expect(aliases.get(`${prefix}/signing`)).not.toBe(first);
    // A token of the old key still verifies; hashes are looked up under both keys.
    const after = await keyServiceOf(kms);
    expect(await readToken(after, ISSUER, 'madauth-test+jwt', before)).toMatchObject({ sub: 'usr_1' });
    expect(await after.macs(new TextEncoder().encode('123456'))).toHaveLength(2);
  });

  it('KR3: the old signing key is disabled and its alias removed once its sessions have expired; old hash keys stay', async () => {
    const { kms, aliases, keys, calls } = fakeKms();
    const prefix = aliasPrefix(DEPLOYMENT);
    await setUpKmsKeys(kms, DEPLOYMENT, START);
    const oldSigning = aliases.get(`${prefix}/signing`)!;
    const oldMac = aliases.get(`${prefix}/mac`)!;
    await rotateKmsKeys(kms, DEPLOYMENT, START + 365 * DAY);
    await rotateKmsKeys(kms, DEPLOYMENT, START + 365 * DAY + 2 * HOUR);

    expect((await rotateKmsKeys(kms, DEPLOYMENT, START + 365 * DAY + 2 * HOUR + 31 * DAY)).done).toEqual([]);
    expect((await rotateKmsKeys(kms, DEPLOYMENT, START + 365 * DAY + 2 * HOUR + 32 * DAY)).done).toEqual([
      `Disabled the signing key ${oldSigning} and removed ${prefix}/signing/20261017T120000Z: the sessions it signed have expired.`,
    ]);
    expect(keys.get(oldSigning)!.enabled).toBe(false);
    expect(aliases.has(`${prefix}/signing/20261017T120000Z`)).toBe(false);
    expect(keys.get(oldMac)!.enabled).toBe(true);
    // A disabled key is published no more, and its public key not even asked for.
    calls.length = 0;
    expect(await (await keyServiceOf(kms)).verificationKeys()).toHaveLength(1);
    expect(calls).not.toContain(`publicKey ${oldSigning}`);
    expect(await rotateKmsKeys(kms, DEPLOYMENT, START + 400 * DAY)).toEqual({ done: [], problems: [] });
  });

  it('KR4: a running server reads its keys again every five minutes, and keeps them when a read fails', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { kms, aliases } = fakeKms();
    await setUpKmsKeys(kms, DEPLOYMENT, START);
    const keys = await keyServiceOf(kms);
    const signing = (await keys.verificationKeys())[0]!.kid;
    await rotateKmsKeys(kms, DEPLOYMENT, START + 365 * DAY);

    expect(await keys.verificationKeys()).toHaveLength(1);
    vi.useFakeTimers({ toFake: ['Date'], now: START + 5 * 60_000 });
    expect(await keys.verificationKeys()).toHaveLength(2);

    vi.spyOn(console, 'error').mockImplementation(() => {});
    aliases.delete(`${aliasPrefix(DEPLOYMENT)}/signing`);
    vi.useFakeTimers({ toFake: ['Date'], now: START + 10 * 60_000 });
    expect((await keys.verificationKeys())[0]!.kid).toBe(signing);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('the ones read before stay'));
  });

  it("KR5: the server's role may only use keys with its deployment's aliases", () => {
    expect(serverKmsPolicy(DEPLOYMENT)).toEqual([
      {
        Effect: 'Allow',
        Action: ['kms:GetPublicKey', 'kms:Sign', 'kms:GenerateMac', 'kms:Encrypt', 'kms:Decrypt'],
        Resource: '*',
        Condition: { 'ForAnyValue:StringLike': { 'kms:ResourceAliases': `alias/madauth/${DEPLOYMENT}/*` } },
      },
      { Effect: 'Allow', Action: 'kms:ListAliases', Resource: '*' },
    ]);
  });
});
