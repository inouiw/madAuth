// The key service and rotating the signing key. Behaviour described in "Signing key" in docs/server.md; update
// the doc when changing it.
import { createHmac } from 'node:crypto';
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { base32Decode, stepOf, totp } from './authenticator.js';
import { decrypt, deriveKey, encrypt } from './crypto.js';
import { createLocalKeyService, parseSigningKeys } from './key-service.js';
import { generateSigningKey } from './keys.js';
import { codeHashes } from './password.js';
import { ISSUER, cookies, linkAndCode, passwordApp, post, setMethods, type TestMethods } from './test/helpers.js';
import { readToken, signToken } from './tokens.js';
import { Users, authenticatorAccountKey } from './users.js';

const START = 1_700_000_015_000;
const grace = { email: 'grace@example.com', name: 'Grace Hopper' };
const standalone: TestMethods = { password: { secondFactor: 'optional' }, authenticator: {} };

afterEach(() => vi.useRealTimers());

const oldKey = await generateSigningKey();
const newKey = await generateSigningKey();
const before = await createLocalKeyService([oldKey]);
const rotated = await createLocalKeyService([newKey, oldKey]);
const onlyNew = await createLocalKeyService([newKey]);

describe('the local key service', () => {
  it('KS1: MADAUTH_SIGNING_KEY is one private JWK or a set of them, the newest first', async () => {
    expect(await parseSigningKeys(JSON.stringify(oldKey))).toEqual({ keys: [oldKey] });
    expect(await parseSigningKeys(JSON.stringify({ keys: [newKey, oldKey] }))).toEqual({ keys: [newKey, oldKey] });
    expect(await parseSigningKeys('{')).toEqual({ problem: 'is not valid JSON' });
    expect(await parseSigningKeys('{"keys":"x"}')).toMatchObject({ problem: expect.stringContaining('a set of them') });
    expect((await rotated.verificationKeys()).map((key) => key.kid)).toEqual([newKey.kid, oldKey.kid]);
    expect(await rotated.verificationKeys()).toEqual([expect.not.objectContaining({ d: expect.anything() }), expect.not.objectContaining({ d: expect.anything() })]);
  });

  it('KS2: reads what madAuth stored before the key service: the same derived keys', async () => {
    const secret = Buffer.from('a secret of an authenticator app');
    const storedBefore = encrypt(deriveKey(oldKey.d!, 'madauth totp secret'), secret);
    expect(await before.decrypt('authenticator-secret', storedBefore)).toEqual({ plaintext: new Uint8Array(secret), current: true });
    expect(decrypt(deriveKey(oldKey.d!, 'madauth provider token'), await before.encrypt('provider-token', secret))).toEqual(secret);
    const hashedBefore = createHmac('sha256', deriveKey(oldKey.d!, 'madauth e-mail code')).update('123456').digest('base64url');
    expect(await codeHashes(before, '123456')).toEqual([hashedBefore]);
  });

  it('KS3: after a rotation the new key signs, hashes and encrypts, and the old one still verifies, finds and decrypts', async () => {
    const oldToken = await signToken(before, ISSUER, 'madauth-test+jwt', { sub: 'usr_1' }, 60);
    const newToken = await signToken(rotated, ISSUER, 'madauth-test+jwt', { sub: 'usr_1' }, 60);
    expect(decodeProtectedHeader(newToken).kid).toBe(newKey.kid);
    expect(await readToken(rotated, ISSUER, 'madauth-test+jwt', oldToken)).toMatchObject({ sub: 'usr_1' });
    expect(await readToken(rotated, ISSUER, 'madauth-test+jwt', newToken)).toMatchObject({ sub: 'usr_1' });
    // Backends verify with the published keys.
    expect((await jwtVerify(newToken, createLocalJWKSet({ keys: await rotated.verificationKeys() }))).payload.sub).toBe('usr_1');

    const oldValue = await before.encrypt('authenticator-secret', Buffer.from('s'));
    expect(await rotated.decrypt('authenticator-secret', oldValue)).toEqual({ plaintext: new Uint8Array(Buffer.from('s')), current: false });
    expect(await rotated.decrypt('authenticator-secret', await rotated.encrypt('authenticator-secret', Buffer.from('s')))).toMatchObject({ current: true });

    const [oldHash] = await codeHashes(before, '123456');
    const hashes = await codeHashes(rotated, '123456');
    expect(hashes).toHaveLength(2);
    expect(hashes[1]).toBe(oldHash);
    expect(hashes[0]).not.toBe(oldHash);
  });

  it('KS10: an RS256 key in the set signs ID tokens in RS256 and is published after the ES256 keys; it hashes and encrypts nothing', async () => {
    const rsaKey = await generateSigningKey('RS256');
    expect(rsaKey).toMatchObject({ kty: 'RSA', alg: 'RS256', kid: expect.any(String) });
    expect(await parseSigningKeys(JSON.stringify({ keys: [newKey, oldKey, rsaKey] }))).toEqual({ keys: [newKey, oldKey, rsaKey] });
    expect(await parseSigningKeys(JSON.stringify(rsaKey))).toMatchObject({ problem: expect.stringContaining('has no EC P-256 key') });
    expect(await parseSigningKeys(JSON.stringify({ keys: [newKey, { ...rsaKey, n: 'short' }] }))).toMatchObject({ problem: expect.stringContaining('shorter than 2048 bits') });
    const { p: _p, ...withoutCrt } = rsaKey;
    expect(await parseSigningKeys(JSON.stringify({ keys: [newKey, withoutCrt] }))).toMatchObject({ problem: expect.stringContaining('without p, q, dp, dq and qi') });
    // A key service from before RS256 publishes keys without `alg`: they are ES256 keys.
    const legacy = { ...before, verificationKeys: async () => (await before.verificationKeys()).map(({ alg: _alg, ...key }) => key) };
    expect(decodeProtectedHeader(await signToken(legacy, ISSUER, 'madauth-test+jwt', { sub: 'usr_1' }, 60))).toMatchObject({ alg: 'ES256', kid: oldKey.kid });
    await expect(createLocalKeyService([rsaKey])).rejects.toThrow('at least one ES256 key');

    const withRsa = await createLocalKeyService([newKey, rsaKey, oldKey]);
    expect((await withRsa.verificationKeys()).map((key) => [key.kid, key.alg])).toEqual([
      [newKey.kid, 'ES256'],
      [oldKey.kid, 'ES256'],
      [rsaKey.kid, 'RS256'],
    ]);
    expect((await withRsa.verificationKeys())[2]).toEqual({ kty: 'RSA', n: rsaKey.n, e: rsaKey.e, alg: 'RS256', use: 'sig', kid: rsaKey.kid });
    // The ES256 keys derive the hash and encryption keys, as without the RSA key.
    expect(await codeHashes(withRsa, '123456')).toEqual(await codeHashes(rotated, '123456'));

    const es256 = await signToken(withRsa, ISSUER, 'madauth-test+jwt', { sub: 'usr_1' }, 60);
    expect(decodeProtectedHeader(es256)).toMatchObject({ alg: 'ES256', kid: newKey.kid });
    const rs256 = await signToken(withRsa, ISSUER, 'JWT', { sub: 'usr_1' }, 60, 'RS256');
    expect(decodeProtectedHeader(rs256)).toMatchObject({ alg: 'RS256', kid: rsaKey.kid });
    expect(await readToken(withRsa, ISSUER, 'JWT', rs256)).toMatchObject({ sub: 'usr_1' });
    // A relying party verifies it with the published keys, with RS256 alone.
    const jwks = createLocalJWKSet({ keys: await withRsa.verificationKeys() });
    expect((await jwtVerify(rs256, jwks, { algorithms: ['RS256'] })).payload.sub).toBe('usr_1');
    await expect(signToken(rotated, ISSUER, 'JWT', { sub: 'usr_1' }, 60, 'RS256')).rejects.toThrow('no RS256 key');
  });

  it('KS4: a key that is removed verifies, finds and decrypts nothing any more', async () => {
    const oldToken = await signToken(before, ISSUER, 'madauth-test+jwt', { sub: 'usr_1' }, 60);
    expect(await readToken(onlyNew, ISSUER, 'madauth-test+jwt', oldToken)).toBeNull();
    expect(await onlyNew.decrypt('authenticator-secret', await before.encrypt('authenticator-secret', Buffer.from('s')))).toBeNull();
    expect(await codeHashes(onlyNew, '123456')).not.toContain((await codeHashes(before, '123456'))[0]);
  });
});

describe('rotating MADAUTH_SIGNING_KEY on a running deployment', () => {
  /** Grace, signed up with the authenticator app alone under the old key; then the server gets the new key first. */
  async function graceThenRotation() {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const first = passwordApp({ keyService: before });
    await setMethods(first.store, standalone);
    await post(first.app, '/auth/authenticator/signup', { ...grace, redirectTo: 'https://app.example.com/account' });
    const confirmed = await post(first.app, '/auth/email/verify', { token: linkAndCode(first.hook.lastEmail()).token });
    const challenge = `madauth_challenge=${cookies(confirmed).madauth_challenge.value}`;
    const setup = await post(first.app, '/auth/authenticator/setup', {}, { Cookie: challenge });
    const secret = base32Decode(((await setup.json()) as { secret: string }).secret)!;
    const setupCookie = `madauth_authenticator_setup=${cookies(setup).madauth_authenticator_setup.value}`;
    const confirm = await post(first.app, '/auth/authenticator/confirm', { code: totp(secret, stepOf(Date.now())) }, { Cookie: `${challenge}; ${setupCookie}` });
    const { recoveryCodes } = (await confirm.json()) as { recoveryCodes: string[] };
    const oldCookies = `madauth_session=${cookies(confirm).madauth_session.value}; madauth_renewal=${cookies(confirm).madauth_renewal.value}`;
    // The same store, now with the new key first.
    const second = passwordApp({ store: first.store, keyService: rotated });
    // passwordApp answers a store of its own: the shared one is the first app's.
    return { ...second, store: first.store, secret, recoveryCodes, oldCookies };
  }

  it('KS5: sessions signed with the old key keep working and renew with the new one; the published keys list both', async () => {
    const { app, oldCookies } = await graceThenRotation();

    const jwks = (await (await app.request('/.well-known/jwks.json')).json()) as { keys: { kid: string }[] };
    expect(jwks.keys.map((key) => key.kid)).toEqual([newKey.kid, oldKey.kid]);
    const session = await app.request('/auth/session', { headers: { Cookie: oldCookies } });
    expect(session.status).toBe(200);

    // Past half its lifetime the session is renewed: signed with the new key.
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 2 * 3600_000 });
    const renewed = await app.request('/auth/session', { headers: { Cookie: oldCookies } });
    expect(renewed.status).toBe(200);
    expect(decodeProtectedHeader(cookies(renewed).madauth_session.value).kid).toBe(newKey.kid);
  });

  it('KS6: an authenticator secret under the old key still signs in, and moves to the new key at that use', async () => {
    const { app, store, secret } = await graceThenRotation();
    const account = await store.findOne('account', { key: authenticatorAccountKey(String((await store.findMany('user', {}))[0]!.id)) });
    expect(await onlyNew.decrypt('authenticator-secret', account!.secret as string)).toBeNull();

    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 60_000 });
    const signedIn = await post(app, '/auth/authenticator/signin', { email: grace.email, code: totp(secret, stepOf(Date.now())) });
    expect(signedIn.status).toBe(200);
    const [moved] = await store.findMany('account', { id: account!.id });
    expect(await onlyNew.decrypt('authenticator-secret', moved!.secret as string)).toEqual({ plaintext: new Uint8Array(secret), current: true });
  });

  it('KS9: a wrong code moves nothing, and a secret that a new setup replaced meanwhile is not overwritten', async () => {
    const { app, store, secret } = await graceThenRotation();
    const account = await store.findOne('account', { key: authenticatorAccountKey(String((await store.findMany('user', {}))[0]!.id)) });
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 60_000 });
    expect((await post(app, '/auth/authenticator/signin', { email: grace.email, code: '000000' })).status).toBe(401);
    expect((await store.findOne('account', { id: account!.id }))!.secret).toBe(account!.secret);

    // A setup confirmed meanwhile wrote another secret: the old one, re-encrypted, must not replace it.
    await store.update('account', { id: account!.id }, { secret: 'v1.the-new-apps-secret' });
    const users = new Users(store, rotated);
    expect(await users.reencryptSecret(account as never, await rotated.encrypt('authenticator-secret', secret))).toBe(false);
    expect((await store.findOne('account', { id: account!.id }))!.secret).toBe('v1.the-new-apps-secret');
  });

  it('KS7: recovery codes made under the old key still work', async () => {
    const { app, recoveryCodes } = await graceThenRotation();
    expect((await post(app, '/auth/authenticator/signin', { email: grace.email, recoveryCode: recoveryCodes[0] })).status).toBe(200);
  });

  it('KS8: a code e-mailed under the old key is accepted after the rotation', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const first = passwordApp({ keyService: before });
    await post(first.app, '/auth/password/signup', { email: 'ada@example.com', password: 'correct horse battery', name: 'Ada', redirectTo: 'https://app.example.com/account' });
    const { code } = linkAndCode(first.hook.lastEmail());

    const second = passwordApp({ store: first.store, keyService: rotated });
    const verified = await post(second.app, '/auth/email/verify', { email: 'ada@example.com', code });
    expect(verified.status).toBe(200);
  });
});
