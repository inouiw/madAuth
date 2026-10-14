// Behaviour described in docs/passkey-security.md; update the doc when changing it.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runCli } from '../cli.js';
import { loadConfig } from '../config.js';
import { readToken } from '../tokens.js';
import { SESSION_TYP } from '../user.js';
import { importSigningKeys } from '../keys.js';
import { createSqliteAdapter } from '../store/sqlite.js';
import { Users } from '../users.js';
import {
  APP_ORIGIN,
  ISSUER,
  REDIRECT_TO,
  WEBHOOK_SECRET,
  WEBHOOK_URL,
  cookies,
  linkAndCode,
  passwordApp,
  post,
  setClaims,
  setMethods,
  signUpVerified,
  signingKey,
  type TestMethods,
} from '../test/helpers.js';
import { softAuthenticator, type SoftPasskey } from '../test/webauthn.js';

type Made = ReturnType<typeof passwordApp>;
type App = Made['app'];

const START = 1_700_000_015_000;
const grace = { email: 'grace@example.com', password: 'correct horse battery' };
const ON = { allowAsSignInMethod: true, secondFactor: 'none' } as const;
const FACTOR = { allowAsSignInMethod: false, secondFactor: 'none' } as const;
const browser = softAuthenticator(APP_ORIGIN);

afterEach(() => {
  vi.useRealTimers();
});

const startClock = () => vi.useFakeTimers({ toFake: ['Date'], now: START });
const advance = (ms: number) => vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
const session = (value: string) => `madauth_session=${value}`;
const ceremonyOf = (res: Response) => `madauth_passkey=${cookies(res).madauth_passkey.value}`;
const challengeOf = (res: Response) => `madauth_challenge=${cookies(res).madauth_challenge.value}`;
const join2 = (...parts: (string | undefined)[]) => parts.filter(Boolean).join('; ');

/** Asks for the options to add a passkey and answers them with a new one; `cookie` says who (a session or a challenge). */
async function addPasskey(app: App, cookie: string, create: Parameters<typeof browser.create>[1] = {}) {
  const options = await post(app, '/auth/passkey/register/options', {}, { Cookie: cookie });
  expect(options.status).toBe(200);
  const { passkey, response } = browser.create(await options.json(), create);
  const res = await post(app, '/auth/passkey/register/verify', { response, name: 'Laptop' }, { Cookie: join2(cookie, ceremonyOf(options)) });
  return { passkey, res, options };
}

/** Signs in with a passkey alone, as the browser's passkey dialog would. */
async function signInWithPasskey(app: App, passkey: SoftPasskey, get: Parameters<typeof browser.get>[2] = {}) {
  const options = await post(app, '/auth/passkey/signin/options', {});
  if (options.status !== 200) return options;
  return post(app, '/auth/passkey/signin/verify', { response: browser.get(await options.json(), passkey, get) }, { Cookie: ceremonyOf(options) });
}

/** Grace, signed up with a password just now, on a server with passkeys as `methods` set them. */
async function withGrace(methods: TestMethods = { google: ON, password: ON, passkey: ON }) {
  startClock();
  const made = passwordApp();
  await setMethods(made.store, methods);
  const value = await signUpVerified(made.app, made.hook);
  made.hook.calls.length = 0;
  return { ...made, cookie: session(value) };
}

/** The session's claims, as a backend verifies them. */
async function sessionClaims(res: Response) {
  return readToken<{ amr: string[]; auth_time: number }>(await importSigningKeys(signingKey), ISSUER, SESSION_TYP, cookies(res).madauth_session.value);
}

describe('adding a passkey', () => {
  it('PK1: a user who signed in adds a passkey; it signs them in on its own, without the address', async () => {
    const { app, hook, store, cookie } = await withGrace();

    const { passkey, res } = await addPasskey(app, cookie);

    expect(res.status).toBe(200);
    const added = (await res.json()) as { passkey: { id: string; name: string } };
    expect(added.passkey).toMatchObject({ id: expect.stringMatching(/^acc_/), name: 'Laptop', lastUsedAt: 0 });
    expect(hook.types()).toEqual(['user.method_added']);
    expect(hook.calls[0].data).toMatchObject({ method: 'passkey', passkey: { name: 'Laptop' }, user: { email: grace.email } });
    // Stored under the hash of its credential id, with the public key: nothing that signs in.
    const [account] = await store.findMany('account', { name: 'Laptop' });
    expect(account).toMatchObject({ key: expect.stringMatching(/^passkey:[\w-]{43}$/), credentialId: passkey.id, primaryUserId: null, transports: 'internal,hybrid' });

    advance(60_000);
    const signedIn = await signInWithPasskey(app, passkey);
    expect(signedIn.status).toBe(200);
    expect(await signedIn.json()).toMatchObject({ user: { email: grace.email } });
    expect((await sessionClaims(signedIn))?.amr).toEqual(['passkey']);
    expect(hook.types().at(-1)).toBe('user.signed_in');
    expect(hook.calls.at(-1)!.data).toMatchObject({ method: 'passkey' });
    expect(await store.findOne('account', { id: account.id })).toMatchObject({ lastUsedAt: Date.now() });
    // The list of her methods has both.
    const list = await app.request('/auth/methods', { headers: { Cookie: cookie } });
    expect(await list.json()).toMatchObject({ methods: [{ method: 'password', signIn: true }, { method: 'passkey', name: 'Laptop', signIn: true }] });
  });

  it('PK2: only within ten minutes of signing in: a session that someone took over gives them no passkey of their own', async () => {
    const { app, cookie } = await withGrace();
    advance(11 * 60_000);

    const late = await post(app, '/auth/passkey/register/options', {}, { Cookie: cookie });

    expect(late.status).toBe(401);
    expect(await late.json()).toMatchObject({ error: 'reauth_required' });
    // Signing in again counts from then on, and a renewed session keeps the time of its sign-in.
    const again = await post(app, '/auth/password/signin', grace);
    expect((await sessionClaims(again))?.auth_time).toBe(Math.floor(Date.now() / 1000));
    expect((await addPasskey(app, session(cookies(again).madauth_session.value))).res.status).toBe(200);
    // Nobody signed in: no passkey.
    expect(await (await post(app, '/auth/passkey/register/options', {})).json()).toMatchObject({ error: 'no_session' });
  });

  it('PK3: an answer counts only for its own options, from the app, with the user verified, once', async () => {
    const { app, store, cookie } = await withGrace();
    const options = await post(app, '/auth/passkey/register/options', {}, { Cookie: cookie });
    const body = await options.json();
    const verifyWith = (response: unknown, ceremony = ceremonyOf(options)) => post(app, '/auth/passkey/register/verify', { response }, { Cookie: join2(cookie, ceremony) });
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    // A passkey without a PIN or biometrics (only presence) is refused.
    expect(await (await verifyWith(browser.create(body, { verified: false }).response)).json()).toMatchObject({ error: 'verification_failed' });
    // Another site's page, or the answer to other options, does not fit.
    expect((await verifyWith(browser.create(body, { clientOverrides: { origin: 'https://evil.example' } }).response)).status).toBe(401);
    const other = await post(app, '/auth/passkey/register/options', {}, { Cookie: cookie });
    expect((await verifyWith(browser.create(body).response, ceremonyOf(other))).status).toBe(401);
    // Nothing was stored.
    expect(await store.findMany('account', { name: 'Passkey' })).toEqual([]);
    // The options add one passkey: a browser that kept the cookie adds no second one with them.
    expect((await verifyWith(browser.create(body).response)).status).toBe(200);
    expect(await (await verifyWith(browser.create(body).response)).json()).toMatchObject({ error: 'verification_failed' });
    expect(await store.findMany('account', { name: 'Passkey' })).toHaveLength(1);
    // Options of a sign-in don't add a passkey.
    const signin = await post(app, '/auth/passkey/signin/options', {});
    expect(await (await verifyWith(browser.create({ ...(await signin.json()), rp: { id: 'app.example.com' }, user: { id: 'x' } }).response, ceremonyOf(signin))).json()).toMatchObject({ error: 'setup_expired' });
  });

  it('PK4: the options name the user by id, ask for a discoverable passkey with user verification, and leave out the passkeys the user has', async () => {
    const { app, cookie, store } = await withGrace();
    const { passkey } = await addPasskey(app, cookie);
    const [{ id: userId }] = await store.findMany('user', {});

    const options = await (await post(app, '/auth/passkey/register/options', {}, { Cookie: cookie })).json();

    expect(options).toMatchObject({
      rp: { id: 'app.example.com', name: 'app.example.com' },
      user: { id: Buffer.from(userId as string).toString('base64url'), name: grace.email, displayName: 'Grace Hopper' },
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
      excludeCredentials: [{ id: passkey.id, type: 'public-key', transports: ['internal', 'hybrid'] }],
    });
  });

  it('PK5: switched off, nothing about passkeys works; only as a second factor, they sign nobody in alone', async () => {
    const { app, store, cookie } = await withGrace();
    const { passkey } = await addPasskey(app, cookie);

    await setMethods(store, { google: ON, password: ON });
    expect(await (await post(app, '/auth/passkey/register/options', {}, { Cookie: cookie })).json()).toMatchObject({ error: 'method_disabled' });
    expect(await (await signInWithPasskey(app, passkey)).json()).toMatchObject({ error: 'method_disabled' });
    expect(await (await app.request('/auth/config')).json()).toMatchObject({ passkey: null });

    await setMethods(store, { google: ON, password: { allowAsSignInMethod: true, secondFactor: 'optional' }, passkey: FACTOR });
    expect(await (await app.request('/auth/config')).json()).toMatchObject({ passkey: { signIn: false, secondFactor: 'none' } });
    expect(await (await signInWithPasskey(app, passkey)).json()).toMatchObject({ error: 'method_disabled' });
    // A user can still add one, as a second factor.
    advance(60_000);
    expect((await addPasskey(app, cookie)).res.status).toBe(200);
  });
});

describe('signing in with a passkey', () => {
  it('PK6: refuses a passkey nobody has, another user\'s handle, a missing user verification, another domain, and a counter that went back', async () => {
    const { app, cookie } = await withGrace();
    const { passkey } = await addPasskey(app, cookie);

    const stranger = browser.create({ challenge: 'x', rp: { id: 'app.example.com' }, user: { id: 'y' } }).passkey;
    expect(await (await signInWithPasskey(app, stranger)).json()).toMatchObject({ error: 'passkey_unknown' });
    expect(await (await signInWithPasskey(app, passkey, { userHandle: Buffer.from('usr_other').toString('base64url') })).json()).toMatchObject({ error: 'verification_failed' });
    expect(await (await signInWithPasskey(app, passkey, { verified: false })).json()).toMatchObject({ error: 'verification_failed' });
    expect(await (await signInWithPasskey(app, passkey, { rpId: 'example.com' })).json()).toMatchObject({ error: 'verification_failed' });

    // A security key counts its signatures: one that comes back with an old count is a copy.
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect((await signInWithPasskey(app, passkey, { counts: true })).status).toBe(200);
    expect((await signInWithPasskey(app, passkey, { counts: true })).status).toBe(200);
    passkey.counter = 1;
    expect(await (await signInWithPasskey(app, passkey)).json()).toMatchObject({ error: 'verification_failed' });
  });

  it('PK7: the answer of one sign-in does not sign in again', async () => {
    const { app, store, cookie } = await withGrace();
    const { passkey } = await addPasskey(app, cookie);
    const options = await post(app, '/auth/passkey/signin/options', {});
    const response = browser.get(await options.json(), passkey);

    expect((await post(app, '/auth/passkey/signin/verify', { response }, { Cookie: ceremonyOf(options) })).status).toBe(200);
    // The cookie is deleted with the first answer; a browser that kept it sends a used challenge.
    const replay = await post(app, '/auth/passkey/signin/verify', { response }, { Cookie: ceremonyOf(options) });
    expect(await replay.json()).toMatchObject({ error: 'verification_failed' });
    // Two at once: one of them signs in.
    const again = await post(app, '/auth/passkey/signin/options', {});
    const twice = browser.get(await again.json(), passkey);
    const both = await Promise.all([1, 2].map(() => post(app, '/auth/passkey/signin/verify', { response: twice }, { Cookie: ceremonyOf(again) })));
    expect(both.map((r) => r.status).sort()).toEqual([200, 401]);
    // Clearing the user's links and codes (a password reset does) keeps what was used.
    const [{ id: userId }] = await store.findMany('user', {});
    await new Users(store).clearVerifications(userId as string);
    expect(await (await post(app, '/auth/passkey/signin/verify', { response }, { Cookie: ceremonyOf(options) })).json()).toMatchObject({ error: 'verification_failed' });
    // A browser without the cookie gets nowhere.
    expect(await (await post(app, '/auth/passkey/signin/verify', { response })).json()).toMatchObject({ error: 'setup_expired' });
  });

  it('PK8: its own policy can ask for a second factor after it, which is never a passkey', async () => {
    const { app, cookie } = await withGrace({ google: ON, password: ON, passkey: { allowAsSignInMethod: true, secondFactor: 'required' }, totp: FACTOR });
    const { passkey } = await addPasskey(app, cookie);

    const res = await signInWithPasskey(app, passkey);

    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'totp_setup_required', method: 'passkey', factors: ['totp'] });
    expect(cookies(res).madauth_session?.value ?? '').toBe('');
  });
});

describe('a passkey as the second factor', () => {
  const policy: TestMethods = { google: ON, password: { allowAsSignInMethod: true, secondFactor: 'optional' }, passkey: FACTOR, totp: FACTOR };

  it('PK9: after the password, the user confirms with their passkey; it comes first of the factors they have', async () => {
    const { app, hook, cookie } = await withGrace(policy);
    await addPasskey(app, cookie);
    const { passkey } = await addPasskey(app, cookie);
    advance(60_000);

    const first = await post(app, '/auth/password/signin', grace);
    expect(first.status).toBe(401);
    expect(await first.json()).toMatchObject({ error: 'passkey_required', method: 'password', factors: ['passkey'] });

    const options = await post(app, '/auth/passkey/verify/options', {}, { Cookie: challengeOf(first) });
    const body = (await options.json()) as { allowCredentials: { id: string }[] };
    // Only her own passkeys, both of them.
    expect(body.allowCredentials).toHaveLength(2);
    const res = await post(app, '/auth/passkey/verify', { response: browser.get(body as never, passkey) }, { Cookie: join2(challengeOf(first), ceremonyOf(options)) });
    expect(res.status).toBe(200);
    expect((await sessionClaims(res))?.amr).toEqual(['pwd', 'passkey']);
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.signed_in', data: { method: 'password', secondFactor: 'passkey' } });
  });

  it("PK10: another user's passkey does not finish the sign-in, nor does one without a challenge", async () => {
    const { app, hook, cookie } = await withGrace(policy);
    await addPasskey(app, cookie);
    advance(61_000);
    const other = await signUpVerified(app, hook, 'ada@example.com', 'adas password!');
    const { passkey: adas } = await addPasskey(app, session(other));
    advance(60_000);

    const first = await post(app, '/auth/password/signin', grace);
    const options = await post(app, '/auth/passkey/verify/options', {}, { Cookie: challengeOf(first) });
    const res = await post(app, '/auth/passkey/verify', { response: browser.get(await options.json(), adas) }, { Cookie: join2(challengeOf(first), ceremonyOf(options)) });
    expect(await res.json()).toMatchObject({ error: 'verification_failed' });
    expect(await (await post(app, '/auth/passkey/verify/options', {})).json()).toMatchObject({ error: 'challenge_expired' });
  });

  it('PK11: a required policy lets a user without a second factor add a passkey in the sign-in, which finishes it', async () => {
    const { app, hook, store } = await withGrace({ google: ON, password: { allowAsSignInMethod: true, secondFactor: 'required' }, passkey: FACTOR, totp: FACTOR });
    advance(60_000);

    const first = await post(app, '/auth/password/signin', grace);
    expect(await first.json()).toMatchObject({ error: 'totp_setup_required', factors: ['passkey', 'totp'] });

    const { res } = await addPasskey(app, challengeOf(first));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ user: { email: grace.email }, passkey: { name: 'Laptop' } });
    expect((await sessionClaims(res))?.amr).toEqual(['pwd', 'passkey']);
    // Her first session: the sign-up is complete only now.
    expect(hook.types()).toEqual(['user.method_added', 'user.signed_up', 'user.signed_in']);
    expect(await store.findMany('account', { name: 'Laptop' })).toHaveLength(1);
  });

  it('PK12: a sign-up with the authenticator app sets the app up, never a passkey', async () => {
    startClock();
    const { app, hook, store } = passwordApp();
    await setMethods(store, { password: ON, totp: ON, passkey: FACTOR });
    await post(app, '/auth/totp/signup', { email: 'new@example.com', redirectTo: `${APP_ORIGIN}/` });
    const link = hook.lastEmail()!.data.link as string;
    const first = await post(app, '/auth/email/verify', { token: link.split('=').at(-1) });
    expect(await first.json()).toMatchObject({ error: 'totp_setup_required', factors: ['totp'] });

    const refused = await post(app, '/auth/passkey/register/options', {}, { Cookie: challengeOf(first) });
    expect(await refused.json()).toMatchObject({ error: 'no_session' });
  });
});

describe('signing up with a passkey alone', () => {
  const signUp = (app: App, email = grace.email) => post(app, '/auth/passkey/signup', { email, name: 'Grace Hopper', redirectTo: REDIRECT_TO, locale: 'de' });
  /** Confirms the address with the link of the last e-mail: the answer, and its challenge cookie. */
  const confirm = async (made: Made) => {
    const res = await post(made.app, '/auth/email/verify', { token: linkAndCode(made.hook.lastEmail()).token });
    return { res, challenge: cookies(res).madauth_challenge?.value ? challengeOf(res) : '' };
  };
  const onlyPasskeys: TestMethods = { password: ON, passkey: ON };

  it('PK19: the address is confirmed by e-mail, then the passkey is created, and the user is in with it as their method', async () => {
    startClock();
    const made = passwordApp();
    const { app, hook, store } = made;
    await setMethods(store, { ...onlyPasskeys, totp: FACTOR });
    expect(await (await app.request('/auth/config')).json()).toMatchObject({ passkey: { signIn: true, signUp: true, secondFactor: 'none' } });

    expect((await signUp(app)).status).toBe(202);
    const [user] = await store.findMany('user', {});
    expect(user).toMatchObject({ email: grace.email, name: 'Grace Hopper', emailVerified: false, signUpMethod: 'passkey' });
    expect(await store.findMany('account', {})).toEqual([]);
    expect(hook.types()).toEqual(['user.signing_up', 'email.send_verification']);
    expect(hook.calls[0].data).toEqual({ email: grace.email, name: 'Grace Hopper', locale: 'de', method: 'passkey' });

    // Confirming does not sign in yet: the passkey has to be created first, and nothing else can be set up.
    const { res: confirmed, challenge } = await confirm(made);
    expect(confirmed.status).toBe(401);
    expect(await confirmed.json()).toMatchObject({ error: 'totp_setup_required', method: 'passkey', factors: ['passkey'] });
    expect(cookies(confirmed).madauth_session?.value ?? '').toBe('');
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.email_verified', data: { method: 'passkey', via: 'link' } });
    expect(await (await post(app, '/auth/totp/setup', {}, { Cookie: challenge })).json()).toMatchObject({ error: 'no_session' });
    hook.calls.length = 0;

    const { passkey, res } = await addPasskey(app, challenge);
    expect(passkey.userHandle).toBe(Buffer.from(user.id as string).toString('base64url'));

    expect(res.status).toBe(200);
    const graceUser = { id: user.id, email: grace.email, name: 'Grace Hopper' };
    expect(await res.json()).toEqual({ passkey: expect.objectContaining({ name: 'Laptop' }), user: { ...graceUser, amr: ['passkey'] } });
    expect((await sessionClaims(res))?.amr).toEqual(['passkey']);
    // The passkey is how she signs up, not a method she added: her sign-up is complete, and she is in.
    expect(hook.calls).toEqual([
      { type: 'user.signed_up', data: { user: graceUser, method: 'passkey' } },
      { type: 'user.signed_in', data: { user: graceUser, method: 'passkey' } },
    ]);
    expect(await store.findMany('account', { userId: user.id })).toEqual([expect.objectContaining({ primaryUserId: user.id, credentialId: passkey.id })]);
    // It is her only way in: it can't be removed.
    const [{ id: accountId }] = await store.findMany('account', { userId: user.id });
    const removal = await post(app, '/auth/methods/remove', { id: accountId }, { Cookie: session(cookies(res).madauth_session.value) });
    expect(await removal.json()).toMatchObject({ error: 'only_method' });
    advance(60_000);
    expect((await signInWithPasskey(app, passkey)).status).toBe(200);
    // A sign-up with the address afterwards only tells her she is registered, with a passkey.
    advance(60_000);
    await post(app, '/auth/password/signup', { ...grace, redirectTo: REDIRECT_TO });
    expect(hook.lastEmail()).toMatchObject({ type: 'email.send_already_registered', data: { methods: ['passkey'] } });
  });

  it('PK20: the code confirms like the link; an unfinished sign-up starts over, and the latest unproven sign-up wins', async () => {
    startClock();
    const made = passwordApp();
    const { app, hook, store } = made;
    await setMethods(store, { password: ON, passkey: ON, totp: ON });
    // Someone (perhaps not Grace) signed the address up with a password; nobody confirmed it.
    await post(app, '/auth/password/signup', { ...grace, redirectTo: REDIRECT_TO });
    advance(61_000);

    await signUp(app);
    expect(await store.findMany('account', {})).toEqual([]);
    const byCode = await post(app, '/auth/email/verify', { email: grace.email, code: linkAndCode(hook.lastEmail()).code });
    expect(await byCode.json()).toMatchObject({ error: 'totp_setup_required', factors: ['passkey'] });
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(401);

    // Confirmed, but no passkey was created: a sign-up with the app for the address starts over and wins.
    advance(61_000);
    await post(app, '/auth/totp/signup', { email: grace.email, redirectTo: REDIRECT_TO });
    expect(await store.findMany('user', {})).toMatchObject([{ signUpMethod: 'totp' }]);
    // And a passkey sign-up after it wins again.
    advance(61_000);
    await signUp(app);
    const { res } = await confirm(made);
    expect(await res.json()).toMatchObject({ error: 'totp_setup_required', factors: ['passkey'] });
  });

  it('PK21: a password sign-up meanwhile needs its own e-mail; until it is used, the passkey wins, afterwards it is refused', async () => {
    startClock();
    const made = passwordApp();
    const { app, store } = made;
    await setMethods(store, onlyPasskeys);
    await signUp(app);
    const { challenge } = await confirm(made);
    // Before the passkey is created, someone signs the address up with their own password.
    advance(61_000);
    await post(app, '/auth/password/signup', { ...grace, redirectTo: REDIRECT_TO });
    const passwordLink = linkAndCode(made.hook.lastEmail()).token;
    const [{ id: userId }] = await store.findMany('user', {});

    const { res } = await addPasskey(app, challenge);
    expect(res.status).toBe(200);
    expect(await store.findMany('account', { userId })).toEqual([expect.objectContaining({ primaryUserId: userId, name: 'Laptop' })]);
    expect((await post(app, '/auth/email/verify', { token: passwordLink })).status).toBe(400);

    // Another address: the password's e-mail is used first, so the password is the user's method.
    const other = passwordApp();
    await setMethods(other.store, onlyPasskeys);
    await signUp(other.app);
    const first = await confirm(other);
    advance(61_000);
    await post(other.app, '/auth/password/signup', { ...grace, redirectTo: REDIRECT_TO });
    expect((await confirm(other)).res.status).toBe(200);
    const late = await addPasskey(other.app, first.challenge);
    expect(late.res.status).toBe(400);
    expect(await late.res.json()).toMatchObject({ error: 'setup_expired' });
    expect((await other.store.findMany('account', {})).map((a) => a.key)).toEqual([expect.stringMatching(/^password:/)]);
  });

  it('PK22: with a policy that asks for a second factor after a passkey, the sign-up sets that up next; never a second passkey', async () => {
    startClock();
    const made = passwordApp();
    const { app, hook, store } = made;
    await setMethods(store, { password: ON, passkey: { allowAsSignInMethod: true, secondFactor: 'required' }, totp: FACTOR });
    await signUp(app);
    const { challenge } = await confirm(made);
    hook.calls.length = 0;

    const { res } = await addPasskey(app, challenge);

    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'totp_setup_required', method: 'passkey', factors: ['totp'] });
    expect(cookies(res).madauth_session?.value ?? '').toBe('');
    expect(hook.calls).toEqual([]);
    const next = challengeOf(res);
    // The setup of the policy's factor is no sign-up step: it takes no passkey.
    expect(await (await post(app, '/auth/passkey/register/options', {}, { Cookie: next })).json()).toMatchObject({ error: 'no_session' });
    const setup = await post(app, '/auth/totp/setup', {}, { Cookie: next });
    expect(setup.status).toBe(200);
  });

  it('PK23: only while passkeys sign in on their own and the server confirms addresses; a link waits while they are off', async () => {
    startClock();
    const made = passwordApp();
    const { app, hook, store } = made;
    await setMethods(store, { password: ON, passkey: FACTOR });
    expect(await (await app.request('/auth/config')).json()).toMatchObject({ passkey: { signIn: false, signUp: false } });
    expect(await (await signUp(app)).json()).toMatchObject({ error: 'method_disabled' });
    await setMethods(store, { password: ON });
    expect(await (await signUp(app)).json()).toMatchObject({ error: 'method_disabled' });

    await setMethods(store, onlyPasskeys);
    await signUp(app);
    const { token } = linkAndCode(hook.lastEmail());
    await setMethods(store, { password: ON, passkey: FACTOR });
    expect(await (await post(app, '/auth/email/verify', { token })).json()).toMatchObject({ error: 'method_disabled' });
    // Nor is the e-mail sent again: the sign-up recorded its method, and it is off.
    advance(61_000);
    await post(app, '/auth/email/send-verification', { email: grace.email, redirectTo: REDIRECT_TO });
    expect(hook.emails()).toHaveLength(1);
    expect((await store.findMany('user', {}))[0]).toMatchObject({ emailVerified: false });
    await setMethods(store, onlyPasskeys);
    expect(await (await post(app, '/auth/email/verify', { token })).json()).toMatchObject({ error: 'totp_setup_required', factors: ['passkey'] });

    // Without the confirmation e-mails there is no sign-up route.
    const noEmails = passwordApp({ password: undefined, webhook: undefined });
    await setMethods(noEmails.store, { google: ON, passkey: ON });
    expect(await (await noEmails.app.request('/auth/config')).json()).toMatchObject({ passkey: { signIn: true, signUp: false } });
    expect((await signUp(noEmails.app)).status).toBe(404);
  });
});

describe('the user\'s passkeys', () => {
  it('PK13: renamed and removed while signed in; a removed one is unknown, and the device is told so', async () => {
    const { app, hook, cookie } = await withGrace();
    const { passkey, res } = await addPasskey(app, cookie);
    const { passkey: added } = (await res.json()) as { passkey: { id: string } };

    const renamed = await post(app, '/auth/passkey/rename', { id: added.id, name: '  Work phone  ' }, { Cookie: cookie });
    expect(await renamed.json()).toMatchObject({ passkey: { id: added.id, name: 'Work phone' } });
    expect((await post(app, '/auth/passkey/rename', { id: added.id, name: ' ' }, { Cookie: cookie })).status).toBe(400);
    expect((await post(app, '/auth/passkey/rename', { id: 'acc_other', name: 'x' }, { Cookie: cookie })).status).toBe(404);

    hook.calls.length = 0;
    const removed = await post(app, '/auth/methods/remove', { id: added.id }, { Cookie: cookie });
    expect(removed.status).toBe(200);
    expect(hook.calls[0]).toMatchObject({ type: 'user.method_removed', data: { method: 'passkey', passkey: { id: added.id, name: 'Work phone' } } });
    expect(await (await signInWithPasskey(app, passkey)).json()).toMatchObject({ error: 'passkey_unknown' });
  });

  it('PK14: the last way in can\'t go, nor the last second factor a policy requires', async () => {
    const { app, store, cookie } = await withGrace();
    const { res } = await addPasskey(app, cookie);
    const { passkey: added } = (await res.json()) as { passkey: { id: string } };
    const remove = () => post(app, '/auth/methods/remove', { id: added.id }, { Cookie: cookie });

    // Password sign-in is off: the passkey is how she signs in now.
    await setMethods(store, { google: ON, passkey: ON });
    expect(await (await remove()).json()).toMatchObject({ error: 'only_method' });

    // The password requires a second factor, and the passkey is her only one.
    await setMethods(store, { google: ON, password: { allowAsSignInMethod: true, secondFactor: 'required' }, passkey: FACTOR });
    expect(await (await remove()).json()).toMatchObject({ error: 'required_by_policy', message: expect.stringContaining('e-mail & password') });
    // With a second passkey, one of them may go.
    const second = await addPasskey(app, cookie);
    expect(second.res.status).toBe(200);
    expect((await remove()).status).toBe(200);

    // Ten minutes after signing in, nothing can be removed any more.
    advance(11 * 60_000);
    const { passkey: last } = (await second.res.json()) as { passkey: { id: string } };
    expect(await (await post(app, '/auth/methods/remove', { id: last.id }, { Cookie: cookie })).json()).toMatchObject({ error: 'reauth_required' });
  });

  it('PK17: the passkeys\' own policy doesn\'t keep the last passkey: without it, the user signs in no more with one', async () => {
    const { app, cookie } = await withGrace({ google: ON, password: ON, passkey: { allowAsSignInMethod: true, secondFactor: 'required' }, totp: FACTOR });
    const { res } = await addPasskey(app, cookie);
    const { passkey: added } = (await res.json()) as { passkey: { id: string } };

    expect((await post(app, '/auth/methods/remove', { id: added.id }, { Cookie: cookie })).status).toBe(200);
  });

  it('PK18: a passkey counts as a second factor only on the domain it was made for', async () => {
    startClock();
    const made = passwordApp({ allowedOrigins: [APP_ORIGIN, 'https://other.test'] });
    await setMethods(made.store, { google: ON, password: { allowAsSignInMethod: true, secondFactor: 'optional' }, passkey: FACTOR, totp: FACTOR });
    const value = await signUpVerified(made.app, made.hook);
    await addPasskey(made.app, session(value));
    advance(60_000);

    // On the app it was made on, the passkey is asked for; on another, it couldn't answer, so it is no factor there.
    expect(await (await post(made.app, '/auth/password/signin', grace)).json()).toMatchObject({ error: 'passkey_required' });
    const elsewhere = await post(made.app, '/auth/password/signin', grace, { Origin: 'https://other.test' });
    expect(elsewhere.status).toBe(200);
    expect(await made.store.findMany('account', { name: 'Laptop' })).toMatchObject([{ rpId: 'app.example.com' }]);
  });

  it('PK15: an admin, or the command line, removes the passkeys of a user who lost them', async () => {
    const { app, hook, store, cookie } = await withGrace();
    await addPasskey(app, cookie);
    await addPasskey(app, cookie);
    await setClaims(store, grace.email, { roles: ['admin'] });
    hook.calls.length = 0;

    const res = await post(app, '/auth/admin/passkey/remove', { email: grace.email }, { Cookie: cookie });

    expect(await res.json()).toMatchObject({ email: grace.email, passkeys: 0 });
    expect(hook.types()).toEqual(['user.method_removed', 'user.method_removed']);
    expect(hook.calls[0].data).toMatchObject({ method: 'passkey', by: grace.email });
    expect(await store.findMany('account', { name: 'Laptop' })).toEqual([]);

    const dir = mkdtempSync(join(tmpdir(), 'madauth-'));
    try {
      const path = join(dir, 'madauth.db');
      const file = createSqliteAdapter(path);
      const cli = passwordApp({ store: file });
      await setMethods(file, { google: ON, password: ON, passkey: ON });
      const value = await signUpVerified(cli.app, cli.hook);
      await addPasskey(cli.app, session(value));
      const env = { DATABASE_URL: `sqlite:${path}` };
      expect(await runCli(['remove-passkeys', grace.email], undefined, env)).toEqual({ exitCode: 0, output: `Removed the passkey of ${grace.email}.` });
      expect(await runCli(['remove-passkeys', grace.email], undefined, env)).toEqual({ exitCode: 0, output: `${grace.email} has no passkeys.` });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('the domain of the passkeys', () => {
  it('PK16: PASSKEY_RP_ID shares passkeys across the apps of a domain, and must be one of them or above', async () => {
    const env = {
      MADAUTH_ISSUER: ISSUER,
      MADAUTH_SIGNING_KEY: JSON.stringify(signingKey),
      ALLOWED_ORIGINS: `${APP_ORIGIN},https://other.test`,
      DATABASE_URL: 'sqlite::memory:',
      WEBHOOK_URL,
      WEBHOOK_SECRET,
      WEBHOOK_EVENTS: 'email.send_verification,email.send_password_reset',
    };
    expect((await loadConfig({ ...env, PASSKEY_RP_ID: 'Example.com' })).passkeyRpId).toBe('example.com');
    await expect(loadConfig({ ...env, PASSKEY_RP_ID: 'evil.example' })).rejects.toThrow(/PASSKEY_RP_ID/);

    startClock();
    const shared = passwordApp({ passkeyRpId: 'example.com', allowedOrigins: [APP_ORIGIN, 'https://other.test'] });
    await setMethods(shared.store, { google: ON, password: ON, passkey: ON });
    const value = await signUpVerified(shared.app, shared.hook);
    const options = await (await post(shared.app, '/auth/passkey/register/options', {}, { Cookie: session(value) })).json();
    expect(options).toMatchObject({ rp: { id: 'example.com' } });
    // An app outside the domain can't use them.
    const outside = await post(shared.app, '/auth/passkey/signin/options', {}, { Origin: 'https://other.test' });
    expect(await outside.json()).toMatchObject({ error: 'forbidden_origin' });
  });
});
