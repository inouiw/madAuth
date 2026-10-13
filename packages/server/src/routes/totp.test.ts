// Behaviour described in docs/totp-security.md; update the doc when changing it.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runCli } from '../cli.js';
import { loadConfig } from '../config.js';
import { generateSigningKey } from '../keys.js';
import { createSqliteAdapter } from '../store/sqlite.js';
import {
  ALL_EVENTS,
  APP_ORIGIN,
  ISSUER,
  REDIRECT_TO,
  WEBHOOK_SECRET,
  WEBHOOK_URL,
  cookies,
  getNonce,
  googleIdToken,
  linkAndCode,
  passwordApp,
  post,
  setClaims,
  signIn,
  signInResponse,
  signUpVerified,
  signingKey,
  testApp,
  verify,
  setMethods,
  type TestMethods,
} from '../test/helpers.js';
import { base32Decode, stepOf, totp } from '../totp.js';

type App = ReturnType<typeof testApp>;

const grace = { email: 'grace@example.com', password: 'correct horse battery' };
const graceUser = { id: expect.stringMatching(/^usr_/), email: 'grace@example.com', name: 'Grace Hopper' };
/** Mid-step, so a test never crosses a step boundary by itself. */
const START = 1_700_000_015_000;

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function advance(ms: number) {
  vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
}

/** The code the app shows now, or `offset` steps away. */
const codeFor = (secret: Buffer, offset = 0) => totp(secret, stepOf(Date.now()) + offset);

/** Which methods are on, written as an admin would. */

const withSession = (session: string, more = '') => ({ Cookie: `madauth_session=${session}${more ? `; ${more}` : ''}` });

/** Sets the app up for the signed-in user: returns the secret and the recovery codes. */
async function setUp(app: App, session: string, body: Record<string, unknown> = {}) {
  const setup = await post(app, '/auth/totp/setup', body, withSession(session));
  const { secret: base32 } = (await setup.json()) as { secret: string };
  const secret = base32Decode(base32)!;
  const setupCookie = `madauth_totp_setup=${cookies(setup).madauth_totp_setup.value}`;
  const confirm = await post(app, '/auth/totp/confirm', { code: codeFor(secret) }, withSession(session, setupCookie));
  const { recoveryCodes } = (await confirm.json()) as { recoveryCodes: string[] };
  return { secret, recoveryCodes, confirm, setup, setupCookie };
}

/** Grace with a password and the app, on a server where password sign-in asks for it when set up. */
async function enrolled(methods: TestMethods = { google: { secondFactor: 'none' }, password: { secondFactor: 'optional' } }) {
  vi.useFakeTimers({ toFake: ['Date'], now: START });
  const made = passwordApp();
  await setMethods(made.store, methods);
  const session = await signUpVerified(made.app, made.hook);
  const [{ id: userId }] = await made.store.findMany('user', {});
  const { secret, recoveryCodes } = await setUp(made.app, session);
  made.hook.calls.length = 0;
  return { ...made, session, userId: userId as string, secret, recoveryCodes };
}

const standalone: TestMethods = { google: { secondFactor: 'none' }, password: { secondFactor: 'optional' }, totp: {} };

/** Grace, who signed up with the app alone: it is how she signs in, not a second factor. */
async function appUser(methods: TestMethods = standalone) {
  vi.useFakeTimers({ toFake: ['Date'], now: START });
  const made = passwordApp();
  await setMethods(made.store, methods);
  await post(made.app, '/auth/totp/signup', { email: grace.email, name: 'Grace Hopper', redirectTo: REDIRECT_TO });
  const confirmed = await post(made.app, '/auth/email/verify', { token: linkAndCode(made.hook.lastEmail()).token });
  const challenge = `madauth_challenge=${cookies(confirmed).madauth_challenge.value}`;
  const setup = await post(made.app, '/auth/totp/setup', {}, { Cookie: challenge });
  const secret = base32Decode(((await setup.json()) as { secret: string }).secret)!;
  const confirm = await post(made.app, '/auth/totp/confirm', { code: codeFor(secret) }, { Cookie: `${challenge}; madauth_totp_setup=${cookies(setup).madauth_totp_setup.value}` });
  const { recoveryCodes } = (await confirm.json()) as { recoveryCodes: string[] };
  const [{ id: userId }] = await made.store.findMany('user', {});
  made.hook.calls.length = 0;
  return { ...made, session: cookies(confirm).madauth_session.value, userId: userId as string, secret, recoveryCodes };
}

const signInWithApp = (app: App, body: Record<string, unknown>) => post(app, '/auth/totp/signin', body);

const sessionClaims = async (app: App, res: Response) => {
  const jwks = createLocalJWKSet(await (await app.request('/.well-known/jwks.json')).json());
  return (await jwtVerify(cookies(res).madauth_session.value, jwks, { issuer: ISSUER })).payload;
};

describe('setting up the authenticator app while signed in', () => {
  it('T1: setup gives a new secret and the otpauth URI, in a short-lived cookie; nothing is stored yet', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, { password: { secondFactor: 'optional' } });
    const session = await signUpVerified(app, hook);

    expect((await post(app, '/auth/totp/setup', {})).status).toBe(401);
    const res = await post(app, '/auth/totp/setup', {}, withSession(session));

    expect(res.status).toBe(200);
    const { secret, uri } = (await res.json()) as { secret: string; uri: string };
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(uri).toBe(`otpauth://totp/app.example.com:grace%40example.com?secret=${secret}&issuer=app.example.com&algorithm=SHA1&digits=6&period=30`);
    expect(cookies(res).madauth_totp_setup.attrs).toMatchObject({ httponly: true, secure: true, samesite: 'Strict', path: '/auth/totp', 'max-age': '600' });
    expect(await store.findMany('account', {})).toHaveLength(1);
    expect(hook.types()).not.toContain('user.second_factor_enabled');

    const named = passwordApp({ totpIssuer: 'My App' });
    await setMethods(named.store, { password: { secondFactor: 'optional' } });
    const other = await post(named.app, '/auth/totp/setup', {}, withSession(await signUpVerified(named.app, named.hook)));
    expect(((await other.json()) as { uri: string }).uri).toMatch(/^otpauth:\/\/totp\/My%20App:grace%40example\.com\?/);
  });

  it('T2: the first code proves the setup: the app is stored encrypted, with ten recovery codes, and the webhook is told', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, { password: { secondFactor: 'optional' } });
    const session = await signUpVerified(app, hook);
    const [{ id: userId }] = await store.findMany('user', {});

    const { confirm, recoveryCodes, secret } = await setUp(app, session);

    expect(confirm.status).toBe(200);
    expect(recoveryCodes).toHaveLength(10);
    for (const code of recoveryCodes) expect(code).toMatch(/^[a-z2-7]{5}-[a-z2-7]{5}$/);
    expect(cookies(confirm).madauth_totp_setup).toMatchObject({ value: '', attrs: { 'max-age': '0' } });
    const account = await store.findOne('account', { key: `totp:${userId}` });
    expect(account).toMatchObject({ userId, failedAttempts: 0, lockedUntil: 0, lastUsedStep: stepOf(START) });
    expect(String(account!.secret)).toMatch(/^v1\./);
    expect(String(account!.secret)).not.toContain(secret.toString('base64url'));
    expect(await store.findMany('recoveryCode', { userId })).toHaveLength(10);
    // A second factor of her password: the account says it is not how she signs in.
    expect(account).toMatchObject({ primaryUserId: null, secondFactor: true });
    expect(await store.findOne('account', { key: `password:${userId}` })).toMatchObject({ primaryUserId: userId });
    expect(hook.calls.at(-1)).toEqual({ type: 'user.second_factor_enabled', data: { user: graceUser, method: 'totp' } });
    const status = await app.request('/auth/totp/status', { headers: withSession(session) });
    expect(await status.json()).toEqual({ enabled: true, recoveryCodesLeft: 10 });
    // Replacing it is told the same way.
    hook.calls.length = 0;
    advance(60_000);
    expect((await setUp(app, session, { code: codeFor(secret) })).confirm.status).toBe(200);
    expect(hook.calls).toEqual([{ type: 'user.second_factor_enabled', data: { user: graceUser, method: 'totp' } }]);
  });

  it('T3: a setup is confirmed only by its own user, with the current code, within ten minutes', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, { password: { secondFactor: 'optional' } });
    const session = await signUpVerified(app, hook);
    const ada = await signUpVerified(app, hook, 'ada@example.com', 'adas password!');
    const setup = await post(app, '/auth/totp/setup', {}, withSession(session));
    const secret = base32Decode(((await setup.json()) as { secret: string }).secret)!;
    const setupCookie = `madauth_totp_setup=${cookies(setup).madauth_totp_setup.value}`;
    const confirm = (code: string, headers: Record<string, string>) => post(app, '/auth/totp/confirm', { code }, headers);

    // A wrong code keeps the setup: the right one can follow.
    const wrong = await confirm(codeFor(secret, 3), withSession(session, setupCookie));
    expect(wrong.status).toBe(400);
    expect(await wrong.json()).toMatchObject({ error: 'code_invalid' });
    expect(await store.findMany('account', {})).toHaveLength(2);
    expect((await confirm('', withSession(session, setupCookie))).status).toBe(400);
    expect(await (await confirm(codeFor(secret), withSession(session))).json()).toMatchObject({ error: 'setup_expired' });
    expect(await (await confirm(codeFor(secret), withSession(ada, setupCookie))).json()).toMatchObject({ error: 'setup_expired' });
    expect(await (await confirm(codeFor(secret), withSession(session, `madauth_totp_setup=${session}`))).json()).toMatchObject({ error: 'setup_expired' });
    expect((await confirm(codeFor(secret), { Cookie: setupCookie })).status).toBe(401);
    expect((await confirm(codeFor(secret), withSession(session, setupCookie))).status).toBe(200);

    // Too late for a fresh setup (which takes a current code now that an app exists).
    const again = await post(app, '/auth/totp/setup', { code: codeFor(secret, 1) }, withSession(session));
    const late = `madauth_totp_setup=${cookies(again).madauth_totp_setup.value}`;
    const lateSecret = base32Decode(((await again.json()) as { secret: string }).secret)!;
    advance(11 * 60_000);
    expect(await (await confirm(codeFor(lateSecret), withSession(session, late))).json()).toMatchObject({ error: 'setup_expired' });
  });

  it('T4: setting the app up again takes a current code, and replaces the old one, its codes and its lock', async () => {
    const { app, hook, store, session, userId, secret: old, recoveryCodes: oldCodes } = await appUser();
    await store.update('account', { key: `totp:${userId}` }, { failedAttempts: 3, lockedUntil: 0 });
    advance(60_000);

    // A stolen session alone must not swap the app and the recovery codes: the current app has to agree.
    const bare = await post(app, '/auth/totp/setup', {}, withSession(session));
    expect(bare.status).toBe(401);
    expect(await bare.json()).toMatchObject({ error: 'code_required' });
    const wrong = await post(app, '/auth/totp/setup', { code: '000000' }, withSession(session));
    expect(wrong.status).toBe(401);
    expect(await wrong.json()).toMatchObject({ error: 'code_invalid' });
    expect(cookies(wrong).madauth_totp_setup).toBeUndefined();
    expect(await store.findOne('account', { key: `totp:${userId}` })).toMatchObject({ failedAttempts: 4 });
    const { secret, recoveryCodes } = await setUp(app, session, { code: codeFor(old) });

    expect(await store.findOne('account', { key: `totp:${userId}` })).toMatchObject({ failedAttempts: 0, lockedUntil: 0 });
    // Still the one account she signs in with; it is no second factor, so nothing is told.
    expect(await store.findMany('account', { userId })).toEqual([expect.objectContaining({ key: `totp:${userId}`, primaryUserId: userId })]);
    expect(hook.types()).toEqual([]);
    advance(60_000);
    expect((await signInWithApp(app, { email: grace.email, code: codeFor(old) })).status).toBe(401);
    expect((await signInWithApp(app, { email: grace.email, recoveryCode: oldCodes[0] })).status).toBe(401);
    expect((await signInWithApp(app, { email: grace.email, recoveryCode: recoveryCodes[0] })).status).toBe(200);
    advance(60_000);
    expect((await signInWithApp(app, { email: grace.email, code: codeFor(secret) })).status).toBe(200);
  });

  it('T30: the current app\'s approval holds for ten minutes, so starting again costs no second code', async () => {
    const { app, store, session, userId, recoveryCodes } = await enrolled(standalone);
    advance(60_000);
    const first = await post(app, '/auth/totp/setup', { recoveryCode: recoveryCodes[0] }, withSession(session));
    expect(first.status).toBe(200);
    expect(await store.findMany('recoveryCode', { userId })).toHaveLength(9);
    const approval = `madauth_totp_setup=${cookies(first).madauth_totp_setup.value}`;

    // Starting again within ten minutes: the earlier approval counts, no code is used up.
    advance(5 * 60_000);
    const again = await post(app, '/auth/totp/setup', {}, withSession(session, approval));
    expect(again.status).toBe(200);
    expect(await store.findMany('recoveryCode', { userId })).toHaveLength(9);
    // Another browser, without the setup cookie, needs a code.
    expect((await post(app, '/auth/totp/setup', {}, withSession(session))).status).toBe(401);
    // Ten minutes after the code, a code is needed again, although the latest setup cookie is still valid.
    advance(6 * 60_000);
    const late = await post(app, '/auth/totp/setup', {}, withSession(session, `madauth_totp_setup=${cookies(again).madauth_totp_setup.value}`));
    expect(late.status).toBe(401);
    expect(await late.json()).toMatchObject({ error: 'code_required' });
  });

  it('T31: allowed as a sign-in method, the app signs in everyone who has one; only as a second factor, nobody; it never goes as the last way in', async () => {
    const { app, hook, store, session, secret } = await enrolled(standalone);
    advance(60_000);

    // The admin allows the app as a sign-in method: Grace, who added it as a second factor of her password,
    // signs in with it alone as well.
    const alone = await signInWithApp(app, { email: grace.email, code: codeFor(secret) });
    expect(alone.status).toBe(200);
    expect(hook.types()).toEqual(['user.signed_in']);

    // Only as a second factor, it is a step of her password again, and no way in by itself.
    await setMethods(store, { google: {}, password: { secondFactor: 'optional' } });
    advance(60_000);
    expect(await (await signInWithApp(app, { email: grace.email, code: codeFor(secret) })).json()).toMatchObject({ error: 'method_disabled' });

    // With password sign-in off, the app is her last way in: it can't go.
    await setMethods(store, { google: {}, totp: {} });
    advance(60_000);
    const last = await post(app, '/auth/totp/remove', { code: codeFor(secret) }, withSession(session));
    expect(last.status).toBe(403);
    expect(await last.json()).toMatchObject({ error: 'only_method' });
    // With her password on again, it can.
    await setMethods(store, standalone);
    advance(60_000);
    expect((await post(app, '/auth/totp/remove', { code: codeFor(secret) }, withSession(session))).status).toBe(200);
  });

  it('T32: a setup confirms only the state it started in, so the app and its recovery codes always belong together', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, standalone);
    const session = await signUpVerified(app, hook);
    const [{ id: userId }] = await store.findMany('user', {});
    const start = async (body: Record<string, unknown> = {}, cookie = '') => {
      const res = await post(app, '/auth/totp/setup', body, withSession(session, cookie));
      expect(res.status).toBe(200);
      return { secret: base32Decode(((await res.json()) as { secret: string }).secret)!, cookie: `madauth_totp_setup=${cookies(res).madauth_totp_setup.value}` };
    };
    const confirm = (secret: Buffer, cookie: string) => post(app, '/auth/totp/confirm', { code: codeFor(secret) }, withSession(session, cookie));
    const codesOf = async () => (await store.findMany('recoveryCode', { userId })).map((code) => code.setupId);

    // Two tabs start a setup; the first one to confirm wins, the second is told to start again.
    const a = await start();
    const b = await start();
    expect((await confirm(a.secret, a.cookie)).status).toBe(200);
    const account = (await store.findOne('account', { key: `totp:${userId}` }))!;
    expect(account.setupId).toMatch(/^tsu_/);
    expect(await codesOf()).toEqual(Array(10).fill(account.setupId));
    const lost = await confirm(b.secret, b.cookie);
    expect(lost.status).toBe(400);
    expect(await lost.json()).toMatchObject({ error: 'setup_expired', message: expect.stringContaining('elsewhere') });
    expect(cookies(lost).madauth_totp_setup.attrs['max-age']).toBe('0');
    expect(await store.findOne('account', { key: `totp:${userId}` })).toMatchObject({ secret: account.secret, setupId: account.setupId });
    expect(await codesOf()).toEqual(Array(10).fill(account.setupId));
    expect(hook.types().filter((type) => type === 'user.second_factor_enabled')).toHaveLength(1);

    // A setup that started before the app was removed is refused as well.
    advance(60_000);
    const stale = await start({ code: codeFor(a.secret) });
    advance(60_000);
    const removed = await post(app, '/auth/totp/remove', { code: codeFor(a.secret) }, withSession(session));
    expect(removed.status).toBe(200);
    expect((await confirm(stale.secret, stale.cookie)).status).toBe(400);
    expect(await codesOf()).toEqual([]);
    // Starting again works: there is no app now, so no code is asked for.
    const fresh = await start();
    expect((await confirm(fresh.secret, fresh.cookie)).status).toBe(200);
    expect(await codesOf()).toHaveLength(10);
  });

  it('T5: removing the app and renewing the recovery codes take a current code; a required policy forbids removing', async () => {
    const { app, hook, store, session, userId, secret, recoveryCodes } = await enrolled(standalone);
    const status = () => Promise.resolve(app.request('/auth/totp/status', { headers: withSession(session) })).then((r) => r.json());
    const remove = (body: Record<string, unknown>, cookie = session) => post(app, '/auth/totp/remove', body, withSession(cookie));

    expect((await app.request('/auth/totp/status')).status).toBe(401);
    expect(await (await post(app, '/auth/totp/recovery-codes', { code: 'x' })).json()).toMatchObject({ error: 'no_session' });
    // New recovery codes: the old ones stop working.
    const renewed = await post(app, '/auth/totp/recovery-codes', { recoveryCode: recoveryCodes[0] }, withSession(session));
    expect(renewed.status).toBe(200);
    const { recoveryCodes: fresh } = (await renewed.json()) as { recoveryCodes: string[] };
    expect(fresh).toHaveLength(10);
    expect(fresh).not.toContain(recoveryCodes[1]);
    expect(await status()).toEqual({ enabled: true, recoveryCodesLeft: 10 });
    advance(60_000);
    const first = await post(app, '/auth/password/signin', grace);
    const stale = await post(app, '/auth/totp/verify', { recoveryCode: recoveryCodes[1] }, { Cookie: `madauth_challenge=${cookies(first).madauth_challenge.value}` });
    expect(stale.status).toBe(401);

    // Removing needs a code that works.
    expect(await (await remove({})).json()).toMatchObject({ error: 'code_invalid' });
    expect(await (await remove({ code: codeFor(secret, 3) })).json()).toMatchObject({ error: 'code_invalid' });
    expect(await status()).toMatchObject({ enabled: true });
    hook.calls.length = 0;
    expect((await remove({ code: codeFor(secret) })).status).toBe(200);
    expect(await store.findOne('account', { key: `totp:${userId}` })).toBeNull();
    expect(await store.findMany('recoveryCode', { userId })).toEqual([]);
    expect(hook.calls).toEqual([{ type: 'user.second_factor_disabled', data: { user: graceUser, method: 'totp' } }]);
    expect(await status()).toEqual({ enabled: false, recoveryCodesLeft: 0 });
    // Nothing to remove any more: no second event.
    expect((await remove({ code: '000000' })).status).toBe(200);
    expect(hook.types()).toEqual(['user.second_factor_disabled']);
    expect(await (await post(app, '/auth/totp/recovery-codes', { code: '000000' }, withSession(session))).json()).toMatchObject({ error: 'no_authenticator' });

    // With a policy that requires the app, nobody can remove it.
    const required = await enrolled();
    await setMethods(required.store, { password: { secondFactor: 'required' } });
    const refused = await post(required.app, '/auth/totp/remove', { code: codeFor(required.secret) }, withSession(required.session));
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: 'required_by_policy', message: expect.stringContaining('password') });
  });
});

describe('signing in with the app alone', () => {
  it('T6: the e-mail address and the code give a session for the app as the method', async () => {
    const { app, hook, store, userId, secret } = await appUser();
    advance(60_000);

    const res = await signInWithApp(app, { email: 'Grace@Example.com', code: codeFor(secret) });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: { ...graceUser, amr: ['otp'] } });
    expect(await sessionClaims(app, res)).toMatchObject({ sub: userId, amr: ['otp'], sv: 0 });
    expect(hook.calls).toEqual([{ type: 'user.signed_in', data: { user: graceUser, method: 'totp' } }]);
    expect(await store.findOne('account', { key: `totp:${userId}` })).toMatchObject({ lastUsedStep: stepOf(Date.now()), failedAttempts: 0 });
  });

  it('T7: a code is accepted one step early or late, never twice, and never one from before the last used', async () => {
    const { app, secret } = await appUser();
    advance(60_000);
    const signin = (offset: number) => signInWithApp(app, { email: grace.email, code: codeFor(secret, offset) });

    expect((await signin(-1)).status).toBe(200);
    expect((await signin(-1)).status).toBe(401);
    expect((await signin(1)).status).toBe(200);
    expect((await signin(0)).status).toBe(401);
    expect((await signin(2)).status).toBe(401);
    expect((await signin(-2)).status).toBe(401);
  });

  it('T8: a recovery code signs in once, and the webhook learns how many are left', async () => {
    const { app, hook, secret, recoveryCodes } = await appUser();
    advance(60_000);
    const [code] = recoveryCodes;

    const res = await signInWithApp(app, { email: grace.email, recoveryCode: ` ${code.toUpperCase()} ` });

    expect(res.status).toBe(200);
    expect(await sessionClaims(app, res)).toMatchObject({ amr: ['otp'] });
    expect(hook.types()).toEqual(['user.recovery_code_used', 'user.signed_in']);
    expect(hook.calls[0].data).toEqual({ user: graceUser, remaining: 9 });
    expect((await signInWithApp(app, { email: grace.email, recoveryCode: code })).status).toBe(401);
    // A recovery code is not a code from the app, and the other way round.
    expect((await signInWithApp(app, { email: grace.email, code })).status).toBe(401);
    expect((await signInWithApp(app, { email: grace.email, recoveryCode: codeFor(secret) })).status).toBe(401);
  });

  it('T9: nothing reveals whether an address has an account or an app', async () => {
    const { app, hook, store, userId, secret } = await appUser();
    await signUpVerified(app, hook, 'ada@example.com', 'adas password!');
    advance(60_000);
    const answers: Response[] = [];
    for (const body of [
      { email: 'nobody@example.com', code: codeFor(secret) },
      { email: 'ada@example.com', code: codeFor(secret) },
      { email: grace.email, code: codeFor(secret, 3) },
      { email: grace.email, code: '12 34' },
      { email: grace.email },
      { email: 'not an address', code: codeFor(secret) },
    ]) {
      answers.push(await signInWithApp(app, body));
    }
    await store.update('user', { id: userId }, { emailVerified: false });
    answers.push(await signInWithApp(app, { email: grace.email, code: codeFor(secret) }));

    for (const res of answers) {
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: 'invalid_credentials', message: 'E-mail or code is wrong.' });
    }
  });

  it('T10: wrong codes lock the app like wrong passwords, also when they come at once', async () => {
    const { app, store, userId, secret } = await appUser();
    advance(60_000);
    const wrong = () => signInWithApp(app, { email: grace.email, code: codeFor(secret, 5) });
    const right = () => signInWithApp(app, { email: grace.email, code: codeFor(secret) });

    for (let i = 0; i < 5; i++) expect((await wrong()).status).toBe(401);
    const locked = await right();
    expect(locked.status).toBe(429);
    expect(await locked.json()).toMatchObject({ error: 'too_many_attempts', message: expect.stringContaining('Try again in') });
    advance(1_100);
    expect((await right()).status).toBe(200);
    expect(await store.findOne('account', { key: `totp:${userId}` })).toMatchObject({ failedAttempts: 0, lockedUntil: 0 });

    await store.update('account', { key: `totp:${userId}` }, { failedAttempts: 10, lockedUntil: 0 });
    const atOnce = await Promise.all([wrong(), wrong(), wrong(), wrong(), wrong()]);
    expect(atOnce.map((r) => r.status).sort()).toEqual([401, 429, 429, 429, 429]);
    expect(await store.findOne('account', { key: `totp:${userId}` })).toMatchObject({ failedAttempts: 11 });

    await store.update('account', { key: `totp:${userId}` }, { failedAttempts: 30, lockedUntil: 0 });
    await wrong();
    const { lockedUntil } = (await store.findOne('account', { key: `totp:${userId}` }))!;
    expect(lockedUntil).toBe(Date.now() + 15 * 60_000);
  });

  it('T11: only the configured apps may call the routes', async () => {
    const { app, secret } = await enrolled(standalone);
    advance(60_000);

    const foreign = await app.request('/auth/totp/signin', {
      method: 'POST',
      headers: { Origin: 'https://evil.example', 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: grace.email, code: codeFor(secret) }),
    });
    const status = await app.request('/auth/totp/status', { headers: { Origin: 'https://evil.example' } });

    expect(foreign.status).toBe(403);
    expect(status.status).toBe(401);
    expect(status.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('T12: the app is off until an admin lists it or a policy asks for it; the app alone is a method of its own', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    const session = await signUpVerified(app, hook);
    const config = () => Promise.resolve(app.request('/auth/config')).then((r) => r.json());

    // Never set: Google and password, no second factor, no app.
    expect(await config()).toMatchObject({ totp: null });
    const off = await post(app, '/auth/totp/setup', {}, withSession(session));
    expect(off.status).toBe(403);
    expect(await off.json()).toMatchObject({ error: 'method_disabled' });

    // As a second factor only: it can be set up, but does not sign in by itself.
    await setMethods(store, { password: { secondFactor: 'optional' } });
    expect(await config()).toMatchObject({ password: { secondFactor: 'optional' }, totp: { signIn: false, signUp: false } });
    const { secret } = await setUp(app, session);
    advance(60_000);
    const alone = await signInWithApp(app, { email: grace.email, code: codeFor(secret) });
    expect(alone.status).toBe(403);
    expect(await alone.json()).toMatchObject({ error: 'method_disabled' });

    // Allowed as a sign-in method: people sign up with the app, and everyone who has one signs in with it, Grace too.
    await setMethods(store, standalone);
    expect(await config()).toMatchObject({ totp: { signIn: true, signUp: true } });
    expect((await signInWithApp(app, { email: grace.email, code: codeFor(secret) })).status).toBe(200);
  });

  it('T13: deleting the account takes a current code once the app is set up, and removes it with the codes', async () => {
    const { app, hook, store, session, userId, secret } = await enrolled(standalone);
    advance(60_000);
    const del = (body?: Record<string, unknown>) =>
      app.request('/auth/account/delete', {
        method: 'POST',
        headers: { Origin: APP_ORIGIN, 'Content-Type': 'application/json', ...withSession(session) },
        body: body ? JSON.stringify(body) : undefined,
      });

    const without = await del();
    expect(without.status).toBe(401);
    expect(await without.json()).toMatchObject({ error: 'code_required' });
    expect(await (await del({ code: codeFor(secret, 3) })).json()).toMatchObject({ error: 'code_invalid' });
    expect(await store.findMany('user', {})).toHaveLength(1);

    expect((await del({ code: codeFor(secret) })).status).toBe(204);

    for (const model of ['user', 'account', 'verification', 'recoveryCode']) expect(await store.findMany(model, {})).toEqual([]);
    expect(hook.calls.at(-1)).toEqual({ type: 'user.deleted', data: { user: graceUser } });
    advance(60_000);
    expect((await signInWithApp(app, { email: grace.email, code: codeFor(secret) })).status).toBe(401);
    expect(userId).toMatch(/^usr_/);
  });

  it('T29: an app that is switched off server-wide protects nothing, so deleting the account takes no code', async () => {
    const { app, store, session } = await enrolled(standalone);
    await setMethods(store, { google: { secondFactor: 'none' }, password: { secondFactor: 'none' } });

    const res = await app.request('/auth/account/delete', { method: 'POST', headers: { Origin: APP_ORIGIN, ...withSession(session) } });

    expect(res.status).toBe(204);
    expect(await store.findMany('user', {})).toEqual([]);
  });

  it('T14: with another signing key the secrets can not be read: the app does not sign in, and the log says why', async () => {
    const { app, hook, store, secret } = await appUser();
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const otherKey = testApp({
      store,
      signingKey: await generateSigningKey(),
      password: {},
      webhook: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET, events: ALL_EVENTS },
      webhookFetch: hook.fetch,
    });
    advance(60_000);

    expect((await signInWithApp(app, { email: grace.email, code: codeFor(secret) })).status).toBe(200);
    advance(60_000);
    expect((await signInWithApp(otherKey, { email: grace.email, code: codeFor(secret) })).status).toBe(401);
    expect(error).toHaveBeenCalledWith(expect.stringContaining('MADAUTH_SIGNING_KEY'));
  });
});

describe('the second step after a password, Google or GitHub', () => {
  it('T15: a password alone no longer signs in once the app is set up: the code finishes the sign-in', async () => {
    const { app, hook, userId, secret } = await enrolled();

    const first = await post(app, '/auth/password/signin', grace);

    expect(first.status).toBe(401);
    expect(await first.json()).toMatchObject({ error: 'totp_required' });
    expect(cookies(first).madauth_session?.value ?? '').toBe('');
    const challenge = cookies(first).madauth_challenge;
    expect(challenge.attrs).toMatchObject({ httponly: true, secure: true, samesite: 'Strict', path: '/auth', 'max-age': '600' });
    expect(hook.types()).toEqual([]);

    const second = await post(app, '/auth/totp/verify', { code: codeFor(secret, 1) }, { Cookie: `madauth_challenge=${challenge.value}` });

    expect(second.status).toBe(200);
    expect(await second.json()).toEqual({ user: { ...graceUser, amr: ['pwd', 'otp'] } });
    expect(await sessionClaims(app, second)).toMatchObject({ sub: userId, amr: ['pwd', 'otp'], sv: 0 });
    expect(cookies(second).madauth_challenge).toMatchObject({ value: '', attrs: { 'max-age': '0' } });
    expect(hook.calls).toEqual([{ type: 'user.signed_in', data: { user: graceUser, method: 'password', secondFactor: 'totp' } }]);
  });

  it('T16: a recovery code finishes the sign-in as well, and says so', async () => {
    const { app, hook, recoveryCodes } = await enrolled();
    const first = await post(app, '/auth/password/signin', grace);

    const second = await post(app, '/auth/totp/verify', { recoveryCode: recoveryCodes[3] }, { Cookie: `madauth_challenge=${cookies(first).madauth_challenge.value}` });

    expect(second.status).toBe(200);
    expect(await sessionClaims(app, second)).toMatchObject({ amr: ['pwd', 'otp'] });
    expect(hook.types()).toEqual(['user.recovery_code_used', 'user.signed_in']);
    expect(hook.calls[1].data).toMatchObject({ method: 'password', secondFactor: 'recovery_code' });
  });

  it('T17: the second step needs a current code, within ten minutes, for the sign-in that started it', async () => {
    const { app, hook, store, userId, secret } = await enrolled();
    const first = await post(app, '/auth/password/signin', grace);
    const withChallenge = (cookie = cookies(first).madauth_challenge.value) => ({ Cookie: `madauth_challenge=${cookie}` });
    const verifyStep = (body: Record<string, unknown>, headers: Record<string, string> = withChallenge()) => post(app, '/auth/totp/verify', body, headers);

    const wrong = await verifyStep({ code: codeFor(secret, 3) });
    expect(wrong.status).toBe(401);
    expect(await wrong.json()).toMatchObject({ error: 'code_invalid' });
    expect(await store.findOne('account', { key: `totp:${userId}` })).toMatchObject({ failedAttempts: 1 });
    expect(await (await verifyStep({ code: codeFor(secret) }, {})).json()).toMatchObject({ error: 'challenge_expired' });
    // A password reset ends the sign-in that was under way.
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const reset = await post(app, '/auth/password/reset', { token: linkAndCode(hook.lastEmail()).token, password: 'new teapot sky!' });
    expect(await (await verifyStep({ code: codeFor(secret) })).json()).toMatchObject({ error: 'challenge_expired' });
    // The reset itself ends in the second step too, and ends the older sessions.
    expect(reset.status).toBe(401);
    expect(await reset.json()).toMatchObject({ error: 'totp_required' });
    const afterReset = await verifyStep({ code: codeFor(secret) }, withChallenge(cookies(reset).madauth_challenge.value));
    expect(afterReset.status).toBe(200);
    expect(await sessionClaims(app, afterReset)).toMatchObject({ amr: ['pwd', 'otp'], sv: 1 });
    // Too late.
    const again = await post(app, '/auth/password/signin', { ...grace, password: 'new teapot sky!' });
    advance(11 * 60_000);
    expect(await (await verifyStep({ code: codeFor(secret) }, withChallenge(cookies(again).madauth_challenge.value))).json()).toMatchObject({ error: 'challenge_expired' });
  });

  it('T18: without the app, or without a policy, a password signs in as before', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, { google: { secondFactor: 'none' }, password: { secondFactor: 'optional' } });
    const session = await signUpVerified(app, hook);
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(200);

    await setUp(app, session);
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(401);
    // The admin takes the policy away: the password is enough again, even with the app set up.
    await setMethods(store, { google: { secondFactor: 'none' }, password: { secondFactor: 'none' } });
    const res = await post(app, '/auth/password/signin', grace);
    expect(res.status).toBe(200);
    expect(await sessionClaims(app, res)).toMatchObject({ amr: ['pwd'] });
  });

  it('T19: a required policy makes a user without the app set it up before they are in, and signs them in with it', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, { password: { secondFactor: 'required' } });
    // The sign-up confirmation already asks for it.
    await post(app, '/auth/password/signup', { ...grace, name: 'Grace Hopper', redirectTo: REDIRECT_TO });
    const confirmed = await post(app, '/auth/email/verify', { token: linkAndCode(hook.lastEmail()).token });
    expect(confirmed.status).toBe(401);
    expect(await confirmed.json()).toMatchObject({ error: 'totp_setup_required' });

    const first = await post(app, '/auth/password/signin', grace);
    expect(first.status).toBe(401);
    expect(await first.json()).toMatchObject({ error: 'totp_setup_required' });
    const challenge = `madauth_challenge=${cookies(first).madauth_challenge.value}`;
    hook.calls.length = 0;

    const setup = await post(app, '/auth/totp/setup', {}, { Cookie: challenge });
    expect(setup.status).toBe(200);
    const secret = base32Decode(((await setup.json()) as { secret: string }).secret)!;
    const setupCookie = `madauth_totp_setup=${cookies(setup).madauth_totp_setup.value}`;
    // A code (as opposed to the setup) is not what this sign-in waits for.
    expect(await (await post(app, '/auth/totp/verify', { code: codeFor(secret) }, { Cookie: challenge })).json()).toMatchObject({ error: 'challenge_expired' });
    const confirm = await post(app, '/auth/totp/confirm', { code: codeFor(secret) }, { Cookie: `${challenge}; ${setupCookie}` });

    expect(confirm.status).toBe(200);
    const body = (await confirm.json()) as { user: unknown; recoveryCodes: string[] };
    expect(body.user).toEqual({ ...graceUser, amr: ['pwd', 'otp'] });
    expect(body.recoveryCodes).toHaveLength(10);
    expect(await sessionClaims(app, confirm)).toMatchObject({ amr: ['pwd', 'otp'] });
    expect(cookies(confirm).madauth_challenge).toMatchObject({ value: '' });
    // Her first session: the sign-up is complete only now, with the app the policy asks for, not at the e-mail.
    expect(hook.types()).toEqual(['user.second_factor_enabled', 'user.signed_up', 'user.signed_in']);
    expect(hook.calls[1].data).toEqual({ user: graceUser, method: 'password' });
    expect(hook.calls[2].data).toEqual({ user: graceUser, method: 'password', secondFactor: 'totp' });
  });

  it('T20: Google asks for the code too when its policy says so, in both flows', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, { google: { secondFactor: 'optional' }, password: { secondFactor: 'none' } });
    const session = await signIn(app);
    const { secret } = await setUp(app, session);
    hook.calls.length = 0;

    const fedcm = await signInResponse(app);
    expect(fedcm.status).toBe(401);
    expect(await fedcm.json()).toMatchObject({ error: 'totp_required' });
    // The challenge carries what the session will show, and nothing else of Google's profile.
    const jwks = createLocalJWKSet(await (await app.request('/.well-known/jwks.json')).json());
    const challengeClaims = (await jwtVerify(cookies(fedcm).madauth_challenge.value, jwks, { issuer: ISSUER })).payload;
    expect(challengeClaims.profile).toEqual({ name: 'Ada Lovelace', picture: 'https://example.com/ada.png' });
    const second = await post(app, '/auth/totp/verify', { code: codeFor(secret, 1) }, { Cookie: `madauth_challenge=${cookies(fedcm).madauth_challenge.value}` });
    expect(second.status).toBe(200);
    // What Google told about the user is in the session, as without the code step.
    expect(await second.json()).toMatchObject({ user: { name: 'Ada Lovelace', picture: 'https://example.com/ada.png' } });
    expect(await sessionClaims(app, second)).toMatchObject({ amr: ['google', 'otp'] });
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.signed_in', data: { method: 'google', secondFactor: 'totp' } });

    const started = await app.request(`/auth/google/start?return_to=${encodeURIComponent(`${APP_ORIGIN}/page`)}`);
    const location = new URL(started.headers.get('location')!);
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ id_token: await googleIdToken({ nonce: location.searchParams.get('nonce')! }) })));
    const back = await app.request(`/auth/google/callback?code=c&state=${location.searchParams.get('state')}`, {
      headers: { Cookie: `madauth_oauth=${cookies(started).madauth_oauth.value}` },
    });
    expect(back.headers.get('location')).toBe(`${APP_ORIGIN}/page#madauth_next=totp&madauth_factors=totp&madauth_method=google`);
    expect(cookies(back).madauth_session?.value ?? '').toBe('');
    expect(cookies(back).madauth_challenge.value).toBeTruthy();

    // Without a policy for Google, Google alone is enough.
    await setMethods(store, { google: { secondFactor: 'none' }, password: { secondFactor: 'none' } });
    expect((await signInResponse(app)).status).toBe(200);
  });

  it('T21: an admin changes the policy while the server runs, and it applies to the next sign-in', async () => {
    // The app is listed on its own, so it can be set up although no policy asks for it yet.
    const { app, store, session, secret } = await enrolled({ google: { secondFactor: 'none' }, password: { secondFactor: 'none' }, totp: {} });
    await setClaims(store, grace.email, { roles: ['admin'] });
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(200);

    const methods = {
      google: { allowAsSignInMethod: true, secondFactor: 'none' },
      password: { allowAsSignInMethod: true, secondFactor: 'required' },
      totp: { allowAsSignInMethod: false, secondFactor: 'none' },
    };
    const set = await post(app, '/auth/admin/settings/set', { methods }, withSession(session));

    expect(set.status).toBe(200);
    expect(await set.json()).toMatchObject({
      methods: { password: { enabled: true, secondFactor: 'required' }, totp: { configured: true, enabled: true, allowAsSignInMethod: false } },
    });
    const next = await post(app, '/auth/password/signin', grace);
    expect(await next.json()).toMatchObject({ error: 'totp_required' });
    expect((await post(app, '/auth/totp/verify', { code: codeFor(secret, 1) }, { Cookie: `madauth_challenge=${cookies(next).madauth_challenge.value}` })).status).toBe(200);
  });

  it('T26: a challenge finishes only while its method is still on', async () => {
    const { app, hook, store, secret } = await enrolled({ google: { secondFactor: 'optional' }, password: { secondFactor: 'optional' } });
    const first = await post(app, '/auth/password/signin', grace);
    expect(await first.json()).toMatchObject({ error: 'totp_required' });
    const challenge = `madauth_challenge=${cookies(first).madauth_challenge.value}`;
    // Password sign-in is switched off during the ten minutes of the second step; the app stays on for Google.
    await setMethods(store, { google: { secondFactor: 'optional' } });

    const refused = await post(app, '/auth/totp/verify', { code: codeFor(secret, 1) }, { Cookie: challenge });

    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: 'method_disabled' });
    expect(cookies(refused).madauth_session?.value ?? '').toBe('');
    expect(hook.types()).toEqual([]);

    // The same for a setup a sign-in waits for.
    await setMethods(store, { google: { secondFactor: 'optional' }, password: { secondFactor: 'required' } });
    // Ada's sign-up ends in the setup step instead of a session.
    await signUpVerified(app, hook, 'ada@example.com', 'adas password!').catch(() => null);
    const step = await post(app, '/auth/password/signin', { email: 'ada@example.com', password: 'adas password!' });
    expect(await step.json()).toMatchObject({ error: 'totp_setup_required' });
    await setMethods(store, { google: { secondFactor: 'optional' } });
    const setup = await post(app, '/auth/totp/setup', {}, { Cookie: `madauth_challenge=${cookies(step).madauth_challenge.value}` });
    expect(setup.status).toBe(403);
  });

  it('T27: at one browser, the sign-in that waits for the setup wins over an older session, and a new session ends the wait', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, { google: { secondFactor: 'none' }, password: { secondFactor: 'optional' } });
    const graceSession = await signUpVerified(app, hook);
    await signUpVerified(app, hook, 'ada@example.com', 'adas password!');
    await setMethods(store, { google: { secondFactor: 'none' }, password: { secondFactor: 'required' } });
    // Grace is signed in; Ada signs in at the same browser and has to set the app up.
    const adaStep = await post(app, '/auth/password/signin', { email: 'ada@example.com', password: 'adas password!' }, withSession(graceSession));
    expect(await adaStep.json()).toMatchObject({ error: 'totp_setup_required' });
    const challenge = `madauth_challenge=${cookies(adaStep).madauth_challenge.value}`;
    // Grace is signed out by Ada's sign-in: the browser drops her session, so an abandoned step can't be
    // taken for her own setup later.
    expect(cookies(adaStep).madauth_session.attrs['max-age']).toBe('0');

    const setup = await post(app, '/auth/totp/setup', {}, withSession(graceSession, challenge));
    const key = (await setup.json()) as { secret: string; uri: string };
    expect(key.uri).toContain('ada%40example.com');
    const secret = base32Decode(key.secret)!;
    const confirm = await post(app, '/auth/totp/confirm', { code: codeFor(secret) }, withSession(graceSession, `${challenge}; madauth_totp_setup=${cookies(setup).madauth_totp_setup.value}`));

    expect(confirm.status).toBe(200);
    expect(await confirm.json()).toMatchObject({ user: { email: 'ada@example.com', amr: ['pwd', 'otp'] }, recoveryCodes: expect.any(Array) });
    // Ada's session replaces Grace's, and the wait is over.
    expect(cookies(confirm).madauth_session.value).not.toBe(graceSession);
    expect(cookies(confirm).madauth_challenge.attrs['max-age']).toBe('0');
    const [graceUserRow] = await store.findMany('user', { emailNormalized: grace.email });
    expect(await store.findOne('account', { key: `totp:${graceUserRow.id}` })).toBeNull();
    // Signing out ends a wait as well.
    expect(cookies(await post(app, '/auth/logout', {}, withSession(graceSession, challenge))).madauth_challenge.attrs['max-age']).toBe('0');
  });
});

describe('the operator resets a lost app', () => {
  it('T22: the admin API and the CLI remove the app and the codes; a required policy then asks for a new setup', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'madauth-'));
    const path = join(dir, 'madauth.db');
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const store = createSqliteAdapter(path);
    const { app, hook } = passwordApp({ store });
    await setMethods(store, { google: { secondFactor: 'none' }, password: { secondFactor: 'optional' } });
    const session = await signUpVerified(app, hook, 'admin@example.com', 'admins password!');
    await setClaims(store, 'admin@example.com', { roles: ['admin'] });
    await setUp(app, session);
    const grace = await signUpVerified(app, hook, 'grace@example.com');
    const { secret } = await setUp(app, grace);
    const [{ id: userId }] = await store.findMany('user', { emailNormalized: 'grace@example.com' });
    // From now on everybody needs the app.
    await setMethods(store, { google: { secondFactor: 'none' }, password: { secondFactor: 'required' } });
    hook.calls.length = 0;
    const remove = (body: unknown, cookie?: string) => post(app, '/auth/admin/totp/remove', body, cookie ? withSession(cookie) : {});

    expect((await remove({ email: 'grace@example.com' })).status).toBe(401);
    expect((await remove({ email: 'grace@example.com' }, grace)).status).toBe(403);
    expect((await remove({ email: 'nobody@example.com' }, session)).status).toBe(404);
    expect((await remove({ email: 'nope' }, session)).status).toBe(400);
    const res = await remove({ email: 'Grace@Example.com' }, session);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ email: 'grace@example.com', userId, enabled: false });
    expect(await store.findOne('account', { key: `totp:${userId}` })).toBeNull();
    expect(await store.findMany('recoveryCode', { userId })).toEqual([]);
    expect(hook.calls).toEqual([
      { type: 'user.second_factor_disabled', data: { user: { id: userId, email: 'grace@example.com', name: 'Grace Hopper' }, method: 'totp', by: 'admin@example.com' } },
    ]);
    // Grace sets it up again at her next sign-in; her old app is of no use.
    const next = await post(app, '/auth/password/signin', { email: 'grace@example.com', password: 'correct horse battery' });
    expect(await next.json()).toMatchObject({ error: 'totp_setup_required' });
    expect(codeFor(secret)).toMatch(/^\d{6}$/);

    // The same from the command line, with the store alone.
    const io = { ask: async () => '', askSecret: async () => '' };
    expect(await runCli(['remove-totp', 'admin@example.com'], io, { DATABASE_URL: `sqlite:${path}` })).toEqual({
      exitCode: 0,
      output: 'Removed the authenticator app of admin@example.com.',
    });
    expect(await runCli(['remove-totp', 'admin@example.com'], io, { DATABASE_URL: `sqlite:${path}` })).toEqual({
      exitCode: 0,
      output: 'admin@example.com has no authenticator app.',
    });
    expect(await runCli(['remove-totp', 'nobody@example.com'], io, { DATABASE_URL: `sqlite:${path}` })).toMatchObject({ exitCode: 1 });
    expect(await runCli(['remove-totp', 'x'], io, { DATABASE_URL: `sqlite:${path}` })).toMatchObject({ exitCode: 1 });
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('signing up with the app alone', () => {
  const signUp = (app: App, email = 'grace@example.com') => post(app, '/auth/totp/signup', { email, name: 'Grace Hopper', redirectTo: REDIRECT_TO, locale: 'de' });

  it('T23: the address is confirmed by e-mail, then the app is set up, and the user is in with the app as their method', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, standalone);

    const res = await signUp(app);

    expect(res.status).toBe(202);
    const [user] = await store.findMany('user', {});
    expect(user).toMatchObject({ email: 'grace@example.com', name: 'Grace Hopper', emailVerified: false });
    expect(await store.findMany('account', {})).toEqual([]);
    expect(hook.types()).toEqual(['user.signing_up', 'email.send_verification']);
    expect(hook.calls[0].data).toEqual({ email: 'grace@example.com', name: 'Grace Hopper', locale: 'de', method: 'totp' });
    const { token, code } = linkAndCode(hook.lastEmail());
    expect(code).toMatch(/^\d{6}$/);

    // Confirming does not sign in yet: the app has to be set up first.
    const confirmed = await post(app, '/auth/email/verify', { token });
    expect(confirmed.status).toBe(401);
    expect(await confirmed.json()).toMatchObject({ error: 'totp_setup_required' });
    expect(cookies(confirmed).madauth_session?.value ?? '').toBe('');
    expect(await store.findOne('user', { id: user.id })).toMatchObject({ emailVerified: true });
    const challenge = `madauth_challenge=${cookies(confirmed).madauth_challenge.value}`;
    hook.calls.length = 0;

    const setup = await post(app, '/auth/totp/setup', {}, { Cookie: challenge });
    const secret = base32Decode(((await setup.json()) as { secret: string }).secret)!;
    const confirm = await post(app, '/auth/totp/confirm', { code: codeFor(secret) }, { Cookie: `${challenge}; madauth_totp_setup=${cookies(setup).madauth_totp_setup.value}` });

    expect(confirm.status).toBe(200);
    expect(((await confirm.json()) as { user: unknown }).user).toEqual({ ...graceUser, amr: ['otp'] });
    expect(await sessionClaims(app, confirm)).toMatchObject({ amr: ['otp'], sv: 0 });
    // The app is how she signs in, not a second factor: her sign-up is complete, and she is in.
    expect(hook.calls).toEqual([
      { type: 'user.signed_up', data: { user: graceUser, method: 'totp' } },
      { type: 'user.signed_in', data: { user: graceUser, method: 'totp' } },
    ]);
    expect(await store.findOne('account', { key: `totp:${user.id}` })).toMatchObject({ primaryUserId: user.id });
    // The app is her only way in: it can't be removed, only the account deleted.
    const removal = await post(app, '/auth/totp/remove', { code: codeFor(secret, 1) }, withSession(cookies(confirm).madauth_session.value));
    expect(removal.status).toBe(403);
    expect(await removal.json()).toMatchObject({ error: 'only_method' });
    advance(60_000);
    expect((await signInWithApp(app, { email: grace.email, code: codeFor(secret) })).status).toBe(200);
    // A password sign-up with the address afterwards only tells her she is registered, with the app.
    advance(60_000);
    await post(app, '/auth/password/signup', { ...grace, redirectTo: REDIRECT_TO });
    expect(hook.lastEmail()).toMatchObject({ type: 'email.send_already_registered', data: { methods: ['totp'] } });
  });

  it('T24: an unfinished sign-up starts over, and the latest unproven sign-up wins', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, standalone);
    await signUp(app);
    const first = linkAndCode(hook.lastEmail());
    // Confirmed, but the app was never set up: nobody can sign in as her yet.
    await post(app, '/auth/email/verify', { token: first.token });
    advance(61_000);

    expect((await signUp(app)).status).toBe(202);
    expect(hook.lastEmail()?.type).toBe('email.send_verification');
    expect(await store.findMany('user', {})).toHaveLength(1);
    // Someone signs up with a password for the same address before it is proven: the password is what counts then.
    advance(61_000);
    await post(app, '/auth/password/signup', { ...grace, redirectTo: REDIRECT_TO });
    expect(hook.lastEmail()?.type).toBe('email.send_verification');
    const confirmed = await post(app, '/auth/email/verify', { token: linkAndCode(hook.lastEmail()).token });
    expect(confirmed.status).toBe(200);
    expect(await sessionClaims(app, confirmed)).toMatchObject({ amr: ['pwd'] });
    // Google takes over a sign-up nobody finished, too.
    const other = passwordApp();
    await setMethods(other.store, standalone);
    await signUp(other.app, 'ada@example.com');
    const { nonce, cookie } = await getNonce(other.app);
    expect((await verify(other.app, await googleIdToken({ nonce }), cookie)).status).toBe(200);
    expect((await other.store.findMany('account', {})).map((a) => a.key)).toEqual(['google:1001']);
  });

  it('T33: a password sign-up for a confirmed address without a sign-in method needs its own e-mail; until then the pending app setup wins', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, standalone);
    await signUp(app);
    const confirmed = await post(app, '/auth/email/verify', { token: linkAndCode(hook.lastEmail()).token });
    const challenge = `madauth_challenge=${cookies(confirmed).madauth_challenge.value}`;
    // Before the app is set up, someone signs the address up with their own password.
    advance(61_000);
    expect((await post(app, '/auth/password/signup', { ...grace, redirectTo: REDIRECT_TO })).status).toBe(202);
    const [{ id: userId }] = await store.findMany('user', {});
    expect(await store.findMany('account', { userId })).toEqual([expect.objectContaining({ key: `password:${userId}` })]);
    // The password doesn't sign in before its confirmation e-mail is used.
    const signIn = await post(app, '/auth/password/signin', grace);
    expect(signIn.status).toBe(403);
    expect(await signIn.json()).toMatchObject({ error: 'email_unverified' });
    const passwordLink = linkAndCode(hook.lastEmail()).token;

    const setup = await post(app, '/auth/totp/setup', {}, { Cookie: challenge });
    const secret = base32Decode(((await setup.json()) as { secret: string }).secret)!;
    const confirm = await post(app, '/auth/totp/confirm', { code: codeFor(secret) }, { Cookie: `${challenge}; madauth_totp_setup=${cookies(setup).madauth_totp_setup.value}` });

    expect(confirm.status).toBe(200);
    expect(await confirm.json()).toMatchObject({ user: { id: userId, email: 'grace@example.com' } });
    expect(await store.findMany('account', { userId })).toEqual([expect.objectContaining({ key: `totp:${userId}`, primaryUserId: userId })]);
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(401);
    expect((await post(app, '/auth/email/verify', { token: passwordLink })).status).toBe(400);
  });

  it('T33: the password of such a sign-up signs in once its confirmation e-mail is used; then the app setup is refused', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, standalone);
    await signUp(app);
    const confirmed = await post(app, '/auth/email/verify', { token: linkAndCode(hook.lastEmail()).token });
    const challenge = `madauth_challenge=${cookies(confirmed).madauth_challenge.value}`;
    advance(61_000);
    await post(app, '/auth/password/signup', { ...grace, redirectTo: REDIRECT_TO });
    const [{ id: userId }] = await store.findMany('user', {});

    const verified = await post(app, '/auth/email/verify', { token: linkAndCode(hook.lastEmail()).token });
    expect(verified.status).toBe(200);
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(200);

    // The password is now the user's one sign-in method: the app can't be added as a second.
    const setup = await post(app, '/auth/totp/setup', {}, { Cookie: challenge });
    const secret = base32Decode(((await setup.json()) as { secret: string }).secret)!;
    const confirm = await post(app, '/auth/totp/confirm', { code: codeFor(secret) }, { Cookie: `${challenge}; madauth_totp_setup=${cookies(setup).madauth_totp_setup.value}` });
    expect(confirm.status).toBe(400);
    expect(await confirm.json()).toMatchObject({ error: 'setup_expired' });
    expect(await store.findMany('account', { userId })).toHaveLength(1);
    expect(await store.findMany('recoveryCode', { userId })).toEqual([]);
  });

  it('T28: a sign-up with the app drops the password of an earlier sign-up nobody confirmed', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, standalone);
    // Someone (perhaps not Grace) signed the address up with a password; nobody confirmed it.
    await post(app, '/auth/password/signup', { ...grace, redirectTo: REDIRECT_TO });
    advance(61_000);

    expect((await signUp(app)).status).toBe(202);

    expect(await store.findMany('account', {})).toEqual([]);
    const confirmed = await post(app, '/auth/email/verify', { token: linkAndCode(hook.lastEmail()).token });
    expect(confirmed.status).toBe(401);
    expect(await confirmed.json()).toMatchObject({ error: 'totp_setup_required' });
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(401);
  });

  it('T25: sign-up with the app needs the app listed and the confirmation e-mails; an app-only server has both from the start', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const { app, hook, store } = passwordApp();
    await setMethods(store, { password: { secondFactor: 'optional' } });
    expect((await signUp(app)).status).toBe(403);
    expect(await (await signUp(app)).json()).toMatchObject({ error: 'method_disabled' });
    // A confirmed address without any account, and the app not listed: the confirmation says so.
    await setMethods(store, standalone);
    await signUp(app);
    const { token } = linkAndCode(hook.lastEmail());
    await setMethods(store, { password: { secondFactor: 'optional' } });
    const confirmed = await post(app, '/auth/email/verify', { token });
    expect(confirmed.status).toBe(403);
    expect(await confirmed.json()).toMatchObject({ error: 'method_disabled' });
    // On only as a second factor, the app signs nobody up either, and the link is not used up for it.
    await setMethods(store, { password: { allowAsSignInMethod: true, secondFactor: 'optional' }, totp: { allowAsSignInMethod: false, secondFactor: 'none' } });
    expect(await (await post(app, '/auth/email/verify', { token })).json()).toMatchObject({ error: 'method_disabled' });
    expect((await store.findMany('user', {}))[0]).toMatchObject({ emailVerified: false });
    await setMethods(store, standalone);
    expect(await (await post(app, '/auth/email/verify', { token })).json()).toMatchObject({ error: 'totp_setup_required' });
    await setMethods(store, { password: { secondFactor: 'optional' } });

    // Without the e-mails there is no sign-up route, but setting the app up still works.
    const noEmails = passwordApp({ password: undefined, webhook: undefined });
    await setMethods(noEmails.store, { google: { secondFactor: 'optional' }, totp: {} });
    expect(await (await noEmails.app.request('/auth/config')).json()).toMatchObject({ totp: { signIn: true, signUp: false }, email: { verification: false } });
    expect((await signUp(noEmails.app)).status).toBe(404);

    // An app-only server: nothing but a webhook that sends email.send_verification.
    const config = await loadConfig({
      MADAUTH_ISSUER: ISSUER,
      MADAUTH_SIGNING_KEY: JSON.stringify(signingKey),
      ALLOWED_ORIGINS: APP_ORIGIN,
      DATABASE_URL: 'sqlite::memory:',
      WEBHOOK_URL,
      WEBHOOK_SECRET,
      WEBHOOK_EVENTS: 'email.send_verification',
    });
    expect(config.google).toBeUndefined();
    expect(config.password).toBeUndefined();
    const only = testApp({ ...config, webhookFetch: hook.fetch });
    expect(await (await only.request('/auth/config')).json()).toEqual({
      google: null,
      github: null,
      password: null,
      totp: { signIn: true, signUp: true },
      email: { verification: true },
      emailLink: null,
      sms: false,
      passkey: null,
    });
    expect((await signUp(only)).status).toBe(202);
  });
});
