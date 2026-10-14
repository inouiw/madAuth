// Resetting the sign-in of a user who lost every way in: POST /auth/admin/sign-in/reset. Behaviour described in
// "Resetting a user's sign-in" in docs/server.md; update the doc when changing it.
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  APP_ORIGIN,
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  REDIRECT_TO,
  cookies,
  getNonce,
  googleIdToken,
  linkAndCode,
  passwordApp,
  post,
  setClaims,
  setMethods,
  signInWithGitHub,
  signUpVerified,
  stubGitHub,
  verify,
  type TestMethods,
} from './test/helpers.js';
import { softAuthenticator } from './test/webauthn.js';
import { base32Decode, stepOf, totp } from './totp.js';

type Made = ReturnType<typeof passwordApp>;
type App = Made['app'];

const START = 1_700_000_015_000;
const grace = { email: 'grace@example.com', password: 'correct horse battery' };
const ON = { allowAsSignInMethod: true, secondFactor: 'none' } as const;
const FACTOR = { allowAsSignInMethod: false, secondFactor: 'none' } as const;
/** Every method, a password sign-in asks for a second factor when the user has one. */
const everything: TestMethods = {
  google: ON,
  github: ON,
  password: { allowAsSignInMethod: true, secondFactor: 'optional' },
  'email-link': ON,
  passkey: ON,
  totp: FACTOR,
  sms: FACTOR,
};
const github = { github: { clientId: GITHUB_CLIENT_ID, clientSecret: GITHUB_CLIENT_SECRET } };
const browser = softAuthenticator(APP_ORIGIN);

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const startClock = () => vi.useFakeTimers({ toFake: ['Date'], now: START });
const advance = (ms: number) => vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
const session = (value: string) => `madauth_session=${value}`;
const reset = (app: App, email: string, cookie?: string) => post(app, '/auth/admin/sign-in/reset', { email }, cookie ? { Cookie: cookie } : {});
const sessionStatus = async (app: App, cookie: string) => (await app.request('/auth/session', { headers: { Cookie: cookie } })).status;

/** A server with every method, its admin, and Grace, signed up with a password just now. */
async function withAdminAndGrace(methods: TestMethods = everything) {
  startClock();
  const made = passwordApp(github);
  await setMethods(made.store, methods);
  const admin = session(await signUpVerified(made.app, made.hook, 'admin@example.com', 'the admins own password'));
  await setClaims(made.store, 'admin@example.com', { roles: ['admin'] });
  const cookie = session(await signUpVerified(made.app, made.hook));
  const [user] = await made.store.findMany('user', { emailNormalized: grace.email });
  return { ...made, admin, cookie, userId: user.id as string };
}

/** Adds to Grace's sign-in every other method and second factor there is: the e-mail link, GitHub, a passkey, the app and a phone. */
async function addEverything({ app, hook }: Made, cookie: string) {
  expect((await post(app, '/auth/email-link/add', {}, { Cookie: cookie })).status).toBe(200);

  const started = await app.request(`/auth/github/start?link=1&return_to=${encodeURIComponent(APP_ORIGIN)}`, { headers: { Cookie: cookie } });
  const state = new URL(started.headers.get('location')!).searchParams.get('state')!;
  const linked = await app.request(`/auth/github/callback?code=c&state=${state}`, { headers: { Cookie: `madauth_oauth=${cookies(started).madauth_oauth.value}; ${cookie}` } });
  expect(linked.headers.get('location')).toContain('madauth_linked=github');

  const options = await post(app, '/auth/passkey/register/options', {}, { Cookie: cookie });
  const { passkey, response } = browser.create(await options.json());
  const added = await post(app, '/auth/passkey/register/verify', { response, name: 'Laptop' }, { Cookie: `${cookie}; madauth_passkey=${cookies(options).madauth_passkey.value}` });
  expect(added.status).toBe(200);

  const setup = await post(app, '/auth/totp/setup', {}, { Cookie: cookie });
  const secret = base32Decode(((await setup.json()) as { secret: string }).secret)!;
  const code = totp(secret, stepOf(Date.now()));
  const confirmed = await post(app, '/auth/totp/confirm', { code }, { Cookie: `${cookie}; madauth_totp_setup=${cookies(setup).madauth_totp_setup.value}` });
  expect(confirmed.status).toBe(200);

  const phone = await post(app, '/auth/sms/setup', { phone: '+41791234567' }, { Cookie: cookie });
  const sms = await post(app, '/auth/sms/confirm', { code: hook.lastSms()!.data.code }, { Cookie: `${cookie}; madauth_sms_setup=${cookies(phone).madauth_sms_setup.value}` });
  expect(sms.status).toBe(200);
  return { passkey, secret };
}

/** Signs in with a Google ID token for `claims` (One Tap / FedCM). */
async function googleSignIn(app: App, claims: Record<string, unknown>) {
  const { nonce, cookie } = await getNonce(app);
  return verify(app, await googleIdToken({ nonce, ...claims }), cookie);
}

describe('resetting a user\'s sign-in', () => {
  it('R1: every way in goes, her sessions and pending steps end, and her next sign-up keeps her id and claims', async () => {
    const made = await withAdminAndGrace();
    const { app, hook, store, admin, cookie, userId } = made;
    const revoked = stubGitHub({ emails: [{ email: 'gh@example.com', primary: true, verified: true }] });
    const { passkey, secret } = await addEverything(made, cookie);
    await setClaims(store, grace.email, { roles: ['editor'] });
    expect((await store.findMany('account', { userId })).map((account) => String(account.key).split(':')[0]).sort()).toEqual(
      ['email-link', 'github', 'passkey', 'password', 'sms', 'totp'],
    );
    expect(await store.findMany('recoveryCode', { userId })).toHaveLength(10);
    // A password reset under way, a sign-in that waits for its second step, and wrong codes counted.
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const resetLink = linkAndCode(hook.lastEmail()).token;
    const waiting = await post(app, '/auth/password/signin', grace);
    expect(await waiting.json()).toMatchObject({ error: 'passkey_required', factors: ['passkey', 'totp', 'sms'] });
    const challenge = `madauth_challenge=${cookies(waiting).madauth_challenge.value}`;
    await store.update('user', { id: userId }, { wrongCodes: 7 });
    const [before] = await store.findMany('user', { id: userId });
    hook.calls.length = 0;

    const res = await reset(app, 'Grace@Example.com', admin);

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ email: grace.email, userId });
    expect(await store.findMany('account', { userId })).toEqual([]);
    expect(await store.findMany('recoveryCode', { userId })).toEqual([]);
    expect((await store.findMany('verification', { userId })).filter((record) => record.purpose !== 'passkey')).toEqual([]);
    // The user stays, with her address unconfirmed: her next sign-up proves the inbox again.
    expect(await store.findMany('user', { id: userId })).toEqual([
      { ...before, emailVerified: false, sessionVersion: Number(before.sessionVersion) + 1, wrongCodes: 0 },
    ]);
    // GitHub's authorization goes with its account; one event tells the webhook, none per method.
    expect(revoked.revocations()).toHaveLength(1);
    expect(hook.calls).toEqual([
      {
        type: 'user.sign_in_reset',
        data: { user: { id: userId, email: grace.email, name: 'Grace Hopper', claims: { roles: ['editor'] } }, by: 'admin@example.com' },
      },
    ]);

    // Her sessions and the sign-in that waited for its second step have ended; the admin's has not.
    expect(await sessionStatus(app, cookie)).toBe(401);
    expect(await sessionStatus(app, admin)).toBe(200);
    const step = await post(app, '/auth/totp/verify', { code: totp(secret, stepOf(Date.now())) }, { Cookie: challenge });
    expect(await step.json()).toMatchObject({ error: 'challenge_expired' });
    // Nothing she had signs her in, and the reset link is gone.
    expect(await (await post(app, '/auth/password/signin', grace)).json()).toMatchObject({ error: 'invalid_credentials' });
    const options = await post(app, '/auth/passkey/signin/options', {});
    const signedIn = await post(app, '/auth/passkey/signin/verify', { response: browser.get(await options.json(), passkey) }, { Cookie: `madauth_passkey=${cookies(options).madauth_passkey.value}` });
    expect(await signedIn.json()).toMatchObject({ error: 'passkey_unknown' });
    expect(await (await post(app, '/auth/password/reset', { token: resetLink, password: 'a new teapot sky!' })).json()).toMatchObject({ error: 'link_invalid' });

    // She signs up again, with another method: the same user, with her claims, and no second user.signed_up.
    advance(61_000);
    hook.calls.length = 0;
    expect((await post(app, '/auth/email-link/send', { email: grace.email, redirectTo: REDIRECT_TO })).status).toBe(202);
    const back = await post(app, '/auth/email-link/verify', { token: linkAndCode(hook.lastEmail()).token });

    expect(await back.json()).toMatchObject({ user: { id: userId, email: grace.email, claims: { roles: ['editor'] } } });
    expect(hook.types()).toEqual(['user.signing_up', 'email.send_signin_link', 'user.email_verified', 'user.signed_in']);
    expect((await store.findMany('account', { userId })).map((account) => account.key)).toEqual([`email-link:${userId}`]);
    expect(await store.findMany('user', { id: userId })).toMatchObject([{ emailVerified: true, signedUpAt: before.signedUpAt }]);
  });

  it('R2: until a sign-up proves the address, the latest one wins, and a Google sign-in with it takes the user over', async () => {
    const { app, hook, store, admin, userId } = await withAdminAndGrace();
    expect((await reset(app, grace.email, admin)).status).toBe(200);

    // A password sign-up for her address waits for its e-mail; Google, which verified the address, comes first.
    advance(61_000);
    expect((await post(app, '/auth/password/signup', { ...grace, password: 'someone elses password', redirectTo: REDIRECT_TO })).status).toBe(202);
    const pending = linkAndCode(hook.lastEmail()).token;
    hook.calls.length = 0;
    const google = await googleSignIn(app, { sub: '2002', email: grace.email });

    expect(await google.json()).toMatchObject({ user: { id: userId, email: grace.email } });
    expect(hook.types()).toEqual(['user.signed_in']);
    expect((await store.findMany('account', { userId })).map((account) => account.key)).toEqual(['google:2002']);
    // The password's e-mail went with it.
    expect(await (await post(app, '/auth/email/verify', { token: pending })).json()).toMatchObject({ error: 'link_invalid' });
  });

  it('R3: only admins, for a user that exists; an admin who resets herself is signed out', async () => {
    const { app, admin, cookie } = await withAdminAndGrace();

    expect(await (await reset(app, grace.email)).json()).toMatchObject({ error: 'no_session' });
    expect(await (await reset(app, 'admin@example.com', cookie)).json()).toMatchObject({ error: 'forbidden' });
    expect(await (await reset(app, 'nope', admin)).json()).toMatchObject({ error: 'invalid_email' });
    expect(await (await reset(app, 'nobody@example.com', admin)).json()).toMatchObject({ error: 'user_not_found' });
    expect(await sessionStatus(app, cookie)).toBe(200);

    expect((await reset(app, 'admin@example.com', admin)).status).toBe(200);
    expect(await sessionStatus(app, admin)).toBe(401);
  });

  it("R4: GitHub refusing to revoke its authorization is logged, and the reset goes ahead", async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    startClock();
    const { app, hook, store } = passwordApp(github);
    await setMethods(store, everything);
    const admin = session(await signUpVerified(app, hook, 'admin@example.com', 'the admins own password'));
    await setClaims(store, 'admin@example.com', { roles: ['admin'] });
    const revoked = stubGitHub({ revokeStatus: 422 });
    expect(cookies(await signInWithGitHub(app)).madauth_session.value).toBeTruthy();

    expect((await reset(app, 'ada@example.com', admin)).status).toBe(200);

    expect(revoked.revocations()).toHaveLength(1);
    expect(error).toHaveBeenLastCalledWith(expect.stringContaining('did not revoke'));
    expect(await store.findMany('account', { email: 'ada@example.com' })).toEqual([]);
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.sign_in_reset', data: { user: { email: 'ada@example.com' } } });
  });
});
