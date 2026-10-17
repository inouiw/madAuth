// Several sign-in methods per user: a signed-in user adds and removes them. Behaviour described in
// docs/sign-in-methods.md; update the doc when changing it.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Providers } from '../providers.js';
import { Settings } from '../settings.js';
import { Users } from '../users.js';
import {
  APP_ORIGIN,
  GITHUB_EMAILS,
  cookies,
  getNonce,
  googleIdToken,
  linkAndCode,
  passwordApp,
  post,
  setMethods,
  signUpVerified,
  startGitHub,
  stubGitHub,
  githubCallback,
  keyService,
  verify,
  type TestMethods,
} from '../test/helpers.js';

type Made = ReturnType<typeof passwordApp>;
type App = Made['app'];

const START = 1_700_000_015_000;
const grace = { email: 'grace@example.com', password: 'correct horse battery' };
const ON = { allowAsSignInMethod: true, secondFactor: 'none' } as const;
const everything: TestMethods = { google: ON, github: ON, password: ON, 'email-link': ON };

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const startClock = () => vi.useFakeTimers({ toFake: ['Date'], now: START });
const advance = (ms: number) => vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
const session = (value: string) => `madauth_session=${value}`;
const githubConfig = { github: { clientId: 'Iv1.test', clientSecret: 'secret' } };

/** Grace, signed up with a password just now, on a server with every method. */
async function withGrace(methods: TestMethods = everything) {
  startClock();
  const made = passwordApp(githubConfig);
  await setMethods(made.store, methods);
  const value = await signUpVerified(made.app, made.hook);
  made.hook.calls.length = 0;
  return { ...made, cookie: session(value) };
}

/** Signs in with a Google ID token for `claims` (One Tap / FedCM). */
async function googleSignIn(app: App, claims: Record<string, unknown> = {}) {
  const { nonce, cookie } = await getNonce(app);
  return verify(app, await googleIdToken({ nonce, ...claims }), cookie);
}

/** Adds the Google account of `claims` to the signed-in user, as the web library does with One Tap. */
async function linkGoogle(app: App, cookie: string, claims: Record<string, unknown> = {}) {
  const { nonce, cookie: nonceCookie } = await getNonce(app);
  return post(app, '/auth/google/link', { credential: await googleIdToken({ nonce, ...claims }) }, { Cookie: `${cookie}; ${nonceCookie}` });
}

const methodsOf = async (app: App, cookie: string) =>
  ((await (await app.request('/auth/methods', { headers: { Cookie: cookie } })).json()) as { methods: { id: string; method: string }[] }).methods;

describe('adding a sign-in method', () => {
  it('M1: a password user adds Google: from then on Google signs her in too, whatever address it has', async () => {
    const { app, hook, cookie } = await withGrace();

    const linked = await linkGoogle(app, cookie, { sub: '2002', email: 'grace.hopper@gmail.com' });

    expect(linked.status).toBe(200);
    expect(hook.types()).toEqual(['user.method_added']);
    expect(hook.calls[0].data).toMatchObject({ method: 'google', email: 'grace.hopper@gmail.com', user: { email: grace.email } });
    const signedIn = await googleSignIn(app, { sub: '2002', email: 'grace.hopper@gmail.com' });
    expect(await signedIn.json()).toMatchObject({ user: { email: grace.email } });
    // Her password still signs her in.
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(200);
    expect((await methodsOf(app, cookie)).map((m) => m.method)).toEqual(['password', 'google']);
  });

  it('M2: a Google account that signs in another user stays theirs, and linking it again changes nothing', async () => {
    const { app, cookie } = await withGrace();
    expect((await googleSignIn(app, { sub: '1001', email: 'ada@example.com' })).status).toBe(200);

    const taken = await linkGoogle(app, cookie, { sub: '1001', email: 'ada@example.com' });
    expect(taken.status).toBe(409);
    expect(await taken.json()).toMatchObject({ error: 'account_taken' });

    expect((await linkGoogle(app, cookie, { sub: '2002' })).status).toBe(200);
    expect((await linkGoogle(app, cookie, { sub: '2002' })).status).toBe(200);
    expect((await methodsOf(app, cookie)).filter((m) => m.method === 'google')).toHaveLength(1);
  });

  it('M3: only while signed in, within ten minutes of signing in; a sign-in with a new method is still refused', async () => {
    const { app, cookie } = await withGrace();

    // Without a session, a Google sign-in for her address does not join her: it is told how she signs in.
    const other = await googleSignIn(app, { sub: '2002', email: grace.email });
    expect(await other.json()).toMatchObject({ error: 'other_method', methods: ['password'] });
    expect(await (await linkGoogle(app, '', { sub: '2002' })).json()).toMatchObject({ error: 'no_session' });

    advance(11 * 60_000);
    expect(await (await linkGoogle(app, cookie, { sub: '2002' })).json()).toMatchObject({ error: 'reauth_required' });
    expect(await (await post(app, '/auth/email-link/add', {}, { Cookie: cookie })).json()).toMatchObject({ error: 'reauth_required' });
  });

  it('M13: the sign-in time is the one of the token the user was read from, not of another user\'s token in the request', async () => {
    const { app, hook } = await withGrace({ ...everything, passkey: ON });
    // Grace's renewal token, from a sign-in that is no longer recent.
    const renewal = cookies(await post(app, '/auth/password/signin', grace)).madauth_renewal.value;
    advance(11 * 60_000);
    // Mallory signs up just now and deletes her account: her session token is fresh, but its user is gone.
    const mallory = session(await signUpVerified(app, hook, 'mallory@example.com'));
    expect((await post(app, '/auth/account/delete', {}, { Cookie: mallory })).status).toBe(204);
    const mixed = `${mallory}; madauth_renewal=${renewal}`;

    // The request is Grace's, through her renewal token, and so is the time of its sign-in.
    expect((await methodsOf(app, mixed)).map((m) => m.method)).toEqual(['password']);
    expect(await (await linkGoogle(app, mixed, { sub: '2002' })).json()).toMatchObject({ error: 'reauth_required' });
    expect(await (await post(app, '/auth/email-link/add', {}, { Cookie: mixed })).json()).toMatchObject({ error: 'reauth_required' });
    expect(await (await post(app, '/auth/passkey/register/options', {}, { Cookie: mixed })).json()).toMatchObject({ error: 'reauth_required' });
  });

  it('M4: a Google user adds a password and the e-mail link; "Forgot password?" then resets it', async () => {
    startClock();
    const { app, hook, store } = passwordApp();
    await setMethods(store, everything);
    const google = await googleSignIn(app, { sub: '1001', email: 'ada@example.com' });
    const cookie = session(cookies(google).madauth_session.value);
    hook.calls.length = 0;

    expect(await (await post(app, '/auth/password/add', { password: 'short' }, { Cookie: cookie })).json()).toMatchObject({ error: 'weak_password' });
    expect((await post(app, '/auth/password/add', { password: 'adas own password!' }, { Cookie: cookie })).status).toBe(200);
    expect(await (await post(app, '/auth/password/add', { password: 'another one, please' }, { Cookie: cookie })).json()).toMatchObject({ error: 'already_added' });
    expect((await post(app, '/auth/password/signin', { email: 'ada@example.com', password: 'adas own password!' })).status).toBe(200);

    expect((await post(app, '/auth/email-link/add', {}, { Cookie: cookie })).status).toBe(200);
    expect(await (await post(app, '/auth/email-link/add', {}, { Cookie: cookie })).json()).toMatchObject({ error: 'already_added' });
    expect(hook.types().filter((t) => t === 'user.method_added')).toHaveLength(2);
    // The e-mail link now sends her a sign-in link, not the note that she signs in another way.
    hook.calls.length = 0;
    expect((await post(app, '/auth/email-link/send', { email: 'ada@example.com', redirectTo: `${APP_ORIGIN}/` })).status).toBe(202);
    const { token } = linkAndCode(hook.lastEmail());
    expect((await post(app, '/auth/email-link/verify', { token })).status).toBe(200);
  });

  it('M5: a password user adds GitHub through the redirect flow; it comes back with madauth_linked', async () => {
    const { app, hook, cookie } = await withGrace();
    const github = stubGitHub({ emails: [{ email: 'gh@example.com', primary: true, verified: true }] });

    const started = await app.request(`/auth/github/start?link=1&return_to=${encodeURIComponent(`${APP_ORIGIN}/account`)}`, { headers: { Cookie: cookie } });
    expect(started.status).toBe(302);
    const state = new URL(started.headers.get('location')!).searchParams.get('state')!;
    const oauth = `madauth_oauth=${cookies(started).madauth_oauth.value}`;
    const back = await app.request(`/auth/github/callback?code=c&state=${state}`, { headers: { Cookie: `${oauth}; ${cookie}` } });

    expect(back.headers.get('location')).toBe(`${APP_ORIGIN}/account#madauth_linked=github`);
    // No new session: she is signed in already.
    expect(cookies(back).madauth_session?.value ?? '').toBe('');
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.method_added', data: { method: 'github', email: 'gh@example.com' } });
    // GitHub signs her in now, without a session.
    const signedIn = await githubCallback(app, await startGitHub(app));
    expect(cookies(signedIn).madauth_session.value).toBeTruthy();
    expect(github.calls.length).toBeGreaterThan(0);
  });

  it('M6: the redirect flow adds nothing without a recent sign-in, nor for another browser', async () => {
    const { app, cookie } = await withGrace();
    stubGitHub({ emails: GITHUB_EMAILS });

    const anonymous = await app.request(`/auth/github/start?link=1&return_to=${encodeURIComponent(APP_ORIGIN)}`);
    expect(anonymous.headers.get('location')).toBe(`${APP_ORIGIN}/#madauth_error=no_session&madauth_method=github`);

    const started = await app.request(`/auth/github/start?link=1&return_to=${encodeURIComponent(APP_ORIGIN)}`, { headers: { Cookie: cookie } });
    const state = new URL(started.headers.get('location')!).searchParams.get('state')!;
    // The callback comes in a browser without her session.
    const back = await app.request(`/auth/github/callback?code=c&state=${state}`, { headers: { Cookie: `madauth_oauth=${cookies(started).madauth_oauth.value}` } });
    expect(back.headers.get('location')).toBe(`${APP_ORIGIN}/#madauth_error=no_session&madauth_method=github`);

    advance(11 * 60_000);
    const late = await app.request(`/auth/google/start?link=1&return_to=${encodeURIComponent(APP_ORIGIN)}`, { headers: { Cookie: cookie } });
    expect(late.headers.get('location')).toBe(`${APP_ORIGIN}/#madauth_error=reauth_required&madauth_method=google`);
  });
});

describe('removing a sign-in method', () => {
  it('M7: a method goes while another one signs the user in; the last one stays', async () => {
    const { app, hook, cookie } = await withGrace();
    await linkGoogle(app, cookie, { sub: '2002' });
    const [password, google] = await methodsOf(app, cookie);
    hook.calls.length = 0;

    expect((await post(app, '/auth/methods/remove', { id: password.id }, { Cookie: cookie })).status).toBe(200);
    expect(hook.calls[0]).toMatchObject({ type: 'user.method_removed', data: { method: 'password' } });
    expect(await (await post(app, '/auth/password/signin', grace)).json()).toMatchObject({ error: 'invalid_credentials' });

    const last = await post(app, '/auth/methods/remove', { id: google.id }, { Cookie: cookie });
    expect(last.status).toBe(403);
    expect(await last.json()).toMatchObject({ error: 'only_method' });
    expect(await (await post(app, '/auth/methods/remove', { id: 'acc_nobody' }, { Cookie: cookie })).json()).toMatchObject({ error: 'method_not_found' });
    // Google still signs her in.
    expect((await googleSignIn(app, { sub: '2002' })).status).toBe(200);
  });

  it('M8: a method the admin switched off does not count as a way in', async () => {
    const { app, store, cookie } = await withGrace();
    await linkGoogle(app, cookie, { sub: '2002' });
    const [password] = await methodsOf(app, cookie);

    await setMethods(store, { github: ON, password: ON, 'email-link': ON });

    expect(await (await post(app, '/auth/methods/remove', { id: password.id }, { Cookie: cookie })).json()).toMatchObject({ error: 'only_method' });
    expect((await methodsOf(app, cookie)).map((m) => [m.method, (m as unknown as { signIn: boolean }).signIn])).toEqual([
      ['password', true],
      ['google', false],
    ]);
  });

  it('M10: a method the server is not configured for does not count as a way in, though it is listed', async () => {
    const { app, store, cookie } = await withGrace();
    const [{ id: userId }] = await store.findMany('user', {});
    await new Users(store).linkAccount(userId as string, { key: 'github:7001', email: 'grace@example.com', primary: false });
    // An admin removed the GitHub provider; the settings still list GitHub.
    await new Providers(new Settings(store), keyService).remove('github', null);
    const [password] = await methodsOf(app, cookie);

    expect(await (await post(app, '/auth/methods/remove', { id: password.id }, { Cookie: cookie })).json()).toMatchObject({ error: 'only_method' });
  });

  it('M11: allowed as a sign-in method, a first authenticator app needs a recent sign-in too; only as a second factor, it doesn\'t', async () => {
    const { app, store, cookie } = await withGrace({ ...everything, authenticator: { allowAsSignInMethod: true, secondFactor: 'none' } });
    advance(11 * 60_000);

    expect(await (await post(app, '/auth/authenticator/setup', {}, { Cookie: cookie })).json()).toMatchObject({ error: 'reauth_required' });
    await setMethods(store, { ...everything, authenticator: { allowAsSignInMethod: false, secondFactor: 'none' } });
    expect((await post(app, '/auth/authenticator/setup', {}, { Cookie: cookie })).status).toBe(200);
  });

  it('M12: two removals at once of the last two ways in leave one', async () => {
    const { app, cookie } = await withGrace();
    await linkGoogle(app, cookie, { sub: '2002' });
    const [password, google] = await methodsOf(app, cookie);

    const results = await Promise.all([password, google].map((m) => post(app, '/auth/methods/remove', { id: m.id }, { Cookie: cookie })));

    expect(results.some((r) => r.status === 403)).toBe(true);
    expect((await methodsOf(app, cookie)).length).toBeGreaterThan(0);
  });

  it('M9: removing GitHub takes back its authorization at GitHub; the app is removed with a code of its own', async () => {
    const { app, cookie } = await withGrace({ ...everything, authenticator: { allowAsSignInMethod: false, secondFactor: 'none' } });
    const github = stubGitHub();
    const started = await app.request(`/auth/github/start?link=1&return_to=${encodeURIComponent(APP_ORIGIN)}`, { headers: { Cookie: cookie } });
    const state = new URL(started.headers.get('location')!).searchParams.get('state')!;
    await app.request(`/auth/github/callback?code=c&state=${state}`, { headers: { Cookie: `madauth_oauth=${cookies(started).madauth_oauth.value}; ${cookie}` } });
    const linked = (await methodsOf(app, cookie)).find((m) => m.method === 'github')!;

    expect((await post(app, '/auth/methods/remove', { id: linked.id }, { Cookie: cookie })).status).toBe(200);
    expect(github.revocations()).toHaveLength(1);
  });
});
