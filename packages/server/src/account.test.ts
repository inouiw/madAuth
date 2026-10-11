// Deleting the account: POST /auth/account/delete. See "HTTP API" in docs/server.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { APP_ORIGIN, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, REDIRECT_TO, cookies, linkAndCode, passwordApp, post, signIn, signInWithGithub, signUpVerified, stubGithub, type testApp } from './test/helpers.js';
import { Users } from './users.js';

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const grace = { email: 'grace@example.com', password: 'correct horse battery' };
type App = ReturnType<typeof testApp>;

const deleteAccount = (app: App, session?: string, origin = APP_ORIGIN) =>
  app.request('/auth/account/delete', {
    method: 'POST',
    headers: { Origin: origin, ...(session ? { Cookie: `madauth_session=${session}` } : {}) },
  });

/** Moves the clock forward without touching timers, so scrypt's callbacks still run. */
function advance(ms: number) {
  vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
}

const sendReset = (app: App) => post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });

describe('deleting the account', () => {
  it('deletes the user with everything stored, signs out and tells the webhook', async () => {
    const { app, hook, store } = passwordApp();
    const session = await signUpVerified(app, hook);
    advance(61_000);
    await sendReset(app);
    expect(await store.findMany('verification', {})).toHaveLength(1);
    const [{ id: userId }] = await store.findMany('user', {});

    const res = await deleteAccount(app, session);

    expect(res.status).toBe(204);
    expect(cookies(res).madauth_session).toMatchObject({ value: '', attrs: { 'max-age': '0' } });
    for (const model of ['user', 'account', 'verification']) expect(await store.findMany(model, {})).toEqual([]);
    expect(hook.calls.at(-1)).toEqual({
      type: 'user.deleted',
      data: { user: { id: userId, email: 'grace@example.com', name: 'Grace Hopper' } },
    });
    // The cookie of another device no longer counts, and the password no longer signs in.
    expect((await app.request('/auth/session', { headers: { Cookie: `madauth_session=${session}` } })).status).toBe(401);
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(401);
  });

  it('the address can sign up again afterwards', async () => {
    const { app, hook, store } = passwordApp();
    const first = await signUpVerified(app, hook);
    await deleteAccount(app, first);
    advance(61_000);

    const second = await signUpVerified(app, hook);

    expect(second).toBeTruthy();
    expect(await store.findMany('user', {})).toHaveLength(1);
    expect(await store.findMany('account', {})).toHaveLength(1);
  });

  it('a Google session deletes the user with all their sign-in methods', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook, 'Ada@Example.com');
    const [{ id: userId }] = await store.findMany('user', {});
    // Ada has both methods (a Google account linked in the store, as a sign-in alone never joins a user).
    await new Users(store).linkAccount(userId as string, { key: 'google:1001', email: 'ada@example.com' });
    const google = await signIn(app);
    expect(await store.findMany('account', {})).toHaveLength(2);

    const res = await deleteAccount(app, google);

    // The web library revokes the app's access to the Google account with the sub.
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ googleSub: '1001' });

    expect(await store.findMany('user', {})).toEqual([]);
    expect(await store.findMany('account', {})).toEqual([]);
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.deleted', data: { user: { id: userId, email: 'Ada@Example.com' } } });
  });

  it('a user who only ever signed in with Google is deleted too, and is signed out', async () => {
    const { app, hook, store } = passwordApp();
    const session = await signIn(app);

    const res = await deleteAccount(app, session);

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ googleSub: '1001' });
    expect(cookies(res).madauth_session).toMatchObject({ value: '' });
    expect(await store.findMany('user', {})).toEqual([]);
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.deleted', data: { user: { email: 'ada@example.com' } } });
    expect((await app.request('/auth/session', { headers: { Cookie: `madauth_session=${session}` } })).status).toBe(401);
  });

  it('needs a session that has not ended, from an allowed origin', async () => {
    const { app, hook, store } = passwordApp();
    const session = await signUpVerified(app, hook);

    expect((await deleteAccount(app)).status).toBe(401);
    expect((await deleteAccount(app, session, 'https://evil.example')).status).toBe(403);

    // A password reset ends older sessions; they can't delete the account either.
    advance(61_000);
    await sendReset(app);
    await post(app, '/auth/password/reset', { token: linkAndCode(hook.lastEmail()).token, password: 'new teapot sky!' });
    expect((await deleteAccount(app, session)).status).toBe(401);
    expect(await store.findMany('user', {})).toHaveLength(1);
  });

  it("O12: a GitHub user's deletion revokes the OAuth App's authorization at GitHub, with the token of the last sign-in", async () => {
    const { app, hook, store } = passwordApp({ github: { clientId: GITHUB_CLIENT_ID, clientSecret: GITHUB_CLIENT_SECRET } });
    const github = stubGithub({ token: 'gho_latest' });
    const session = cookies(await signInWithGithub(app)).madauth_session.value;

    const res = await deleteAccount(app, session);

    expect(res.status).toBe(204);
    const [revoke] = github.revocations();
    expect(revoke.url).toBe(`https://api.github.com/applications/${GITHUB_CLIENT_ID}/grant`);
    expect(new Headers(revoke.init.headers).get('authorization')).toBe(`Basic ${Buffer.from(`${GITHUB_CLIENT_ID}:${GITHUB_CLIENT_SECRET}`).toString('base64')}`);
    expect(JSON.parse(String(revoke.init.body))).toEqual({ access_token: 'gho_latest' });
    expect(await store.findMany('user', {})).toEqual([]);
    expect(await store.findMany('account', {})).toEqual([]);
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.deleted', data: { user: { email: 'ada@example.com' } } });
    expect((await app.request('/auth/session', { headers: { Cookie: `madauth_session=${session}` } })).status).toBe(401);
  });

  it("O13: the deletion goes ahead when GitHub refuses the revocation or can't be reached, and the log says so", async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const github = { clientId: GITHUB_CLIENT_ID, clientSecret: GITHUB_CLIENT_SECRET };
    const refusing = passwordApp({ github });
    stubGithub({ revokeStatus: 422 });
    const first = cookies(await signInWithGithub(refusing.app)).madauth_session.value;
    expect((await deleteAccount(refusing.app, first)).status).toBe(204);
    expect(await refusing.store.findMany('user', {})).toEqual([]);
    expect(error).toHaveBeenLastCalledWith(expect.stringContaining('did not revoke'));
    expect(error).toHaveBeenLastCalledWith(expect.stringContaining('HTTP 422'));

    vi.unstubAllGlobals();
    const unreachable = passwordApp({ github });
    const failing = stubGithub({});
    const second = cookies(await signInWithGithub(unreachable.app)).madauth_session.value;
    failing.calls.length = 0;
    vi.unstubAllGlobals();
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('fetch failed'); }));
    expect((await deleteAccount(unreachable.app, second)).status).toBe(204);
    expect(await unreachable.store.findMany('user', {})).toEqual([]);
    expect(error).toHaveBeenLastCalledWith(expect.stringContaining('did not revoke'));
  });
});
