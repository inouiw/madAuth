// Deleting the account: POST /auth/account/delete. See "HTTP API" in docs/server.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { APP_ORIGIN, REDIRECT_TO, cookies, linkAndCode, passwordApp, post, signIn, signUpVerified, type testApp } from './test/helpers.js';

afterEach(() => {
  vi.useRealTimers();
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
    // Google's verified address is Ada's: the Google account joins her user.
    const google = await signIn(app);
    expect(await store.findMany('account', {})).toHaveLength(2);

    expect((await deleteAccount(app, google)).status).toBe(204);

    expect(await store.findMany('user', {})).toEqual([]);
    expect(await store.findMany('account', {})).toEqual([]);
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.deleted', data: { user: { id: userId, email: 'Ada@Example.com' } } });
  });

  it('a user who only ever signed in with Google is deleted too, and is signed out', async () => {
    const { app, hook, store } = passwordApp();
    const session = await signIn(app);

    const res = await deleteAccount(app, session);

    expect(res.status).toBe(204);
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
    await post(app, '/auth/password/reset', { token: linkAndCode(hook.lastEmail()).token, password: 'new password!' });
    expect((await deleteAccount(app, session)).status).toBe(401);
    expect(await store.findMany('user', {})).toHaveLength(1);
  });
});
