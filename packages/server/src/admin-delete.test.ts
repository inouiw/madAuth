// Deleting a user as an admin: POST /auth/admin/users/delete. Behaviour described in "Deleting a user" in
// docs/server.md; update the doc when changing it.
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  REDIRECT_TO,
  linkAndCode,
  passwordApp,
  post,
  setClaims,
  signInWithGitHub,
  signUpVerified,
  stubGitHub,
} from './test/helpers.js';

type App = ReturnType<typeof passwordApp>['app'];

const START = 1_700_000_015_000;
const grace = { email: 'grace@example.com', password: 'correct horse battery' };

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const advance = (ms: number) => vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
const session = (value: string) => `madauth_session=${value}`;
const deleteUser = (app: App, email: unknown, cookie?: string) => post(app, '/auth/admin/users/delete', { email }, cookie ? { Cookie: cookie } : {});
const sessionStatus = async (app: App, cookie: string) => (await app.request('/auth/session', { headers: { Cookie: cookie } })).status;
/** A program's call with a key: no cookies, no Origin. */
const withKey = (app: App, path: string, key: string, body: unknown) =>
  app.request(path, { method: 'POST', headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

/** A server with its admin and Grace, both signed up with a password just now. */
async function withAdminAndGrace(overrides: Parameters<typeof passwordApp>[0] = {}) {
  vi.useFakeTimers({ toFake: ['Date'], now: START });
  const made = passwordApp(overrides);
  const admin = session(await signUpVerified(made.app, made.hook, 'admin@example.com', 'the admins own password'));
  await setClaims(made.store, 'admin@example.com', { roles: ['admin'] });
  const cookie = session(await signUpVerified(made.app, made.hook));
  const [user] = await made.store.findMany('user', { emailNormalized: grace.email });
  made.hook.calls.length = 0;
  return { ...made, admin, cookie, userId: user.id as string };
}

describe('deleting a user as an admin', () => {
  it('D1: the user goes with everything stored, their sessions end, and the address signs up as new', async () => {
    const { app, hook, store, admin, cookie, userId } = await withAdminAndGrace();
    await setClaims(store, grace.email, { roles: ['editor'] });
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    hook.calls.length = 0;

    const res = await deleteUser(app, 'Grace@Example.com', admin);

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ email: grace.email, userId });
    expect(await store.findMany('user', { id: userId })).toEqual([]);
    expect(await store.findMany('account', { userId })).toEqual([]);
    expect(await store.findMany('verification', { userId })).toEqual([]);
    expect(hook.calls).toEqual([
      { type: 'user.deleted', data: { user: { id: userId, email: grace.email, name: 'Grace Hopper', claims: { roles: ['editor'] } }, by: 'admin@example.com' } },
    ]);
    expect(await sessionStatus(app, cookie)).toBe(401);
    expect(await sessionStatus(app, admin)).toBe(200);
    expect(await (await post(app, '/auth/password/signin', grace)).json()).toMatchObject({ error: 'invalid_credentials' });

    // A new sign-up: a new id, no claims, and user.signed_up again.
    advance(61_000);
    hook.calls.length = 0;
    expect((await post(app, '/auth/password/signup', { ...grace, redirectTo: REDIRECT_TO })).status).toBe(202);
    const back = await post(app, '/auth/email/verify', { token: linkAndCode(hook.lastEmail()).token });
    const { user } = (await back.json()) as { user: { id: string; claims?: unknown } };
    expect(user.id).not.toBe(userId);
    expect(user.claims ?? {}).toEqual({});
    expect(hook.types()).toContain('user.signed_up');
  });

  it('D2: only admins with a recent sign-in, for a user that exists and is no admin', async () => {
    const { app, store, admin, cookie } = await withAdminAndGrace();

    expect(await (await deleteUser(app, grace.email)).json()).toMatchObject({ error: 'no_session' });
    expect(await (await deleteUser(app, 'admin@example.com', cookie)).json()).toMatchObject({ error: 'forbidden' });
    expect(await (await deleteUser(app, 'nope', admin)).json()).toMatchObject({ error: 'invalid_email' });
    expect(await (await deleteUser(app, 'nobody@example.com', admin)).json()).toMatchObject({ error: 'user_not_found' });
    // Not themselves, and no other admin: another admin takes the role first.
    expect(await (await deleteUser(app, 'admin@example.com', admin)).json()).toMatchObject({ error: 'own_admin_role' });
    await setClaims(store, grace.email, { roles: ['admin'] });
    expect(await (await deleteUser(app, grace.email, admin)).json()).toMatchObject({ error: 'forbidden' });
    await setClaims(store, grace.email, null);
    // A session older than two minutes signs in again first.
    advance(121_000);
    expect(await (await deleteUser(app, grace.email, admin)).json()).toMatchObject({ error: 'reauth_required' });
    expect(await store.findMany('user', { emailNormalized: grace.email })).toHaveLength(1);
  });

  it('D3: a program deletes with an admin key that has the scope, without a recent sign-in; the event names the key', async () => {
    const { app, hook, store, admin } = await withAdminAndGrace();
    const created = await post(app, '/auth/api-keys/create', { name: 'cleanup', scopes: ['madauth:users:read', 'madauth:users:delete'] }, { Cookie: admin });
    const { key, apiKey } = (await created.json()) as { key: string; apiKey: { id: string } };
    const readOnly = (await (await post(app, '/auth/api-keys/create', { name: 'read', scopes: ['madauth:users:read'] }, { Cookie: admin })).json()) as { key: string };
    advance(10 * 60_000);
    hook.calls.length = 0;

    expect(await (await withKey(app, '/auth/admin/users/delete', readOnly.key, { email: grace.email })).json()).toMatchObject({ error: 'insufficient_scope' });
    const res = await withKey(app, '/auth/admin/users/delete', key, { email: grace.email });

    expect(res.status).toBe(200);
    expect(await store.findMany('user', { emailNormalized: grace.email })).toEqual([]);
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.deleted', data: { by: 'admin@example.com', byApiKey: { id: apiKey.id, name: 'cleanup' } } });
  });

  it("D4: GitHub's authorization is taken back", async () => {
    const { app, hook, admin } = await withAdminAndGrace({ github: { clientId: GITHUB_CLIENT_ID, clientSecret: GITHUB_CLIENT_SECRET } });
    const revoked = stubGitHub();
    await signInWithGitHub(app);
    hook.calls.length = 0;

    expect((await deleteUser(app, 'ada@example.com', admin)).status).toBe(200);
    expect(revoked.revocations()).toHaveLength(1);
  });
});
