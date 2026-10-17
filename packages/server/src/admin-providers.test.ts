// Admins manage the sign-in providers, and the setup token does before the first admin exists: see "Providers"
// and "First setup" in docs/server.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setupToken, announceSetupOf } from './setup.js';
import { Users } from './users.js';
import { CLIENT_ID, ISSUER, keyService, passwordApp, post, setClaims, setMethods, signUpVerified } from './test/helpers.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

type Made = ReturnType<typeof passwordApp>;
const ON = { allowAsSignInMethod: true, secondFactor: 'none' } as const;
const GITHUB = { kind: 'github', clientId: 'Ov23liAbc', clientSecret: 'gh-secret' };

/** A server without Google or GitHub, with Ada, an admin who signed in just now. */
async function withAdmin(): Promise<Made & { cookie: string }> {
  vi.useFakeTimers({ toFake: ['Date'], now: 1_700_000_000_000 });
  const made = passwordApp({ google: undefined });
  const cookie = `madauth_session=${await signUpVerified(made.app, made.hook, 'ada@example.com', 'the admins own password')}`;
  await setClaims(made.store, 'ada@example.com', { roles: ['admin'] });
  made.hook.calls.length = 0;
  return { ...made, cookie };
}

const call = (made: Made, action: string, body: unknown, headers: Record<string, string>) => post(made.app, `/auth/admin/providers/${action}`, body, headers);
const json = async (res: Response | Promise<Response>) => (await res).json() as Promise<Record<string, any>>;

describe('admins manage the providers', () => {
  it('AP1: add, list, change and remove a provider; its secret is never answered; each change is an event', async () => {
    const made = await withAdmin();
    const admin = { Cookie: made.cookie };

    const added = await json(call(made, 'add', GITHUB, admin));
    expect(added.provider).toEqual({
      id: 'github',
      kind: 'github',
      name: 'GitHub',
      clientId: 'Ov23liAbc',
      hasClientSecret: true,
      callbackUrl: `${ISSUER}/auth/providers/github/callback`,
      createdAt: expect.any(Number),
      updatedAt: expect.any(Number),
    });
    expect(JSON.stringify(added)).not.toContain('gh-secret');
    expect(await json(call(made, 'add', GITHUB, admin))).toMatchObject({ error: 'provider_exists' });
    await call(made, 'add', { kind: 'google', clientId: CLIENT_ID }, admin);
    expect((await json(call(made, 'list', {}, admin))).providers.map((p: { id: string }) => p.id)).toEqual(['github', 'google']);

    expect((await json(call(made, 'update', { id: 'github', name: 'GitHub Enterprise' }, admin))).provider).toMatchObject({ name: 'GitHub Enterprise', hasClientSecret: true });
    expect(await json(call(made, 'update', { id: 'github', kind: 'google' }, admin))).toMatchObject({ error: 'invalid_provider' });
    expect(await json(call(made, 'update', { id: 'gitlab', name: 'x' }, admin))).toMatchObject({ error: 'provider_not_found' });
    expect(await json(call(made, 'remove', { id: 'google' }, admin))).toMatchObject({ provider: { id: 'google' }, usersWithoutSignIn: 0 });

    expect(made.hook.calls.map((c) => [c.type, c.data.provider.id, c.data.by])).toEqual([
      ['provider.added', 'github', 'ada@example.com'],
      ['provider.added', 'google', 'ada@example.com'],
      ['provider.changed', 'github', 'ada@example.com'],
      ['provider.removed', 'google', 'ada@example.com'],
    ]);
  });

  it('AP2: changing providers takes an admin with a fresh sign-in and a session; reading them takes an API key too', async () => {
    const made = await withAdmin();
    const grace = `madauth_session=${await signUpVerified(made.app, made.hook, 'grace@example.com', 'correct horse battery')}`;
    expect((await call(made, 'add', GITHUB, { Cookie: grace })).status).toBe(403);
    expect((await call(made, 'list', {}, {})).status).toBe(401);

    const created = await json(post(made.app, '/auth/api-keys/create', { name: 'k', scopes: ['madauth:providers:read'] }, { Cookie: made.cookie }));
    const withKey = (action: string, body: unknown) =>
      made.app.request(`/auth/admin/providers/${action}`, { method: 'POST', headers: { Authorization: `Bearer ${created.key}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    expect((await withKey('list', {})).status).toBe(200);
    expect(await json(withKey('add', GITHUB))).toMatchObject({ error: 'forbidden' });

    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 11 * 60_000 });
    expect(await json(call(made, 'add', GITHUB, { Cookie: made.cookie }))).toMatchObject({ error: 'reauth_required' });
    expect((await call(made, 'list', {}, { Cookie: made.cookie })).status).toBe(200);
  });

  it('AP3: a new provider is off until an admin switches it on, also where the methods were never saved', async () => {
    const made = await withAdmin();
    const config = async () => (await made.app.request('/auth/config')).json() as Promise<{ github: unknown; password: unknown }>;
    expect(await config()).toMatchObject({ github: null, password: expect.anything() });

    await call(made, 'add', GITHUB, { Cookie: made.cookie });
    expect(await config()).toMatchObject({ github: null, password: expect.anything() });
    await setMethods(made.store, { github: ON, password: ON });
    expect(await config()).toMatchObject({ github: { secondFactor: 'none' } });
  });

  it('AP4: removing a provider says how many users signed in with it alone; their accounts stay, its setting goes', async () => {
    const made = await withAdmin();
    await call(made, 'add', GITHUB, { Cookie: made.cookie });
    await setMethods(made.store, { github: ON, password: ON });
    const users = new Users(made.store);
    const ada = (await users.findByEmail('ada@example.com'))!;
    // Ada also has GitHub; Linus has nothing else.
    await users.linkAccount(ada.id, { key: 'github:1', email: 'ada@example.com', primary: false });
    const linus = await users.createUser({ email: 'linus@example.com', emailNormalized: 'linus@example.com', name: null, emailVerified: true, account: { key: 'github:2', email: 'linus@example.com' } });

    expect(await json(call(made, 'remove', { id: 'github' }, { Cookie: made.cookie }))).toMatchObject({ usersWithoutSignIn: 1 });
    expect(await users.findAccountByKey('github:2')).toMatchObject({ userId: linus!.id });

    // Added again, it is off until an admin switches it on, as a new provider is.
    await call(made, 'add', GITHUB, { Cookie: made.cookie });
    expect(((await (await made.app.request('/auth/config')).json()) as { github: unknown }).github).toBeNull();
  });
});

describe('the setup token, while no admin exists', () => {
  /** A new server: nobody has the role admin yet. */
  const fresh = (initialAdminEmail?: string) => passwordApp({ google: undefined, initialAdminEmail });
  const bearer = async () => ({ Authorization: `Bearer ${await setupToken(keyService, ISSUER)}` });

  it('AP5: works on the provider and settings calls, not on the others, and is printed at the start', async () => {
    const made = fresh('ada@example.com');
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await announceSetupOf({ store: made.store, keyService, issuer: ISSUER, initialAdminEmail: 'ada@example.com' });
    expect(String(warn.mock.calls[0]![0])).toContain(`Bearer ${await setupToken(keyService, ISSUER)}`);

    const headers = await bearer();
    expect((await json(call(made, 'add', { kind: 'google', clientId: CLIENT_ID }, headers))).provider).toMatchObject({ id: 'google' });
    expect((await post(made.app, '/auth/admin/settings/set', { methods: { google: ON, password: ON } }, headers)).status).toBe(200);
    expect(((await json(made.app.request('/auth/config'))) as { google: unknown }).google).toMatchObject({ clientId: CLIENT_ID });
    expect(made.hook.calls.find((c) => c.type === 'provider.added')?.data).toMatchObject({ by: null, bySetupToken: true });

    expect((await post(made.app, '/auth/admin/users/search', {}, headers)).status).toBe(401);
    expect((await post(made.app, '/auth/admin/claims/get', { email: 'ada@example.com' }, headers)).status).toBe(401);
    expect(await json(call(made, 'list', {}, { Authorization: 'Bearer madauth_setup_wrong' }))).toMatchObject({ error: 'invalid_setup_token' });
  });

  it('AP6: stops once INITIAL_ADMIN_EMAIL signed in, and is no longer printed', async () => {
    const made = fresh('ada@example.com');
    const headers = await bearer();
    expect((await call(made, 'list', {}, headers)).status).toBe(200);

    await signUpVerified(made.app, made.hook, 'ada@example.com', 'the admins own password');
    expect(await json(call(made, 'list', {}, headers))).toMatchObject({ error: 'invalid_setup_token' });
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await announceSetupOf({ store: made.store, keyService, issuer: ISSUER, initialAdminEmail: 'ada@example.com' });
    expect(warn).not.toHaveBeenCalled();
  });

  it('AP8: stops at once on every instance, also on one that just found it open', async () => {
    const one = fresh('ada@example.com');
    const other = passwordApp({ google: undefined, initialAdminEmail: 'ada@example.com', store: one.store, webhookFetch: one.hook.fetch });
    const headers = await bearer();
    expect((await call(one, 'list', {}, headers)).status).toBe(200);

    await signUpVerified(one.app, one.hook, 'ada@example.com', 'the admins own password');
    expect(await json(call(other, 'list', {}, headers))).toMatchObject({ error: 'invalid_setup_token' });
    expect(await json(call(one, 'list', {}, headers))).toMatchObject({ error: 'invalid_setup_token' });
  });

  it('AP7: does nothing on a server that has an admin already, e.g. one from before 0.7', async () => {
    const made = fresh();
    await signUpVerified(made.app, made.hook, 'ada@example.com', 'the admins own password');
    await setClaims(made.store, 'ada@example.com', { roles: ['admin'] });

    expect(await json(call(made, 'list', {}, await bearer()))).toMatchObject({ error: 'invalid_setup_token' });
  });
});
