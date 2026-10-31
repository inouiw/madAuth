import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { Password } from '../providers/password.js';
import { SERVER, ada, fakeServer, resetAll } from '../test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

const admin = { ...ada, claims: { roles: ['admin'] } };

describe('Madauth.admin', () => {
  it('an admin reads and sets the claims of a user', async () => {
    const server = fakeServer();
    server.user = admin;
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    expect(Madauth.currentUser?.claims).toEqual({ roles: ['admin'] });
    expect(await Madauth.admin.getClaims('grace@example.com')).toEqual({ isSuccess: true, userId: 'usr_grace', claims: {} });
    expect(await Madauth.admin.setClaims('grace@example.com', { roles: ['editor'], plan: 'pro' })).toEqual({
      isSuccess: true,
      userId: 'usr_grace',
      claims: { roles: ['editor'], plan: 'pro' },
    });
    expect(await Madauth.admin.getClaims('grace@example.com')).toMatchObject({ isSuccess: true, claims: { plan: 'pro' } });

    expect(server.requests.at(-2)).toMatchObject({
      method: 'POST',
      url: `${SERVER}/auth/admin/claims/set`,
      body: { email: 'grace@example.com', claims: { roles: ['editor'], plan: 'pro' } },
      credentials: 'include',
    });
  });

  it('fails with forbidden for other users, no_session when signed out, and names invalid input', async () => {
    const server = fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });
    expect(await Madauth.admin.getClaims('grace@example.com')).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });

    server.user = ada;
    expect(await Madauth.admin.setClaims('grace@example.com', { roles: ['admin'] })).toMatchObject({ isSuccess: false, error: { code: 'forbidden' } });
    expect(await Madauth.admin.getSettings()).toMatchObject({ isSuccess: false, error: { code: 'forbidden' } });

    server.user = admin;
    expect(await Madauth.admin.setClaims('nope', {})).toMatchObject({ isSuccess: false, error: { code: 'invalid_email' } });
    expect(await Madauth.admin.setClaims('nobody@example.com', {})).toMatchObject({ isSuccess: false, error: { code: 'user_not_found' } });
    expect(await Madauth.admin.setClaims('grace@example.com', ['admin'] as unknown as Record<string, unknown>)).toMatchObject({
      isSuccess: false,
      error: { code: 'invalid_claims' },
    });
  });

  it('an admin reads the settings and switches sign-in methods off and on', async () => {
    const server = fakeServer();
    server.user = admin;
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    expect(await Madauth.admin.getSettings()).toEqual({
      isSuccess: true,
      password: { minLength: 8, minScore: 2 },
      loginUrl: null,
      methods: {
        google: { configured: true, enabled: true, allowAsSignInMethod: true, secondFactor: 'none' },
        github: { configured: false, enabled: false, allowAsSignInMethod: false, secondFactor: 'none' },
        password: { configured: true, enabled: true, allowAsSignInMethod: true, secondFactor: 'none' },
        authenticator: { configured: true, enabled: false, allowAsSignInMethod: false, secondFactor: 'none' },
        'email-link': { configured: true, enabled: false, allowAsSignInMethod: false, secondFactor: 'none' },
        passkey: { configured: true, enabled: false, allowAsSignInMethod: false, secondFactor: 'none' },
        sms: { configured: true, enabled: false, allowAsSignInMethod: false, secondFactor: 'none' },
      },
    });
    // The list replaces what was on: password is left out, Google asks for a second factor, the app signs in alone.
    const methods = {
      google: { allowAsSignInMethod: true, secondFactor: 'optional' },
      authenticator: { allowAsSignInMethod: true, secondFactor: 'none' },
    } as const;
    expect(await Madauth.admin.setSettings({ methods })).toMatchObject({
      isSuccess: true,
      methods: {
        google: { enabled: true, secondFactor: 'optional' },
        password: { configured: true, enabled: false },
        authenticator: { configured: true, enabled: true },
      },
    });
    expect(server.requests.at(-1)).toMatchObject({
      url: `${SERVER}/auth/admin/settings/set`,
      body: { methods },
    });
    // The password rules alone leave the methods as they are.
    expect(await Madauth.admin.setSettings({ password: { minLength: 12 } })).toMatchObject({
      isSuccess: true,
      password: { minLength: 12, minScore: 2 },
      methods: { google: { secondFactor: 'optional' } },
    });
    expect(server.requests.at(-1)!.body).toEqual({ password: { minLength: 12 } });
  });

  it('an admin resets the sign-in of a user who lost every way in', async () => {
    const server = fakeServer();
    server.user = admin;
    server.authenticators.add('grace@example.com');
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });

    expect(await Madauth.admin.resetSignIn('grace@example.com')).toEqual({ isSuccess: true, userId: 'usr_grace' });

    expect(server.requests.at(-1)).toMatchObject({ method: 'POST', url: `${SERVER}/auth/admin/sign-in/reset`, body: { email: 'grace@example.com' } });
    expect(server.authenticators.has('grace@example.com')).toBe(false);
    expect(server.accounts.get('grace@example.com')).toMatchObject({ verified: false });
    // Her password is gone with the rest: nothing signs her in.
    expect(await Madauth.password.signIn({ email: 'grace@example.com', password: '' })).toMatchObject({ isSuccess: false, error: { code: 'invalid_credentials' } });
    expect(await Madauth.password.signIn({ email: 'grace@example.com', password: 'correct horse battery' })).toMatchObject({ isSuccess: false, error: { code: 'invalid_credentials' } });
    expect(await Madauth.admin.resetSignIn('nobody@example.com')).toMatchObject({ isSuccess: false, error: { code: 'user_not_found' } });
    server.user = ada;
    expect(await Madauth.admin.resetSignIn('grace@example.com')).toMatchObject({ isSuccess: false, error: { code: 'forbidden' } });
  });

  it('an admin searches users page by page, with the filters in the body', async () => {
    const server = fakeServer();
    server.user = admin;
    server.claims.set('grace@example.com', { roles: ['editor'] });
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    const first = await Madauth.admin.searchUsers({ role: 'editor', limit: 1 });
    expect(first).toMatchObject({ isSuccess: true, users: [{ email: 'grace@example.com', claims: { roles: ['editor'] }, pending: false }] });
    expect(server.requests.at(-1)).toMatchObject({ method: 'POST', url: `${SERVER}/auth/admin/users/search`, body: { role: 'editor', limit: 1 } });

    const all = await Madauth.admin.searchUsers();
    expect(all).toMatchObject({ isSuccess: true, users: expect.any(Array) });
    expect(all.isSuccess && 'cursor' in all).toBe(false);
    expect(await Madauth.admin.searchUsers({ method: 'passkey' } as never)).toMatchObject({ isSuccess: false, error: { code: 'invalid_search' } });
    server.user = ada;
    expect(await Madauth.admin.searchUsers({})).toMatchObject({ isSuccess: false, error: { code: 'forbidden' } });
  });

  it('an admin adds, lists, renames and removes a provider', async () => {
    const server = fakeServer();
    server.user = admin;
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    expect(await Madauth.admin.addProvider({ kind: 'github', clientId: 'Ov23liAbc', clientSecret: 'gh-secret' })).toMatchObject({
      isSuccess: true,
      provider: { id: 'github', kind: 'github', hasClientSecret: true, callbackUrl: `${SERVER}/auth/providers/github/callback` },
    });
    expect(server.requests.at(-1)).toMatchObject({ method: 'POST', url: `${SERVER}/auth/admin/providers/add`, body: { kind: 'github', clientId: 'Ov23liAbc', clientSecret: 'gh-secret' } });
    expect(await Madauth.admin.addProvider({ kind: 'github', clientId: 'x' })).toMatchObject({ isSuccess: false, error: { code: 'provider_exists' } });
    expect(await Madauth.admin.updateProvider('github', { name: 'GitHub Enterprise' })).toMatchObject({ isSuccess: true, provider: { name: 'GitHub Enterprise' } });
    expect(server.requests.at(-1)!.body).toEqual({ id: 'github', name: 'GitHub Enterprise' });
    expect(await Madauth.admin.listProviders()).toMatchObject({ isSuccess: true, providers: [{ id: 'google' }, { id: 'github' }], callbackBase: `${SERVER}/auth/providers/` });
    // A dry run counts, and leaves the provider.
    expect(await Madauth.admin.removeProvider('github', { dryRun: true })).toMatchObject({ isSuccess: true, usersWithoutSignIn: 0 });
    expect(server.requests.at(-1)!.body).toEqual({ id: 'github', dryRun: true });
    expect(await Madauth.admin.setMethod('github', { allowAsSignInMethod: true, secondFactor: 'none' })).toMatchObject({ isSuccess: true, methods: { github: { enabled: true } } });
    expect(server.requests.at(-1)).toMatchObject({ path: '/auth/admin/settings/method', body: { method: 'github', setting: { allowAsSignInMethod: true, secondFactor: 'none' } } });
    expect(await Madauth.admin.removeProvider('github')).toMatchObject({ isSuccess: true, usersWithoutSignIn: 0 });
    expect(server.requests.at(-1)!.body).toEqual({ id: 'github' });
    expect(await Madauth.admin.removeProvider('github')).toMatchObject({ isSuccess: false, error: { code: 'provider_not_found' } });
  });

  it('an admin registers, lists, changes and removes an OpenID Connect client, and sets the login page', async () => {
    const server = fakeServer();
    server.user = admin;
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    const added = await Madauth.admin.addClient({ name: 'Grafana', redirectUris: ['https://grafana.example.org/cb'] });
    expect(added).toMatchObject({ isSuccess: true, client: { id: 'mc_1', name: 'Grafana', public: false }, clientSecret: 'mcs_secret' });
    expect(server.requests.at(-1)).toMatchObject({ path: '/auth/admin/clients/add', body: { name: 'Grafana', redirectUris: ['https://grafana.example.org/cb'] } });
    const native = await Madauth.admin.addClient({ name: 'Editor', redirectUris: ['vscode://x/cb'], public: true });
    expect(native.isSuccess && 'clientSecret' in native).toBe(false);
    expect(await Madauth.admin.listClients()).toMatchObject({ isSuccess: true, clients: [{ id: 'mc_1' }, { id: 'mc_2' }] });
    expect(await Madauth.admin.updateClient('mc_1', { name: 'Grafana 2', newSecret: true, deviceFlow: true })).toMatchObject({ isSuccess: true, client: { name: 'Grafana 2', deviceFlow: true }, clientSecret: 'mcs_new' });
    expect(server.requests.at(-1)!.body).toEqual({ id: 'mc_1', name: 'Grafana 2', newSecret: true, deviceFlow: true });
    expect(await Madauth.admin.removeClient('mc_1')).toMatchObject({ isSuccess: true, client: { id: 'mc_1' } });
    expect(await Madauth.admin.removeClient('mc_1')).toMatchObject({ isSuccess: false, error: { code: 'client_not_found' } });
    expect(await Madauth.admin.addClient({ name: 'Bad', redirectUris: [] })).toMatchObject({ isSuccess: false, error: { code: 'invalid_client' } });

    expect(await Madauth.admin.setSettings({ loginUrl: '/login' })).toMatchObject({ isSuccess: true, loginUrl: '/login' });
    expect(server.requests.at(-1)!.body).toEqual({ loginUrl: '/login' });
    expect(await Madauth.admin.getSettings()).toMatchObject({ isSuccess: true, loginUrl: '/login' });
  });

  it('waits for initialize, and reports when madAuth is not set up', async () => {
    expect(await Madauth.admin.getClaims('grace@example.com')).toMatchObject({ isSuccess: false, error: { code: 'not_initialized' } });
  });

  it('a claims change reaches listeners when the session is checked', async () => {
    const server = fakeServer();
    server.user = ada;
    const listener = vi.fn();
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });
    Madauth.onAuthStateChanged(listener);

    server.user = admin;
    await Madauth.getSession();

    expect(listener).toHaveBeenLastCalledWith(admin);
  });
});
