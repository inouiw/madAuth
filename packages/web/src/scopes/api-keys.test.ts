import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { Password } from '../providers/password.js';
import { SERVER, ada, fakeServer, grace, resetAll } from '../test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

const init = () => Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });

describe('Madauth.apiKeys', () => {
  it("AW1: lists every scope, with whether the signed-in user may give a key it (their roles)", async () => {
    const server = fakeServer();
    server.user = grace;
    await init();

    const allowed = async () => {
      const result = await Madauth.apiKeys.scopes();
      return result.isSuccess ? Object.fromEntries(result.scopes.map((scope) => [scope.name, scope.allowed])) : result;
    };
    expect(await allowed()).toEqual({ 'madauth:claims:read': false, 'orders:read': true, 'orders:refund': false });
    expect(await Madauth.apiKeys.scopes()).toMatchObject({
      isSuccess: true,
      scopes: expect.arrayContaining([{ name: 'madauth:claims:read', description: "Read a user's claims and roles", role: 'admin', endpoints: ['POST /auth/admin/claims/get'], allowed: false }]),
    });

    // The server decides, with the claims as stored: no new session needed.
    server.user = { ...grace, claims: { roles: ['staff'] } };
    expect(await allowed()).toEqual({ 'madauth:claims:read': false, 'orders:read': true, 'orders:refund': true });
  });

  it('AW2: makes a key, shown once, lists it without the key and revokes it', async () => {
    const server = fakeServer();
    server.user = grace;
    await init();

    const made = await Madauth.apiKeys.create({ name: 'CI deploy', scopes: ['orders:read'], expiresAt: 5_000 });
    expect(made).toEqual({ isSuccess: true, key: 'madauth_secret1', apiKey: { id: 'key_1', name: 'CI deploy', scopes: ['orders:read'], createdAt: 1, expiresAt: 5_000, lastUsedAt: 0 } });
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/api-keys/create`, body: { name: 'CI deploy', scopes: ['orders:read'], expiresAt: 5_000 } });
    expect(await Madauth.apiKeys.list()).toEqual({ isSuccess: true, apiKeys: [{ id: 'key_1', name: 'CI deploy', scopes: ['orders:read'], createdAt: 1, expiresAt: 5_000, lastUsedAt: 0 }] });

    expect(await Madauth.apiKeys.revoke('key_1')).toEqual({ isSuccess: true });
    expect(await Madauth.apiKeys.revoke('key_1')).toMatchObject({ isSuccess: false, error: { code: 'api_key_not_found' } });
    expect(await Madauth.apiKeys.list()).toEqual({ isSuccess: true, apiKeys: [] });
  });

  it("AW3: needs a recent sign-in to make one, only with scopes the user holds, and a session", async () => {
    const server = fakeServer();
    server.user = grace;
    await init();

    expect(await Madauth.apiKeys.create({ name: 'k', scopes: ['orders:refund'] })).toMatchObject({ isSuccess: false, error: { code: 'scope_not_allowed' } });
    expect(await Madauth.apiKeys.create({ name: 'k', scopes: ['orders:write'] })).toMatchObject({ isSuccess: false, error: { code: 'invalid_scopes' } });
    server.staleSignIn = true;
    expect(await Madauth.apiKeys.create({ name: 'k', scopes: ['orders:read'] })).toMatchObject({ isSuccess: false, error: { code: 'reauth_required' } });
    server.user = null;
    expect(await Madauth.apiKeys.list()).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
    expect(await Madauth.apiKeys.revoke('key_1')).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
  });
});

describe('Madauth.admin and API keys', () => {
  it("AW4: an admin lists a user's keys and revokes one; others are forbidden", async () => {
    const server = fakeServer();
    server.user = grace;
    await init();
    await Madauth.apiKeys.create({ name: 'graces script', scopes: ['orders:read'] });

    server.user = { ...ada, claims: { roles: ['admin'] } };
    expect(await Madauth.admin.listApiKeys('grace@example.com')).toEqual({
      isSuccess: true,
      userId: 'usr_grace',
      apiKeys: [{ id: 'key_1', name: 'graces script', scopes: ['orders:read'], createdAt: 1, expiresAt: null, lastUsedAt: 0 }],
    });
    expect(await Madauth.admin.revokeApiKey('grace@example.com', 'key_1')).toEqual({ isSuccess: true, userId: 'usr_grace' });
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/admin/api-keys/revoke`, body: { email: 'grace@example.com', id: 'key_1' } });
    expect(await Madauth.admin.revokeApiKey('grace@example.com', 'key_1')).toMatchObject({ isSuccess: false, error: { code: 'api_key_not_found' } });

    server.user = ada;
    expect(await Madauth.admin.listApiKeys('grace@example.com')).toMatchObject({ isSuccess: false, error: { code: 'forbidden' } });
  });
});
