import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
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
      methods: { google: { available: true, enabled: true }, password: { available: true, enabled: true } },
    });
    expect(await Madauth.admin.setSettings({ methods: { password: false } })).toMatchObject({
      isSuccess: true,
      methods: { google: { enabled: true }, password: { available: true, enabled: false } },
    });
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/admin/settings/set`, body: { methods: { password: false } } });
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
