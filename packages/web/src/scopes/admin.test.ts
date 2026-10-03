import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { SERVER, ada, fakeServer, resetAll } from '../test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

describe('Madauth.admin', () => {
  it('an admin reads and sets the roles of an address', async () => {
    const server = fakeServer();
    server.user = { ...ada, roles: ['admin'] };
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    expect(Madauth.currentUser?.roles).toEqual(['admin']);
    expect(await Madauth.admin.getRoles('grace@example.com')).toEqual({ isSuccess: true, roles: [] });
    expect(await Madauth.admin.setRoles('grace@example.com', ['editor', 'admin'])).toEqual({ isSuccess: true, roles: ['admin', 'editor'] });
    expect(await Madauth.admin.getRoles('grace@example.com')).toEqual({ isSuccess: true, roles: ['admin', 'editor'] });

    expect(server.requests.at(-2)).toMatchObject({
      method: 'POST',
      url: `${SERVER}/auth/admin/roles/set`,
      body: { email: 'grace@example.com', roles: ['editor', 'admin'] },
      credentials: 'include',
    });
  });

  it('fails with forbidden for other users, no_session when signed out, and names invalid input', async () => {
    const server = fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });
    expect(await Madauth.admin.getRoles('grace@example.com')).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });

    server.user = ada;
    expect(await Madauth.admin.setRoles('grace@example.com', ['admin'])).toMatchObject({ isSuccess: false, error: { code: 'forbidden' } });

    server.user = { ...ada, roles: ['admin'] };
    expect(await Madauth.admin.setRoles('nope', ['admin'])).toMatchObject({ isSuccess: false, error: { code: 'invalid_email' } });
    expect(await Madauth.admin.setRoles('grace@example.com', 'admin' as unknown as string[])).toMatchObject({
      isSuccess: false,
      error: { code: 'invalid_roles' },
    });
  });

  it('waits for initialize, and reports when madAuth is not set up', async () => {
    expect(await Madauth.admin.getRoles('grace@example.com')).toMatchObject({ isSuccess: false, error: { code: 'not_initialized' } });
  });

  it('a role change reaches listeners when the session is checked', async () => {
    const server = fakeServer();
    server.user = ada;
    const listener = vi.fn();
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });
    Madauth.onAuthStateChanged(listener);

    server.user = { ...ada, roles: ['admin'] };
    await Madauth.getSession();

    expect(listener).toHaveBeenLastCalledWith({ ...ada, roles: ['admin'] });
  });
});
