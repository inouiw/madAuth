// Roles: see "Roles" in docs/server.md.
import { createLocalJWKSet } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { importSigningKeys } from './keys.js';
import { Roles, parseRoles } from './roles.js';
import {
  APP_ORIGIN,
  ISSUER,
  REDIRECT_TO,
  cookieHeader,
  cookies,
  getNonce,
  googleIdToken,
  linkAndCode,
  passwordApp,
  post,
  signIn,
  signUpVerified,
  signingKey,
  testApp,
  verify,
} from './test/helpers.js';
import { createSessionVerifier } from './verify.js';

afterEach(() => {
  vi.useRealTimers();
});

type App = ReturnType<typeof testApp>;
const grace = { email: 'grace@example.com', password: 'correct horse battery' };
const session = (app: App, cookie: string) => app.request('/auth/session', { headers: { Cookie: `madauth_session=${cookie}` } });
const admin = (app: App, cookie: string | undefined, action: 'get' | 'set', body: unknown, origin = APP_ORIGIN) =>
  app.request(`/auth/admin/roles/${action}`, {
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/json', ...(cookie ? { Cookie: `madauth_session=${cookie}` } : {}) },
    body: JSON.stringify(body),
  });

/** Moves the clock forward without touching timers, so scrypt's callbacks still run. */
function advance(ms: number) {
  vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
}

describe('parseRoles', () => {
  it('accepts names of lower-case letters, digits, "-" and "_", sorted and without duplicates', () => {
    expect(parseRoles(['editor', 'admin', 'editor', 'team-2', 'read_only'])).toEqual(['admin', 'editor', 'read_only', 'team-2']);
    expect(parseRoles([])).toEqual([]);
  });

  it('refuses anything else', () => {
    for (const bad of [['Admin'], ['with space'], ['2fast'], [''], ['a'.repeat(33)], [7], 'admin', undefined, null]) {
      expect(parseRoles(bad)).toBeNull();
    }
    expect(parseRoles(Array.from({ length: 21 }, (_, i) => `role${i}`))).toBeNull();
  });
});

describe('roles in the session', () => {
  it('a password sign-in gets the roles of its address, in the answer and in the session', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook);
    await new Roles(store).set('grace@example.com', ['admin', 'editor'], null);

    const res = await post(app, '/auth/password/signin', grace);

    expect((await res.json()).user).toMatchObject({ email: 'grace@example.com', roles: ['admin', 'editor'] });
    const cookie = cookies(res).madauth_session.value;
    // Backends read them from the session without asking madAuth.
    const { publicJwk } = await importSigningKeys(signingKey);
    const verifySession = createSessionVerifier({ issuer: ISSUER, jwks: createLocalJWKSet({ keys: [publicJwk] }) });
    expect((await verifySession(cookie))?.roles).toEqual(['admin', 'editor']);
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.signed_in', data: { user: { roles: ['admin', 'editor'] } } });
  });

  it('a Google sign-in gets the roles of its address too, however the address is written', async () => {
    const { app, store } = passwordApp();
    await new Roles(store).set('ada@example.com', ['admin'], null);
    const { nonce, cookie } = await getNonce(app);

    const res = await verify(app, await googleIdToken({ nonce, email: 'Ada@Example.com' }), cookie);

    expect((await res.json()).user).toMatchObject({ id: 'google:1001', email: 'Ada@Example.com', roles: ['admin'] });
  });

  it('a user without roles has no roles field', async () => {
    const { app, hook } = passwordApp();
    const cookie = await signUpVerified(app, hook);

    expect((await (await session(app, cookie)).json()).user).toEqual({ id: expect.any(String), email: 'grace@example.com', name: 'Grace Hopper' });
  });

  it('a change shows the next time the app checks the session, which gets a new session token', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook);
    const signedIn = await post(app, '/auth/password/signin', grace);
    const check = (cookie: string) => app.request('/auth/session', { headers: { Cookie: cookie } });
    const roles = new Roles(store);

    await roles.set('grace@example.com', ['admin'], null);
    const granted = await check(cookieHeader(signedIn));
    expect((await granted.json()).user.roles).toEqual(['admin']);
    expect(cookies(granted).madauth_session.value).toBeTruthy();

    // Unchanged roles leave the cookies alone.
    expect(cookies(await check(cookieHeader(granted))).madauth_session).toBeUndefined();

    await roles.set('grace@example.com', [], null);
    const revoked = await check(cookieHeader(granted));
    expect((await revoked.json()).user.roles).toBeUndefined();
    expect(cookies(revoked).madauth_session.value).toBeTruthy();
  });

  it('a session without its renewal token shows the new roles but keeps its token', async () => {
    const { app, hook, store } = passwordApp();
    const cookie = await signUpVerified(app, hook);
    await new Roles(store).set('grace@example.com', ['admin'], null);

    const res = await session(app, cookie);

    expect((await res.json()).user.roles).toEqual(['admin']);
    expect(cookies(res).madauth_session).toBeUndefined();
  });

  it('without a store there are no roles and no admin routes', async () => {
    const app = testApp();
    const cookie = await signIn(app);

    expect((await (await session(app, cookie)).json()).user.roles).toBeUndefined();
    expect((await admin(app, cookie, 'get', { email: 'ada@example.com' })).status).toBe(404);
    expect((await admin(app, cookie, 'set', { email: 'ada@example.com', roles: ['admin'] })).status).toBe(404);
  });
});

describe('the admin API', () => {
  /** An app whose user grace@example.com is an admin; returns her session. */
  async function withAdmin() {
    const made = passwordApp();
    await signUpVerified(made.app, made.hook);
    await new Roles(made.store).set('grace@example.com', ['admin'], null);
    const res = await post(made.app, '/auth/password/signin', grace);
    return { ...made, cookie: cookies(res).madauth_session.value };
  }

  it('an admin sets and reads the roles of any address, and the webhook is told', async () => {
    const { app, hook, cookie } = await withAdmin();

    const set = await admin(app, cookie, 'set', { email: ' Ada@Example.com ', roles: ['editor', 'admin'] });
    expect(set.status).toBe(200);
    expect(await set.json()).toEqual({ email: 'ada@example.com', roles: ['admin', 'editor'] });
    expect(hook.calls.at(-1)).toEqual({
      type: 'roles.changed',
      data: { email: 'ada@example.com', roles: ['admin', 'editor'], by: 'grace@example.com' },
    });

    const get = await admin(app, cookie, 'get', { email: 'ADA@example.com' });
    expect(await get.json()).toEqual({ email: 'ada@example.com', roles: ['admin', 'editor'] });

    // The address needs no account: its owner gets the roles on the first sign-in.
    const { nonce, cookie: nonceCookie } = await getNonce(app);
    const ada = await verify(app, await googleIdToken({ nonce }), nonceCookie);
    expect((await ada.json()).user.roles).toEqual(['admin', 'editor']);

    expect(await (await admin(app, cookie, 'set', { email: 'ada@example.com', roles: [] })).json()).toEqual({ email: 'ada@example.com', roles: [] });
    expect(await (await admin(app, cookie, 'get', { email: 'ada@example.com' })).json()).toEqual({ email: 'ada@example.com', roles: [] });
  });

  it('is for admins only, asked from the store and not from the session', async () => {
    const { app, hook, store, cookie } = await withAdmin();
    const { nonce, cookie: nonceCookie } = await getNonce(app);
    const ada = cookies(await verify(app, await googleIdToken({ nonce }), nonceCookie)).madauth_session.value;
    const body = { email: 'ada@example.com', roles: ['admin'] };

    expect((await admin(app, undefined, 'set', body)).status).toBe(401);
    const forbidden = await admin(app, ada, 'set', body);
    expect(forbidden.status).toBe(403);
    expect(await forbidden.json()).toMatchObject({ error: 'forbidden' });
    expect((await admin(app, ada, 'get', body)).status).toBe(403);
    expect((await admin(app, cookie, 'set', body, 'https://evil.example')).status).toBe(403);

    // Her session still says "admin", but the role is gone: it stops counting at once.
    await new Roles(store).set('grace@example.com', [], null);
    expect((await admin(app, cookie, 'set', body)).status).toBe(403);
    expect(hook.types()).not.toContain('roles.changed');
    expect(await new Roles(store).get('ada@example.com')).toEqual([]);
  });

  it('refuses invalid addresses and role names', async () => {
    const { app, cookie } = await withAdmin();

    expect(await (await admin(app, cookie, 'set', { email: 'nope', roles: ['admin'] })).json()).toMatchObject({ error: 'invalid_email' });
    expect((await admin(app, cookie, 'get', {})).status).toBe(400);
    for (const roles of [['Admin'], 'admin', undefined, [1]]) {
      const res = await admin(app, cookie, 'set', { email: 'ada@example.com', roles });
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ error: 'invalid_roles' });
    }
  });

  it('a session that a password reset ended can not manage roles', async () => {
    const { app, hook, cookie } = await withAdmin();
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    await post(app, '/auth/password/reset', { token: linkAndCode(hook.lastEmail()).token, password: 'new password!' });

    expect((await admin(app, cookie, 'set', { email: 'ada@example.com', roles: ['admin'] })).status).toBe(401);
  });

  it('deleting the account removes the roles of its address', async () => {
    const { app, store, cookie } = await withAdmin();

    await app.request('/auth/account/delete', { method: 'POST', headers: { Origin: APP_ORIGIN, Cookie: `madauth_session=${cookie}` } });

    expect(await new Roles(store).get('grace@example.com')).toEqual([]);
  });
});

describe('Roles', () => {
  it('sets, replaces and removes the roles of an address', async () => {
    const { store } = passwordApp();
    const roles = new Roles(store);

    expect(await roles.get('ada@example.com')).toEqual([]);
    await roles.set('ada@example.com', ['admin'], null);
    await roles.set('ada@example.com', ['admin', 'editor'], 'grace@example.com');
    expect(await roles.get('ada@example.com')).toEqual(['admin', 'editor']);
    expect(await store.findOne('role', { id: 'ada@example.com' })).toMatchObject({ roles: 'admin editor', updatedBy: 'grace@example.com' });

    await roles.set('ada@example.com', [], null);
    expect(await store.findOne('role', { id: 'ada@example.com' })).toBeNull();
  });
});
