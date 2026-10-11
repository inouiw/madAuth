// Claims: see "Claims" in docs/server.md.
import { createLocalJWKSet } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseClaims, parseRoles } from './claims.js';
import { importSigningKeys } from './keys.js';
import { Users } from './users.js';
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
  setClaims,
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
  app.request(`/auth/admin/claims/${action}`, {
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

describe('parseClaims', () => {
  it('accepts a JSON object with named keys, in canonical form', () => {
    expect(parseClaims({ plan: 'pro', roles: ['editor', 'admin'], limits: { projects: 3 }, beta: true, note: null })).toEqual({
      beta: true,
      limits: { projects: 3 },
      note: null,
      plan: 'pro',
      roles: ['admin', 'editor'],
    });
    expect(parseClaims({})).toEqual({});
    expect(JSON.stringify(parseClaims({ b: 1, a: 2 }))).toBe('{"a":2,"b":1}');
  });

  it('refuses what is not an object, bad names, bad roles, and more than 2048 characters', () => {
    for (const bad of [null, undefined, 'admin', ['admin'], 7, { '1st': true }, { 'with space': 1 }, { 'a-b': 1 }, { roles: ['Admin'] }, { roles: 'admin' }]) {
      expect(parseClaims(bad)).toBeNull();
    }
    expect(parseClaims({ ['k'.repeat(65)]: 1 })).toBeNull();
    expect(parseClaims({ big: 'x'.repeat(2040) })).toBeNull();
    expect(parseClaims({ big: 'x'.repeat(2000) })).not.toBeNull();
    // Values JSON can't carry would change on the way.
    expect(parseClaims({ when: () => 1 })).toBeNull();
    expect(parseClaims({ n: Number.NaN })).toBeNull();
  });
});

describe('claims in the session', () => {
  it('a password sign-in gets the claims of its user, in the answer and in the session', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook);
    await setClaims(store, 'grace@example.com', { roles: ['admin', 'editor'], plan: 'pro' });

    const res = await post(app, '/auth/password/signin', grace);

    expect((await res.json()).user).toMatchObject({ email: 'grace@example.com', claims: { roles: ['admin', 'editor'], plan: 'pro' } });
    const cookie = cookies(res).madauth_session.value;
    // Backends read them from the session without asking madAuth.
    const { publicJwk } = await importSigningKeys(signingKey);
    const verifySession = createSessionVerifier({ issuer: ISSUER, jwks: createLocalJWKSet({ keys: [publicJwk] }) });
    expect((await verifySession(cookie))?.claims).toEqual({ roles: ['admin', 'editor'], plan: 'pro' });
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.signed_in', data: { user: { claims: { plan: 'pro' } } } });
  });

  it('a Google sign-in gets the claims of the user with its address too, however the address is written', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook, 'ada@example.com');
    await setClaims(store, 'ada@example.com', { roles: ['admin'] });
    // Her Google account, linked in the store: a sign-in alone never joins a user who signs in another way.
    const [user] = await store.findMany('user', {});
    await new Users(store).linkAccount(user.id as string, { key: 'google:1001', email: 'ada@example.com' });
    const { nonce, cookie } = await getNonce(app);

    const res = await verify(app, await googleIdToken({ nonce, email: 'Ada@Example.com' }), cookie);

    expect((await res.json()).user).toMatchObject({ id: expect.stringMatching(/^usr_/), email: 'ada@example.com', claims: { roles: ['admin'] } });
  });

  it('a user without claims has no claims field', async () => {
    const { app, hook } = passwordApp();
    const cookie = await signUpVerified(app, hook);

    expect((await (await session(app, cookie)).json()).user).toEqual({ id: expect.any(String), email: 'grace@example.com', name: 'Grace Hopper', amr: ['pwd'] });
  });

  it('a change shows the next time the app checks the session, which gets a new session token', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook);
    const signedIn = await post(app, '/auth/password/signin', grace);
    const check = (cookie: string) => app.request('/auth/session', { headers: { Cookie: cookie } });

    await setClaims(store, 'grace@example.com', { roles: ['admin'] });
    const granted = await check(cookieHeader(signedIn));
    expect((await granted.json()).user.claims).toEqual({ roles: ['admin'] });
    expect(cookies(granted).madauth_session.value).toBeTruthy();

    // Unchanged claims leave the cookies alone.
    expect(cookies(await check(cookieHeader(granted))).madauth_session).toBeUndefined();

    await setClaims(store, 'grace@example.com', null);
    const revoked = await check(cookieHeader(granted));
    expect((await revoked.json()).user.claims).toBeUndefined();
    expect(cookies(revoked).madauth_session.value).toBeTruthy();
  });

  it('a session without its renewal token shows the new claims but keeps its token', async () => {
    const { app, hook, store } = passwordApp();
    const cookie = await signUpVerified(app, hook);
    await setClaims(store, 'grace@example.com', { roles: ['admin'] });

    const res = await session(app, cookie);

    expect((await res.json()).user.claims).toEqual({ roles: ['admin'] });
    expect(cookies(res).madauth_session).toBeUndefined();
  });
});

describe('the admin API for claims', () => {
  /** An app whose user grace@example.com is an admin, and Ada a user; returns Grace's session. */
  async function withAdmin() {
    const made = passwordApp();
    await signUpVerified(made.app, made.hook);
    await setClaims(made.store, 'grace@example.com', { roles: ['admin'] });
    const res = await post(made.app, '/auth/password/signin', grace);
    const ada = await signUpVerified(made.app, made.hook, 'Ada@Example.com', 'adas password!');
    return { ...made, cookie: cookies(res).madauth_session.value, ada };
  }

  it('an admin sets and reads the claims of any user, and the webhook is told', async () => {
    const { app, hook, cookie, ada } = await withAdmin();

    const set = await admin(app, cookie, 'set', { email: ' Ada@Example.com ', claims: { roles: ['editor', 'admin'], plan: 'pro' } });
    expect(set.status).toBe(200);
    const expected = { email: 'ada@example.com', userId: expect.stringMatching(/^usr_/), claims: { plan: 'pro', roles: ['admin', 'editor'] } };
    expect(await set.json()).toEqual(expected);
    expect(hook.calls.at(-1)).toEqual({
      type: 'user.claims_changed',
      data: { ...expected, by: 'grace@example.com' },
    });

    const get = await admin(app, cookie, 'get', { email: 'ADA@example.com' });
    expect(await get.json()).toEqual(expected);
    // Ada sees them at her next session check.
    expect((await (await session(app, ada)).json()).user.claims).toEqual({ plan: 'pro', roles: ['admin', 'editor'] });

    // An empty object removes them.
    expect(await (await admin(app, cookie, 'set', { email: 'ada@example.com', claims: {} })).json()).toEqual({ ...expected, claims: {} });
    expect((await (await session(app, ada)).json()).user.claims).toBeUndefined();
  });

  it('needs a user with the address', async () => {
    const { app, cookie } = await withAdmin();

    const res = await admin(app, cookie, 'set', { email: 'nobody@example.com', claims: { roles: ['admin'] } });

    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({ error: 'user_not_found' });
    expect((await admin(app, cookie, 'get', { email: 'nobody@example.com' })).status).toBe(404);
  });

  it('is for admins only, asked from the store and not from the session', async () => {
    const { app, hook, store, cookie, ada } = await withAdmin();
    const body = { email: 'ada@example.com', claims: { roles: ['admin'] } };

    expect((await admin(app, undefined, 'set', body)).status).toBe(401);
    const forbidden = await admin(app, ada, 'set', body);
    expect(forbidden.status).toBe(403);
    expect(await forbidden.json()).toMatchObject({ error: 'forbidden' });
    expect((await admin(app, ada, 'get', body)).status).toBe(403);
    expect((await admin(app, cookie, 'set', body, 'https://evil.example')).status).toBe(403);

    // Her session still says "admin", but the role is gone: it stops counting at once.
    await setClaims(store, 'grace@example.com', null);
    expect((await admin(app, cookie, 'set', body)).status).toBe(403);
    expect(hook.types()).not.toContain('user.claims_changed');
    expect((await (await session(app, ada)).json()).user.claims).toBeUndefined();
  });

  it('refuses invalid addresses and claims', async () => {
    const { app, cookie } = await withAdmin();

    expect(await (await admin(app, cookie, 'set', { email: 'nope', claims: {} })).json()).toMatchObject({ error: 'invalid_email' });
    expect((await admin(app, cookie, 'get', {})).status).toBe(400);
    for (const claims of [{ roles: ['Admin'] }, ['admin'], undefined, 'admin', { '1st': true }]) {
      const res = await admin(app, cookie, 'set', { email: 'ada@example.com', claims });
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ error: 'invalid_claims' });
    }
  });

  it('a session that a password reset ended can not manage claims', async () => {
    const { app, hook, cookie } = await withAdmin();
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    await post(app, '/auth/password/reset', { token: linkAndCode(hook.lastEmail()).token, password: 'new password!' });

    expect((await admin(app, cookie, 'set', { email: 'ada@example.com', claims: {} })).status).toBe(401);
  });
});
