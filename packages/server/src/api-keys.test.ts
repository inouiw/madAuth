// API keys: a user makes keys for programs that call your app's API or madAuth's admin API on their behalf.
// Behaviour described in docs/api-keys.md; update the doc when changing it.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MAX_API_KEYS, parseAppScopes } from './api-keys.js';
import { passwordApp, post, setClaims, signUpVerified } from './test/helpers.js';
import { createApiKeyVerifier } from './verify.js';

type Made = ReturnType<typeof passwordApp>;
type App = Made['app'];

const START = 1_700_000_015_000;
const SCOPES_URL = 'https://app.example.com/api/scopes';
const APP_SCOPES = {
  scopes: [
    { name: 'orders:read', description: 'Read your orders', endpoints: ['GET /api/orders'] },
    { name: 'orders:refund', description: 'Refund orders', role: 'staff' },
  ],
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const startClock = () => vi.useFakeTimers({ toFake: ['Date'], now: START });
const advance = (ms: number) => vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
const session = (value: string) => `madauth_session=${value}`;

/** What the app's scope URL answers, changeable by the test. */
function scopesServer(answer: () => Response | Promise<Response> = () => Response.json(APP_SCOPES)) {
  const state = { answer, calls: 0 };
  const fetch = vi.fn(async (url: string | URL | Request) => {
    expect(String(url)).toBe(SCOPES_URL);
    state.calls++;
    return state.answer();
  }) as unknown as typeof globalThis.fetch;
  return { state, fetch };
}

/** A server whose app lists its scopes, with Grace signed up with a password just now. */
async function withGrace(scopes = scopesServer()) {
  startClock();
  const made = passwordApp({ apiKeyScopesUrl: SCOPES_URL, scopesFetch: scopes.fetch });
  const cookie = session(await signUpVerified(made.app, made.hook));
  made.hook.calls.length = 0;
  return { ...made, scopes, cookie };
}

const create = (app: App, cookie: string, data: Record<string, unknown>) => post(app, '/auth/api-keys/create', data, { Cookie: cookie });
const createKey = async (app: App, cookie: string, data: Record<string, unknown>) => {
  const res = await create(app, cookie, data);
  expect(res.status).toBe(200);
  return (await res.json()) as { key: string; apiKey: { id: string; name: string; scopes: string[] } };
};
const list = async (app: App, cookie: string) =>
  ((await (await app.request('/auth/api-keys', { headers: { Cookie: cookie } })).json()) as { apiKeys: { id: string; name: string }[] }).apiKeys;
/** A program's call with a key: no cookies, no Origin. */
const withKey = (app: App, path: string, key: string, body?: unknown) =>
  app.request(path, {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
const verifyKey = (app: App, key: string) => withKey(app, '/auth/api-keys/verify', key);

describe('making and using API keys', () => {
  it("AK1: lists madAuth's and the app's scopes; a key is shown once, listed without it, and a backend learns whom it acts for", async () => {
    const { app, hook, cookie } = await withGrace();

    const { scopes } = (await (await app.request('/auth/api-keys/scopes', { headers: { Cookie: cookie } })).json()) as {
      scopes: { name: string; role: string | null; allowed: boolean }[];
    };
    expect(scopes.map((s) => s.name)).toEqual([
      'madauth:claims:read',
      'madauth:claims:write',
      'madauth:settings:read',
      'madauth:settings:write',
      'madauth:sign-in:reset',
      'madauth:users:read',
      'madauth:providers:read',
      'orders:read',
      'orders:refund',
    ]);
    expect(scopes.find((s) => s.name === 'orders:refund')).toMatchObject({ role: 'staff', allowed: false });
    expect(scopes.filter((s) => s.allowed).map((s) => s.name)).toEqual(['orders:read']);

    const made = await createKey(app, cookie, { name: ' CI deploy ', scopes: ['orders:read'] });
    expect(made.key).toMatch(/^madauth_[A-Za-z0-9_-]{43}$/);
    expect(made.apiKey).toEqual({ id: expect.stringMatching(/^key_/), name: 'CI deploy', scopes: ['orders:read'], createdAt: START, expiresAt: null, lastUsedAt: 0 });
    expect(hook.types()).toEqual(['user.api_key_created']);
    expect(hook.calls[0].data).toMatchObject({ user: { email: 'grace@example.com' }, apiKey: { name: 'CI deploy', scopes: ['orders:read'] } });
    expect(JSON.stringify(hook.calls[0].data)).not.toContain(made.key);

    expect(await list(app, cookie)).toEqual([made.apiKey]);
    const verified = await verifyKey(app, made.key);
    expect(verified.status).toBe(200);
    expect(await verified.json()).toEqual({ user: { id: expect.any(String), email: 'grace@example.com', name: 'Grace Hopper' }, apiKey: { id: made.apiKey.id, name: 'CI deploy', scopes: ['orders:read'] } });
    expect((await list(app, cookie))[0]).toMatchObject({ lastUsedAt: START });
    // A key is no session.
    expect((await app.request('/auth/api-keys', { headers: { Authorization: `Bearer ${made.key}` } })).status).toBe(401);
  });

  it('AK2: only within ten minutes of signing in, with a name, known scopes and a future expiry; a key has only scopes its user holds', async () => {
    const { app, store, cookie } = await withGrace();

    expect(await (await create(app, cookie, { name: '', scopes: ['orders:read'] })).json()).toMatchObject({ error: 'invalid_options' });
    expect(await (await create(app, cookie, { name: 'x'.repeat(65), scopes: ['orders:read'] })).json()).toMatchObject({ error: 'invalid_options' });
    expect(await (await create(app, cookie, { name: 'k', scopes: [] })).json()).toMatchObject({ error: 'invalid_options' });
    expect(await (await create(app, cookie, { name: 'k', scopes: ['orders:read', 'orders:read'] })).json()).toMatchObject({ error: 'invalid_options' });
    expect(await (await create(app, cookie, { name: 'k', scopes: ['orders:read'], expiresAt: START })).json()).toMatchObject({ error: 'invalid_options' });
    expect(await (await create(app, cookie, { name: 'k', scopes: ['orders:write'] })).json()).toMatchObject({ error: 'invalid_scopes' });
    // madAuth's scopes need the role admin, the app's orders:refund the role staff.
    const denied = await create(app, cookie, { name: 'k', scopes: ['orders:read', 'madauth:claims:read', 'orders:refund'] });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ error: 'scope_not_allowed', message: expect.stringContaining('madauth:claims:read, orders:refund') });
    await setClaims(store, 'grace@example.com', { roles: ['staff'] });
    expect((await create(app, cookie, { name: 'k', scopes: ['orders:refund'] })).status).toBe(200);

    advance(11 * 60_000);
    expect(await (await create(app, cookie, { name: 'later', scopes: ['orders:read'] })).json()).toMatchObject({ error: 'reauth_required' });
    expect(await (await create(app, '', { name: 'k', scopes: ['orders:read'] })).json()).toMatchObject({ error: 'no_session' });
  });

  it('AK3: a revoked key stops working at once; nobody revokes the key of another user', async () => {
    const { app, hook, cookie } = await withGrace();
    const made = await createKey(app, cookie, { name: 'script', scopes: ['orders:read'] });
    const ada = session(await signUpVerified(app, hook, 'ada@example.com'));
    hook.calls.length = 0;

    expect(await (await post(app, '/auth/api-keys/revoke', { id: made.apiKey.id }, { Cookie: ada })).json()).toMatchObject({ error: 'api_key_not_found' });
    expect((await verifyKey(app, made.key)).status).toBe(200);

    expect((await post(app, '/auth/api-keys/revoke', { id: made.apiKey.id }, { Cookie: cookie })).status).toBe(200);
    expect(hook.types()).toEqual(['user.api_key_revoked']);
    expect(hook.calls[0].data).toMatchObject({ user: { email: 'grace@example.com' }, apiKey: { id: made.apiKey.id, name: 'script' } });
    const refused = await verifyKey(app, made.key);
    expect(refused.status).toBe(401);
    expect(await refused.json()).toMatchObject({ error: 'invalid_api_key' });
    expect(await list(app, cookie)).toEqual([]);
    expect(await (await post(app, '/auth/api-keys/revoke', { id: made.apiKey.id }, { Cookie: cookie })).json()).toMatchObject({ error: 'api_key_not_found' });
  });

  it('AK4: a key expires when its user chose; without expiresAt it never does', async () => {
    const { app, cookie } = await withGrace();
    const day = await createKey(app, cookie, { name: 'a day', scopes: ['orders:read'], expiresAt: START + 24 * 60 * 60_000 });
    const forever = await createKey(app, cookie, { name: 'forever', scopes: ['orders:read'] });

    advance(24 * 60 * 60_000);
    expect((await verifyKey(app, day.key)).status).toBe(401);
    expect((await verifyKey(app, forever.key)).status).toBe(200);
    expect((await verifyKey(app, 'madauth_unknown')).status).toBe(401);
    expect((await verifyKey(app, 'not-a-key')).status).toBe(401);
  });

  it('AK5: a scope counts at each use only while its user holds its role and the app lists it', async () => {
    const scopes = scopesServer();
    const { app, store, cookie } = await withGrace(scopes);
    await setClaims(store, 'grace@example.com', { roles: ['staff'] });
    const made = await createKey(app, cookie, { name: 'refunds', scopes: ['orders:read', 'orders:refund'] });

    const granted = async () => ((await (await verifyKey(app, made.key)).json()) as { apiKey: { scopes: string[] } }).apiKey.scopes;
    expect(await granted()).toEqual(['orders:read', 'orders:refund']);
    await setClaims(store, 'grace@example.com', null);
    expect(await granted()).toEqual(['orders:read']);

    // The app's list is read again after five minutes: a scope it dropped no longer counts.
    scopes.state.answer = () => Response.json({ scopes: [APP_SCOPES.scopes[1]] });
    await setClaims(store, 'grace@example.com', { roles: ['staff'] });
    advance(5 * 60_000);
    expect(await granted()).toEqual(['orders:refund']);
  });

  it(`AK6: at most ${MAX_API_KEYS} keys per user; expired ones don't count and go`, async () => {
    const { app, cookie } = await withGrace();
    await createKey(app, cookie, { name: 'expiring', scopes: ['orders:read'], expiresAt: START + 60_000 });
    for (let i = 1; i < MAX_API_KEYS; i++) await createKey(app, cookie, { name: `key ${i}`, scopes: ['orders:read'] });
    const refused = await create(app, cookie, { name: 'one more', scopes: ['orders:read'] });
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ error: 'too_many_api_keys' });

    advance(60_000);
    expect((await create(app, cookie, { name: 'one more', scopes: ['orders:read'] })).status).toBe(200);
    expect((await list(app, cookie)).map((k) => k.name)).not.toContain('expiring');
  });
});

describe("the app's list of scopes", () => {
  it("AK7: while it can't be read, keys have madAuth's scopes and making one with the app's waits; a list read once stays", async () => {
    const scopes = scopesServer(() => new Response('down', { status: 502 }));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const { app, store, cookie } = await withGrace(scopes);
    await setClaims(store, 'grace@example.com', { roles: ['admin'] });

    const names = async () => ((await (await app.request('/auth/api-keys/scopes')).json()) as { scopes: { name: string }[] }).scopes.map((s) => s.name);
    expect(await names()).not.toContain('orders:read');
    const waits = await create(app, cookie, { name: 'k', scopes: ['orders:read'] });
    expect(waits.status).toBe(503);
    expect(await waits.json()).toMatchObject({ error: 'temporarily_unavailable' });
    expect((await create(app, cookie, { name: 'admin', scopes: ['madauth:claims:read'] })).status).toBe(200);
    // A failed read is tried again after a minute, not at every request.
    const calls = scopes.state.calls;
    await names();
    expect(scopes.state.calls).toBe(calls);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('API_KEY_SCOPES_URL'));

    scopes.state.answer = () => Response.json(APP_SCOPES);
    advance(60_000);
    expect(await names()).toContain('orders:read');
    const made = await createKey(app, cookie, { name: 'k', scopes: ['orders:read'] });
    // Down again: the list read last stays.
    scopes.state.answer = () => Promise.reject(new Error('connection refused'));
    advance(5 * 60_000);
    expect(((await (await verifyKey(app, made.key)).json()) as { apiKey: { scopes: string[] } }).apiKey.scopes).toEqual(['orders:read']);
  });

  it('AK8: the list must be well-formed: names of lower-case words, never madAuth\'s, each with a description', () => {
    expect(parseAppScopes(APP_SCOPES)).toEqual([
      { name: 'orders:read', description: 'Read your orders', role: null, endpoints: ['GET /api/orders'] },
      { name: 'orders:refund', description: 'Refund orders', role: 'staff', endpoints: [] },
    ]);
    expect(parseAppScopes({ scopes: [] })).toEqual([]);
    for (const bad of [
      null,
      [],
      { scopes: [{ name: 'Orders', description: 'd' }] },
      { scopes: [{ name: 'madauth:claims:read', description: 'd' }] },
      { scopes: [{ name: 'orders:read', description: '' }] },
      { scopes: [{ name: 'a', description: 'd' }, { name: 'a', description: 'd' }] },
      { scopes: [{ name: 'a', description: 'd', role: 'Staff' }] },
      { scopes: [{ name: 'a', description: 'd', endpoints: 'GET /' }] },
    ]) {
      expect(parseAppScopes(bad)).toBeNull();
    }
  });
});

describe("madAuth's admin API with a key", () => {
  /** Grace as an admin, with a key of `scopes`. */
  async function adminKey(scopes: string[]) {
    const made = await withGrace();
    await setClaims(made.store, 'grace@example.com', { roles: ['admin'] });
    const { key, apiKey } = await createKey(made.app, made.cookie, { name: 'roles sync', scopes });
    made.hook.calls.length = 0;
    return { ...made, key, apiKey };
  }

  it('AK9: a key with the scope calls the admin task, without a browser; the event names the key', async () => {
    const { app, hook, key, apiKey } = await adminKey(['madauth:claims:read', 'madauth:claims:write']);

    const got = await withKey(app, '/auth/admin/claims/get', key, { email: 'grace@example.com' });
    expect(got.status).toBe(200);
    expect(await got.json()).toMatchObject({ email: 'grace@example.com', claims: { roles: ['admin'] } });

    const set = await withKey(app, '/auth/admin/claims/set', key, { email: 'grace@example.com', claims: { roles: ['admin', 'staff'] } });
    expect(set.status).toBe(200);
    expect(hook.types()).toEqual(['user.claims_changed']);
    expect(hook.calls[0].data).toMatchObject({ by: 'grace@example.com', byApiKey: { id: apiKey.id, name: 'roles sync' } });

    const settings = await withKey(app, '/auth/admin/settings/get', key, {});
    expect(settings.status).toBe(403);
    expect(await settings.json()).toMatchObject({ error: 'insufficient_scope', message: expect.stringContaining('madauth:settings:read') });
    expect((await withKey(app, '/auth/admin/claims/get', 'madauth_revoked', { email: 'grace@example.com' })).status).toBe(401);
  });

  it('AK10: a key stops counting for the admin API when its user loses the role', async () => {
    const { app, store, key } = await adminKey(['madauth:claims:read']);
    await setClaims(store, 'grace@example.com', { roles: ['staff'] });

    const refused = await withKey(app, '/auth/admin/claims/get', key, { email: 'grace@example.com' });
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: 'forbidden' });
    expect(((await (await verifyKey(app, key)).json()) as { apiKey: { scopes: string[] } }).apiKey.scopes).toEqual([]);
  });

  it("AK11: a key never manages keys; an admin lists and revokes a user's keys with a session", async () => {
    const { app, hook, cookie, key, apiKey } = await adminKey(['madauth:claims:read']);
    const admin = cookie;
    const ada = session(await signUpVerified(app, hook, 'ada@example.com'));
    const adas = await createKey(app, ada, { name: 'ada script', scopes: ['orders:read'] });
    hook.calls.length = 0;

    expect((await withKey(app, '/auth/admin/api-keys/list', key, { email: 'ada@example.com' })).status).toBe(403);
    expect((await withKey(app, '/auth/admin/api-keys/revoke', key, { email: 'ada@example.com', id: adas.apiKey.id })).status).toBe(403);

    const listed = await post(app, '/auth/admin/api-keys/list', { email: 'ada@example.com' }, { Cookie: admin });
    expect(await listed.json()).toMatchObject({ email: 'ada@example.com', apiKeys: [{ id: adas.apiKey.id, name: 'ada script' }] });
    expect(await (await post(app, '/auth/admin/api-keys/revoke', { email: 'ada@example.com', id: apiKey.id }, { Cookie: admin })).json()).toMatchObject({ error: 'api_key_not_found' });
    expect((await post(app, '/auth/admin/api-keys/revoke', { email: 'ada@example.com', id: adas.apiKey.id }, { Cookie: admin })).status).toBe(200);
    expect(hook.types()).toEqual(['user.api_key_revoked']);
    expect(hook.calls[0].data).toMatchObject({ user: { email: 'ada@example.com' }, apiKey: { id: adas.apiKey.id }, by: 'grace@example.com' });
    expect((await verifyKey(app, adas.key)).status).toBe(401);
    // Not an admin: no other user's keys.
    expect((await post(app, '/auth/admin/api-keys/list', { email: 'grace@example.com' }, { Cookie: ada })).status).toBe(403);
  });

  it("AK12: resetting a user's sign-in and deleting a user remove their keys", async () => {
    const { app, hook, cookie, key } = await adminKey(['madauth:claims:read']);
    const ada = session(await signUpVerified(app, hook, 'ada@example.com'));
    const adas = await createKey(app, ada, { name: 'ada script', scopes: ['orders:read'] });

    expect((await withKey(app, '/auth/admin/sign-in/reset', key, { email: 'ada@example.com' })).status).toBe(403);
    expect((await post(app, '/auth/admin/sign-in/reset', { email: 'ada@example.com' }, { Cookie: cookie })).status).toBe(200);
    expect((await verifyKey(app, adas.key)).status).toBe(401);

    const bob = session(await signUpVerified(app, hook, 'bob@example.com'));
    const bobs = await createKey(app, bob, { name: 'bob script', scopes: ['orders:read'] });
    expect((await post(app, '/auth/account/delete', {}, { Cookie: bob })).status).toBe(204);
    expect((await verifyKey(app, bobs.key)).status).toBe(401);
  });
});

describe('createApiKeyVerifier', () => {
  it('AK13: asks madAuth once per key and minute, and reuses the answer meanwhile', async () => {
    const { app, cookie } = await withGrace();
    const made = await createKey(app, cookie, { name: 'script', scopes: ['orders:read'] });
    const asked = vi.fn((input: string | URL | Request, init?: RequestInit) => app.request(String(input).replace('https://auth.example.com', ''), init));
    const verifyApiKey = createApiKeyVerifier({ issuer: 'https://auth.example.com/', fetch: asked as unknown as typeof fetch });
    const request = new Request('https://api.example.com/orders', { headers: { Authorization: `Bearer ${made.key}` } });

    expect(await verifyApiKey(request)).toMatchObject({ user: { email: 'grace@example.com' }, apiKey: { name: 'script', scopes: ['orders:read'] } });
    expect(await verifyApiKey(made.key)).toMatchObject({ apiKey: { name: 'script' } });
    expect(asked).toHaveBeenCalledOnce();
    expect(String(asked.mock.calls[0][0])).toBe('https://auth.example.com/auth/api-keys/verify');

    // Revoked: the answer it has counts until it is a minute old.
    expect((await post(app, '/auth/api-keys/revoke', { id: made.apiKey.id }, { Cookie: cookie })).status).toBe(200);
    expect(await verifyApiKey(request)).not.toBeNull();
    advance(60_000);
    expect(await verifyApiKey(request)).toBeNull();

    expect(await verifyApiKey(new Request('https://api.example.com/orders'))).toBeNull();
    expect(await verifyApiKey('a session token')).toBeNull();
    expect(asked).toHaveBeenCalledTimes(2);
  });

  it("AK14: madAuth not answering counts as no key, and says so", async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const verifyApiKey = createApiKeyVerifier({ issuer: 'https://auth.example.com', fetch: (() => Promise.reject(new Error('timeout'))) as typeof fetch });
    expect(await verifyApiKey('madauth_anything')).toBeNull();
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('did not answer'));
  });
});
