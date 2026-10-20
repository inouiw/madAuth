// Sensitive changes made with a session take a sign-in within the last two minutes (RECENT_SIGN_IN_MS); API
// keys, the setup token and what only takes access away are exempt. See "Only within two minutes of signing in" in docs/sign-in-methods.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setupToken } from './setup.js';
import { APP_ORIGIN, ISSUER, cookies, keyService, passwordApp, post, setClaims, setMethods, signUpVerified, stubGitHub, type TestMethods } from './test/helpers.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const START = 1_700_000_000_000;
const ON = { allowAsSignInMethod: true, secondFactor: 'none' } as const;
const everything: TestMethods = { github: ON, password: ON };
const advance = (ms: number) => vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
const TOO_LATE = 2 * 60_000 + 1;

/** Grace, signed up with a password just now; with `admin`, she has the role. */
async function withGrace({ admin = false } = {}) {
  vi.useFakeTimers({ toFake: ['Date'], now: START });
  const made = passwordApp({ github: { clientId: 'Iv1.test', clientSecret: 'secret' } });
  await setMethods(made.store, everything);
  const session = await signUpVerified(made.app, made.hook);
  if (admin) await setClaims(made.store, 'grace@example.com', { roles: ['admin'] });
  const cookie = { Cookie: `madauth_session=${session}` };
  return { ...made, cookie };
}

describe('a sign-in within two minutes', () => {
  it('RS1: deleting the account takes it', async () => {
    const { app, cookie } = await withGrace();
    advance(TOO_LATE);
    expect(await (await post(app, '/auth/account/delete', {}, cookie)).json()).toMatchObject({ error: 'reauth_required' });

    const fresh = await withGrace();
    advance(60_000);
    expect((await post(fresh.app, '/auth/account/delete', {}, fresh.cookie)).status).toBe(204);
  });

  it("RS2: the admin API's changes take it with a session; an API key with the scope is its own proof", async () => {
    const { app, cookie } = await withGrace({ admin: true });
    const created = (await (await post(app, '/auth/api-keys/create', { name: 'script', scopes: ['madauth:claims:write', 'madauth:settings:write'] }, cookie)).json()) as { key: string };
    const changes: [string, unknown][] = [
      ['/auth/admin/claims/set', { email: 'grace@example.com', claims: { roles: ['admin'], plan: 'pro' } }],
      ['/auth/admin/settings/set', { methods: everything }],
      ['/auth/admin/settings/method', { method: 'github', setting: ON }],
    ];
    for (const [path, body] of changes) expect((await post(app, path, body, cookie)).status).toBe(200);

    advance(TOO_LATE);
    for (const [path, body] of changes) expect(await (await post(app, path, body, cookie)).json()).toMatchObject({ error: 'reauth_required' });
    expect(await (await post(app, '/auth/admin/sign-in/reset', { email: 'grace@example.com' }, cookie)).json()).toMatchObject({ error: 'reauth_required' });
    // Reading needs no recent sign-in.
    expect((await post(app, '/auth/admin/settings/get', {}, cookie)).status).toBe(200);
    // A key has no sign-in: with its scope, it changes as before.
    const withKey = { Authorization: `Bearer ${created.key}` };
    expect((await post(app, '/auth/admin/claims/set', { email: 'grace@example.com', claims: { roles: ['admin'] } }, withKey)).status).toBe(200);
    expect((await post(app, '/auth/admin/settings/method', { method: 'github', setting: ON }, withKey)).status).toBe(200);
  });

  it('RS3: the setup token needs none, and taking access away needs none either', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: START });
    const fresh = passwordApp();
    const bearer = { Authorization: `Bearer ${await setupToken(keyService, ISSUER)}` };
    expect((await post(fresh.app, '/auth/admin/settings/method', { method: 'password', setting: ON }, bearer)).status).toBe(200);

    const { app, cookie } = await withGrace({ admin: true });
    const created = (await (await post(app, '/auth/api-keys/create', { name: 'script', scopes: ['madauth:claims:read'] }, cookie)).json()) as { apiKey: { id: string } };
    advance(TOO_LATE);
    expect(await (await post(app, '/auth/api-keys/create', { name: 'another', scopes: ['madauth:claims:read'] }, cookie)).json()).toMatchObject({ error: 'reauth_required' });
    expect((await post(app, '/auth/api-keys/revoke', { id: created.apiKey.id }, cookie)).status).toBe(200);
    expect((await post(app, '/auth/logout', {}, cookie)).status).toBe(204);
  });

  it("RS4: a change of several steps checks it when it starts: a provider's redirect that takes longer still adds it", async () => {
    const { app, cookie } = await withGrace();
    stubGitHub();
    const started = await app.request(`/auth/providers/github/start?link=1&return_to=${encodeURIComponent(APP_ORIGIN)}`, { headers: cookie });
    const state = new URL(started.headers.get('location')!).searchParams.get('state')!;
    // The user takes their time at GitHub.
    advance(TOO_LATE);
    const back = await app.request(`/auth/providers/github/callback?code=c&state=${state}`, { headers: { Cookie: `madauth_oauth=${cookies(started).madauth_oauth.value}; ${cookie.Cookie}` } });
    expect(back.headers.get('location')).toBe(`${APP_ORIGIN}/#madauth_linked=github`);

    // Starting it too late is refused at the start.
    const late = await app.request(`/auth/providers/github/start?link=1&return_to=${encodeURIComponent(APP_ORIGIN)}`, { headers: cookie });
    expect(late.headers.get('location')).toContain('madauth_error=reauth_required');
  });
});
