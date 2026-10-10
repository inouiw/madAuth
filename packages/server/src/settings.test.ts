// Settings admins change at runtime: which sign-in methods are on. See "Sign-in methods" in docs/server.md.
import { describe, expect, it } from 'vitest';
import { Settings, parseMethodSettings } from './settings.js';
import { APP_ORIGIN, cookies, getNonce, googleIdToken, passwordApp, post, setClaims, signUpVerified, testApp, verify } from './test/helpers.js';

type App = ReturnType<typeof testApp>;
const grace = { email: 'grace@example.com', password: 'correct horse battery' };
const settingsApi = (app: App, cookie: string | undefined, action: 'get' | 'set', body: unknown = {}) =>
  app.request(`/auth/admin/settings/${action}`, {
    method: 'POST',
    headers: { Origin: APP_ORIGIN, 'Content-Type': 'application/json', ...(cookie ? { Cookie: `madauth_session=${cookie}` } : {}) },
    body: JSON.stringify(body),
  });
const config = async (app: App) => (await app.request('/auth/config')).json();

/** An app with both methods whose user grace@example.com is an admin; returns her session. */
async function withAdmin() {
  const made = passwordApp();
  await signUpVerified(made.app, made.hook);
  await setClaims(made.store, 'grace@example.com', { roles: ['admin'] });
  const res = await post(made.app, '/auth/password/signin', grace);
  return { ...made, cookie: cookies(res).madauth_session.value };
}

describe('parseMethodSettings', () => {
  it('accepts booleans for the known methods only', () => {
    expect(parseMethodSettings({ google: false })).toEqual({ google: false });
    expect(parseMethodSettings({})).toEqual({});
    for (const bad of [null, [], 'google', { sms: true }, { google: 'off' }]) expect(parseMethodSettings(bad)).toBeNull();
  });
});

describe('Settings', () => {
  it('keeps a JSON value per id and replaces it', async () => {
    const { store } = passwordApp();
    const settings = new Settings(store);

    expect(await settings.get('methods')).toBeUndefined();
    await settings.set('methods', { google: false }, null);
    await settings.set('methods', { google: true, password: false }, 'grace@example.com');

    expect(await settings.get('methods')).toEqual({ google: true, password: false });
    expect(await store.findOne('setting', { id: 'methods' })).toMatchObject({ value: '{"google":true,"password":false}', updatedBy: 'grace@example.com' });
    expect(await settings.methods()).toEqual({ google: true, password: false });
  });
});

describe('switching sign-in methods off and on', () => {
  it('an admin switches a method off: it leaves /auth/config and its routes answer method_disabled, at once', async () => {
    const { app, cookie } = await withAdmin();
    expect(await config(app)).toMatchObject({ google: { clientId: expect.any(String) }, password: { minLength: 8 } });

    const off = await settingsApi(app, cookie, 'set', { methods: { password: false } });

    expect(off.status).toBe(200);
    expect(await off.json()).toEqual({
      methods: { google: { available: true, enabled: true }, password: { available: true, enabled: false } },
    });
    expect(await config(app)).toMatchObject({ google: { clientId: expect.any(String) }, password: null });
    const signin = await post(app, '/auth/password/signin', grace);
    expect(signin.status).toBe(403);
    expect(await signin.json()).toMatchObject({ error: 'method_disabled' });
    expect((await post(app, '/auth/password/signup', { ...grace, redirectTo: APP_ORIGIN })).status).toBe(403);
    // Google still works, and the existing session too.
    const { nonce, cookie: nonceCookie } = await getNonce(app);
    expect((await verify(app, await googleIdToken({ nonce }), nonceCookie)).status).toBe(200);
    expect((await settingsApi(app, cookie, 'get')).status).toBe(200);

    // And on again.
    await settingsApi(app, cookie, 'set', { methods: { password: true } });
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(200);
  });

  it('Google can be switched off as well, for both flows', async () => {
    const { app, cookie } = await withAdmin();

    await settingsApi(app, cookie, 'set', { methods: { google: false } });

    expect(await config(app)).toMatchObject({ google: null, password: { minLength: 8 } });
    const nonce = await app.request('/auth/google/nonce', { method: 'POST', headers: { Origin: APP_ORIGIN } });
    expect(nonce.status).toBe(403);
    expect(await nonce.json()).toMatchObject({ error: 'method_disabled' });
    expect((await app.request(`/auth/google/start?return_to=${encodeURIComponent(APP_ORIGIN)}`)).status).toBe(403);
  });

  it('the last method can not be switched off, and a method the server is not configured for is never on', async () => {
    const { app, cookie } = await withAdmin();

    const both = await settingsApi(app, cookie, 'set', { methods: { google: false, password: false } });
    expect(both.status).toBe(400);
    expect(await both.json()).toMatchObject({ error: 'invalid_settings', message: expect.stringContaining('At least one') });
    await settingsApi(app, cookie, 'set', { methods: { google: false } });
    expect((await settingsApi(app, cookie, 'set', { methods: { password: false } })).status).toBe(400);

    // Only Google is configured here: password can't be switched on.
    const googleOnly = passwordApp({ password: undefined, webhook: undefined });
    await settingsApi(googleOnly.app, undefined, 'get');
    expect(await config(googleOnly.app)).toEqual({ google: { clientId: expect.any(String), codeFlow: true }, password: null });
  });

  it('is for admins only and checks its input', async () => {
    const { app, cookie, hook } = await withAdmin();
    const other = await signUpVerified(app, hook, 'ada@example.com', 'adas password!');

    expect((await settingsApi(app, undefined, 'get')).status).toBe(401);
    expect((await settingsApi(app, other, 'get')).status).toBe(403);
    expect((await settingsApi(app, other, 'set', { methods: { google: false } })).status).toBe(403);
    const bad = await settingsApi(app, cookie, 'set', { methods: { sms: true } });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: 'invalid_settings' });
    expect((await settingsApi(app, cookie, 'set', {})).status).toBe(400);
  });
});
