// Settings admins change at runtime: which sign-in methods are on, and which ask for the authenticator app.
// See "Sign-in methods" in docs/server.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Settings, authenticatorOn, initialMethods, isOn, parseMethodSettings, policyOf } from './settings.js';
import { APP_ORIGIN, cookies, getNonce, googleIdToken, passwordApp, post, setClaims, signUpVerified, testApp, verify } from './test/helpers.js';

afterEach(() => {
  vi.restoreAllMocks();
});

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
  it('reads the list of methods that are on, each with its policy for the authenticator app', () => {
    expect(parseMethodSettings({ google: {}, password: { secondFactor: 'required' }, totp: {} })).toEqual({
      google: {},
      password: { secondFactor: 'required' },
      totp: {},
    });
    // The admin API also takes booleans: true is {}, false is off, like leaving the method out.
    expect(parseMethodSettings({ google: true, password: false, totp: {} }, { booleans: true })).toEqual({ google: {}, totp: {} });
    // What is stored never has them: a value from madAuth 0.3 (booleans meaning something else) is not one.
    expect(parseMethodSettings({ google: true })).toBeNull();
    expect(parseMethodSettings({ password: false })).toBeNull();
    expect(parseMethodSettings({})).toEqual({});
    for (const bad of [null, [], 'google', { sms: true }, { google: 'off' }, { google: { secondFactor: 'always' } }, { totp: { secondFactor: 'none' } }, { google: { other: 1 } }]) {
      expect(parseMethodSettings(bad)).toBeNull();
    }
  });

  it('decides what is on from the list, with none as the policy that is not set', () => {
    const configured = (method: string) => method !== 'totp' || true;
    const methods = { google: {}, password: { secondFactor: 'optional' as const } };

    expect(isOn('google', configured, methods)).toBe(true);
    expect(isOn('totp', configured, methods)).toBe(false);
    expect(isOn('password', () => false, methods)).toBe(false);
    expect(policyOf('google', methods)).toBe('none');
    expect(policyOf('password', methods)).toBe('optional');
    expect(authenticatorOn(configured, methods)).toBe(true);
    expect(authenticatorOn(configured, { google: {} })).toBe(false);
    expect(authenticatorOn(configured, { totp: {} })).toBe(true);
  });

  it('a server runs its configured methods without a second factor until an admin sets them; the app alone only on an app-only server', () => {
    expect(initialMethods({ google: {}, password: {} })).toEqual({ google: { secondFactor: 'none' }, password: { secondFactor: 'none' } });
    expect(initialMethods({ google: {} })).toEqual({ google: { secondFactor: 'none' } });
    expect(initialMethods({ emailVerification: true })).toEqual({ totp: {} });
    expect(initialMethods({ password: {}, emailVerification: true })).toEqual({ password: { secondFactor: 'none' } });
  });
});

describe('Settings', () => {
  it('keeps a JSON value per id and replaces it', async () => {
    const { store } = passwordApp();
    const settings = new Settings(store, { google: { secondFactor: 'none' } });

    expect(await settings.get('methods')).toBeUndefined();
    expect(await settings.methods()).toEqual({ google: { secondFactor: 'none' } });
    await settings.set('methods', { google: {} }, null);
    await settings.set('methods', { password: { secondFactor: 'required' } }, 'grace@example.com');

    expect(await settings.get('methods')).toEqual({ password: { secondFactor: 'required' } });
    expect(await store.findOne('setting', { id: 'methods' })).toMatchObject({ value: '{"password":{"secondFactor":"required"}}', updatedBy: 'grace@example.com' });
    expect(await settings.methods()).toEqual({ password: { secondFactor: 'required' } });
  });

  it('a value stored by an older madAuth does not count: it is warned about once, and the initial methods hold', async () => {
    const { store } = passwordApp();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await store.create('setting', { id: 'methods', value: '{"password":false}', updatedAt: 1, updatedBy: null });
    const settings = new Settings(store, { google: { secondFactor: 'none' }, password: { secondFactor: 'none' } });

    expect(await settings.methods()).toEqual({ google: { secondFactor: 'none' }, password: { secondFactor: 'none' } });
    expect(await settings.methods()).toEqual({ google: { secondFactor: 'none' }, password: { secondFactor: 'none' } });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain('set-methods');
    // The next change replaces it.
    await settings.changeMethods((current) => ({ ...current, totp: {} }), null);
    expect(await settings.methods()).toEqual({ google: { secondFactor: 'none' }, password: { secondFactor: 'none' }, totp: {} });
  });

  it('a change sees what another change wrote in between, so a guard on the written value holds', async () => {
    const { store } = passwordApp();
    const settings = new Settings(store);
    const atLeastOne = (next: Record<string, object>) => (Object.keys(next).length ? next : null);
    let first = true;
    // While the first change is being applied, another request switches password off.
    const results = await Promise.all([
      settings.changeMethods((current) => {
        if (first) {
          first = false;
          // Simulates the other write landing between this read and this write (same thread: do it inline).
          void store.create('setting', { id: 'methods', value: '{"google":{}}', updatedAt: 1, updatedBy: null });
        }
        const { google: _, ...rest } = current;
        return atLeastOne(rest);
      }, 'a@example.com'),
    ]);

    // The first attempt lost the race; the second saw { google: {} } and the guard refused.
    expect(results).toEqual([null]);
    expect(await settings.methods()).toEqual({ google: {} });
  });
});

describe('switching sign-in methods off and on', () => {
  it('an admin switches a method off: it leaves /auth/config and its routes answer method_disabled, at once', async () => {
    const { app, cookie } = await withAdmin();
    expect(await config(app)).toMatchObject({ google: { clientId: expect.any(String) }, password: { minLength: 8 } });

    // The list replaces what was on: password is not in it any more.
    const off = await settingsApi(app, cookie, 'set', { methods: { google: {} } });

    expect(off.status).toBe(200);
    expect(await off.json()).toEqual({
      methods: {
        google: { configured: true, enabled: true, secondFactor: 'none' },
        password: { configured: true, enabled: false, secondFactor: 'none' },
        totp: { configured: true, enabled: false },
      },
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

    // And on again, now asking for the authenticator app when the user has one.
    await settingsApi(app, cookie, 'set', { methods: { google: true, password: { secondFactor: 'optional' } } });
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(200);
    expect(await config(app)).toMatchObject({ password: { minLength: 8, secondFactor: 'optional' }, totp: { signIn: false, signUp: false } });
  });

  it('Google can be switched off as well, for both flows', async () => {
    const { app, cookie } = await withAdmin();

    await settingsApi(app, cookie, 'set', { methods: { password: {} } });

    expect(await config(app)).toMatchObject({ google: null, password: { minLength: 8 } });
    const nonce = await app.request('/auth/google/nonce', { method: 'POST', headers: { Origin: APP_ORIGIN } });
    expect(nonce.status).toBe(403);
    expect(await nonce.json()).toMatchObject({ error: 'method_disabled' });
    expect((await app.request(`/auth/google/start?return_to=${encodeURIComponent(APP_ORIGIN)}`)).status).toBe(403);
  });

  it('the last method can not be switched off, and a method the server is not configured for is never on', async () => {
    const { app, cookie } = await withAdmin();

    const none = await settingsApi(app, cookie, 'set', { methods: {} });
    expect(none.status).toBe(400);
    expect(await none.json()).toMatchObject({ error: 'invalid_settings', message: expect.stringContaining('At least one') });
    // The authenticator app alone keeps a server usable for those who set it up: it counts as a method.
    expect((await settingsApi(app, cookie, 'set', { methods: { totp: {} } })).status).toBe(200);
    expect(await config(app)).toMatchObject({ google: null, password: null, totp: { signIn: true, signUp: true } });

    // Only Google is configured here: password can't be switched on, and nothing else is listed by default.
    const googleOnly = passwordApp({ password: undefined, webhook: undefined });
    await settingsApi(googleOnly.app, undefined, 'get');
    expect(await config(googleOnly.app)).toEqual({
      google: { clientId: expect.any(String), codeFlow: true, secondFactor: 'none' },
      password: null,
      totp: null,
      email: { verification: false },
    });
  });

  it('is for admins only and checks its input', async () => {
    const { app, cookie, hook } = await withAdmin();
    const other = await signUpVerified(app, hook, 'ada@example.com', 'adas password!');

    expect((await settingsApi(app, undefined, 'get')).status).toBe(401);
    expect((await settingsApi(app, other, 'get')).status).toBe(403);
    expect((await settingsApi(app, other, 'set', { methods: { google: {} } })).status).toBe(403);
    const bad = await settingsApi(app, cookie, 'set', { methods: { sms: true } });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: 'invalid_settings', message: expect.stringContaining('secondFactor') });
    expect((await settingsApi(app, cookie, 'set', { methods: { totp: { secondFactor: 'required' } } })).status).toBe(400);
    expect((await settingsApi(app, cookie, 'set', {})).status).toBe(400);
  });
});
