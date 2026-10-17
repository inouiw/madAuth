// Settings admins change at runtime: which methods are on, which sign in on their own, and which ask for a second factor.
// See "Sign-in methods" in docs/server.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  Settings,
  anyOn,
  canSignUp,
  checkMethodSettings,
  factorsOn,
  initialMethods,
  isConfigured,
  isOn,
  legacyAppProblem,
  parseLegacyMethodSettings,
  parseMethodSettings,
  parsePasswordRules,
  policyOf,
  renameStoredMethods,
  signsIn,
} from './settings.js';
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

/** A method that signs in on its own, with a policy for the second factor. */
const signIn = (secondFactor: 'none' | 'optional' | 'required' = 'none') => ({ allowAsSignInMethod: true, secondFactor });
/** A method that is on only as a second factor. */
const factorOnly = { allowAsSignInMethod: false, secondFactor: 'none' } as const;
const everything = { configured: () => true, signsUp: () => true };

describe('parseMethodSettings', () => {
  it('O15: GitHub is configured by its OAuth App, on from the start, and takes a policy like Google', () => {
    expect(isConfigured({ github: {} }, 'github')).toBe(true);
    expect(isConfigured({ google: {} }, 'github')).toBe(false);
    expect(canSignUp({ github: {} }, 'github')).toBe(true);
    expect(initialMethods({ github: {} })).toEqual({ github: signIn() });
    // The app alone is the default only on a server where nothing else creates users.
    expect(initialMethods({ github: {}, emailVerification: true })).toEqual({ github: signIn() });
    expect(parseMethodSettings({ github: signIn('required') })).toEqual({ github: signIn('required') });
  });

  it('reads the methods that are on, each with both of its settings', () => {
    const methods = { google: signIn(), password: signIn('required'), authenticator: factorOnly, passkey: signIn('optional') };
    expect(parseMethodSettings(methods)).toEqual(methods);
    expect(parseMethodSettings({})).toEqual({});
    for (const bad of [
      null,
      [],
      'google',
      { google: true },
      { google: {} },
      { google: { secondFactor: 'none' } },
      { google: { allowAsSignInMethod: true } },
      { google: { allowAsSignInMethod: 'yes', secondFactor: 'none' } },
      { google: { allowAsSignInMethod: true, secondFactor: 'always' } },
      { google: { ...signIn(), other: 1 } },
      { fax: signIn() },
    ]) {
      expect(parseMethodSettings(bad)).toBeNull();
    }
  });

  it('reads what madAuth before 0.6 stored, as it was meant: the app is a second factor wherever a policy asks for one, and never more', () => {
    expect(parseLegacyMethodSettings({ google: {}, password: { secondFactor: 'required' }, sms: {} })).toEqual({
      google: signIn(),
      password: signIn('required'),
      sms: factorOnly,
      authenticator: factorOnly,
    });
    // Listed, the app signed in on its own for the users who signed up with it, which has no meaning now: it
    // counts as a second factor only until an admin chooses, and the operator is told how.
    expect(parseLegacyMethodSettings({ google: {}, authenticator: {} })).toEqual({ google: signIn(), authenticator: factorOnly });
    // The stored value names the app `totp`, its id before 0.6; the message names it as it is now.
    expect(legacyAppProblem({ google: {}, password: { secondFactor: 'required' }, totp: {} })).toContain('Madauth.admin.setSettings: authenticator with allowAsSignInMethod false');
    expect(legacyAppProblem({ google: {}, password: { secondFactor: 'required' } })).toBeNull();
    // On an app-only server, the app keeps signing in, or nobody could: there is nothing to choose.
    expect(parseLegacyMethodSettings({ authenticator: {}, sms: {} })).toEqual({ authenticator: signIn(), sms: factorOnly });
    expect(legacyAppProblem({ totp: {}, sms: {} })).toBeNull();
    expect(legacyAppProblem({ totp: signIn() })).toBeNull();
    expect(legacyAppProblem(undefined)).toBeNull();
    for (const bad of [{ google: true }, { authenticator: { secondFactor: 'required' } }, { passkey: {} }, { google: signIn() }]) {
      expect(parseLegacyMethodSettings(bad)).toBeNull();
    }
  });

  it('decides what is on and what signs in from the list, with none as the policy that is not set', () => {
    const configured = () => true;
    const methods = { google: signIn(), password: signIn('optional'), authenticator: factorOnly };

    expect(isOn('google', configured, methods)).toBe(true);
    expect(isOn('authenticator', configured, methods)).toBe(true);
    expect(signsIn('authenticator', configured, methods)).toBe(false);
    expect(isOn('passkey', configured, methods)).toBe(false);
    expect(isOn('password', () => false, methods)).toBe(false);
    expect(policyOf('google', methods)).toBe('none');
    expect(policyOf('password', methods)).toBe('optional');
    expect(factorsOn(configured, { ...methods, passkey: signIn(), sms: factorOnly })).toEqual(['passkey', 'authenticator', 'sms']);
    // A passkey is no second factor of a passkey sign-in.
    expect(factorsOn(configured, { passkey: signIn(), sms: factorOnly }, 'passkey')).toEqual(['sms']);
  });

  it('checks what the settings mean together', () => {
    expect(checkMethodSettings({ google: signIn(), password: signIn('required'), authenticator: factorOnly }, everything)).toBeNull();
    expect(checkMethodSettings({ google: factorOnly }, everything)).toContain('always signs in');
    expect(checkMethodSettings({ google: signIn(), sms: signIn() }, everything)).toContain('only a second factor');
    expect(checkMethodSettings({ google: signIn(), passkey: { allowAsSignInMethod: false, secondFactor: 'required' } }, everything)).toContain('asks for no second factor');
    expect(checkMethodSettings({ google: signIn(), authenticator: signIn('required'), sms: factorOnly }, everything)).toContain('second factor itself');
    // A policy needs a second factor that is on, other than the method itself.
    expect(checkMethodSettings({ password: signIn('optional') }, everything)).toContain('none is on');
    expect(checkMethodSettings({ password: signIn(), passkey: signIn('required') }, everything)).toContain('none is on');
    expect(checkMethodSettings({ password: signIn(), passkey: signIn('required'), authenticator: factorOnly }, everything)).toBeNull();
    // SMS can't be the second factor on a server that doesn't send SMS.
    expect(checkMethodSettings({ password: signIn('optional'), sms: factorOnly }, { ...everything, configured: (m) => m !== 'sms' })).toContain('none is on');
    expect(checkMethodSettings({ passkey: signIn() }, { ...everything, signsUp: (m) => m !== 'passkey' })).toContain('At least one');
  });

  it('a server runs its configured methods without a second factor until an admin sets them; the app alone only on an app-only server', () => {
    expect(initialMethods({ google: {}, password: {} })).toEqual({ google: signIn(), password: signIn() });
    expect(initialMethods({ google: {} })).toEqual({ google: signIn() });
    expect(initialMethods({ emailVerification: true })).toEqual({ authenticator: signIn() });
    expect(initialMethods({ password: {}, emailVerification: true })).toEqual({ password: signIn() });
    expect(initialMethods({ password: {}, sms: true })).toEqual({ password: signIn(), sms: factorOnly });
  });
});

describe('Settings', () => {
  it('keeps a JSON value per id and replaces it', async () => {
    const { store } = passwordApp();
    const settings = new Settings(store);
    const initial = { google: signIn() };

    expect(await settings.get('methods')).toBeUndefined();
    expect(await settings.methods(initial)).toEqual({ google: signIn() });
    await settings.set('methods', { google: signIn() }, null);
    await settings.set('methods', { password: signIn('required') }, 'grace@example.com');

    expect(await settings.get('methods')).toEqual({ password: signIn('required') });
    expect(await store.findOne('setting', { id: 'methods' })).toMatchObject({
      value: '{"password":{"allowAsSignInMethod":true,"secondFactor":"required"}}',
      updatedBy: 'grace@example.com',
    });
    expect(await settings.methods()).toEqual({ password: signIn('required') });
  });

  it('a list from before 0.6 with the app on its own makes the app a second factor only, and is warned about once', async () => {
    const { store } = passwordApp();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await store.create('setting', { id: 'methods', value: '{"password":{"secondFactor":"optional"},"totp":{}}', updatedAt: 1, updatedBy: null });
    const settings = new Settings(store);

    expect(await settings.methods()).toEqual({ password: signIn('optional'), authenticator: factorOnly });
    expect(await settings.methods()).toEqual({ password: signIn('optional'), authenticator: factorOnly });
    expect(warn).toHaveBeenCalledOnce();
    expect(String(warn.mock.calls[0][0])).toContain('Until an admin chooses, it is a second factor only');
  });

  it('with a list from before 0.6 with the app on its own, an admin chooses while the server runs', async () => {
    const { app, store, cookie } = await withAdmin();
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    await new Settings(store).set('methods', { google: {}, password: { secondFactor: 'optional' }, totp: {} }, null);

    // Until then the app is a second factor only.
    expect(await config(app)).toMatchObject({ password: { secondFactor: 'optional' }, authenticator: { signIn: false } });
    const chosen = await settingsApi(app, cookie, 'set', { methods: { google: signIn(), password: signIn('optional'), authenticator: signIn() } });

    expect(chosen.status).toBe(200);
    expect(await config(app)).toMatchObject({ authenticator: { signIn: true } });
    expect(legacyAppProblem(await new Settings(store).get('methods'))).toBeNull();
  });

  it('a value stored by madAuth before 0.6 keeps its meaning after the upgrade', async () => {
    const { store } = passwordApp();
    await store.create('setting', { id: 'methods', value: '{"google":{},"password":{"secondFactor":"optional"}}', updatedAt: 1, updatedBy: null });
    const settings = new Settings(store);

    expect(await settings.methods({ google: signIn() })).toEqual({ google: signIn(), password: signIn('optional'), authenticator: factorOnly });
  });

  it('a list saved with the app as totp, its id before 0.6, is read with authenticator in its place; a change saves authenticator', async () => {
    const { store } = passwordApp();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const saved = '{"password":{"allowAsSignInMethod":true,"secondFactor":"optional"},"totp":{"allowAsSignInMethod":false,"secondFactor":"none"},"sms":{"allowAsSignInMethod":false,"secondFactor":"none"}}';
    await store.create('setting', { id: 'methods', value: saved, updatedAt: 1, updatedBy: null });
    const settings = new Settings(store);

    expect(await settings.methods()).toEqual({ password: signIn('optional'), authenticator: factorOnly, sms: factorOnly });
    expect(Object.keys(await settings.methods())).toEqual(['password', 'authenticator', 'sms']);
    expect(legacyAppProblem(JSON.parse(saved))).toBeNull();
    expect(warn).not.toHaveBeenCalled();
    await settings.changeMethods((current) => ({ ...current, password: signIn('required') }), null);
    expect(JSON.parse(String((await store.findOne('setting', { id: 'methods' }))?.value))).toEqual({
      password: signIn('required'),
      authenticator: factorOnly,
      sms: factorOnly,
    });
    // Only what is stored: totp is no method id an admin can set.
    expect(parseMethodSettings({ totp: factorOnly })).toBeNull();
    // A list with both, which no madAuth writes, keeps the setting of authenticator.
    expect(renameStoredMethods({ totp: signIn(), authenticator: factorOnly, sms: factorOnly })).toEqual({ authenticator: factorOnly, sms: factorOnly });
  });

  it('a value nobody can read does not count: it is warned about once, and the initial methods hold', async () => {
    const { store } = passwordApp();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await store.create('setting', { id: 'methods', value: '{"password":false}', updatedAt: 1, updatedBy: null });
    const settings = new Settings(store);
    const initial = { google: signIn(), password: signIn() };

    expect(await settings.methods(initial)).toEqual({ google: signIn(), password: signIn() });
    expect(await settings.methods(initial)).toEqual({ google: signIn(), password: signIn() });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain('Madauth.admin.setSettings');
    // The next change replaces it.
    await settings.changeMethods((current) => ({ ...current, authenticator: signIn() }), null, initial);
    expect(await settings.methods()).toEqual({ google: signIn(), password: signIn(), authenticator: signIn() });
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
          void store.create('setting', { id: 'methods', value: JSON.stringify({ google: signIn() }), updatedAt: 1, updatedBy: null });
        }
        const { google: _, ...rest } = current;
        return atLeastOne(rest);
      }, 'a@example.com'),
    ]);

    // The first attempt lost the race; the second saw only Google and the guard refused.
    expect(results).toEqual([null]);
    expect(await settings.methods()).toEqual({ google: signIn() });
  });
});

describe('switching sign-in methods off and on', () => {
  it('an admin switches a method off: it leaves /auth/config and its routes answer method_disabled, at once', async () => {
    const { app, cookie } = await withAdmin();
    expect(await config(app)).toMatchObject({ google: { clientId: expect.any(String) }, password: { minLength: 8, minScore: 2 } });

    // The list replaces what was on: password is not in it any more.
    const off = await settingsApi(app, cookie, 'set', { methods: { google: signIn() } });

    expect(off.status).toBe(200);
    expect(await off.json()).toEqual({
      password: { minLength: 8, minScore: 2 },
      methods: {
        google: { configured: true, enabled: true, allowAsSignInMethod: true, secondFactor: 'none' },
        github: { configured: false, enabled: false, allowAsSignInMethod: false, secondFactor: 'none' },
        password: { configured: true, enabled: false, allowAsSignInMethod: false, secondFactor: 'none' },
        authenticator: { configured: true, enabled: false, allowAsSignInMethod: false, secondFactor: 'none' },
        'email-link': { configured: true, enabled: false, allowAsSignInMethod: false, secondFactor: 'none' },
        passkey: { configured: true, enabled: false, allowAsSignInMethod: false, secondFactor: 'none' },
        sms: { configured: true, enabled: false, allowAsSignInMethod: false, secondFactor: 'none' },
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
    await settingsApi(app, cookie, 'set', { methods: { google: signIn(), password: signIn('optional'), authenticator: factorOnly } });
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(200);
    expect(await config(app)).toMatchObject({ password: { minLength: 8, secondFactor: 'optional' }, authenticator: { signIn: false, signUp: false } });
  });

  it('Google can be switched off as well, for both flows', async () => {
    const { app, cookie } = await withAdmin();

    await settingsApi(app, cookie, 'set', { methods: { password: signIn() } });

    expect(await config(app)).toMatchObject({ google: null, password: { minLength: 8 } });
    const nonce = await app.request('/auth/providers/google/nonce', { method: 'POST', headers: { Origin: APP_ORIGIN } });
    expect(nonce.status).toBe(403);
    expect(await nonce.json()).toMatchObject({ error: 'method_disabled' });
    // The redirect flow's start sends the browser back to the app: it is on its way, and a JSON error would strand it.
    const start = await app.request(`/auth/providers/google/start?return_to=${encodeURIComponent(APP_ORIGIN)}`);
    expect(start.status).toBe(302);
    expect(start.headers.get('location')).toBe(`${APP_ORIGIN}/#madauth_error=method_disabled&madauth_method=google`);
  });

  it('the last method can not be switched off, and a method the server is not configured for is never on', async () => {
    const { app, cookie } = await withAdmin();

    const none = await settingsApi(app, cookie, 'set', { methods: {} });
    expect(none.status).toBe(400);
    expect(await none.json()).toMatchObject({ error: 'invalid_settings', message: expect.stringContaining('At least one') });
    // The authenticator app alone keeps a server usable for those who set it up: it counts as a method.
    expect((await settingsApi(app, cookie, 'set', { methods: { authenticator: signIn() } })).status).toBe(200);
    expect(await config(app)).toMatchObject({ google: null, password: null, authenticator: { signIn: true, signUp: true } });

    // Only Google is configured here: password can't be switched on, and nothing else is listed by default.
    const googleOnly = passwordApp({ password: undefined, webhook: undefined });
    await settingsApi(googleOnly.app, undefined, 'get');
    expect(await config(googleOnly.app)).toEqual({
      google: { clientId: expect.any(String), codeFlow: true, secondFactor: 'none' },
      github: null,
      password: null,
      authenticator: null,
      email: { verification: false },
      emailLink: null,
      sms: false,
      passkey: null,
      providers: [{ id: 'google', kind: 'google', name: 'Google' }],
    });
  });

  it('keeps a method on that creates users: the app or passkeys alone count only with sign-up by e-mail', () => {
    const googleOnly = { google: {}, emailVerification: false };
    expect(anyOn((m) => canSignUp(googleOnly, m), { authenticator: signIn() })).toBe(false);
    expect(anyOn((m) => canSignUp(googleOnly, m), { google: signIn(), authenticator: signIn() })).toBe(true);
    const emails = { password: {}, emailVerification: true };
    expect(anyOn((m) => canSignUp(emails, m), { authenticator: signIn() })).toBe(true);
    // Only as a second factor, the app lets nobody in.
    expect(anyOn((m) => canSignUp(emails, m), { authenticator: factorOnly })).toBe(false);
    expect(anyOn((m) => canSignUp(emails, m), { google: signIn() })).toBe(false);
    // Passkeys alike: people sign up with one alone only where the address is confirmed by e-mail first.
    expect(anyOn((m) => canSignUp(emails, m), { passkey: signIn() })).toBe(true);
    expect(anyOn((m) => canSignUp(emails, m), { passkey: factorOnly })).toBe(false);
    expect(anyOn((m) => canSignUp(googleOnly, m), { passkey: signIn() })).toBe(false);
  });

  it('is for admins only and checks its input', async () => {
    const { app, cookie, hook } = await withAdmin();
    const other = await signUpVerified(app, hook, 'ada@example.com', 'adas password!');

    expect((await settingsApi(app, undefined, 'get')).status).toBe(401);
    expect((await settingsApi(app, other, 'get')).status).toBe(403);
    expect((await settingsApi(app, other, 'set', { methods: { google: signIn() } })).status).toBe(403);
    const bad = await settingsApi(app, cookie, 'set', { methods: { fax: signIn() } });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: 'invalid_settings', message: expect.stringContaining('allowAsSignInMethod') });
    // Both settings are always given: the shorthand of madAuth before 0.6 is not taken.
    expect((await settingsApi(app, cookie, 'set', { methods: { google: {} } })).status).toBe(400);
    expect((await settingsApi(app, cookie, 'set', { methods: { google: true } })).status).toBe(400);
    expect((await settingsApi(app, cookie, 'set', { methods: { google: signIn(), authenticator: signIn('required') } })).status).toBe(400);
    // The app is `authenticator`: its id before 0.6 is no alias.
    expect(await (await settingsApi(app, cookie, 'set', { methods: { google: signIn(), totp: factorOnly } })).json()).toMatchObject({ error: 'invalid_settings' });
    // SMS codes take no policy, and sign nobody in alone.
    expect((await settingsApi(app, cookie, 'set', { methods: { google: signIn(), sms: { allowAsSignInMethod: false, secondFactor: 'required' } } })).status).toBe(400);
    expect((await settingsApi(app, cookie, 'set', { methods: { google: signIn(), sms: signIn() } })).status).toBe(400);
    expect(await (await settingsApi(app, cookie, 'set', { methods: { sms: factorOnly } })).json()).toMatchObject({ error: 'invalid_settings', message: expect.stringContaining('At least one') });
    expect((await settingsApi(app, cookie, 'set', {})).status).toBe(400);
  });
});

describe('password rules', () => {
  it('parsePasswordRules takes minLength and minScore, each with its default', () => {
    expect(parsePasswordRules({})).toEqual({ minLength: 8, minScore: 2 });
    expect(parsePasswordRules({ minLength: 12, minScore: 0 })).toEqual({ minLength: 12, minScore: 0 });
    for (const bad of [null, [], 8, { minLength: 0 }, { minLength: 129 }, { minLength: 8.5 }, { minScore: 5 }, { minScore: '3' }, { require: ['digit'] }]) {
      expect(parsePasswordRules(bad)).toBeNull();
    }
  });

  it('are at least 8 characters and score 2 until set; an unusable stored value is warned about and the defaults hold', async () => {
    const { store } = passwordApp();
    const settings = new Settings(store);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

    expect(await settings.passwordRules()).toEqual({ minLength: 8, minScore: 2 });
    await settings.set('password', { minLength: 'long' }, null);
    expect(await settings.passwordRules()).toEqual({ minLength: 8, minScore: 2 });
    expect(warn).toHaveBeenCalledOnce();
  });

  it('an admin sets them: /auth/config shows them, and sign-up and reset follow them at once', async () => {
    const { app, cookie } = await withAdmin();

    const res = await settingsApi(app, cookie, 'set', { password: { minLength: 12, minScore: 3 } });

    expect(await res.json()).toMatchObject({ password: { minLength: 12, minScore: 3 }, methods: { password: { enabled: true } } });
    expect(await (await settingsApi(app, cookie, 'get')).json()).toMatchObject({ password: { minLength: 12, minScore: 3 } });
    expect(await config(app)).toMatchObject({ password: { minLength: 12, minScore: 3, secondFactor: 'none' } });
    const signUp = (password: string) => post(app, '/auth/password/signup', { email: 'new@example.com', password, redirectTo: `${APP_ORIGIN}/` });
    expect(await (await signUp('long enough')).json()).toMatchObject({ error: 'weak_password', minLength: 12 });
    // Long enough, but a common word with digits.
    expect(await (await signUp('password1234')).json()).toMatchObject({ error: 'weak_password', minScore: 3 });
    expect((await signUp('correct horse battery')).status).toBe(202);
  });

  it('the admin API checks them before it writes anything', async () => {
    const { app, cookie } = await withAdmin();

    const bad = await settingsApi(app, cookie, 'set', { methods: { google: signIn() }, password: { minScore: 9 } });

    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: 'invalid_settings', message: expect.stringContaining('minScore') });
    // The methods were not changed either.
    expect(await config(app)).toMatchObject({ password: { minLength: 8 } });
  });

  it('a failed write of the methods undoes the password rules, so a failed request changes nothing', async () => {
    const { app, cookie } = await withAdmin();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(Settings.prototype, 'changeMethods').mockRejectedValueOnce(new Error('throttled'));

    const res = await settingsApi(app, cookie, 'set', { methods: { google: signIn() }, password: { minLength: 12 } });

    expect(res.status).toBe(500);
    expect(await (await settingsApi(app, cookie, 'get')).json()).toMatchObject({
      password: { minLength: 8, minScore: 2 },
      methods: { password: { enabled: true } },
    });
  });
});
