import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { Password } from '../providers/password.js';
import { Totp } from '../providers/totp.js';
import { CODE, RECOVERY_CODES, SERVER, TOTP_SECRET, VERIFY_TOKEN, fakeServer, grace, resetAll, settle } from '../test-helpers.js';

let warnLog: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  warnLog = vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(resetAll);

const init = (options: Partial<Parameters<typeof Madauth.initialize>[0]> = {}) =>
  Madauth.initialize({ serverUrl: SERVER, providers: [new Password(), new Totp()], ...options });

const credentials = { email: 'grace@example.com', password: 'correct horse battery' };

describe('Madauth.totp', () => {
  it('H13: signIn signs in with the e-mail address and a code from the app, or a recovery code once', async () => {
    const server = fakeServer();
    server.methods.totp = true;
    server.authenticators.add('grace@example.com');
    server.recoveryCodes.set('grace@example.com', [...RECOVERY_CODES]);
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    await init();

    const result = await Madauth.totp.signIn({ email: 'grace@example.com', code: CODE });

    expect(result).toEqual({ isSuccess: true, user: grace });
    expect(listener).toHaveBeenLastCalledWith(grace);
    expect(Madauth.currentUser).toEqual(grace);
    expect(server.requests.at(-1)).toMatchObject({
      method: 'POST',
      url: `${SERVER}/auth/totp/signin`,
      credentials: 'include',
      body: { email: 'grace@example.com', code: CODE },
    });
    expect(await Madauth.totp.signIn({ email: 'grace@example.com', code: '000000' })).toMatchObject({ isSuccess: false, error: { code: 'invalid_credentials' } });
    expect(await Madauth.totp.signIn({ email: 'nobody@example.com', code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'invalid_credentials' } });
    expect(await Madauth.totp.signIn({ email: 'grace@example.com', recoveryCode: RECOVERY_CODES[0] })).toEqual({ isSuccess: true, user: grace });
    expect(await Madauth.totp.signIn({ email: 'grace@example.com', recoveryCode: RECOVERY_CODES[0] })).toMatchObject({ isSuccess: false, error: { code: 'invalid_credentials' } });
    server.locked = true;
    expect(await Madauth.totp.signIn({ email: 'grace@example.com', code: CODE })).toMatchObject({
      isSuccess: false,
      error: { code: 'too_many_attempts', message: 'Too many failed attempts. Try again in 30 seconds.' },
    });
    // Switched off meanwhile.
    server.locked = false;
    server.methods.totp = false;
    expect(await Madauth.totp.signIn({ email: 'grace@example.com', code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'method_disabled' } });
  });

  it('H14: fails clearly without the Totp provider, without asking the server', async () => {
    const server = fakeServer();
    server.methods.totp = true;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    const before = server.requests.length;

    const results = await Promise.all([
      Madauth.totp.signIn({ email: 'grace@example.com', code: CODE }),
      Madauth.totp.verify({ code: CODE }),
      Madauth.totp.startSetup(),
      Madauth.totp.confirmSetup({ code: CODE }),
      Madauth.totp.remove({ code: CODE }),
      Madauth.totp.newRecoveryCodes({ code: CODE }),
      Madauth.totp.status(),
      Madauth.totp.signUp({ email: 'x@example.com' }),
      Madauth.setUpAuthenticator(),
    ]);

    for (const result of results) {
      expect(result).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled', message: expect.stringContaining('new Totp()') } });
    }
    expect(server.requests.length).toBe(before);
    expect(Madauth.totp.pendingStep).toBeNull();
    expect(Madauth.totp.policy).toBeNull();
  });

  it('H15: the provider is left out when the server has the app switched off', async () => {
    fakeServer();

    const result = await init();

    expect(result).toEqual({ isSuccess: true, leftOut: ['totp'] });
    expect(warnLog).toHaveBeenCalledWith('[madauth]', 'flow_not_enabled', expect.stringContaining('switched off'));
    expect(await Madauth.totp.status()).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
    expect(await Madauth.password.signIn(credentials)).toEqual({ isSuccess: true, user: grace });

    const alone = await Madauth.initialize({ serverUrl: SERVER, providers: [new Totp()] });
    expect(alone).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' }, leftOut: ['totp'] });
  });

  it('H16: the signed-in user sets the app up, renews the recovery codes and removes it, each with a code', async () => {
    const server = fakeServer();
    server.policy.password = 'optional';
    server.user = grace;
    await init();
    expect(Madauth.totp.policy).toEqual({ signIn: false, signUp: false, secondFactorFor: ['password'] });
    expect(await Madauth.totp.status()).toEqual({ isSuccess: true, enabled: false, recoveryCodesLeft: 0 });

    const setup = await Madauth.totp.startSetup();

    expect(setup).toMatchObject({ isSuccess: true, secret: TOTP_SECRET, uri: expect.stringContaining(`secret=${TOTP_SECRET}`) });
    expect((setup as { qrSvg: string }).qrSvg).toMatch(/^<svg [^>]*><path d="M[^"]+" fill="currentColor"\/><\/svg>$/);
    expect(server.requests.at(-1)).toMatchObject({ method: 'POST', url: `${SERVER}/auth/totp/setup`, body: {} });
    expect(await Madauth.totp.confirmSetup({ code: CODE })).toEqual({ isSuccess: true, recoveryCodes: RECOVERY_CODES });
    expect(await Madauth.totp.status()).toEqual({ isSuccess: true, enabled: true, recoveryCodesLeft: 10 });
    expect(server.requests.at(-1)).toMatchObject({ method: 'GET', url: `${SERVER}/auth/totp/status`, credentials: 'include' });

    const renewed = await Madauth.totp.newRecoveryCodes({ recoveryCode: RECOVERY_CODES[0] });
    expect(renewed).toMatchObject({ isSuccess: true, recoveryCodes: expect.arrayContaining([expect.stringMatching(/^[a-z0-9-]{11}$/)]) });
    expect((renewed as { recoveryCodes: string[] }).recoveryCodes).toHaveLength(10);
    expect(await Madauth.totp.status()).toEqual({ isSuccess: true, enabled: true, recoveryCodesLeft: 10 });

    expect(await Madauth.totp.remove({ code: CODE })).toEqual({ isSuccess: true });
    expect(await Madauth.totp.status()).toEqual({ isSuccess: true, enabled: false, recoveryCodesLeft: 0 });
    expect(await Madauth.totp.newRecoveryCodes({ code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'no_authenticator' } });
  });

  it('H17: the setup and the removal are refused with a wrong code, an expired setup, or a policy that requires the app', async () => {
    const server = fakeServer();
    server.policy.password = 'optional';
    server.user = grace;
    await init();

    expect(await Madauth.totp.confirmSetup({ code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'setup_expired' } });
    await Madauth.totp.startSetup();
    expect(await Madauth.totp.confirmSetup({ code: '000000' })).toMatchObject({ isSuccess: false, error: { code: 'code_invalid' } });
    server.totpSetup = undefined;
    expect(await Madauth.totp.confirmSetup({ code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'setup_expired' } });
    await Madauth.totp.startSetup();
    expect(await Madauth.totp.confirmSetup({ code: CODE })).toMatchObject({ isSuccess: true });

    expect(await Madauth.totp.remove({ code: '000000' })).toMatchObject({ isSuccess: false, error: { code: 'code_invalid' } });
    server.policy.password = 'required';
    expect(await Madauth.totp.remove({ code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'required_by_policy' } });
  });

  it('H18: the signed-in calls fail with no_session when nobody is signed in', async () => {
    const server = fakeServer();
    server.policy.password = 'optional';
    server.methods.totp = true;
    await init();

    for (const call of [
      () => Madauth.totp.startSetup(),
      () => Madauth.totp.confirmSetup({ code: CODE }),
      () => Madauth.totp.remove({ code: CODE }),
      () => Madauth.totp.newRecoveryCodes({ code: CODE }),
      () => Madauth.totp.status(),
    ]) {
      expect(await call()).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
    }
    // Not a session matter: a wrong code at sign-in stays what it is.
    expect(await Madauth.totp.signIn({ email: 'grace@example.com', code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'invalid_credentials' } });
  });

  it('H19: a password sign-in goes on with the app: verify finishes it, and pendingStep says so meanwhile', async () => {
    const server = fakeServer();
    server.policy.password = 'optional';
    server.authenticators.add('grace@example.com');
    server.recoveryCodes.set('grace@example.com', [...RECOVERY_CODES]);
    const listener = vi.fn();
    await init();
    Madauth.onAuthStateChanged(listener);
    await settle();
    listener.mockClear();

    const first = await Madauth.password.signIn(credentials);

    expect(first).toMatchObject({ isSuccess: false, error: { code: 'totp_required', method: 'password' } });
    expect(Madauth.totp.pendingStep).toEqual({ step: 'code', method: 'password' });
    expect(listener).not.toHaveBeenCalled();
    expect(Madauth.currentUser).toBeNull();

    expect(await Madauth.totp.verify({ code: '000000' })).toMatchObject({ isSuccess: false, error: { code: 'code_invalid' } });
    expect(Madauth.totp.pendingStep).toEqual({ step: 'code', method: 'password' });
    const second = await Madauth.totp.verify({ recoveryCode: RECOVERY_CODES[1] });
    expect(second).toEqual({ isSuccess: true, user: grace });
    expect(listener).toHaveBeenLastCalledWith(grace);
    expect(Madauth.totp.pendingStep).toBeNull();
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/totp/verify`, body: { recoveryCode: RECOVERY_CODES[1] } });

    // Too late: the sign-in starts over.
    await Madauth.signOut();
    await Madauth.password.signIn(credentials);
    server.challenge = undefined;
    expect(await Madauth.totp.verify({ code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'challenge_expired' } });
  });

  it('H20: a required policy makes the sign-in set the app up first, which then signs the user in', async () => {
    const server = fakeServer();
    server.policy.password = 'required';
    await init();

    const first = await Madauth.password.signIn(credentials);

    expect(first).toMatchObject({ isSuccess: false, error: { code: 'totp_setup_required', method: 'password' } });
    expect(Madauth.totp.pendingStep).toEqual({ step: 'setup', method: 'password' });
    expect(await Madauth.totp.startSetup()).toMatchObject({ isSuccess: true, secret: TOTP_SECRET });
    const done = await Madauth.totp.confirmSetup({ code: CODE });
    expect(done).toEqual({ isSuccess: true, recoveryCodes: RECOVERY_CODES, user: grace });
    expect(Madauth.currentUser).toEqual(grace);
    expect(Madauth.totp.pendingStep).toBeNull();
    // From now on the password asks for the code.
    await Madauth.signOut();
    expect(await Madauth.password.signIn(credentials)).toMatchObject({ isSuccess: false, error: { code: 'totp_required' } });
  });

  it('H21: signUp creates an account with the app alone; confirming the address leads to the setup', async () => {
    const server = fakeServer();
    server.methods.totp = true;
    await init();

    expect(await Madauth.totp.signUp({ email: 'new@example.com', name: 'New User' })).toEqual({ isSuccess: true });
    expect(server.requests.at(-1)).toMatchObject({
      url: `${SERVER}/auth/totp/signup`,
      body: { email: 'new@example.com', name: 'New User', redirectTo: 'https://app.example.com/page' },
    });
    expect(server.mails.at(-1)).toMatchObject({ purpose: 'verify', to: 'new@example.com' });
    expect(await Madauth.totp.sendVerificationEmail({ email: 'new@example.com' })).toEqual({ isSuccess: true });
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/email/send-verification` });

    expect(await Madauth.totp.verifyEmail({ email: 'new@example.com', code: CODE })).toMatchObject({
      isSuccess: false,
      error: { code: 'totp_setup_required', method: 'totp' },
    });
    expect(Madauth.totp.pendingStep).toEqual({ step: 'setup', method: 'totp' });
    await Madauth.totp.startSetup();
    expect(await Madauth.totp.confirmSetup({ code: CODE })).toEqual({
      isSuccess: true,
      recoveryCodes: RECOVERY_CODES,
      user: { id: 'usr_new', email: 'new@example.com', name: 'New User' },
    });
    expect(Madauth.currentUser?.email).toBe('new@example.com');

    // Without the app on its own there is no sign-up with it.
    server.methods.totp = false;
    server.policy.password = 'optional';
    expect(await Madauth.totp.signUp({ email: 'other@example.com' })).toMatchObject({ isSuccess: false, error: { code: 'method_disabled' } });
  });

  it('H22: the link in the confirmation e-mail of a sign-up with the app leads to the setup when the page opens', async () => {
    const server = fakeServer();
    server.methods.totp = true;
    server.accounts.set('new@example.com', { password: '', verified: false, name: 'New User', app: true });
    server.mails.push({ purpose: 'verify', to: 'new@example.com', redirectTo: 'https://app.example.com/page' });
    history.replaceState(null, '', `/page?x=1#other=1&madauth_verify=${VERIFY_TOKEN}`);

    const result = await init({ ui: 'custom' });

    expect(result).toEqual({ isSuccess: true, leftOut: [] });
    expect(location.href).toBe('https://app.example.com/page?x=1#other=1');
    expect(Madauth.totp.pendingStep).toEqual({ step: 'setup', method: 'totp' });
    expect(Madauth.currentUser).toBeNull();
    expect(await Madauth.totp.startSetup()).toMatchObject({ isSuccess: true });
    expect(await Madauth.totp.confirmSetup({ code: CODE })).toMatchObject({ isSuccess: true, user: { email: 'new@example.com' } });
  });

  it('H23: deleting the account takes a code once the app is set up', async () => {
    const server = fakeServer();
    server.policy.password = 'optional';
    server.user = grace;
    server.authenticators.add('grace@example.com');
    await init();

    expect(await Madauth.deleteAccount()).toMatchObject({ isSuccess: false, error: { code: 'code_required' } });
    expect(Madauth.currentUser).toEqual(grace);
    expect(await Madauth.deleteAccount({ code: '000000' })).toMatchObject({ isSuccess: false, error: { code: 'code_invalid' } });
    expect(await Madauth.deleteAccount({ code: CODE })).toEqual({ isSuccess: true });
    expect(Madauth.currentUser).toBeNull();
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/account/delete`, body: { code: CODE } });
  });

  it('H24: waits for initialize, and reports when madAuth is not set up', async () => {
    expect(await Madauth.totp.status()).toMatchObject({ isSuccess: false, error: { code: 'not_initialized' } });
    expect(await Madauth.setUpAuthenticator()).toMatchObject({ isSuccess: false, error: { code: 'not_initialized' } });
  });
});
