import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { Password } from '../providers/password.js';
import { Totp } from '../providers/totp.js';
import { CODE, MASKED_PHONE, PHONE, SERVER, fakeServer, grace, resetAll } from '../test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(resetAll);

const init = (options: Partial<Parameters<typeof Madauth.initialize>[0]> = {}) =>
  Madauth.initialize({ serverUrl: SERVER, providers: [new Password(), new Totp()], ...options });

const credentials = { email: 'grace@example.com', password: 'correct horse battery' };

/** A server with SMS codes on, and Grace signed in. */
function smsServer() {
  const server = fakeServer();
  server.methods.sms = true;
  server.policy.password = 'optional';
  server.user = grace;
  return server;
}

describe('Madauth.sms', () => {
  it('H33: setUp sends a code to the number and confirmSetup stores it; status says so', async () => {
    const server = smsServer();
    await init();

    expect(await Madauth.sms.status()).toEqual({ isSuccess: true, enabled: false, phone: null });
    expect(await Madauth.sms.setUp({ phone: 'nope' })).toMatchObject({ isSuccess: false, error: { code: 'invalid_phone' } });
    server.smsTooSoon = true;
    expect(await Madauth.sms.setUp({ phone: PHONE })).toMatchObject({ isSuccess: false, error: { code: 'too_soon' } });
    server.smsTooSoon = false;
    const setUp = await Madauth.sms.setUp({ phone: PHONE });

    expect(setUp).toEqual({ isSuccess: true, phone: MASKED_PHONE });
    expect(server.requests.at(-1)).toMatchObject({ method: 'POST', url: `${SERVER}/auth/sms/setup`, credentials: 'include', body: { phone: PHONE, locale: expect.any(String) } });
    expect(server.texts).toEqual([{ to: '+41791234567', purpose: 'setup' }]);
    expect(await Madauth.sms.confirmSetup({ code: '000000' })).toMatchObject({ isSuccess: false, error: { code: 'code_invalid' } });
    expect(await Madauth.sms.confirmSetup({ code: CODE })).toEqual({ isSuccess: true });
    expect(await Madauth.sms.status()).toEqual({ isSuccess: true, enabled: true, phone: MASKED_PHONE });
    server.smsSetup = undefined;
    expect(await Madauth.sms.confirmSetup({ code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'setup_expired' } });
  });

  it('H34: replacing the number takes a code sent to the current one; removing it too', async () => {
    const server = smsServer();
    server.phones.set(grace.email!, '+41791234567');
    await init();

    expect(await Madauth.sms.setUp({ phone: '+41790000099' })).toMatchObject({ isSuccess: false, error: { code: 'code_required' } });
    expect(await Madauth.sms.send()).toEqual({ isSuccess: true, phone: MASKED_PHONE });
    expect(server.texts.at(-1)).toEqual({ to: '+41791234567', purpose: 'approve' });
    expect(await Madauth.sms.setUp({ phone: '+41790000099', code: CODE })).toEqual({ isSuccess: true, phone: '+41 ••••••• 99' });
    expect(await Madauth.sms.confirmSetup({ code: CODE })).toEqual({ isSuccess: true });
    expect(await Madauth.sms.status()).toEqual({ isSuccess: true, enabled: true, phone: '+41 ••••••• 99' });

    expect(await Madauth.sms.remove({ code: '000000' })).toMatchObject({ isSuccess: false, error: { code: 'code_invalid' } });
    expect(await Madauth.sms.remove({ code: CODE })).toEqual({ isSuccess: true });
    expect(await Madauth.sms.remove({ code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'no_phone' } });
    server.policy.password = 'required';
    server.phones.set(grace.email!, '+41791234567');
    expect(await Madauth.sms.remove({ code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'required_by_policy' } });
    server.user = null;
    expect(await Madauth.sms.status()).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
    expect(await Madauth.sms.send()).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
  });

  it('H35: a password sign-in with only a phone goes on with the SMS: send, then verify', async () => {
    const server = smsServer();
    server.user = null;
    server.phones.set(grace.email!, '+41791234567');
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    await init();

    const first = await Madauth.password.signIn(credentials);

    expect(first).toMatchObject({ isSuccess: false, error: { code: 'sms_required', method: 'password', factors: ['sms'] } });
    expect(Madauth.sms.pendingStep).toEqual({ step: 'sms', method: 'password', factors: ['sms'] });
    expect(Madauth.currentUser).toBeNull();
    expect(listener).not.toHaveBeenCalledWith(grace);
    expect(server.texts).toEqual([]);
    expect(await Madauth.sms.send()).toEqual({ isSuccess: true, phone: MASKED_PHONE });
    expect(server.texts).toEqual([{ to: '+41791234567', purpose: 'signin' }]);
    expect(await Madauth.sms.verify({ code: '000000' })).toMatchObject({ isSuccess: false, error: { code: 'code_invalid' } });
    const done = await Madauth.sms.verify({ code: CODE });

    expect(done).toEqual({ isSuccess: true, user: grace });
    expect(listener).toHaveBeenLastCalledWith(grace);
    expect(Madauth.sms.pendingStep).toBeNull();
    server.challenge = undefined;
    expect(await Madauth.sms.verify({ code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'challenge_expired' } });
  });

  it('H36: with the app and a phone the app comes first and both finish the sign-in', async () => {
    const server = smsServer();
    server.user = null;
    server.phones.set(grace.email!, '+41791234567');
    server.authenticators.add(grace.email!);
    await init();

    expect(await Madauth.password.signIn(credentials)).toMatchObject({ isSuccess: false, error: { code: 'totp_required', factors: ['totp', 'sms'] } });
    expect(Madauth.totp.pendingStep).toEqual({ step: 'code', method: 'password', factors: ['totp', 'sms'] });
    expect(await Madauth.sms.send()).toEqual({ isSuccess: true, phone: MASKED_PHONE });
    expect(await Madauth.sms.verify({ code: CODE })).toEqual({ isSuccess: true, user: grace });

    await Madauth.signOut();
    await Madauth.password.signIn(credentials);
    expect(await Madauth.totp.verify({ code: CODE })).toEqual({ isSuccess: true, user: grace });
  });

  it('H37: a required policy with neither factor: the phone is added during the sign-in and signs in', async () => {
    const server = smsServer();
    server.user = null;
    server.policy.password = 'required';
    await init();

    expect(await Madauth.password.signIn(credentials)).toMatchObject({ isSuccess: false, error: { code: 'totp_setup_required', factors: ['totp', 'sms'] } });
    expect(Madauth.totp.pendingStep).toEqual({ step: 'setup', method: 'password', factors: ['totp', 'sms'] });
    expect(await Madauth.sms.setUp({ phone: PHONE })).toEqual({ isSuccess: true, phone: MASKED_PHONE });
    const done = await Madauth.sms.confirmSetup({ code: CODE });

    expect(done).toEqual({ isSuccess: true, user: grace });
    expect(Madauth.currentUser).toEqual(grace);
    expect(Madauth.sms.pendingStep).toBeNull();
    await Madauth.signOut();
    expect(await Madauth.password.signIn(credentials)).toMatchObject({ isSuccess: false, error: { code: 'sms_required', factors: ['sms'] } });
  });

  it('H38: switched off, every method fails without a request; setUpSms needs the dialog and a session', async () => {
    const server = fakeServer();
    server.user = grace;
    await init({ ui: 'custom' });

    expect(Madauth.sms.available).toBe(false);
    for (const result of [await Madauth.sms.status(), await Madauth.sms.setUp({ phone: PHONE }), await Madauth.sms.send(), await Madauth.sms.verify({ code: CODE })]) {
      expect(result).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
    }
    expect(server.requests.filter((r) => r.path.startsWith('/auth/sms'))).toHaveLength(0);
    expect(await Madauth.setUpSms()).toMatchObject({ isSuccess: false, error: { code: 'invalid_options' } });

    server.methods.sms = true;
    await init();
    expect(Madauth.sms.available).toBe(true);
    server.user = null;
    await Madauth.signOut();
    expect(await Madauth.setUpSms()).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
    server.methods.sms = false;
    await init();
    expect(await Madauth.setUpSms()).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
  });
});
