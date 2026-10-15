// Behaviour described in docs/sms-security.md; update the doc when changing it.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { APP_ORIGIN, WEBHOOK_SECRET, WEBHOOK_URL, cookies, passwordApp, post, signUpVerified, setMethods, type TestMethods } from '../test/helpers.js';
import { base32Decode, stepOf, totp } from '../totp.js';

type Made = ReturnType<typeof passwordApp>;
type App = Made['app'];
type Hook = Made['hook'];

const START = 1_700_000_015_000;
const PHONE = '+41791234567';
const MASKED = '+41 ••••••• 67';
const grace = { email: 'grace@example.com', password: 'correct horse battery' };
const graceUser = { id: expect.stringMatching(/^usr_/), email: 'grace@example.com', name: 'Grace Hopper' };

afterEach(() => {
  vi.useRealTimers();
});

const startClock = () => vi.useFakeTimers({ toFake: ['Date'], now: START });
const advance = (ms: number) => vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
const withSession = (session: string, more = '') => ({ Cookie: `madauth_session=${session}${more ? `; ${more}` : ''}` });
const withChallenge = (res: Response) => ({ Cookie: `madauth_challenge=${cookies(res).madauth_challenge.value}` });
/** The code of the last SMS the webhook got. */
const lastCode = (hook: Hook) => hook.lastSms()!.data.code as string;
const signIn = (app: App) => post(app, '/auth/password/signin', grace);

/** Adds a phone for the signed-in user: the setup SMS, then its code. */
async function addPhone(app: App, hook: Hook, session: string, phone = PHONE) {
  const setup = await post(app, '/auth/sms/setup', { phone, locale: 'de' }, withSession(session));
  const code = lastCode(hook);
  const setupCookie = `madauth_sms_setup=${cookies(setup).madauth_sms_setup.value}`;
  const confirm = await post(app, '/auth/sms/confirm', { code }, withSession(session, setupCookie));
  return { setup, confirm, code };
}

/** Sets the authenticator app up for the signed-in user; returns its secret. */
async function addApp(app: App, session: string): Promise<Buffer> {
  const setup = await post(app, '/auth/totp/setup', {}, withSession(session));
  const secret = base32Decode(((await setup.json()) as { secret: string }).secret)!;
  const setupCookie = `madauth_totp_setup=${cookies(setup).madauth_totp_setup.value}`;
  const confirm = await post(app, '/auth/totp/confirm', { code: totp(secret, stepOf(Date.now())) }, withSession(session, setupCookie));
  expect(confirm.status).toBe(200);
  return secret;
}

/** Grace with a password and a phone, on a server where password sign-in asks for a second factor when there is one. */
async function withPhone(methods: TestMethods = { google: {}, password: { secondFactor: 'optional' }, sms: {} }) {
  startClock();
  const made = passwordApp();
  await setMethods(made.store, methods);
  const session = await signUpVerified(made.app, made.hook);
  advance(61_000);
  const { confirm } = await addPhone(made.app, made.hook, session);
  expect(confirm.status).toBe(200);
  made.hook.calls.length = 0;
  advance(61_000);
  return { ...made, session };
}

describe('adding a phone number', () => {
  it('S1: the setup sends a code to the number, stores nothing until the code is right, and then the webhook is told', async () => {
    startClock();
    const { app, hook, store } = passwordApp();
    await setMethods(store, { password: { secondFactor: 'optional' }, sms: {} });
    const session = await signUpVerified(app, hook);
    advance(61_000);
    hook.calls.length = 0;

    expect((await post(app, '/auth/sms/setup', { phone: PHONE })).status).toBe(401);
    const setup = await post(app, '/auth/sms/setup', { phone: '+41 79 123-45-67', locale: 'de' }, withSession(session));

    expect(setup.status).toBe(202);
    expect(await setup.json()).toEqual({ phone: MASKED });
    expect(cookies(setup).madauth_sms_setup.attrs).toMatchObject({ httponly: true, secure: true, samesite: 'Strict', path: '/auth/sms', 'max-age': '600' });
    expect(hook.calls).toEqual([
      {
        type: 'sms.send_code',
        data: {
          to: PHONE,
          code: expect.stringMatching(/^\d{6}$/),
          purpose: 'setup',
          expiresAt: Date.now() + 10 * 60 * 1000,
          site: 'app.example.com',
          locale: 'de',
          user: { id: expect.stringMatching(/^usr_/), name: 'Grace Hopper' },
        },
      },
    ]);
    expect(await store.findMany('account', {})).toHaveLength(1);
    expect(await (await app.request('/auth/sms/status', { headers: withSession(session) })).json()).toEqual({ enabled: false, phone: null });

    const code = lastCode(hook);
    const setupCookie = `madauth_sms_setup=${cookies(setup).madauth_sms_setup.value}`;
    const wrong = await post(app, '/auth/sms/confirm', { code: '000000' }, withSession(session, setupCookie));
    expect(wrong.status).toBe(401);
    expect(await wrong.json()).toMatchObject({ error: 'code_invalid' });
    expect(await (await post(app, '/auth/sms/confirm', { code }, withSession(session))).json()).toMatchObject({ error: 'setup_expired' });
    const confirm = await post(app, '/auth/sms/confirm', { code: ` ${code.slice(0, 3)} ${code.slice(3)} ` }, withSession(session, setupCookie));

    expect(confirm.status).toBe(200);
    expect(await confirm.json()).toEqual({});
    expect(cookies(confirm).madauth_sms_setup).toMatchObject({ value: '', attrs: { 'max-age': '0' } });
    const [{ id: userId }] = await store.findMany('user', {});
    expect(await store.findOne('account', { key: `sms:${userId}` })).toMatchObject({ userId, phone: PHONE, failedAttempts: 0 });
    expect(hook.calls.at(-1)).toEqual({ type: 'user.second_factor_enabled', data: { user: graceUser, method: 'sms', phone: PHONE } });
    expect(await (await app.request('/auth/sms/status', { headers: withSession(session) })).json()).toEqual({ enabled: true, phone: MASKED });
    // The code is used up, and the setup is over: its cookie no longer confirms anything now that there is a number.
    expect(await store.findOne('verification', { userId, purpose: 'sms' })).toBeNull();
    expect(await (await post(app, '/auth/sms/confirm', { code }, withSession(session, setupCookie))).json()).toMatchObject({ error: 'setup_expired' });

    for (const phone of ['0791234567', '+41', '+0791234567', '41791234567', 'call me', 12, undefined]) {
      const refused = await post(app, '/auth/sms/setup', { phone }, withSession(session));
      expect(refused.status).toBe(400);
      expect(await refused.json()).toMatchObject({ error: 'invalid_phone' });
    }
  });

  it('S2: one SMS per minute, apart from the e-mails; the webhook failing is reported and leaves nothing behind', async () => {
    startClock();
    const { app, hook, store } = passwordApp();
    await setMethods(store, { password: { secondFactor: 'optional' }, sms: {} });
    const session = await signUpVerified(app, hook);

    // The confirmation e-mail was just sent: the SMS goes all the same, but a second one has to wait.
    expect((await post(app, '/auth/sms/setup', { phone: PHONE }, withSession(session))).status).toBe(202);
    const soon = await post(app, '/auth/sms/setup', { phone: PHONE }, withSession(session));
    expect(soon.status).toBe(429);
    expect(await soon.json()).toMatchObject({ error: 'too_soon' });
    hook.calls.length = 0;
    advance(61_000);
    hook.fail = 503;
    hook.failOnly = (type) => type === 'sms.send_code';
    const failed = await post(app, '/auth/sms/setup', { phone: PHONE }, withSession(session));
    expect(failed.status).toBe(503);
    expect(await failed.json()).toMatchObject({ error: 'temporarily_unavailable', message: expect.stringContaining('SMS') });
    expect(cookies(failed).madauth_sms_setup).toBeUndefined();
    // Right away, since nothing was sent.
    hook.fail = undefined;
    expect((await post(app, '/auth/sms/setup', { phone: PHONE }, withSession(session))).status).toBe(202);
    expect(hook.sms()).toHaveLength(1);
    expect((await post(app, '/auth/sms/setup', { phone: PHONE }, withSession(session))).status).toBe(429);
  });

  it('S3: replacing the number takes a code sent to the current one, and removing it too', async () => {
    const { app, hook, store, session } = await withPhone();

    const noCode = await post(app, '/auth/sms/setup', { phone: '+41790000099' }, withSession(session));
    expect(noCode.status).toBe(401);
    expect(await noCode.json()).toMatchObject({ error: 'code_required' });
    expect((await post(app, '/auth/sms/setup', { phone: '+41790000099', code: '000000' }, withSession(session))).status).toBe(401);

    const sent = await post(app, '/auth/sms/send', {}, withSession(session));
    expect(sent.status).toBe(202);
    expect(await sent.json()).toEqual({ phone: MASKED });
    expect(hook.lastSms()!.data).toMatchObject({ to: PHONE, purpose: 'approve' });
    // Approved: the code to the new number follows at once, the minute notwithstanding. The clock ticks
    // between the approval and that check, as a real one does.
    const frozen = Date.now();
    let ticks = 0;
    const ticking = vi.spyOn(Date, 'now').mockImplementation(() => frozen + ++ticks);
    const setup = await post(app, '/auth/sms/setup', { phone: '+41790000099', code: lastCode(hook) }, withSession(session));
    ticking.mockRestore();
    expect(setup.status).toBe(202);
    expect(hook.lastSms()!.data).toMatchObject({ to: '+41790000099', purpose: 'setup' });
    const setupCookie = `madauth_sms_setup=${cookies(setup).madauth_sms_setup.value}`;
    expect((await post(app, '/auth/sms/confirm', { code: lastCode(hook) }, withSession(session, setupCookie))).status).toBe(200);
    const [{ id: userId }] = await store.findMany('user', {});
    expect(await store.findOne('account', { key: `sms:${userId}` })).toMatchObject({ phone: '+41790000099' });
    expect(await (await app.request('/auth/sms/status', { headers: withSession(session) })).json()).toEqual({ enabled: true, phone: '+41 ••••••• 99' });

    advance(61_000);
    expect((await post(app, '/auth/sms/remove', { code: '000000' }, withSession(session))).status).toBe(401);
    await post(app, '/auth/sms/send', {}, withSession(session));
    const code = lastCode(hook);
    hook.calls.length = 0;
    const removed = await post(app, '/auth/sms/remove', { code }, withSession(session));

    expect(removed.status).toBe(200);
    expect(await store.findOne('account', { key: `sms:${userId}` })).toBeNull();
    expect(hook.calls).toEqual([{ type: 'user.second_factor_disabled', data: { user: graceUser, method: 'sms' } }]);
    expect(await (await post(app, '/auth/sms/remove', { code }, withSession(session))).json()).toMatchObject({ error: 'no_phone' });
    expect(await (await post(app, '/auth/sms/send', {}, withSession(session))).json()).toMatchObject({ error: 'no_phone' });
  });

  it('S12: a setup started before the user had a number does not replace the one they added meanwhile', async () => {
    startClock();
    const { app, hook, store } = passwordApp();
    await setMethods(store, { google: {}, password: { secondFactor: 'optional' }, sms: {} });
    const session = await signUpVerified(app, hook);
    advance(61_000);
    // One browser starts adding a number and stops before the code.
    const stale = await post(app, '/auth/sms/setup', { phone: '+41790000099' }, withSession(session));
    expect(stale.status).toBe(202);
    const staleCookie = `madauth_sms_setup=${cookies(stale).madauth_sms_setup.value}`;
    advance(61_000);
    // Another browser adds a number and confirms it.
    expect((await addPhone(app, hook, session)).confirm.status).toBe(200);

    const refused = await post(app, '/auth/sms/confirm', { code: lastCode(hook) }, withSession(session, staleCookie));

    // The first setup never had the current number's approval, whatever code it brings.
    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({ error: 'setup_expired' });
    expect(cookies(refused).madauth_sms_setup).toMatchObject({ value: '' });
    const [{ id: userId }] = await store.findMany('user', {});
    expect(await store.findOne('account', { key: `sms:${userId}` })).toMatchObject({ phone: PHONE });
  });

  it('S4: with a required policy the phone only goes while the app stays, and the app only while a phone stays', async () => {
    const { app, hook, store, session } = await withPhone();
    await setMethods(store, { google: {}, password: { secondFactor: 'required' }, sms: {} });

    await post(app, '/auth/sms/send', {}, withSession(session));
    const refused = await post(app, '/auth/sms/remove', { code: lastCode(hook) }, withSession(session));
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: 'required_by_policy' });

    // With the app as well, the phone may go; and the other way round.
    const secret = await addApp(app, session);
    advance(61_000);
    await post(app, '/auth/sms/send', {}, withSession(session));
    expect((await post(app, '/auth/sms/remove', { code: lastCode(hook) }, withSession(session))).status).toBe(200);
    const appAlone = await post(app, '/auth/totp/remove', { code: totp(secret, stepOf(Date.now()) + 1) }, withSession(session));
    expect(appAlone.status).toBe(403);
    expect(await appAlone.json()).toMatchObject({ error: 'required_by_policy', message: expect.stringContaining('another second factor') });
    advance(61_000);
    await addPhone(app, hook, session);
    expect((await post(app, '/auth/totp/remove', { code: totp(secret, stepOf(Date.now())) }, withSession(session))).status).toBe(200);
  });
});

describe('SMS codes as the second step', () => {
  it('S5: a user with a phone is asked for the code after the password; the code finishes the sign-in', async () => {
    const { app, hook } = await withPhone();

    const first = await signIn(app);

    expect(first.status).toBe(401);
    expect(await first.json()).toEqual({ error: 'sms_required', message: expect.any(String), method: 'password', factors: ['sms'] });
    expect(cookies(first).madauth_session?.value ?? '').toBe('');
    expect(cookies(first).madauth_challenge.attrs).toMatchObject({ httponly: true, secure: true, samesite: 'Strict', path: '/auth', 'max-age': '600' });
    expect(hook.sms()).toEqual([]);

    // The SMS goes when the client asks for it, and only once a minute.
    const sent = await post(app, '/auth/sms/send', { locale: 'de' }, withChallenge(first));
    expect(sent.status).toBe(202);
    expect(await sent.json()).toEqual({ phone: MASKED });
    expect(hook.lastSms()!.data).toMatchObject({ to: PHONE, purpose: 'signin', locale: 'de' });
    expect((await post(app, '/auth/sms/send', {}, withChallenge(first))).status).toBe(429);
    // The app's step is not open: the user has no app.
    expect(await (await post(app, '/auth/totp/verify', { code: '000000' }, withChallenge(first))).json()).toMatchObject({ error: 'challenge_expired' });

    const wrong = await post(app, '/auth/sms/verify', { code: '000000' }, withChallenge(first));
    expect(wrong.status).toBe(401);
    expect(await wrong.json()).toMatchObject({ error: 'code_invalid' });
    const code = lastCode(hook);
    hook.calls.length = 0;
    const done = await post(app, '/auth/sms/verify', { code }, withChallenge(first));

    expect(done.status).toBe(200);
    expect((await done.json()).user).toMatchObject({ email: 'grace@example.com', amr: ['pwd', 'sms'] });
    expect(cookies(done).madauth_session.value).toBeTruthy();
    expect(cookies(done).madauth_challenge).toMatchObject({ value: '', attrs: { 'max-age': '0' } });
    expect(hook.calls).toEqual([{ type: 'user.signed_in', data: { user: { ...graceUser, amr: undefined }, method: 'password', secondFactor: 'sms' } }]);
    // The code and the challenge are used up.
    expect((await post(app, '/auth/sms/verify', { code }, withChallenge(first))).status).toBe(401);
  });

  it('S6: with the app and a phone the app comes first, and the user can switch to the SMS; without a phone nothing changes', async () => {
    const { app, hook, session } = await withPhone();
    const secret = await addApp(app, session);
    advance(61_000);

    const first = await signIn(app);

    expect(await first.json()).toMatchObject({ error: 'totp_required', method: 'password', factors: ['totp', 'sms'] });
    expect((await post(app, '/auth/sms/send', {}, withChallenge(first))).status).toBe(202);
    const bySms = await post(app, '/auth/sms/verify', { code: lastCode(hook) }, withChallenge(first));
    expect((await bySms.json()).user.amr).toEqual(['pwd', 'sms']);

    advance(61_000);
    const second = await signIn(app);
    const byApp = await post(app, '/auth/totp/verify', { code: totp(secret, stepOf(Date.now())) }, withChallenge(second));
    expect((await byApp.json()).user.amr).toEqual(['pwd', 'otp']);

    // Without a phone, an optional policy signs in as before, and the step's answer says the app alone.
    await post(app, '/auth/sms/send', {}, withSession(cookies(byApp).madauth_session.value));
    await post(app, '/auth/sms/remove', { code: lastCode(hook) }, withSession(cookies(byApp).madauth_session.value));
    advance(61_000);
    expect(await (await signIn(app)).json()).toMatchObject({ error: 'totp_required', factors: ['totp'] });
  });

  it('S7: a required policy with neither factor: the phone can be added during the sign-in instead of the app', async () => {
    startClock();
    const { app, hook, store } = passwordApp();
    await setMethods(store, { google: {}, password: { secondFactor: 'required' }, sms: {} });
    await signUpVerified(app, hook);
    advance(61_000);
    hook.calls.length = 0;

    const first = await signIn(app);

    // `factors` are those the user can set up: the app, or a phone.
    expect(await first.json()).toMatchObject({ error: 'totp_setup_required', method: 'password', factors: ['totp', 'sms'] });
    // Neither code step is open yet.
    expect((await post(app, '/auth/sms/send', {}, withChallenge(first))).status).toBe(401);
    const setup = await post(app, '/auth/sms/setup', { phone: PHONE }, withChallenge(first));
    expect(setup.status).toBe(202);
    expect(hook.lastSms()!.data).toMatchObject({ to: PHONE, purpose: 'setup' });
    const cookie = `${withChallenge(first).Cookie}; madauth_sms_setup=${cookies(setup).madauth_sms_setup.value}`;
    const confirm = await post(app, '/auth/sms/confirm', { code: lastCode(hook) }, { Cookie: cookie });

    expect(confirm.status).toBe(200);
    expect((await confirm.json()).user).toMatchObject({ email: 'grace@example.com', amr: ['pwd', 'sms'] });
    expect(cookies(confirm).madauth_session.value).toBeTruthy();
    expect(cookies(confirm).madauth_challenge).toMatchObject({ value: '' });
    // Her first session, with the phone the policy asks for: the sign-up is complete only now.
    expect(hook.types().slice(-3)).toEqual(['user.second_factor_enabled', 'user.signed_up', 'user.signed_in']);
    expect(hook.calls.at(-1)!.data).toMatchObject({ method: 'password', secondFactor: 'sms' });
    // From then on: the SMS step.
    advance(61_000);
    expect(await (await signIn(app)).json()).toMatchObject({ error: 'sms_required', factors: ['sms'] });
  });

  it('S8: a sign-up with the app alone sets the app up, never a phone: SMS codes are no first factor', async () => {
    startClock();
    const { app, hook, store } = passwordApp();
    await setMethods(store, { password: {}, totp: {}, sms: {} });
    await post(app, '/auth/totp/signup', { email: 'linda@example.com', redirectTo: `${APP_ORIGIN}/account` });
    const link = hook.lastEmail()!.data.link as string;
    const first = await post(app, '/auth/email/verify', { token: link.split('=').at(-1) });
    expect(await first.json()).toMatchObject({ error: 'totp_setup_required', method: 'totp', factors: ['totp'] });

    const refused = await post(app, '/auth/sms/setup', { phone: PHONE }, withChallenge(first));

    expect(refused.status).toBe(401);
    expect(await refused.json()).toMatchObject({ error: 'no_session' });
    expect(hook.sms()).toEqual([]);
  });

  it('S9: wrong codes: five per SMS, then the lock on the account; the e-mail codes are not counted', async () => {
    const { app, hook, store } = await withPhone();
    const first = await signIn(app);
    await post(app, '/auth/sms/send', {}, withChallenge(first));
    const code = lastCode(hook);
    const wrong = () => post(app, '/auth/sms/verify', { code: code === '000000' ? '111111' : '000000' }, withChallenge(first));

    for (let i = 0; i < 4; i++) expect((await wrong()).status).toBe(401);
    // The fifth wrong code deletes the record and locks the account for a second: even the right code waits.
    expect(await (await wrong()).json()).toMatchObject({ error: 'code_invalid' });
    const locked = await post(app, '/auth/sms/verify', { code }, withChallenge(first));
    expect(locked.status).toBe(429);
    expect(await locked.json()).toMatchObject({ error: 'too_many_attempts' });
    const [user] = await store.findMany('user', {});
    expect(user.wrongCodes).toBe(0);

    // A new code, once the minute and the lock are over.
    advance(61_000);
    expect((await post(app, '/auth/sms/send', {}, withChallenge(first))).status).toBe(202);
    expect((await post(app, '/auth/sms/verify', { code: lastCode(hook) }, withChallenge(first))).status).toBe(200);
  });

  it('S10: switched off, the routes answer 403 and the phone no longer counts; not configured, they are not there', async () => {
    const { app, hook, store, session } = await withPhone();
    await setMethods(store, { google: {}, password: { secondFactor: 'optional' } });

    expect(await (await app.request('/auth/config')).json()).toMatchObject({ sms: false });
    expect((await app.request('/auth/sms/status', { headers: withSession(session) })).status).toBe(403);
    expect(await (await post(app, '/auth/sms/send', {}, withSession(session))).json()).toMatchObject({ error: 'method_disabled' });
    // Signing in no longer asks for the phone.
    expect((await signIn(app)).status).toBe(200);

    await setMethods(store, { google: {}, password: { secondFactor: 'optional' }, sms: {} });
    expect(await (await app.request('/auth/config')).json()).toMatchObject({ sms: true });
    expect((await signIn(app)).status).toBe(401);
    // An admin switching SMS off ends a sign-in that waits for the code.
    const waiting = await signIn(app);
    await setMethods(store, { google: {}, password: { secondFactor: 'optional' } });
    expect((await post(app, '/auth/sms/verify', { code: '000000' }, withChallenge(waiting))).status).toBe(403);

    const without = passwordApp({ webhook: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET, events: new Set(['email.send_verification', 'email.send_password_reset']) } });
    expect((await post(without.app, '/auth/sms/setup', { phone: PHONE })).status).toBe(404);
    expect(await (await without.app.request('/auth/config')).json()).toMatchObject({ sms: false });
    void hook;
  });
});
