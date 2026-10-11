// How the password routes use the webhook: e-mails must be accepted, the sign-up guard fails closed,
// and events never fail a request. See "Webhooks" in docs/server.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ALL_EVENTS,
  APP_ORIGIN,
  REDIRECT_TO,
  WEBHOOK_SECRET,
  WEBHOOK_URL,
  cookies,
  getNonce,
  googleIdToken,
  linkAndCode,
  passwordApp,
  post,
  signUpVerified,
  verify,
} from '../test/helpers.js';
import { Settings } from '../settings.js';
import { generateWebhookSecret } from '../webhooks.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const grace = { email: 'grace@example.com', password: 'correct horse battery' };
type App = ReturnType<typeof passwordApp>['app'];
const signUp = (app: App, body: Record<string, unknown> = {}) =>
  post(app, '/auth/password/signup', { ...grace, name: 'Grace Hopper', redirectTo: REDIRECT_TO, locale: 'de-CH', ...body });

function advance(ms: number) {
  vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
}

function quietErrors() {
  return vi.spyOn(console, 'error').mockImplementation(() => {});
}

describe('e-mails through the webhook', () => {
  it('K2: sign-up hands the verification e-mail to the webhook, with link, code and locale', async () => {
    const { app, hook } = passwordApp();

    expect((await signUp(app)).status).toBe(202);

    expect(hook.lastEmail()).toMatchObject({
      type: 'email.send_verification',
      data: { to: 'grace@example.com', code: expect.stringMatching(/^\d{6}$/), locale: 'de-CH', site: 'app.example.com' },
    });
    expect(linkAndCode(hook.lastEmail()).link.startsWith(`${REDIRECT_TO}#madauth_verify=`)).toBe(true);
  });

  for (const failure of [500, 'network', 'timeout'] as const) {
    it(`K2: sign-up fails with temporarily_unavailable when the webhook fails (${failure}), and can be retried at once`, async () => {
      const { app, hook, store } = passwordApp();
      const errors = quietErrors();
      hook.fail = failure;
      hook.failOnly = (type) => type.startsWith('email.');

      const res = await signUp(app);

      expect(res.status).toBe(503);
      expect(await res.json()).toMatchObject({ error: 'temporarily_unavailable' });
      expect(errors).toHaveBeenCalledWith(expect.stringContaining('"email.send_verification"'));
      const [user] = await store.findMany('user', {});
      expect(user.lastMailAt).toBe(0);

      hook.fail = undefined;
      expect((await signUp(app)).status).toBe(202);
      expect(hook.emails()).toHaveLength(1);
    });
  }

  it('K2: the "already registered" e-mail must be accepted too', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    advance(61_000);
    quietErrors();
    hook.fail = 500;

    expect((await signUp(app)).status).toBe(503);
  });

  it('K4: send-reset fails visibly for an existing account; an unknown address makes no call', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    advance(61_000);
    quietErrors();
    const before = hook.calls.length;
    hook.fail = 500;

    const existing = await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const unknown = await post(app, '/auth/password/send-reset', { email: 'nobody@example.com', redirectTo: REDIRECT_TO });

    expect(existing.status).toBe(503);
    expect(unknown.status).toBe(202);
    expect(hook.calls).toHaveLength(before);
  });

  it('K4: send-verification fails visibly too', async () => {
    const { app, hook } = passwordApp();
    await signUp(app);
    advance(61_000);
    quietErrors();
    hook.fail = 'network';

    const res = await post(app, '/auth/email/send-verification', { email: grace.email, redirectTo: REDIRECT_TO });

    expect(res.status).toBe(503);
  });

  it('signs its calls with WEBHOOK_SECRET to WEBHOOK_URL', async () => {
    // The recording receiver answers 401 to anything else, which would make the sign-up fail.
    const { app } = passwordApp({ webhook: { url: WEBHOOK_URL, secret: generateWebhookSecret(), events: ALL_EVENTS } });
    quietErrors();

    expect((await signUp(app)).status).toBe(503);
  });
});

describe('the sign-up guard (user.signing_up)', () => {
  it('K3: can refuse a sign-up with a message, before anything is stored or sent', async () => {
    const { app, hook, store } = passwordApp();
    hook.respond = (call) => (call.type === 'user.signing_up' ? { allow: false, message: 'Company addresses only' } : undefined);

    const res = await signUp(app);

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'signup_rejected', message: 'Company addresses only' });
    expect(hook.calls).toEqual([{ type: 'user.signing_up', data: { email: 'grace@example.com', name: 'Grace Hopper', locale: 'de-CH', method: 'password' } }]);
    expect(await store.findMany('user', {})).toEqual([]);
  });

  it('K3: an unreachable guard refuses the sign-up (fail closed)', async () => {
    const { app, hook, store } = passwordApp();
    quietErrors();
    hook.fail = 'timeout';

    const res = await signUp(app);

    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ error: 'temporarily_unavailable' });
    expect(await store.findMany('user', {})).toEqual([]);
  });

  it('K3: an empty 2xx answer allows the sign-up; a refusal without message gets a default one', async () => {
    const { app, hook } = passwordApp();
    expect((await signUp(app)).status).toBe(202);

    hook.respond = (call) => (call.type === 'user.signing_up' ? { allow: false } : undefined);
    const res = await signUp(app, { email: 'other@example.com' });
    expect(await res.json()).toMatchObject({ error: 'signup_rejected', message: expect.stringContaining('not possible') });
  });

  it('K6: is skipped when WEBHOOK_EVENTS does not select it', async () => {
    const events = new Set(['email.send_verification', 'email.send_password_reset', 'user.signed_up']);
    const { app, hook } = passwordApp({ webhook: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET, events } });

    expect((await signUp(app)).status).toBe(202);

    // No check without user.signing_up in the list, and no user.signed_up before the address is confirmed.
    expect(hook.types()).toEqual(['email.send_verification']);
  });
});

describe('a receiver that sends only the two required e-mails', () => {
  const events = new Set(['email.send_verification', 'email.send_password_reset']);

  it('K6: gets nothing else, so a sign-in makes no call', async () => {
    const { app, hook } = passwordApp({ webhook: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET, events } });
    await signUpVerified(app, hook);
    await post(app, '/auth/password/signin', grace);

    expect(hook.types()).toEqual(['email.send_verification']);
  });

  it('K6: a sign-up with a confirmed address answers like any other and sends nothing', async () => {
    const { app, hook } = passwordApp({ webhook: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET, events } });
    await signUpVerified(app, hook);
    advance(61_000);

    const res = await signUp(app, { password: 'another password' });

    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({});
    expect(hook.types()).toEqual(['email.send_verification']);
    // No e-mail was counted either: the reset e-mail goes out right away.
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    expect(hook.types()).toEqual(['email.send_verification', 'email.send_password_reset']);
  });
});

describe('events', () => {
  it('K5: reports the sign-up, the confirmation, sign-ins and the reset', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    await post(app, '/auth/password/signin', grace);
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    await post(app, '/auth/password/reset', { token: linkAndCode(hook.lastEmail()).token, password: 'new teapot sky!' });

    expect(hook.types()).toEqual([
      'user.signing_up',
      'email.send_verification',
      'user.email_verified',
      'user.signed_up',
      'user.signed_in',
      'user.signed_in',
      'email.send_password_reset',
      'user.password_reset',
      'user.signed_in',
    ]);
    const user = { id: expect.stringMatching(/^usr_/), email: 'grace@example.com', name: 'Grace Hopper' };
    expect(hook.calls.find((c) => c.type === 'user.email_verified')!.data).toEqual({ user, method: 'password', via: 'link' });
    expect(hook.calls.find((c) => c.type === 'user.signed_up')!.data).toEqual({ user, method: 'password' });
    expect(hook.calls.find((c) => c.type === 'user.signed_in')!.data).toEqual({ user, method: 'password' });
  });

  it('K5: reports Google sign-ins, and the first one as a sign-up', async () => {
    const { app, hook } = passwordApp();
    const user = { id: expect.stringMatching(/^usr_/), email: 'ada@example.com', name: 'Ada Lovelace' };

    const first = await getNonce(app);
    await verify(app, await googleIdToken({ nonce: first.nonce }), first.cookie);
    expect(hook.calls).toEqual([
      { type: 'user.signing_up', data: { email: 'ada@example.com', name: 'Ada Lovelace', method: 'google' } },
      { type: 'user.signed_up', data: { user: { ...user, picture: 'https://example.com/ada.png' }, method: 'google' } },
      { type: 'user.signed_in', data: { user: { ...user, picture: 'https://example.com/ada.png' }, method: 'google' } },
    ]);

    hook.calls.length = 0;
    const second = await getNonce(app);
    await verify(app, await googleIdToken({ nonce: second.nonce }), second.cookie);
    expect(hook.types()).toEqual(['user.signed_in']);
  });

  it('K3: the sign-up guard applies to Google too, before anything is stored', async () => {
    const { app, hook, store } = passwordApp();
    hook.respond = (call) => (call.type === 'user.signing_up' ? { allow: false, message: 'Company addresses only' } : undefined);
    const { nonce, cookie } = await getNonce(app);

    const res = await verify(app, await googleIdToken({ nonce }), cookie);

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'signup_rejected', message: 'Company addresses only' });
    expect(cookies(res).madauth_session).toBeUndefined();
    expect(await store.findMany('user', {})).toEqual([]);
    expect(hook.types()).toEqual(['user.signing_up']);
  });

  it('K5: a failing receiver does not fail the sign-in, but is logged', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    const errors = quietErrors();
    hook.fail = 500;

    const res = await post(app, '/auth/password/signin', grace);

    expect(res.status).toBe(200);
    expect(errors).toHaveBeenCalledWith('[madauth] Webhook "user.signed_in" failed: HTTP 500');
  });

  it('only allowed origins can trigger calls', async () => {
    const { app, hook } = passwordApp();

    const res = await post(app, '/auth/password/signup', { ...grace, redirectTo: REDIRECT_TO }, { Origin: 'https://evil.example' });

    expect(res.status).toBe(403);
    expect(hook.calls).toEqual([]);
    expect(APP_ORIGIN).toBe('https://app.example.com');
  });
});

describe('user.signed_up', () => {
  const setMethods = (store: ReturnType<typeof passwordApp>['store'], methods: ConstructorParameters<typeof Settings>[1]) =>
    new Settings(store).set('methods', methods, null);

  it('is sent once, at the first session, also when two sign-ins come at once', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: 1_700_000_000_000 });
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook);
    expect(hook.types().filter((type) => type === 'user.signed_up')).toHaveLength(1);
    const [user] = await store.findMany('user', {});
    expect(user.signedUpAt).toBe(1_700_000_000_000);

    // A later sign-in is no sign-up.
    hook.calls.length = 0;
    await post(app, '/auth/password/signin', grace);
    expect(hook.types()).toEqual(['user.signed_in']);

    // The write decides between sign-ins at the same time: one of them tells.
    await store.update('user', { id: user.id }, { signedUpAt: 0 });
    hook.calls.length = 0;
    await Promise.all([post(app, '/auth/password/signin', grace), post(app, '/auth/password/signin', grace)]);
    expect(hook.types().filter((type) => type === 'user.signed_up')).toHaveLength(1);
  });

  it('is not sent for a user from before it existed', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook);
    // Schema version 6 had no signedUpAt: such a user signed up long ago.
    const [user] = await store.findMany('user', {});
    await store.update('user', { id: user.id }, { signedUpAt: null });
    hook.calls.length = 0;

    await post(app, '/auth/password/signin', grace);

    expect(hook.types()).toEqual(['user.signed_in']);
  });

  it('comes for a sign-up started before it existed and finished after, by its link or by Google', async () => {
    // Schema version 6 left an unfinished sign-up with signedUpAt empty, which otherwise reads as complete.
    const linked = passwordApp();
    await signUp(linked.app);
    const [user] = await linked.store.findMany('user', {});
    await linked.store.update('user', { id: user.id }, { signedUpAt: null });
    const { token } = linkAndCode(linked.hook.lastEmail());
    linked.hook.calls.length = 0;
    await post(linked.app, '/auth/email/verify', { token });
    expect(linked.hook.types()).toEqual(['user.email_verified', 'user.signed_up', 'user.signed_in']);

    const google = passwordApp();
    await post(google.app, '/auth/password/signup', { email: 'ada@example.com', password: 'adas password!', redirectTo: REDIRECT_TO });
    const [ada] = await google.store.findMany('user', {});
    await google.store.update('user', { id: ada.id }, { signedUpAt: null });
    google.hook.calls.length = 0;
    const { nonce, cookie } = await getNonce(google.app);
    await verify(google.app, await googleIdToken({ nonce }), cookie);
    expect(google.hook.types()).toEqual(['user.signed_up', 'user.signed_in']);
  });

  it('a sign-up that lost the race for the user\'s one sign-in method sends no e-mail for it', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: 1_700_000_000_000 });
    const { app, hook, store } = passwordApp();
    await signUp(app);
    const [user] = await store.findMany('user', {});
    // Another sign-up won meanwhile: the user has a sign-in method the unproven ones don't drop.
    await store.delete('account', { key: `password:${user.id}` });
    await store.create('account', {
      id: 'acc_won', userId: user.id, key: 'google:9009', secret: null, failedAttempts: 0, lockedUntil: 0, email: grace.email,
      lastUsedStep: 0, setupId: null, phone: null, primaryUserId: user.id, createdAt: 1,
    });
    advance(61_000);
    hook.calls.length = 0;

    expect((await signUp(app)).status).toBe(202);

    expect(hook.types()).toEqual(['user.signing_up']);
    // The e-mail link the same way: no link for a method the user doesn't get.
    hook.calls.length = 0;
    expect((await post(app, '/auth/email-link/send', { email: grace.email, redirectTo: REDIRECT_TO })).status).toBe(202);
    expect(hook.types()).toEqual(['user.signing_up']);
    expect((await store.findMany('account', { userId: user.id })).map((a) => a.key)).toEqual(['google:9009']);
  });

  it('waits for the second factor a policy requires, and comes when the policy no longer does', async () => {
    const { app, hook, store } = passwordApp();
    await setMethods(store, { password: { secondFactor: 'required' } });
    await signUp(app);
    const confirmed = await post(app, '/auth/email/verify', { token: linkAndCode(hook.lastEmail()).token });
    expect(await confirmed.json()).toMatchObject({ error: 'totp_setup_required' });
    expect(hook.types()).not.toContain('user.signed_up');

    // The admin drops the requirement before Grace set the app up: her next sign-in completes the sign-up.
    await setMethods(store, { password: { secondFactor: 'optional' } });
    hook.calls.length = 0;
    expect((await post(app, '/auth/password/signin', grace)).status).toBe(200);
    expect(hook.calls).toEqual([
      { type: 'user.signed_up', data: { user: expect.objectContaining({ email: grace.email }), method: 'password' } },
      { type: 'user.signed_in', data: { user: expect.objectContaining({ email: grace.email }), method: 'password' } },
    ]);
  });

  it('comes when a sign-up nobody confirmed is finished another way: a password reset, or Google', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() });
    const reset = passwordApp();
    await signUp(reset.app);
    advance(61_000);
    await post(reset.app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const { token } = linkAndCode(reset.hook.lastEmail());
    reset.hook.calls.length = 0;
    await post(reset.app, '/auth/password/reset', { token, password: 'new teapot sky!' });
    expect(reset.hook.types()).toEqual(['user.password_reset', 'user.signed_up', 'user.signed_in']);

    const google = passwordApp();
    await post(google.app, '/auth/password/signup', { email: 'ada@example.com', password: 'adas password!', redirectTo: REDIRECT_TO });
    google.hook.calls.length = 0;
    const { nonce, cookie } = await getNonce(google.app);
    await verify(google.app, await googleIdToken({ nonce }), cookie);
    expect(google.hook.types()).toEqual(['user.signed_up', 'user.signed_in']);
    expect(google.hook.calls[0].data).toMatchObject({ method: 'google' });
  });
});
