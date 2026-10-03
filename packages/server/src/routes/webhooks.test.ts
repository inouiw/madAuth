// How the password routes use the webhook: e-mails must be accepted, the sign-up guard fails closed,
// and events never fail a request. See "Webhooks" in docs/server.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  APP_ORIGIN,
  REDIRECT_TO,
  WEBHOOK_SECRET,
  WEBHOOK_URL,
  getNonce,
  googleIdToken,
  linkAndCode,
  passwordApp,
  post,
  signUpVerified,
  verify,
} from '../test/helpers.js';
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
      type: 'email.verify',
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
      expect(errors).toHaveBeenCalledWith(expect.stringContaining('"email.verify"'));
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

    const res = await post(app, '/auth/password/send-verification', { email: grace.email, redirectTo: REDIRECT_TO });

    expect(res.status).toBe(503);
  });

  it('signs its calls with WEBHOOK_SECRET to WEBHOOK_URL', async () => {
    // The recording receiver answers 401 to anything else, which would make the sign-up fail.
    const { app } = passwordApp({ webhook: { url: WEBHOOK_URL, secret: generateWebhookSecret(), events: null } });
    quietErrors();

    expect((await signUp(app)).status).toBe(503);
  });
});

describe('the sign-up guard (signup.before)', () => {
  it('K3: can refuse a sign-up with a message, before anything is stored or sent', async () => {
    const { app, hook, store } = passwordApp();
    hook.respond = (call) => (call.type === 'signup.before' ? { allow: false, message: 'Company addresses only' } : undefined);

    const res = await signUp(app);

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'signup_rejected', message: 'Company addresses only' });
    expect(hook.calls).toEqual([{ type: 'signup.before', data: { email: 'grace@example.com', name: 'Grace Hopper', locale: 'de-CH' } }]);
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

    hook.respond = (call) => (call.type === 'signup.before' ? { allow: false } : undefined);
    const res = await signUp(app, { email: 'other@example.com' });
    expect(await res.json()).toMatchObject({ error: 'signup_rejected', message: expect.stringContaining('not possible') });
  });

  it('K6: is skipped when WEBHOOK_EVENTS does not select it', async () => {
    const { app, hook } = passwordApp({ webhook: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET, events: new Set(['user.created']) } });

    expect((await signUp(app)).status).toBe(202);

    expect(hook.types()).toEqual(['user.created', 'email.verify']);
  });
});

describe('events', () => {
  it('K5: reports creation, verification, sign-in and reset', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    await post(app, '/auth/password/signin', grace);
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    await post(app, '/auth/password/reset', { token: linkAndCode(hook.lastEmail()).token, password: 'new password!' });

    expect(hook.types()).toEqual([
      'signup.before',
      'user.created',
      'email.verify',
      'email.verified',
      'user.signed_in',
      'user.signed_in',
      'email.reset',
      'password.reset',
      'user.signed_in',
    ]);
    const user = { id: expect.stringMatching(/^usr_/), email: 'grace@example.com', name: 'Grace Hopper' };
    expect(hook.calls.find((c) => c.type === 'email.verified')!.data).toEqual({ user, via: 'link' });
    expect(hook.calls.find((c) => c.type === 'user.signed_in')!.data).toEqual({ user, method: 'password' });
  });

  it('K5: reports Google sign-ins', async () => {
    const { app, hook } = passwordApp();
    const { nonce, cookie } = await getNonce(app);

    await verify(app, await googleIdToken({ nonce }), cookie);

    expect(hook.calls).toEqual([{ type: 'user.signed_in', data: { user: expect.objectContaining({ id: 'google:1001' }), method: 'google' } }]);
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
