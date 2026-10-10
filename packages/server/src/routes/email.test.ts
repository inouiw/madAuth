// Confirming an address (POST /auth/email/verify, send-verification), shared by the methods that sign
// people up with one. Most cases live in password.test.ts; these are the ones that are not about passwords.
import { describe, expect, it } from 'vitest';
import {
  ALL_EVENTS,
  APP_ORIGIN,
  REDIRECT_TO,
  WEBHOOK_SECRET,
  WEBHOOK_URL,
  cookies,
  linkAndCode,
  passwordApp,
  post,
  recordingWebhook,
  testApp,
} from '../test/helpers.js';

describe('e-mail confirmation', () => {
  it('E1: a server whose webhook only sends email.verify confirms addresses, without password sign-in', async () => {
    const hook = recordingWebhook();
    const app = testApp({ webhook: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET, events: new Set(['email.verify']) }, webhookFetch: hook.fetch });

    expect(await (await app.request('/auth/config')).json()).toMatchObject({ password: null, email: { verification: true } });
    // The password routes are not there at all; the confirmation routes are.
    expect((await post(app, '/auth/password/signup', { email: 'g@example.com', password: 'correct horse battery', redirectTo: REDIRECT_TO })).status).toBe(404);
    expect((await post(app, '/auth/email/send-verification', { email: 'nobody@example.com', redirectTo: REDIRECT_TO })).status).toBe(202);
    expect((await post(app, '/auth/email/verify', { token: 'nope' })).status).toBe(400);
  });

  it('E2: confirming a password sign-up signs the user in with the password as their method, and the old routes are gone', async () => {
    const { app, hook } = passwordApp();
    await post(app, '/auth/password/signup', { email: 'grace@example.com', password: 'correct horse battery', redirectTo: REDIRECT_TO });

    const res = await post(app, '/auth/email/verify', { token: linkAndCode(hook.lastEmail()).token });

    expect(res.status).toBe(200);
    expect((await res.json()).user).toMatchObject({ email: 'grace@example.com', amr: ['pwd'] });
    expect(cookies(res).madauth_session.value).toBeTruthy();
    expect(hook.types().slice(-2)).toEqual(['email.verified', 'user.signed_in']);
    expect(hook.calls.at(-1)!.data).toMatchObject({ method: 'password' });
    expect((await post(app, '/auth/password/verify-email', { token: 'x' })).status).toBe(404);
  });

  it('E3: a user whose method is switched off can neither confirm nor get the e-mail again', async () => {
    const { app, hook, store } = passwordApp();
    await post(app, '/auth/password/signup', { email: 'grace@example.com', password: 'correct horse battery', redirectTo: REDIRECT_TO });
    const { token } = linkAndCode(hook.lastEmail());
    await store.create('setting', { id: 'methods', value: JSON.stringify({ google: {} }), updatedAt: 1, updatedBy: null });
    hook.calls.length = 0;

    const verify = await post(app, '/auth/email/verify', { token });
    const again = await post(app, '/auth/email/send-verification', { email: 'grace@example.com', redirectTo: REDIRECT_TO });

    expect(verify.status).toBe(403);
    expect(await verify.json()).toMatchObject({ error: 'method_disabled' });
    expect(again.status).toBe(202);
    expect(hook.emails()).toEqual([]);
  });

  it('E4: a POST from another origin is refused, like every other', async () => {
    const { app } = passwordApp({ webhook: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET, events: ALL_EVENTS } });

    const res = await app.request('/auth/email/verify', {
      method: 'POST',
      headers: { Origin: 'https://evil.example', 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'x' }),
    });

    expect(res.status).toBe(403);
    expect(res.headers.get('access-control-allow-origin')).not.toBe(APP_ORIGIN);
  });
});
