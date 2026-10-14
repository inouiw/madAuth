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
  setMethods,
  testApp,
} from '../test/helpers.js';

describe('e-mail confirmation', () => {
  it('E1: a server whose webhook only sends email.send_verification confirms addresses, without password sign-in', async () => {
    const hook = recordingWebhook();
    const app = testApp({ webhook: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET, events: new Set(['email.send_verification']) }, webhookFetch: hook.fetch });

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
    // Confirmed, and in for the first time: the sign-up is complete.
    expect(hook.types().slice(-3)).toEqual(['user.email_verified', 'user.signed_up', 'user.signed_in']);
    expect(hook.calls.at(-3)!.data).toMatchObject({ method: 'password', via: 'link' });
    expect(hook.calls.at(-2)!.data).toMatchObject({ method: 'password', user: { email: 'grace@example.com' } });
    expect(hook.calls.at(-1)!.data).toMatchObject({ method: 'password' });
    expect((await post(app, '/auth/password/verify-email', { token: 'x' })).status).toBe(404);
  });

  it('E3: a user whose method is switched off can neither confirm nor get the e-mail again', async () => {
    const { app, hook, store } = passwordApp();
    await post(app, '/auth/password/signup', { email: 'grace@example.com', password: 'correct horse battery', redirectTo: REDIRECT_TO });
    const { token, code } = linkAndCode(hook.lastEmail());
    await store.create('setting', { id: 'methods', value: JSON.stringify({ google: {} }), updatedAt: 1, updatedBy: null });
    hook.calls.length = 0;

    const verify = await post(app, '/auth/email/verify', { token });
    const byCode = await post(app, '/auth/email/verify', { email: 'grace@example.com', code });
    const again = await post(app, '/auth/email/send-verification', { email: 'grace@example.com', redirectTo: REDIRECT_TO });

    expect(verify.status).toBe(403);
    expect(await verify.json()).toMatchObject({ error: 'method_disabled' });
    expect(byCode.status).toBe(403);
    expect(again.status).toBe(202);
    expect(hook.emails()).toEqual([]);

    // Neither the link nor the code was used up: they work once the method is on again.
    await store.update('setting', { id: 'methods' }, { value: JSON.stringify({ google: {}, password: {} }) });
    expect((await post(app, '/auth/email/verify', { email: 'grace@example.com', code })).status).toBe(200);
  });

  it('E5: the sign-up records the method it confirms the address for; a record without it is read as before', async () => {
    const { app, hook, store } = passwordApp();
    await setMethods(store, { password: {}, totp: {}, passkey: {} });
    const signUp = async (path: string, email: string, password?: string) => {
      await post(app, path, { email, password, redirectTo: REDIRECT_TO });
      const [user] = await store.findMany('user', { emailNormalized: email });
      return { user, token: linkAndCode(hook.lastEmail()).token };
    };
    const passkey = await signUp('/auth/passkey/signup', 'grace@example.com');
    const withApp = await signUp('/auth/totp/signup', 'ada@example.com');
    const password = await signUp('/auth/password/signup', 'alan@example.com', 'correct horse battery');
    expect([passkey, withApp, password].map(({ user }) => user.signUpMethod)).toEqual(['passkey', 'totp', 'password']);

    expect(await (await post(app, '/auth/email/verify', { token: passkey.token })).json()).toMatchObject({ factors: ['passkey'] });
    expect(await (await post(app, '/auth/email/verify', { token: withApp.token })).json()).toMatchObject({ factors: ['totp'] });

    // A user stored before schema version 9: a password if there is one (else the app), as before.
    await store.update('user', { id: password.user.id }, { signUpMethod: null });
    expect((await post(app, '/auth/email/verify', { token: password.token })).status).toBe(200);
    const older = await signUp('/auth/passkey/signup', 'mary@example.com');
    await store.update('user', { id: older.user.id }, { signUpMethod: null });
    expect(await (await post(app, '/auth/email/verify', { token: older.token })).json()).toMatchObject({ error: 'totp_setup_required', factors: ['totp'] });
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
