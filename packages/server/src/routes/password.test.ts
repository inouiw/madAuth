// Behaviour described in docs/password-security.md; update the doc when changing it.
import { createLocalJWKSet, jwtVerify } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as passwordModule from '../password.js';
import { hashLinkToken, hashPassword } from '../password.js';
import {
  APP_ORIGIN,
  ISSUER,
  REDIRECT_TO,
  cookies,
  linkAndCode,
  passwordApp,
  post,
  signUpVerified,
  testApp,
} from '../test/helpers.js';
import { RESET_TTL_MS, VERIFY_TTL_MS } from './password.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const grace = { email: 'grace@example.com', password: 'correct horse battery' };
const signUp = (app: ReturnType<typeof passwordApp>['app'], body: Record<string, unknown> = {}) =>
  post(app, '/auth/password/signup', { ...grace, name: 'Grace Hopper', redirectTo: REDIRECT_TO, ...body });
const signIn = (app: ReturnType<typeof passwordApp>['app'], body: Record<string, unknown> = {}) =>
  post(app, '/auth/password/signin', { ...grace, ...body });

/** Moves the clock forward without touching timers, so scrypt's callbacks still run. */
function advance(ms: number) {
  vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
}

describe('sign-up and e-mail verification', () => {
  it('A1: sends a link to redirectTo and a code, and stores only their hashes', async () => {
    const { app, hook, store } = passwordApp();

    const res = await signUp(app);

    expect(res.status).toBe(202);
    expect(hook.emails()).toHaveLength(1);
    const mail = hook.emails()[0];
    expect(mail).toMatchObject({
      type: 'email.verify',
      data: { to: 'grace@example.com', site: 'app.example.com', user: { name: 'Grace Hopper' }, expiresAt: expect.any(Number) },
    });
    const { link, token, code } = linkAndCode(mail);
    expect(link.startsWith(`${REDIRECT_TO}#madauth_verify=`)).toBe(true);
    expect(code).toMatch(/^\d{6}$/);

    const records = await store.findMany('verification', {});
    expect(records).toHaveLength(1);
    expect(records[0].id).toBe(hashLinkToken(token));
    expect(JSON.stringify(records)).not.toContain(token);
    expect(JSON.stringify(records)).not.toContain(code);
  });

  it('A2: answers the same for an existing account and mails its owner instead', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    advance(61_000);

    const res = await signUp(app, { password: 'another password' });

    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({});
    expect(hook.lastEmail()).toMatchObject({ type: 'email.already_registered', data: { to: 'grace@example.com', link: REDIRECT_TO } });
    // The existing password still works; the new one doesn't.
    expect((await signIn(app)).status).toBe(200);
    expect((await signIn(app, { password: 'another password' })).status).toBe(401);
  });

  it('rejects an invalid e-mail address or a short password', async () => {
    const { app, hook } = passwordApp();

    expect(await (await signUp(app, { email: 'nope' })).json()).toMatchObject({ error: 'invalid_email' });
    expect(await (await signUp(app, { password: 'short' })).json()).toMatchObject({ error: 'weak_password' });
    expect(hook.emails()).toHaveLength(0);
  });

  it('A3: an unverified account can not sign in', async () => {
    const { app } = passwordApp();
    await signUp(app);

    const res = await signIn(app);

    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: 'email_unverified' });
    expect(cookies(res).madauth_session).toBeUndefined();
  });

  it('A4: the link signs in once, with a madAuth session for the password method', async () => {
    const { app, hook } = passwordApp();
    await signUp(app);
    const { token } = linkAndCode(hook.lastEmail());

    const res = await post(app, '/auth/password/verify-email', { token });

    expect(res.status).toBe(200);
    const { user } = (await res.json()) as { user: { id: string } };
    expect(user).toEqual({ id: expect.stringMatching(/^usr_/), email: 'grace@example.com', name: 'Grace Hopper' });
    const jwks = createLocalJWKSet(await (await app.request('/.well-known/jwks.json')).json());
    const { payload } = await jwtVerify(cookies(res).madauth_session.value, jwks, { issuer: ISSUER });
    expect(payload).toMatchObject({ sub: user.id, amr: ['pwd'], sv: 0 });

    expect(await (await post(app, '/auth/password/verify-email', { token })).json()).toMatchObject({ error: 'link_invalid' });
    expect((await signIn(app)).status).toBe(200);
  });

  it('A4: the code signs in as well, once', async () => {
    const { app, hook } = passwordApp();
    await signUp(app);
    const { code } = linkAndCode(hook.lastEmail());

    const res = await post(app, '/auth/password/verify-email', { email: 'Grace@Example.com', code: `${code.slice(0, 3)} ${code.slice(3)}` });

    expect(res.status).toBe(200);
    expect(cookies(res).madauth_session).toBeDefined();
    expect(await (await post(app, '/auth/password/verify-email', { email: grace.email, code })).json()).toMatchObject({
      error: 'code_invalid',
    });
  });

  it('sends the verification e-mail again on request, but not for verified accounts', async () => {
    const { app, hook } = passwordApp();
    await signUp(app);
    advance(61_000);

    await post(app, '/auth/password/send-verification', { email: grace.email, redirectTo: REDIRECT_TO });

    expect(hook.emails()).toHaveLength(2);
    expect(linkAndCode(hook.emails()[1]).token).not.toBe(linkAndCode(hook.emails()[0]).token);
    await post(app, '/auth/password/verify-email', { token: linkAndCode(hook.lastEmail()).token });
    advance(122_000);
    const res = await post(app, '/auth/password/send-verification', { email: grace.email, redirectTo: REDIRECT_TO });
    expect(res.status).toBe(202);
    expect(hook.emails()).toHaveLength(2);
  });

  it('an unconfirmed sign-up can be repeated; the latest password and e-mail count', async () => {
    const { app, hook } = passwordApp();
    await signUp(app, { password: 'first password' });
    const first = linkAndCode(hook.lastEmail());
    advance(61_000);

    await signUp(app, { password: 'second password' });

    expect(hook.emails()).toHaveLength(2);
    expect((await post(app, '/auth/password/verify-email', { token: first.token })).status).toBe(400);
    await post(app, '/auth/password/verify-email', { token: linkAndCode(hook.lastEmail()).token });
    expect((await signIn(app, { password: 'second password' })).status).toBe(200);
    expect((await signIn(app, { password: 'first password' })).status).toBe(401);
  });
});

describe('sign-in', () => {
  it('A5: answers the same for a wrong password and an unknown e-mail, and hashes in both cases', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    const dummy = vi.spyOn(passwordModule, 'verifyAgainstDummy');

    const wrongPassword = await signIn(app, { password: 'wrong password' });
    const unknownEmail = await signIn(app, { email: 'nobody@example.com' });

    expect(wrongPassword.status).toBe(401);
    expect(unknownEmail.status).toBe(401);
    expect(await wrongPassword.json()).toEqual(await unknownEmail.json());
    expect(dummy).toHaveBeenCalledOnce();
  });

  it('A6: makes further attempts wait after 5 failures, then resets the count on success', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);

    for (let i = 0; i < 5; i++) expect((await signIn(app, { password: 'wrong password' })).status).toBe(401);
    const locked = await signIn(app);

    expect(locked.status).toBe(429);
    expect(await locked.json()).toMatchObject({ error: 'too_many_attempts' });
    advance(1_100);
    expect((await signIn(app)).status).toBe(200);
    // The count was reset: another wrong password is a plain 401 again, and the right one works.
    expect((await signIn(app, { password: 'wrong password' })).status).toBe(401);
    expect((await signIn(app)).status).toBe(200);
  });

  it('A6: wrong passwords sent at the same time can not get around the wait', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook);
    await store.update('account', {}, { failedAttempts: 10 });

    const answers = await Promise.all(Array.from({ length: 5 }, () => signIn(app, { password: 'wrong password' })));

    expect(answers.map((res) => res.status).sort()).toEqual([401, 429, 429, 429, 429]);
    const [account] = await store.findMany('account', {});
    expect(account.failedAttempts).toBe(11);
    expect(account.lockedUntil as number).toBeGreaterThan(Date.now());
  });

  it('A6: the wait doubles with every further failure, up to 15 minutes', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook);
    await store.update('account', {}, { failedAttempts: 30 });

    const before = Date.now();
    await signIn(app, { password: 'wrong password' });

    const [account] = await store.findMany('account', {});
    expect(account.lockedUntil as number).toBeLessThanOrEqual(Date.now() + 15 * 60 * 1000);
    expect(account.lockedUntil as number).toBeGreaterThanOrEqual(before + 15 * 60 * 1000);
  });

  it('P2: replaces a hash with older parameters after a successful sign-in', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook);
    await store.update('account', {}, { secret: await hashPassword(grace.password, { logN: 14, r: 8, p: 1 }) });

    expect((await signIn(app)).status).toBe(200);

    const [account] = await store.findMany('account', {});
    expect(account.secret).toMatch(/^scrypt\$15\$8\$3\$/);
    expect((await signIn(app)).status).toBe(200);
  });

  it('A15: rejects requests from origins that are not allowed', async () => {
    const { app } = passwordApp();

    const res = await signIn(app);
    const evil = await post(app, '/auth/password/signin', grace, { Origin: 'https://evil.example' });

    expect(res.status).toBe(401);
    expect(evil.status).toBe(403);
  });
});

describe('password reset', () => {
  it('A7: resets with the link, signs in and ends older sessions', async () => {
    const { app, hook } = passwordApp();
    const oldSession = await signUpVerified(app, hook);
    advance(61_000);

    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const { link, token } = linkAndCode(hook.lastEmail());
    expect(link.startsWith(`${REDIRECT_TO}#madauth_reset=`)).toBe(true);
    const res = await post(app, '/auth/password/reset', { token, password: 'new password!' });

    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ user: { email: grace.email } });
    const newSession = cookies(res).madauth_session.value;
    const session = (cookie: string) => app.request('/auth/session', { headers: { Cookie: `madauth_session=${cookie}` } });
    expect((await session(oldSession)).status).toBe(401);
    expect((await session(newSession)).status).toBe(200);
    expect((await signIn(app)).status).toBe(401);
    expect((await signIn(app, { password: 'new password!' })).status).toBe(200);
    expect(await (await post(app, '/auth/password/reset', { token, password: 'other password' })).json()).toMatchObject({
      error: 'link_invalid',
    });
  });

  it('A7: resets with the code, and also confirms an unverified e-mail address', async () => {
    const { app, hook } = passwordApp();
    await signUp(app);
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const { code } = linkAndCode(hook.lastEmail());

    const res = await post(app, '/auth/password/reset', { email: grace.email, code, password: 'new password!' });

    expect(res.status).toBe(200);
    expect((await signIn(app, { password: 'new password!' })).status).toBe(200);
  });

  it('a reset ends an unused confirmation link', async () => {
    const { app, hook } = passwordApp();
    await signUp(app);
    const { token: verifyToken } = linkAndCode(hook.lastEmail());
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const { token } = linkAndCode(hook.lastEmail());

    expect((await post(app, '/auth/password/reset', { token, password: 'new password!' })).status).toBe(200);

    const res = await post(app, '/auth/password/verify-email', { token: verifyToken });
    expect(await res.json()).toMatchObject({ error: 'link_invalid' });
  });

  it('a weak new password does not use up the link', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const { token } = linkAndCode(hook.lastEmail());

    expect(await (await post(app, '/auth/password/reset', { token, password: 'short' })).json()).toMatchObject({ error: 'weak_password' });
    expect((await post(app, '/auth/password/reset', { token, password: 'long enough' })).status).toBe(200);
  });

  it('A8: links and codes expire', async () => {
    const { app, hook } = passwordApp();
    await signUp(app);
    const verify = linkAndCode(hook.lastEmail());
    advance(VERIFY_TTL_MS + 60_000);
    expect(await (await post(app, '/auth/password/verify-email', { token: verify.token })).json()).toMatchObject({ error: 'link_invalid' });

    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const reset = linkAndCode(hook.lastEmail());
    advance(VERIFY_TTL_MS + 60_000 + RESET_TTL_MS + 60_000);
    expect(await (await post(app, '/auth/password/reset', { email: grace.email, code: reset.code, password: 'new password!' })).json()).toMatchObject({
      error: 'code_invalid',
    });
  });

  it('A9: only sends links to allowed pages', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    advance(61_000);

    const res = await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: 'https://evil.example/x' });

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_options' });
    expect(hook.emails()).toHaveLength(1);
  });

  it('A10: sends at most one e-mail per minute and account, and answers the same', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    advance(61_000);

    const first = await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const second = await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const unknown = await post(app, '/auth/password/send-reset', { email: 'nobody@example.com', redirectTo: REDIRECT_TO });

    expect([first.status, second.status, unknown.status]).toEqual([202, 202, 202]);
    expect(hook.emails().filter((m) => m.type === 'email.reset')).toHaveLength(1);
  });

  it('A11: a code stops working after 5 wrong attempts', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const { code, token } = linkAndCode(hook.lastEmail());
    const wrong = code === '000000' ? '111111' : '000000';

    for (let i = 0; i < 5; i++) {
      const res = await post(app, '/auth/password/reset', { email: grace.email, code: wrong, password: 'new password!' });
      expect(await res.json()).toMatchObject({ error: 'code_invalid' });
    }

    expect((await post(app, '/auth/password/reset', { email: grace.email, code, password: 'new password!' })).status).toBe(400);
    expect((await post(app, '/auth/password/reset', { token, password: 'new password!' })).status).toBe(400);
  });

  it('A12: a new e-mail replaces the earlier link and code', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const first = linkAndCode(hook.lastEmail());
    advance(122_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const second = linkAndCode(hook.lastEmail());

    expect((await post(app, '/auth/password/reset', { token: first.token, password: 'new password!' })).status).toBe(400);
    expect((await post(app, '/auth/password/reset', { email: grace.email, code: first.code, password: 'new password!' })).status).toBe(400);
    expect((await post(app, '/auth/password/reset', { token: second.token, password: 'new password!' })).status).toBe(200);
  });
});

describe('configuration', () => {
  it('A13: the password routes are off without a store', async () => {
    const app = testApp();

    expect((await post(app, '/auth/password/signin', grace)).status).toBe(404);
    expect(await (await app.request('/auth/config')).json()).toMatchObject({ password: null });
  });

  it('reports the password policy and works without Google', async () => {
    const { app } = passwordApp({ google: undefined });

    expect(await (await app.request('/auth/config')).json()).toEqual({ google: null, password: { minLength: 8 } });
    expect((await app.request('/auth/google/nonce', { method: 'POST', headers: { Origin: APP_ORIGIN } })).status).toBe(404);
  });
});
