// Session renewal: a short-lived session token for backends, renewed with a token only this server gets.
// See "Sessions" in docs/server.md.
import { createLocalJWKSet } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { importSigningKeys } from './keys.js';
import { Roles } from './roles.js';
import {
  APP_ORIGIN,
  ISSUER,
  REDIRECT_TO,
  cookieHeader,
  cookies,
  linkAndCode,
  passwordApp,
  post,
  signInResponse,
  signUpVerified,
  signingKey,
  testApp,
} from './test/helpers.js';
import { createSessionVerifier } from './verify.js';

afterEach(() => {
  vi.useRealTimers();
});

type App = ReturnType<typeof testApp>;
const HOUR = 3600 * 1000;
const grace = { email: 'grace@example.com', password: 'correct horse battery' };
const check = (app: App, cookie: string) => app.request('/auth/session', { headers: { Cookie: cookie } });
/** Only the renewal cookie, as when the session cookie has expired in the browser. */
const renewalOnly = (res: Response) => `madauth_renewal=${cookies(res).madauth_renewal.value}`;

/** Moves the clock forward without touching timers, so scrypt's callbacks still run. */
function advance(ms: number) {
  vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
}

describe('the cookies of a session', () => {
  it('are a session token for backends, a renewal token for this server only, and the expiry time for scripts', async () => {
    const now = Math.floor(Date.now() / 1000);
    const set = cookies(await signInResponse(testApp({ cookieDomain: '.example.com' })));

    expect(set.madauth_session.attrs).toMatchObject({ httponly: true, secure: true, samesite: 'Lax', path: '/', 'max-age': '3600', domain: '.example.com' });
    // Path /auth and no Domain: sibling hosts that get the session cookie never get this one.
    expect(set.madauth_renewal.attrs).toMatchObject({ httponly: true, secure: true, samesite: 'Lax', path: '/auth', 'max-age': '2592000' });
    expect(set.madauth_renewal.attrs.domain).toBeUndefined();
    // Readable by scripts, and kept for as long as the session can be renewed.
    expect(set.madauth_session_expires.attrs).toMatchObject({ secure: true, samesite: 'Lax', path: '/', 'max-age': '2592000', domain: '.example.com' });
    expect(set.madauth_session_expires.attrs.httponly).toBeUndefined();
    const expires = Number(set.madauth_session_expires.value);
    expect(expires).toBeGreaterThanOrEqual(now + 3600);
    expect(expires).toBeLessThanOrEqual(now + 3602);
  });

  it('a renewal token is never accepted as a session, here or by a backend', async () => {
    const app = testApp();
    const renewal = cookies(await signInResponse(app)).madauth_renewal.value;
    const { publicJwk } = await importSigningKeys(signingKey);
    const verifySession = createSessionVerifier({ issuer: ISSUER, jwks: createLocalJWKSet({ keys: [publicJwk] }) });

    expect((await check(app, `madauth_session=${renewal}`)).status).toBe(401);
    expect(await verifySession(renewal)).toBeNull();
  });
});

describe('renewal', () => {
  it('gives a new session when the old one has expired, without signing in again', async () => {
    const app = testApp();
    const signedIn = await signInResponse(app);
    advance(2 * HOUR);

    // The session cookie alone is over.
    expect((await check(app, `madauth_session=${cookies(signedIn).madauth_session.value}`)).status).toBe(401);

    const res = await check(app, renewalOnly(signedIn));
    expect(res.status).toBe(200);
    expect((await res.json()).user).toMatchObject({ id: 'google:1001', email: 'ada@example.com' });
    const renewed = cookies(res);
    expect(renewed.madauth_session.value).toBeTruthy();
    expect(renewed.madauth_renewal.value).toBeTruthy();
    expect(Number(renewed.madauth_session_expires.value)).toBeGreaterThan(Date.now() / 1000);
    expect((await check(app, `madauth_session=${renewed.madauth_session.value}`)).status).toBe(200);
  });

  it('each renewal starts the renewal time again, and without one it ends', async () => {
    const app = testApp({ renewalTtlSeconds: 24 * 3600 });
    let last = await signInResponse(app);
    // Three visits, each 20 hours after the one before: 60 hours in all, more than one renewal time.
    for (let visit = 0; visit < 3; visit++) {
      advance(20 * HOUR);
      last = await check(app, renewalOnly(last));
      expect(last.status).toBe(200);
    }

    advance(25 * HOUR);
    const over = await check(app, renewalOnly(last));
    expect(over.status).toBe(401);
    // The web library learns from the cleared cookie that nobody is signed in.
    expect(cookies(over).madauth_session_expires).toMatchObject({ value: '', attrs: { 'max-age': '0' } });
    expect(cookies(over).madauth_renewal).toMatchObject({ value: '', attrs: { 'max-age': '0' } });
  });

  it('a session token without its renewal token lasts until it expires and is not prolonged', async () => {
    const app = testApp();
    const session = `madauth_session=${cookies(await signInResponse(app)).madauth_session.value}`;

    advance(0.75 * HOUR);
    const late = await check(app, session);
    expect(late.status).toBe(200);
    expect(cookies(late).madauth_session).toBeUndefined();
    expect(cookies(late).madauth_renewal).toBeUndefined();
  });

  it('a password reset ends the renewal of older sessions', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    const otherDevice = await post(app, '/auth/password/signin', grace);
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    const reset = await post(app, '/auth/password/reset', { token: linkAndCode(hook.lastEmail()).token, password: 'new password!' });

    expect((await check(app, cookieHeader(otherDevice))).status).toBe(401);
    expect((await check(app, renewalOnly(otherDevice))).status).toBe(401);
    expect((await check(app, renewalOnly(reset))).status).toBe(200);
  });

  it('a deleted account can not be renewed', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    const otherDevice = await post(app, '/auth/password/signin', grace);
    const here = await post(app, '/auth/password/signin', grace);

    const deleted = await app.request('/auth/account/delete', { method: 'POST', headers: { Origin: APP_ORIGIN, Cookie: cookieHeader(here) } });

    expect(deleted.status).toBe(204);
    expect(cookies(deleted).madauth_renewal).toMatchObject({ value: '' });
    expect((await check(app, renewalOnly(otherDevice))).status).toBe(401);
  });

  it('reads the roles again, so a renewed session has the current ones', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook);
    const signedIn = await post(app, '/auth/password/signin', grace);
    await new Roles(store).set('grace@example.com', ['admin'], null);
    advance(2 * HOUR);

    const res = await check(app, renewalOnly(signedIn));

    expect((await res.json()).user.roles).toEqual(['admin']);
    const { publicJwk } = await importSigningKeys(signingKey);
    const verifySession = createSessionVerifier({ issuer: ISSUER, jwks: createLocalJWKSet({ keys: [publicJwk] }) });
    expect((await verifySession(cookies(res).madauth_session.value))?.roles).toEqual(['admin']);
  });

  it('the other routes of this server renew on the way: an expired session token does not sign the user out', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook);
    await new Roles(store).set('grace@example.com', ['admin'], null);
    const signedIn = await post(app, '/auth/password/signin', grace);
    advance(2 * HOUR);

    const res = await app.request('/auth/admin/roles/get', {
      method: 'POST',
      headers: { Origin: APP_ORIGIN, 'Content-Type': 'application/json', Cookie: renewalOnly(signedIn) },
      body: JSON.stringify({ email: 'ada@example.com' }),
    });

    expect(res.status).toBe(200);
    expect(cookies(res).madauth_session.value).toBeTruthy();
  });
});
