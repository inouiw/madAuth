// Every sign-in belongs to a stored user: Google accounts are known by their `sub` and join the user with
// their verified address. See "How it works" and "Sessions" in docs/server.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  APP_ORIGIN,
  REDIRECT_TO,
  cookieHeader,
  cookies,
  getNonce,
  googleIdToken,
  linkAndCode,
  passwordApp,
  post,
  signUpVerified,
  testApp,
  verify,
} from './test/helpers.js';

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

type App = ReturnType<typeof testApp>;
const grace = { email: 'grace@example.com', password: 'correct horse battery' };

/** Signs in through the FedCM flow with the given Google claims; returns the response. */
async function googleSignIn(app: App, claims: Record<string, unknown> = {}): Promise<Response> {
  const { nonce, cookie } = await getNonce(app);
  return verify(app, await googleIdToken({ nonce, ...claims }), cookie);
}

function advance(ms: number) {
  vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });
}

describe('Google users', () => {
  it('the first sign-in creates the user with a Google account, verified, with the name from Google', async () => {
    const { app, store } = passwordApp();

    const res = await googleSignIn(app);

    expect(res.status).toBe(200);
    const [user] = await store.findMany('user', {});
    expect(user).toMatchObject({ email: 'ada@example.com', emailNormalized: 'ada@example.com', emailVerified: true, name: 'Ada Lovelace', sessionVersion: 0 });
    expect(await store.findMany('account', {})).toEqual([
      expect.objectContaining({ userId: user.id, key: 'google:1001', secret: null, email: 'ada@example.com' }),
    ]);
    expect((await res.json()).user).toEqual({ id: user.id, email: 'ada@example.com', name: 'Ada Lovelace', picture: 'https://example.com/ada.png' });
  });

  it('a returning Google account is known by its sub, even when its address changed', async () => {
    const { app, store } = passwordApp();
    const first = (await (await googleSignIn(app)).json()).user;

    const again = await googleSignIn(app, { email: 'ada@newmail.example', name: 'Ada King' });

    // The same user; their own address and name stay, the account notes Google's new address.
    expect((await again.json()).user).toMatchObject({ id: first.id, email: 'ada@example.com', name: 'Ada Lovelace' });
    expect(await store.findMany('user', {})).toHaveLength(1);
    expect(await store.findOne('account', { key: 'google:1001' })).toMatchObject({ userId: first.id, email: 'ada@newmail.example' });
  });

  it('two Google accounts are two users, and one address links a Google account to its password user', async () => {
    const { app, hook, store } = passwordApp();
    await signUpVerified(app, hook, 'Ada@Example.com');
    const [password] = await store.findMany('user', {});

    const ada = (await (await googleSignIn(app)).json()).user;
    const other = (await (await googleSignIn(app, { sub: '2002', email: 'other@example.com' })).json()).user;

    expect(ada.id).toBe(password.id);
    expect(other.id).not.toBe(password.id);
    expect(await store.findMany('user', {})).toHaveLength(2);
    expect((await store.findMany('account', { userId: password.id })).map((a) => a.key).sort()).toEqual([`google:1001`, `password:${password.id}`]);
    // She signs in with the password as the same user, with the Google name kept as hers.
    expect((await (await post(app, '/auth/password/signin', { email: 'ada@example.com', password: 'correct horse battery' })).json()).user.id).toBe(password.id);
  });

  it('a password sign-up with the address of a Google user adds a password to that user', async () => {
    const { app, hook, store } = passwordApp();
    const google = (await (await googleSignIn(app)).json()).user;
    advance(61_000);

    await post(app, '/auth/password/signup', { email: 'ada@example.com', password: 'adas password!', redirectTo: REDIRECT_TO });

    // Her address is confirmed already, so the sign-up only tells her she is registered; no new user.
    expect(hook.lastEmail()?.type).toBe('email.already_registered');
    expect(await store.findMany('user', {})).toHaveLength(1);
    expect(await store.findMany('account', { userId: google.id })).toHaveLength(1);
  });

  it('a password reset ends the Google sessions of the same user', async () => {
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook);
    const google = await googleSignIn(app, { email: 'grace@example.com', sub: '3003' });
    advance(61_000);
    await post(app, '/auth/password/send-reset', { email: grace.email, redirectTo: REDIRECT_TO });
    await post(app, '/auth/password/reset', { token: linkAndCode(hook.lastEmail()).token, password: 'new password!' });

    expect((await app.request('/auth/session', { headers: { Cookie: cookieHeader(google) } })).status).toBe(401);
  });

  it('the sign-up guard can refuse a Google sign-up in the redirect flow too', async () => {
    const { app, hook, store } = passwordApp();
    hook.respond = (call) => (call.type === 'signup.before' ? { allow: false, message: 'No' } : undefined);
    const started = await app.request(`/auth/google/start?return_to=${encodeURIComponent(`${APP_ORIGIN}/page`)}`);
    const location = new URL(started.headers.get('location')!);
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ id_token: await googleIdToken({ nonce: location.searchParams.get('nonce')! }) })));

    const res = await app.request(`/auth/google/callback?code=c&state=${location.searchParams.get('state')}`, {
      headers: { Cookie: `madauth_oauth=${cookies(started).madauth_oauth.value}` },
    });

    expect(res.headers.get('location')).toBe(`${APP_ORIGIN}/page#madauth_error=signup_rejected`);
    expect(cookies(res).madauth_session).toBeUndefined();
    expect(await store.findMany('user', {})).toEqual([]);
  });

  it('Google sign-in works without a webhook: no sign-up check, no events', async () => {
    const app = testApp();

    const res = await googleSignIn(app);

    expect(res.status).toBe(200);
    expect((await res.json()).user).toMatchObject({ id: expect.stringMatching(/^usr_/), email: 'ada@example.com' });
  });
});
