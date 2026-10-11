// GitHub sign-in: GET /auth/github/start and GET /auth/github/callback. See "HTTP API" in docs/server.md
// and docs/github-security.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { METHODS_SETTING, Settings, type MethodSettings } from '../settings.js';
import type { StoreAdapter } from '../store/schema.js';
import {
  APP_ORIGIN,
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  ISSUER,
  REDIRECT_TO,
  cookieHeader,
  cookies,
  githubApp,
  githubCallback,
  passwordApp,
  post,
  signInWithGithub,
  signUpVerified,
  signingKey,
  startGithub,
  stubGithub,
  testApp,
} from '../test/helpers.js';
import { decryptSecret, deriveTokenKey } from '../totp.js';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const GITHUB = { clientId: GITHUB_CLIENT_ID, clientSecret: GITHUB_CLIENT_SECRET };
const tokenKey = deriveTokenKey(signingKey.d!);
const setMethods = (store: StoreAdapter, methods: MethodSettings) => new Settings(store).set(METHODS_SETTING, methods, null);
const session = (app: ReturnType<typeof testApp>, res: Response) => app.request('/auth/session', { headers: { Cookie: cookieHeader(res) } });

describe('GitHub sign-in', () => {
  it('O1: redirects to GitHub with the client id, the callback, the e-mail scope, a state and an S256 PKCE challenge', async () => {
    const { res, location, cookie } = await startGithub(githubApp(), `${APP_ORIGIN}/page?x=1#old`);

    expect(res.status).toBe(302);
    expect(location.origin + location.pathname).toBe('https://github.com/login/oauth/authorize');
    const params = Object.fromEntries(location.searchParams);
    expect(params).toMatchObject({ client_id: GITHUB_CLIENT_ID, redirect_uri: `${ISSUER}/auth/github/callback`, scope: 'user:email', code_challenge_method: 'S256' });
    expect(params.state).toBeTruthy();
    expect(params.nonce).toBeUndefined();
    // The challenge is the SHA-256 of the verifier kept in the (signed) cookie, which comes back on the callback only.
    const payload = JSON.parse(Buffer.from(cookie.split('.')[1], 'base64url').toString());
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload.verifier));
    expect(params.code_challenge).toBe(Buffer.from(digest).toString('base64url'));
    expect(payload.returnTo).toBe(`${APP_ORIGIN}/page?x=1`);
    expect(cookies(res).madauth_oauth.attrs).toMatchObject({ path: '/auth/github', httponly: true, samesite: 'Lax' });
  });

  it('O1: refuses a return_to outside ALLOWED_ORIGINS, and has no routes without GITHUB_CLIENT_ID', async () => {
    expect((await startGithub(githubApp(), 'https://evil.example/')).res.status).toBe(400);
    expect((await startGithub(testApp())).res.status).toBe(404);
    expect((await (await testApp().request('/auth/config')).json()).github).toBeNull();
    expect((await (await githubApp().request('/auth/config')).json()).github).toEqual({ secondFactor: 'none' });
  });

  it('O2: the callback needs the state cookie and the state GitHub sends back, and reports a refusal at GitHub', async () => {
    const app = githubApp();
    stubGithub();

    expect((await app.request('/auth/github/callback?code=c&state=s')).status).toBe(400);
    const mismatch = await githubCallback(app, await startGithub(app), 'code=c&state=forged');
    const cancelled = await githubCallback(app, await startGithub(app), 'error=access_denied');
    const other = await githubCallback(app, await startGithub(app), 'error=application_suspended');

    expect(mismatch.headers.get('location')).toBe(`${APP_ORIGIN}/page#madauth_error=verification_failed&madauth_method=github`);
    expect(cancelled.headers.get('location')).toBe(`${APP_ORIGIN}/page#madauth_error=cancelled&madauth_method=github`);
    expect(other.headers.get('location')).toBe(`${APP_ORIGIN}/page#madauth_error=verification_failed&madauth_method=github`);
    // The cookie is used up by the callback that got it.
    expect(cookies(mismatch).madauth_oauth).toMatchObject({ value: '' });
    for (const res of [mismatch, cancelled, other]) expect(cookies(res).madauth_session).toBeUndefined();
  });

  it('O3: exchanges the code as the app, with the PKCE verifier, and fails when GitHub issues no token', async () => {
    const app = githubApp();
    const github = stubGithub();
    const started = await startGithub(app);

    const res = await githubCallback(app, started);

    expect(res.headers.get('location')).toBe(`${APP_ORIGIN}/page`);
    const [exchange] = github.exchanges();
    expect(new Headers(exchange.init.headers).get('accept')).toBe('application/json');
    const payload = JSON.parse(Buffer.from(started.cookie.split('.')[1], 'base64url').toString());
    expect(Object.fromEntries(exchange.body)).toEqual({
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
      code: 'c',
      redirect_uri: `${ISSUER}/auth/github/callback`,
      code_verifier: payload.verifier,
    });
    // The API is called with the token, and with a User-Agent, which api.github.com insists on.
    const user = github.calls.find((c) => c.url === 'https://api.github.com/user')!;
    expect(new Headers(user.init.headers).get('authorization')).toBe('Bearer gho_test');
    expect(new Headers(user.init.headers).get('user-agent')).toBeTruthy();

    // GitHub answers a bad code with HTTP 200 and an error: no token, no sign-in.
    vi.unstubAllGlobals();
    stubGithub({ token: null });
    const failed = await signInWithGithub(app);
    expect(failed.headers.get('location')).toBe(`${APP_ORIGIN}/page#madauth_error=verification_failed&madauth_method=github`);
    expect(cookies(failed).madauth_session).toBeUndefined();
  });

  it('O4: only an address GitHub has verified counts: the primary one, else another verified one, else nobody signs in', async () => {
    const { app, store } = passwordApp({ github: GITHUB });
    stubGithub({ emails: [{ email: 'ada@example.com', primary: true, verified: false }] });
    const unverified = await signInWithGithub(app);
    expect(unverified.headers.get('location')).toBe(`${APP_ORIGIN}/page#madauth_error=email_unverified&madauth_method=github`);
    expect(await store.findMany('user', {})).toEqual([]);

    vi.unstubAllGlobals();
    stubGithub({
      user: { email: 'typed-in@example.com' },
      emails: [
        { email: 'ada@example.com', primary: true, verified: false },
        { email: 'ada@work.example', primary: false, verified: true },
      ],
    });
    const res = await signInWithGithub(app);
    expect(res.headers.get('location')).toBe(`${APP_ORIGIN}/page`);
    expect((await (await session(app, res)).json()).user.email).toBe('ada@work.example');
  });

  it('O5: the first sign-in creates the user, verified, with the name and picture from GitHub, the token kept encrypted, and tells the webhook', async () => {
    const { app, hook, store } = passwordApp({ github: GITHUB });
    stubGithub();

    const res = await signInWithGithub(app, `${APP_ORIGIN}/page?x=1`);

    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe(`${APP_ORIGIN}/page?x=1`);
    expect(cookies(res).madauth_session.value).toBeTruthy();
    const [user] = await store.findMany('user', {});
    expect(user).toMatchObject({ email: 'ada@example.com', emailNormalized: 'ada@example.com', emailVerified: true, name: 'Ada Lovelace' });
    const [account] = await store.findMany('account', {});
    expect(account).toMatchObject({ userId: user.id, key: 'github:7001', email: 'ada@example.com' });
    expect(decryptSecret(tokenKey, account.secret as string)?.toString()).toBe('gho_test');
    expect((await (await session(app, res)).json()).user).toEqual({
      id: user.id,
      email: 'ada@example.com',
      name: 'Ada Lovelace',
      picture: 'https://avatars.githubusercontent.com/u/7001',
      amr: ['github'],
    });
    expect(hook.types()).toEqual(['signup.before', 'user.created', 'user.signed_in']);
    expect(hook.calls[0].data).toEqual({ email: 'ada@example.com', name: 'Ada Lovelace', method: 'github' });
    expect(hook.calls[1].data).toEqual({ user: { id: user.id, email: 'ada@example.com', name: 'Ada Lovelace' }, method: 'github' });
    expect(hook.calls[2].data).toEqual({ user: { id: user.id, email: 'ada@example.com', name: 'Ada Lovelace', picture: 'https://avatars.githubusercontent.com/u/7001' }, method: 'github' });
  });

  it('O5: an account without a display name is named by its login', async () => {
    const app = githubApp();
    stubGithub({ user: { name: null } });

    const res = await signInWithGithub(app);

    expect((await (await session(app, res)).json()).user).toMatchObject({ name: 'ada' });
  });

  it('O6: a returning GitHub account is known by its id, even when its address and name changed; the token is the latest', async () => {
    const { app, store } = passwordApp({ github: GITHUB });
    stubGithub();
    const first = (await (await session(app, await signInWithGithub(app))).json()).user;

    vi.unstubAllGlobals();
    stubGithub({ token: 'gho_second', user: { login: 'ada-king', name: 'Ada King' }, emails: [{ email: 'ada@newmail.example', primary: true, verified: true }] });
    const again = await signInWithGithub(app);

    // The same user; their own address and name stay, the account notes GitHub's new address.
    expect((await (await session(app, again)).json()).user).toMatchObject({ id: first.id, email: 'ada@example.com', name: 'Ada Lovelace' });
    expect(await store.findMany('user', {})).toHaveLength(1);
    const account = await store.findOne('account', { key: 'github:7001' });
    expect(account).toMatchObject({ userId: first.id, email: 'ada@newmail.example' });
    expect(decryptSecret(tokenKey, account!.secret as string)?.toString()).toBe('gho_second');
  });

  it('O7: a GitHub sign-in never joins a user who signs in another way: the address is refused', async () => {
    const { app, hook, store } = passwordApp({ github: GITHUB });
    await signUpVerified(app, hook, 'Ada@Example.com');
    const [password] = await store.findMany('user', {});
    stubGithub();

    const refused = await signInWithGithub(app);

    // Whoever controls the GitHub account must not get past her password (and authenticator app).
    expect(refused.headers.get('location')).toBe(`${APP_ORIGIN}/page#madauth_error=other_method&madauth_method=github`);
    expect(cookies(refused).madauth_session).toBeUndefined();
    expect((await store.findMany('account', { userId: password.id })).map((a) => a.key)).toEqual([`password:${password.id}`]);
    expect(await store.findMany('user', {})).toHaveLength(1);
  });

  it('O8: a sign-up that was never confirmed is taken over: GitHub proved the address, the unproven password goes', async () => {
    const { app, hook, store } = passwordApp({ github: GITHUB });
    await post(app, '/auth/password/signup', { email: 'ada@example.com', password: 'correct horse battery', name: 'Ada', redirectTo: REDIRECT_TO });
    const [unconfirmed] = await store.findMany('user', {});
    expect(unconfirmed.emailVerified).toBe(false);
    hook.calls.length = 0;
    stubGithub();

    const res = await signInWithGithub(app);

    expect(res.headers.get('location')).toBe(`${APP_ORIGIN}/page`);
    expect((await (await session(app, res)).json()).user).toMatchObject({ id: unconfirmed.id, name: 'Ada', amr: ['github'] });
    expect(await store.findMany('user', {})).toHaveLength(1);
    expect(await store.findOne('user', { id: unconfirmed.id })).toMatchObject({ emailVerified: true });
    expect((await store.findMany('account', {})).map((a) => a.key)).toEqual(['github:7001']);
    expect(hook.types()).toEqual(['user.signed_in']);
  });

  it('O9: the sign-up check can refuse a GitHub sign-up, and GitHub sign-in works without a webhook', async () => {
    const { app, hook, store } = passwordApp({ github: GITHUB });
    hook.respond = (call) => (call.type === 'signup.before' ? { allow: false, message: 'No' } : undefined);
    stubGithub();

    const res = await signInWithGithub(app);

    expect(res.headers.get('location')).toBe(`${APP_ORIGIN}/page#madauth_error=signup_rejected&madauth_method=github`);
    expect(cookies(res).madauth_session).toBeUndefined();
    expect(await store.findMany('user', {})).toEqual([]);

    expect((await signInWithGithub(githubApp())).headers.get('location')).toBe(`${APP_ORIGIN}/page`);
  });

  it('O10: an admin switches GitHub off and on, and gives it a policy for the second factor', async () => {
    const { app, store } = passwordApp({ github: GITHUB });
    stubGithub();
    const config = async () => (await (await app.request('/auth/config')).json()).github;
    const started = await startGithub(app);

    await setMethods(store, { google: { secondFactor: 'none' }, password: { secondFactor: 'none' } });
    expect(await config()).toBeNull();
    expect((await startGithub(app)).res.status).toBe(403);
    expect(await (await startGithub(app)).res.json()).toEqual({ error: 'method_disabled', message: 'GitHub sign-in is switched off.' });
    expect((await githubCallback(app, started)).status).toBe(403);

    await setMethods(store, { github: { secondFactor: 'required' }, password: { secondFactor: 'none' } });
    expect(await config()).toEqual({ secondFactor: 'required' });
    const res = await signInWithGithub(app);
    // Nobody has an app yet: the sign-in goes on with its setup, and the session waits for it.
    expect(res.headers.get('location')).toBe(`${APP_ORIGIN}/page#madauth_next=totp-setup&madauth_method=github`);
    expect(cookies(res).madauth_session?.value ?? '').toBe('');
    expect(cookies(res).madauth_challenge.value).toBeTruthy();
  });

  it('O11: a GitHub user can be deleted, and GitHub sign-in works next to Google, password and the e-mail link on one server', async () => {
    const { app, hook, store } = passwordApp({ github: GITHUB });
    stubGithub();
    const res = await signInWithGithub(app);
    await signUpVerified(app, hook);
    expect(await store.findMany('user', {})).toHaveLength(2);

    const gone = await app.request('/auth/account/delete', { method: 'POST', headers: { Origin: APP_ORIGIN, Cookie: cookieHeader(res) } });

    expect(gone.status).toBe(204);
    expect((await store.findMany('user', {})).map((u) => u.email)).toEqual(['grace@example.com']);
    expect((await store.findMany('account', {})).map((a) => String(a.key).split(':')[0])).toEqual(['password']);
  });
});
