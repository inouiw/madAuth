// Sign in with Apple: see "Apple setup" in docs/server.md and docs/apple-security.md.
import { decodeJwt } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { appleKeyPem, appleUserName } from './apple.js';
import { parseProviderFields, parseProviderKind } from './providers.js';
import { setupToken } from './setup.js';
import { ISSUER, keyService, passwordApp, post, setClaims, signUpVerified } from './test/helpers.js';
import { APPLE_BUNDLE_ID, APPLE_CLIENT_ID, APPLE_KEY_ID, APPLE_TEAM_ID, fakeApple, type FakeApple, type FakeAppleSignIn } from './test/apple.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const APP = 'https://app.example.com';
const ON = { allowAsSignInMethod: true, secondFactor: 'none' } as const;
const CALLBACK = 'https://auth.example.com/auth/providers/apple/callback';

describe('what an admin sends for the Apple provider', () => {
  it('AP1: its id is its kind; the Services ID, the Team ID, the Key ID and the .p8 key are needed, the App IDs are optional, and only Apple has them', async () => {
    const apple = await fakeApple();
    const APPLE = { kind: 'apple', clientId: APPLE_CLIENT_ID, clientSecret: apple.privateKeyPem, teamId: APPLE_TEAM_ID, keyId: APPLE_KEY_ID };
    expect(parseProviderKind({ kind: 'apple' })).toEqual({ kind: 'apple', id: 'apple' });
    expect(parseProviderKind({ kind: 'apple', id: 'icloud' })).toMatchObject({ error: 'invalid_provider' });
    expect(parseProviderKind({ kind: 'oidc', id: 'apple' })).toMatchObject({ error: 'invalid_provider' });
    expect(parseProviderFields('apple', APPLE, true)).toEqual({ clientId: APPLE_CLIENT_ID, clientSecret: apple.privateKeyPem, teamId: APPLE_TEAM_ID, keyId: APPLE_KEY_ID });
    expect(parseProviderFields('apple', { ...APPLE, bundleIds: `${APPLE_BUNDLE_ID} com.example.app.mac` }, true)).toMatchObject({ bundleIds: [APPLE_BUNDLE_ID, 'com.example.app.mac'] });
    expect(parseProviderFields('apple', { ...APPLE, bundleIds: [APPLE_BUNDLE_ID] }, true)).toMatchObject({ bundleIds: [APPLE_BUNDLE_ID] });
    // The key as a JSON string or an environment variable holds it, or pasted on one line: the same PEM.
    expect(parseProviderFields('apple', { ...APPLE, clientSecret: apple.privateKeyPem.replace(/\n/g, '\\n') }, true)).toMatchObject({ clientSecret: apple.privateKeyPem });
    expect(parseProviderFields('apple', { ...APPLE, clientSecret: apple.privateKeyPem.replace(/\n/g, ' ') }, true)).toMatchObject({ clientSecret: apple.privateKeyPem });
    for (const [field, value] of [
      ['teamId', undefined],
      ['teamId', 'team'],
      ['keyId', undefined],
      ['keyId', 'key-1234567'],
      ['clientId', 'not a services id'],
      ['clientSecret', undefined],
      ['clientSecret', 'a fixed secret'],
      ['clientSecret', '-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----'],
      ['bundleIds', 'com.example.app, not a bundle id!'],
    ] as const) {
      expect(parseProviderFields('apple', { ...APPLE, [field]: value }, true)).toMatchObject({ error: 'invalid_provider', message: expect.stringContaining(field) });
    }
    expect(parseProviderFields('github', { teamId: APPLE_TEAM_ID }, false)).toMatchObject({ message: '"teamId" is a field of the Apple provider only.' });
    expect(parseProviderFields('apple', { tenant: 'common' }, false)).toMatchObject({ message: '"tenant" is a field of the Microsoft provider only.' });
    // An update changes any of them, or none.
    expect(parseProviderFields('apple', { name: 'Apple ID' }, false)).toEqual({ name: 'Apple ID' });
    expect(parseProviderFields('apple', { bundleIds: '' }, false)).toEqual({ bundleIds: [] });
    expect(appleKeyPem('nonsense')).toBeNull();
    expect(appleUserName('{"name":{"firstName":" Grace ","lastName":"Hopper"},"email":"g@example.com"}')).toBe('Grace Hopper');
    expect(appleUserName({ name: { firstName: 'Grace' } })).toBe('Grace');
    expect(appleUserName({ name: 'Grace Hopper' })).toBe('Grace Hopper');
    expect(appleUserName('{"name":{}}')).toBeUndefined();
    expect(appleUserName('not json')).toBeUndefined();
  });
});

describe('signing in with Apple', () => {
  /** A server with Apple added and on, next to e-mail & password, with Ada, an admin who signed in just now. */
  async function withApple(bundleIds: string[] = [APPLE_BUNDLE_ID]) {
    vi.useFakeTimers({ toFake: ['Date'], now: 1_700_000_000_000 });
    const apple = await fakeApple();
    const made = passwordApp({ google: undefined, oidcFetch: apple.fetch });
    const cookie = `madauth_session=${await signUpVerified(made.app, made.hook, 'ada@example.com', 'the admins own password')}`;
    await setClaims(made.store, 'ada@example.com', { roles: ['admin'] });
    const fields = { kind: 'apple', clientId: APPLE_CLIENT_ID, clientSecret: apple.privateKeyPem, teamId: APPLE_TEAM_ID, keyId: APPLE_KEY_ID, bundleIds };
    const added = await post(made.app, '/auth/admin/providers/add', fields, { Cookie: cookie });
    expect(added.status).toBe(200);
    expect((await post(made.app, '/auth/admin/settings/set', { methods: { password: ON, apple: ON } }, { Cookie: cookie })).status).toBe(200);
    return { ...made, apple, cookie };
  }
  type Made = Pick<Awaited<ReturnType<typeof withApple>>, 'app' | 'store' | 'cookie' | 'hook'> & { apple: FakeApple };

  /** The sign-in as a browser makes it: start, Apple's page, its POST to the callback, and the GET it sends the browser on to; `link` adds it to Ada's methods. */
  async function signIn(made: Made, signedIn: FakeAppleSignIn | 'cancel', link = false) {
    const start = await made.app.request(`/auth/providers/apple/start?return_to=${encodeURIComponent(`${APP}/page`)}${link ? '&link=1' : ''}`, { headers: link ? { Cookie: made.cookie } : {} });
    expect(start.status).toBe(302);
    const authorize = start.headers.get('location')!;
    const state = start.headers.getSetCookie().find((cookie) => cookie.startsWith('madauth_oauth='))!.split(';')[0]!;
    // Apple's POST comes from its site: no cookie of madAuth's is sent with it.
    const form = signedIn === 'cancel' ? made.apple.cancel(authorize) : made.apple.approve(authorize, signedIn);
    const posted = await made.app.request('/auth/providers/apple/callback', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form.toString() });
    expect(posted.status).toBe(303);
    const nameCookie = posted.headers.getSetCookie().find((cookie) => cookie.startsWith('madauth_provider_name='))?.split(';')[0];
    const next = new URL(posted.headers.get('location')!);
    expect(next.origin + next.pathname).toBe(CALLBACK);
    const cookiesSent = [state, nameCookie, link ? made.cookie : undefined].filter(Boolean).join('; ');
    const callback = await made.app.request(next.pathname + next.search, { headers: { Cookie: cookiesSent } });
    const cookieOf = (name: string) => callback.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))?.split(';')[0];
    return { authorize: new URL(authorize), posted, nameCookie, callback, location: callback.headers.get('location'), session: cookieOf('madauth_session'), pending: cookieOf('madauth_pending_account') };
  }
  const userOf = async (made: Made, session: string | undefined) =>
    ((await (await made.app.request('/auth/session', { headers: { Cookie: session ?? '' } })).json()) as { user?: Record<string, unknown> }).user;
  const accounts = async (made: Made) => (await made.store.findMany('account', {})) as { id: string; key: string; secret: string | null; userId: string }[];
  const appleAccount = async (made: Made) => (await accounts(made)).find((account) => account.key.startsWith('apple:'));
  /** The client secret the last token request carried: the JWT madAuth signed. */
  const lastClientSecret = (made: Made) => new URLSearchParams(made.apple.calls.filter((call) => call.url.endsWith('/auth/token')).at(-1)!.body).get('client_secret')!;

  const grace: FakeAppleSignIn = { idToken: { sub: 'apple-sub-grace', email: 'grace@example.com', email_verified: 'true' }, user: { name: { firstName: 'Grace', lastName: 'Hopper' }, email: 'grace@example.com' } };

  it('AP2: a new user signs up: Apple’s own endpoints and scopes, a form_post answer turned into the GET callback, the name from the POST, the account by sub, the refresh token kept', async () => {
    const made = await withApple();
    const { authorize, posted, nameCookie, location, session } = await signIn(made, grace);

    expect(authorize.origin + authorize.pathname).toBe('https://appleid.apple.com/auth/authorize');
    expect(Object.fromEntries(authorize.searchParams)).toEqual({
      client_id: APPLE_CLIENT_ID,
      redirect_uri: CALLBACK,
      response_type: 'code',
      scope: 'name email',
      response_mode: 'form_post',
      state: expect.any(String),
      nonce: expect.any(String),
    });
    // The POST checked nothing: the name waits in a signed cookie for the GET, which has the state cookie.
    expect(nameCookie).toBeDefined();
    expect(posted.headers.getSetCookie().find((c) => c.startsWith('madauth_provider_name='))).toMatch(/Path=\/auth\/providers\/apple; HttpOnly; Secure; SameSite=Lax/);
    expect(new URL(posted.headers.get('location')!).searchParams.has('user')).toBe(false);
    expect(location).toBe(`${APP}/page`);
    expect(await userOf(made, session)).toMatchObject({ email: 'grace@example.com', name: 'Grace Hopper', amr: ['apple'] });
    expect(made.hook.calls.filter((call) => call.type === 'user.signed_up').at(-1)?.data).toMatchObject({ method: 'apple' });

    // The client secret is a JWT madAuth signed with the developer key, for the Team ID, the Services ID and Apple, short-lived.
    const secret = decodeJwt(lastClientSecret(made));
    expect(secret).toMatchObject({ iss: APPLE_TEAM_ID, sub: APPLE_CLIENT_ID, aud: 'https://appleid.apple.com' });
    expect(secret.exp! - secret.iat!).toBe(300);
    const account = await appleAccount(made);
    expect(account?.key).toBe('apple:apple-sub-grace');
    expect(account?.secret).toEqual(expect.any(String));
    expect(account?.secret).not.toContain('rt-');

    // The next sign-in brings no name (Apple sends it once): the user keeps theirs, and the refresh token is the latest.
    const again = await signIn(made, { idToken: grace.idToken });
    expect(again.nameCookie).toBeUndefined();
    expect(await userOf(made, again.session)).toMatchObject({ name: 'Grace Hopper' });
    expect((await appleAccount(made))?.secret).not.toBe(account?.secret);
  });

  it('AP3: the token must be Apple’s, for the Services ID, with the sign-in’s nonce; a cancelled sign-in and a wrong state come back as such', async () => {
    const failed = `${APP}/page#madauth_error=verification_failed&madauth_method=apple`;
    const made = await withApple();
    expect((await signIn(made, { idToken: { ...grace.idToken, aud: APPLE_BUNDLE_ID } })).location).toBe(failed);
    expect((await signIn(made, { idToken: { ...grace.idToken, nonce: 'another' } })).location).toBe(failed);
    expect((await signIn(made, { idToken: { ...grace.idToken, iss: 'https://accounts.google.com' } })).location).toBe(failed);
    expect((await signIn(made, { idToken: { ...grace.idToken, sub: undefined } })).location).toBe(failed);
    expect((await signIn(made, 'cancel')).location).toBe(`${APP}/page#madauth_error=cancelled&madauth_method=apple`);
    expect(await appleAccount(made)).toBeUndefined();

    // A callback without the state cookie, as a cross-site POST would be if it were handled directly.
    const start = await made.app.request(`/auth/providers/apple/start?return_to=${encodeURIComponent(`${APP}/page`)}`);
    const form = made.apple.approve(start.headers.get('location')!, grace);
    const posted = await made.app.request('/auth/providers/apple/callback', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form.toString() });
    const bare = await made.app.request(new URL(posted.headers.get('location')!).pathname + new URL(posted.headers.get('location')!).search);
    expect(bare.status).toBe(400);
    // The POST route is Apple's: another provider's callback takes no POST.
    expect((await made.app.request('/auth/providers/gitlab/callback', { method: 'POST' })).status).toBe(404);
  });

  it('AP4: a relay address of Hide My Email is the user’s address; an address Apple doesn’t mark verified is confirmed by e-mail; none at all is typed', async () => {
    const made = await withApple();
    const relay = { idToken: { sub: 'apple-sub-hidden', email: 'abc123xyz@privaterelay.appleid.com', email_verified: true, is_private_email: true } };
    const hidden = await signIn(made, relay);
    expect(hidden.location).toBe(`${APP}/page`);
    expect(await userOf(made, hidden.session)).toMatchObject({ email: 'abc123xyz@privaterelay.appleid.com', amr: ['apple'] });

    made.hook.calls.length = 0;
    const unverified = await signIn(made, { idToken: { sub: 'apple-sub-unverified', email: 'linus@example.com', email_verified: false } });
    expect(unverified.location).toBe(`${APP}/page#madauth_next=email-confirmation&madauth_email=l%E2%80%A2%E2%80%A2%E2%80%A2%40example.com&madauth_method=apple`);
    expect(made.hook.lastEmail()).toMatchObject({ type: 'email.send_verification', data: { to: 'linus@example.com' } });

    const none = await signIn(made, { idToken: { sub: 'apple-sub-managed', email: undefined, email_verified: undefined } });
    expect(none.location).toBe(`${APP}/page#madauth_next=email-address&madauth_method=apple`);
    expect(await (await made.app.request('/auth/providers/apple/address', { headers: { Cookie: none.pending! } })).json()).toEqual({ suggestion: null });

    // An address that signs in another way is refused, and nothing is linked.
    expect((await signIn(made, { idToken: { sub: 'apple-sub-mallory', email: 'ada@example.com', email_verified: true } })).location).toBe(`${APP}/page#madauth_error=other_method&madauth_method=apple`);
    expect((await accounts(made)).map((a) => a.key)).not.toContain('apple:apple-sub-mallory');
  });

  it('AP5: a native app signs in with the identity token for its App ID and madAuth’s nonce, passes the name and the code once, and links the same way', async () => {
    const made = await withApple();
    const nonceRes = await post(made.app, '/auth/providers/apple/nonce', {});
    expect(nonceRes.status).toBe(200);
    const { nonce } = (await nonceRes.json()) as { nonce: string };
    const nonceCookie = nonceRes.headers.getSetCookie().find((c) => c.startsWith('madauth_nonce='))!;
    expect(nonceCookie).toMatch(/Path=\/auth\/providers\/apple; HttpOnly; Secure; SameSite=Strict/);
    const cookie = { Cookie: nonceCookie.split(';')[0]! };
    const claims = { sub: 'apple-sub-ios', email: 'ios@example.com' };

    // The token must be for one of the provider's App IDs (or its Services ID), with the nonce from the cookie.
    const wrongApp = await post(made.app, '/auth/providers/apple/verify', { credential: await made.apple.identityToken(claims, 'com.other.app', nonce) }, cookie);
    expect(wrongApp.status).toBe(401);
    const wrongNonce = await post(made.app, '/auth/providers/apple/verify', { credential: await made.apple.identityToken(claims, APPLE_BUNDLE_ID, 'other') }, cookie);
    expect(wrongNonce.status).toBe(401);
    expect((await post(made.app, '/auth/providers/apple/verify', { credential: await made.apple.identityToken(claims, APPLE_BUNDLE_ID, nonce) })).status).toBe(401);

    made.hook.calls.length = 0;
    const token = await made.apple.identityToken(claims, APPLE_BUNDLE_ID, nonce);
    const code = made.apple.nativeCode(APPLE_BUNDLE_ID, { idToken: claims }, nonce);
    const verified = await post(made.app, '/auth/providers/apple/verify', { credential: token, name: { firstName: 'Ada', lastName: 'Byron' }, authorizationCode: code }, cookie);
    expect(verified.status).toBe(200);
    expect(((await verified.json()) as { user: Record<string, unknown> }).user).toMatchObject({ email: 'ios@example.com', name: 'Ada Byron', amr: ['apple'] });
    expect(made.hook.calls.filter((call) => call.type === 'user.signed_up').at(-1)?.data).toMatchObject({ method: 'apple' });
    // The code was exchanged as the App ID, without a redirect URI, and the refresh token is on the account.
    expect(decodeJwt(lastClientSecret(made)).sub).toBe(APPLE_BUNDLE_ID);
    expect((await appleAccount(made))?.secret).toEqual(expect.any(String));
    // The nonce cookie is removed with the sign-in.
    expect(verified.headers.getSetCookie().find((c) => c.startsWith('madauth_nonce='))).toMatch(/Max-Age=0/);

    // A code Apple refuses fails the sign-in; without a code the account has no refresh token to give back.
    const second = await post(made.app, '/auth/providers/apple/nonce', {});
    const secondCookie = { Cookie: second.headers.getSetCookie().find((c) => c.startsWith('madauth_nonce='))!.split(';')[0]! };
    const secondNonce = ((await second.json()) as { nonce: string }).nonce;
    const refused = await post(made.app, '/auth/providers/apple/verify', { credential: await made.apple.identityToken(claims, APPLE_BUNDLE_ID, secondNonce), authorizationCode: 'stale' }, secondCookie);
    expect(refused.status).toBe(401);

    // Ada (the admin, signed in with a password) adds her Apple ID from the app.
    const third = await post(made.app, '/auth/providers/apple/nonce', {});
    const thirdCookie = third.headers.getSetCookie().find((c) => c.startsWith('madauth_nonce='))!.split(';')[0]!;
    const thirdNonce = ((await third.json()) as { nonce: string }).nonce;
    const adaToken = await made.apple.identityToken({ sub: 'apple-sub-ada', email: 'ada@icloud.example.com' }, APPLE_BUNDLE_ID, thirdNonce);
    const linked = await post(made.app, '/auth/providers/apple/link', { credential: adaToken }, { Cookie: `${thirdCookie}; ${made.cookie}` });
    expect(linked.status).toBe(200);
    expect((await accounts(made)).map((a) => a.key)).toContain('apple:apple-sub-ada');

    // Without App IDs, only the Services ID's tokens (Apple's JS on a web page) sign in.
    const webOnly = await withApple([]);
    const fourth = await post(webOnly.app, '/auth/providers/apple/nonce', {});
    const fourthCookie = { Cookie: fourth.headers.getSetCookie().find((c) => c.startsWith('madauth_nonce='))!.split(';')[0]! };
    const fourthNonce = ((await fourth.json()) as { nonce: string }).nonce;
    expect((await post(webOnly.app, '/auth/providers/apple/verify', { credential: await webOnly.apple.identityToken(claims, APPLE_BUNDLE_ID, fourthNonce) }, fourthCookie)).status).toBe(401);
    const fifth = await post(webOnly.app, '/auth/providers/apple/nonce', {});
    const fifthCookie = { Cookie: fifth.headers.getSetCookie().find((c) => c.startsWith('madauth_nonce='))!.split(';')[0]! };
    const fifthNonce = ((await fifth.json()) as { nonce: string }).nonce;
    expect((await post(webOnly.app, '/auth/providers/apple/verify', { credential: await webOnly.apple.identityToken(claims, APPLE_CLIENT_ID, fifthNonce) }, fifthCookie)).status).toBe(200);
  });

  it('AP6: the token exchange takes an Apple identity token as it takes Google’s, told apart by the issuer', async () => {
    const made = await withApple();
    const client = (await (await post(made.app, '/auth/admin/clients/add', { name: 'Phone app', public: true, redirectUris: ['com.example.app:/callback'], tokenExchange: true }, { Cookie: made.cookie })).json()) as { client: { id: string } };
    const postForm = (path: string, data: Record<string, string>) =>
      made.app.request(path, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(data).toString() });
    const nonceRes = await postForm('/auth/oidc/nonce', { client_id: client.client.id });
    expect(nonceRes.status).toBe(200);
    // No Google provider on this server: the answer names Apple only.
    const nonceAnswer = (await nonceRes.json()) as { nonce: string; google_client_id?: string; apple?: boolean };
    expect(nonceAnswer).toMatchObject({ apple: true, expires_in: 300 });
    expect(nonceAnswer.google_client_id).toBeUndefined();

    const claims = { sub: 'apple-sub-phone', email: 'phone@example.com' };
    const exchange = async (data: Record<string, string>) => {
      const res = await postForm('/auth/oidc/token', { grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', client_id: client.client.id, subject_token_type: 'urn:ietf:params:oauth:token-type:id_token', scope: 'openid email offline_access', ...data });
      return { status: res.status, body: (await res.json()) as Record<string, unknown> };
    };
    expect((await exchange({ subject_token: await made.apple.identityToken(claims, 'com.other.app', nonceAnswer.nonce) })).body.error).toBe('invalid_grant');
    const fresh = ((await (await postForm('/auth/oidc/nonce', { client_id: client.client.id })).json()) as { nonce: string }).nonce;
    const code = made.apple.nativeCode(APPLE_BUNDLE_ID, { idToken: claims }, fresh);
    const got = await exchange({ subject_token: await made.apple.identityToken(claims, APPLE_BUNDLE_ID, fresh), name: JSON.stringify({ firstName: 'Phone', lastName: 'User' }), authorization_code: code });
    expect(got.status).toBe(200);
    expect(decodeJwt(got.body.id_token as string)).toMatchObject({ aud: client.client.id, email: 'phone@example.com', amr: ['apple'] });
    expect(await made.store.findOne('user', { emailNormalized: 'phone@example.com' })).toMatchObject({ emailVerified: true, name: 'Phone User' });
    expect((await appleAccount(made))?.secret).toEqual(expect.any(String));
  });

  it('AP7: removing the method, deleting the account, a reset or an admin’s deletion gives the authorization back to Apple with the kept refresh token; a failure is logged', async () => {
    const made = await withApple();
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { session } = await signIn(made, grace);
    const account = (await appleAccount(made))!;

    // The user removes Apple from their methods (they have no other way in, so they add a password first).
    const graceId = (await userOf(made, session))!.id;
    const methods = ((await (await made.app.request('/auth/methods', { headers: { Cookie: session! } })).json()) as { methods: { id: string; method: string }[] }).methods;
    const appleMethod = methods.find((m) => m.method === 'apple')!;
    // A reset by an admin takes the account with its token.
    expect((await post(made.app, '/auth/admin/sign-in/reset', { email: 'grace@example.com' }, { Cookie: made.cookie })).status).toBe(200);
    expect(made.apple.revoked).toEqual([{ clientId: APPLE_CLIENT_ID, token: expect.stringMatching(/^rt-/), hint: 'refresh_token' }]);
    expect(appleMethod.id).toBe(account.id);
    expect(graceId).toBeDefined();

    // The user deletes their account.
    made.apple.revoked.length = 0;
    const linus = await signIn(made, { idToken: { sub: 'apple-sub-linus', email: 'linus@example.com', email_verified: true } });
    const gone = await made.app.request('/auth/account/delete', { method: 'POST', headers: { Origin: APP, Cookie: linus.session! } });
    expect(gone.status).toBe(204);
    expect(made.apple.revoked).toHaveLength(1);

    // An admin deletes a user; Apple's answer isn't 200: logged, the deletion stands.
    made.apple.revoked.length = 0;
    await signIn(made, { idToken: { sub: 'apple-sub-ken', email: 'ken@example.com', email_verified: true } });
    made.apple.failRevocations(400);
    expect((await post(made.app, '/auth/admin/users/delete', { email: 'ken@example.com' }, { Cookie: made.cookie })).status).toBe(200);
    expect(made.apple.revoked).toHaveLength(1);
    expect(error.mock.calls.flat().join('\n')).toContain('Apple did not take back the authorization');
    expect(await made.store.findOne('user', { emailNormalized: 'ken@example.com' })).toBeNull();

    // An account without a token (Apple answered none) has nothing to give back.
    made.apple.revoked.length = 0;
    made.apple.failRevocations(200);
    const quiet = await signIn(made, { idToken: { sub: 'apple-sub-quiet', email: 'quiet@example.com', email_verified: true }, noRefreshToken: true });
    expect((await made.app.request('/auth/account/delete', { method: 'POST', headers: { Origin: APP, Cookie: quiet.session! } })).status).toBe(204);
    expect(made.apple.revoked).toEqual([]);
  });

  it('AP8: a key that isn’t Apple’s is refused when it is set; /auth/config and the admin API name the provider; the key can change', async () => {
    const made = await withApple();
    const wrong = await post(made.app, '/auth/admin/providers/update', { id: 'apple', clientSecret: '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----' }, { Cookie: made.cookie });
    expect(wrong.status).toBe(400);
    expect(await wrong.json()).toMatchObject({ error: 'invalid_provider', message: expect.stringContaining('.p8') });
    const config = (await (await made.app.request('/auth/config')).json()) as { providers: unknown[] };
    expect(config.providers).toContainEqual({ id: 'apple', kind: 'apple', name: 'Apple', secondFactor: 'none' });
    const listed = (await (await post(made.app, '/auth/admin/providers/list', {}, { Cookie: made.cookie })).json()) as { providers: Record<string, unknown>[] };
    expect(listed.providers.find((p) => p.id === 'apple')).toMatchObject({ kind: 'apple', clientId: APPLE_CLIENT_ID, teamId: APPLE_TEAM_ID, keyId: APPLE_KEY_ID, bundleIds: [APPLE_BUNDLE_ID], hasClientSecret: true, callbackUrl: CALLBACK });
    expect(JSON.stringify(listed)).not.toContain('PRIVATE KEY');
    // Another key of the account: the sign-in uses it from then on.
    const other = await fakeApple();
    expect((await post(made.app, '/auth/admin/providers/update', { id: 'apple', clientSecret: other.privateKeyPem, keyId: 'KEY7654321' }, { Cookie: made.cookie })).status).toBe(200);
    expect((await signIn(made, grace)).location).toBe(`${APP}/page#madauth_error=verification_failed&madauth_method=apple`);
  });

  it('AP9: without a webhook that sends e-mails, an account whose address Apple doesn’t vouch for is refused, and the setup token adds the provider', async () => {
    const apple = await fakeApple();
    const quiet = { ...passwordApp({ google: undefined, password: undefined, oidcFetch: apple.fetch, webhook: undefined }), apple, cookie: '' };
    const bearer = { Authorization: `Bearer ${await setupToken(keyService, ISSUER)}` };
    const fields = { kind: 'apple', clientId: APPLE_CLIENT_ID, clientSecret: apple.privateKeyPem, teamId: APPLE_TEAM_ID, keyId: APPLE_KEY_ID };
    expect((await post(quiet.app, '/auth/admin/providers/add', fields, bearer)).status).toBe(200);
    expect((await post(quiet.app, '/auth/admin/settings/set', { methods: { apple: ON } }, bearer)).status).toBe(200);
    expect((await signIn(quiet, { idToken: { sub: 'apple-sub-x', email: 'x@example.com', email_verified: false } })).location).toBe(`${APP}/page#madauth_error=email_unverified&madauth_method=apple`);
    expect((await signIn(quiet, grace)).location).toBe(`${APP}/page`);
  });
});
