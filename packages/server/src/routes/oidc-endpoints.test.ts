// madAuth as an OpenID Connect provider, driven by a standard relying party (openid-client) where it can be.
// Behaviour described in "OpenID Connect provider" in docs/server.md; update the doc when changing it.
import * as oidc from 'openid-client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { REFRESH_TOKEN_TTL_MS } from '../oidc-clients.js';
import { APP_ORIGIN, CLIENT_ID, ISSUER, cookies, googleIdToken, googleJwks, passwordApp, post, setClaims, signUpVerified, linkAndCode } from '../test/helpers.js';
import { Users } from '../users.js';

type Made = Awaited<ReturnType<typeof withAdmin>>;
type App = Made['app'];

const REDIRECT_URI = 'https://grafana.example.org/login/generic_oauth';
const LOGOUT_URI = 'https://grafana.example.org/logged-out';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

/** A server with Grace, an admin who signed up with a password just now. */
async function withAdmin() {
  const made = passwordApp({ allowedOrigins: [APP_ORIGIN, ISSUER], jwksResolver: googleJwks });
  const cookie = `madauth_session=${await signUpVerified(made.app, made.hook)}`;
  await setClaims(made.store, 'grace@example.com', { roles: ['admin'] });
  return { ...made, cookie };
}

const admin = (made: Made, path: string, data: Record<string, unknown>) => post(made.app, `/auth/admin/${path}`, data, { Cookie: made.cookie });

async function addClient(made: Made, data: Record<string, unknown> = {}) {
  const res = await admin(made, 'clients/add', { name: 'Grafana', redirectUris: [REDIRECT_URI], postLogoutRedirectUris: [LOGOUT_URI], ...data });
  expect(res.status).toBe(200);
  return (await res.json()) as { client: { id: string; public: boolean; redirectUris: string[] }; clientSecret?: string };
}

/** openid-client, talking to the app in memory. */
const viaApp = (app: App): NonNullable<oidc.DiscoveryRequestOptions[typeof oidc.customFetch]> => async (url, init) =>
  app.request(url, { method: init.method, headers: init.headers as HeadersInit, body: init.body as BodyInit | undefined });

async function relyingParty(app: App, clientId: string, secret?: string) {
  const fetch = viaApp(app);
  const config = await oidc.discovery(new URL(ISSUER), clientId, secret, secret ? oidc.ClientSecretBasic(secret) : oidc.None(), { [oidc.customFetch]: fetch });
  config[oidc.customFetch] = fetch;
  return config;
}

/** An authorization request with PKCE, a nonce and a state, as openid-client builds it. */
async function authorizationRequest(config: oidc.Configuration, extra: Record<string, string> = {}) {
  const verifier = oidc.randomPKCECodeVerifier();
  const nonce = oidc.randomNonce();
  const state = oidc.randomState();
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT_URI,
    scope: 'openid email profile offline_access',
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
    nonce,
    state,
    ...extra,
  });
  return { url, verifier, nonce, state };
}

/** Signs Grace in at a client: the authorization with her session, then the code for the tokens. */
async function signInAt(made: Made, config: oidc.Configuration) {
  const request = await authorizationRequest(config);
  const res = await made.app.request(request.url.toString(), { headers: { Cookie: made.cookie } });
  expect(res.status).toBe(302);
  const back = new URL(res.headers.get('location')!);
  return oidc.authorizationCodeGrant(config, back, { pkceCodeVerifier: request.verifier, expectedNonce: request.nonce, expectedState: request.state });
}

const form = (data: Record<string, string>) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(data).toString(),
});

describe('madAuth as an OpenID Connect provider', () => {
  it('OP1: discovery names the endpoints, the JWKS and what madAuth supports; browser apps can read it', async () => {
    const { app } = passwordApp();
    const res = await app.request('/.well-known/openid-configuration');
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(await res.json()).toMatchObject({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/auth/oidc/authorize`,
      token_endpoint: `${ISSUER}/auth/oidc/token`,
      userinfo_endpoint: `${ISSUER}/auth/oidc/userinfo`,
      end_session_endpoint: `${ISSUER}/auth/oidc/logout`,
      jwks_uri: `${ISSUER}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      id_token_signing_alg_values_supported: ['ES256'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    });
    expect((await app.request('/.well-known/jwks.json')).headers.get('access-control-allow-origin')).toBe('*');
  });

  it('OP2: an admin registers clients; the secret shows once, and redirect URIs are checked', async () => {
    const made = await withAdmin();
    const confidential = await addClient(made);
    expect(confidential.clientSecret).toMatch(/^mcs_/);
    expect(confidential.client).toMatchObject({ name: 'Grafana', public: false, redirectUris: [REDIRECT_URI], postLogoutRedirectUris: [LOGOUT_URI] });
    // A native app: its own scheme, and this computer at any port.
    const native = await addClient(made, { name: 'Editor', public: true, redirectUris: ['vscode://madauth.signin/callback', 'http://127.0.0.1/callback'] });
    expect(native.clientSecret).toBeUndefined();
    expect(native.client.public).toBe(true);

    const listed = await (await admin(made, 'clients/list', {})).json();
    expect(listed.clients.map((c: { id: string }) => c.id)).toEqual([confidential.client.id, native.client.id]);
    expect(JSON.stringify(listed)).not.toContain(confidential.clientSecret);

    for (const uri of ['http://grafana.example.org/cb', 'https://grafana.example.org/cb#x', 'javascript:alert(1)', 'not a url']) {
      const res = await admin(made, 'clients/add', { name: 'Bad', redirectUris: [uri] });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe('invalid_client');
    }
    expect((await admin(made, 'clients/add', { name: 'None', redirectUris: [] })).status).toBe(400);

    // A new secret replaces the old one; a public client has none to replace.
    const renewed = await (await admin(made, 'clients/update', { id: confidential.client.id, newSecret: true, name: 'Grafana 2' })).json();
    expect(renewed.clientSecret).toMatch(/^mcs_/);
    expect(renewed.clientSecret).not.toBe(confidential.clientSecret);
    expect(renewed.client.name).toBe('Grafana 2');
    expect((await (await admin(made, 'clients/update', { id: native.client.id, newSecret: true })).json()).clientSecret).toBeUndefined();
    expect((await admin(made, 'clients/update', { id: 'mc_nope', name: 'x' })).status).toBe(404);
  });

  it('OP3: only admins manage clients, changes need a recent sign-in, and API keys only list them', async () => {
    const made = await withAdmin();
    await setClaims(made.store, 'grace@example.com', null);
    expect((await admin(made, 'clients/add', { name: 'x', redirectUris: [REDIRECT_URI] })).status).toBe(403);
    await setClaims(made.store, 'grace@example.com', { roles: ['admin'] });

    const key = await (await post(made.app, '/auth/api-keys/create', { name: 'k', scopes: ['madauth:clients:read'] }, { Cookie: made.cookie })).json();
    const withKey = (path: string) =>
      made.app.request(`/auth/admin/${path}`, { method: 'POST', headers: { Authorization: `Bearer ${key.key}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'x', redirectUris: [REDIRECT_URI] }) });
    expect((await withKey('clients/list')).status).toBe(200);
    expect((await withKey('clients/add')).status).toBe(403);

    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 3 * 60 * 1000 });
    expect((await (await admin(made, 'clients/add', { name: 'x', redirectUris: [REDIRECT_URI] })).json()).error).toBe('reauth_required');
  });

  it('OP4: a confidential client signs a user in, gets the user info and refreshes its tokens', async () => {
    const made = await withAdmin();
    await setClaims(made.store, 'grace@example.com', { roles: ['admin'], plan: 'pro' });
    const { client, clientSecret } = await addClient(made);
    const config = await relyingParty(made.app, client.id, clientSecret);

    const tokens = await signInAt(made, config);
    const claims = tokens.claims()!;
    expect(claims).toMatchObject({
      iss: ISSUER,
      aud: client.id,
      email: 'grace@example.com',
      email_verified: true,
      name: 'Grace Hopper',
      amr: ['pwd'],
      claims: { roles: ['admin'], plan: 'pro' },
    });
    expect(typeof claims.auth_time).toBe('number');
    expect(tokens.expires_in).toBe(900);
    expect(tokens.scope).toBe('openid email profile offline_access');

    // The access token is a JWT for APIs (RFC 9068), meant for the client.
    const [header, payload] = tokens.access_token.split('.').slice(0, 2).map((part) => JSON.parse(Buffer.from(part, 'base64url').toString()));
    expect(header).toMatchObject({ typ: 'at+jwt', alg: 'ES256' });
    expect(payload).toMatchObject({ sub: claims.sub, aud: client.id, client_id: client.id, scope: 'openid email profile offline_access' });
    expect(payload.exp - payload.iat).toBe(900);

    expect(await oidc.fetchUserInfo(config, tokens.access_token, claims.sub)).toEqual({
      sub: claims.sub,
      email: 'grace@example.com',
      email_verified: true,
      name: 'Grace Hopper',
      claims: { roles: ['admin'], plan: 'pro' },
    });

    const refreshed = await oidc.refreshTokenGrant(config, tokens.refresh_token!);
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);
    expect(refreshed.claims()).toMatchObject({ sub: claims.sub, auth_time: claims.auth_time });
    // Fewer scopes are fine, more are not; without openid, there is no ID token.
    const narrower = await oidc.refreshTokenGrant(config, refreshed.refresh_token!, { scope: 'openid' });
    expect(narrower.scope).toBe('openid');
    const noOpenid = await oidc.refreshTokenGrant(config, narrower.refresh_token!, { scope: 'email' });
    expect(noOpenid.id_token).toBeUndefined();
    await expect(oidc.refreshTokenGrant(config, noOpenid.refresh_token!, { scope: 'openid email address' })).rejects.toMatchObject({ error: 'invalid_scope' });
  });

  it('OP5: a refresh token works once; using an old one ends the whole chain', async () => {
    const made = await withAdmin();
    const { client, clientSecret } = await addClient(made);
    const config = await relyingParty(made.app, client.id, clientSecret);
    const first = await signInAt(made, config);
    const second = await oidc.refreshTokenGrant(config, first.refresh_token!);

    await expect(oidc.refreshTokenGrant(config, first.refresh_token!)).rejects.toMatchObject({ error: 'invalid_grant' });
    // The newer token went with it: whoever took the old one can't go on, nor can the client.
    await expect(oidc.refreshTokenGrant(config, second.refresh_token!)).rejects.toMatchObject({ error: 'invalid_grant' });
  });

  it('OP6: refresh tokens last 30 days after their last use', async () => {
    const made = await withAdmin();
    const { client, clientSecret } = await addClient(made);
    const config = await relyingParty(made.app, client.id, clientSecret);
    const start = Date.now();
    let token = (await signInAt(made, config)).refresh_token!;
    vi.useFakeTimers({ toFake: ['Date'], now: start + REFRESH_TOKEN_TTL_MS - 1000 });
    token = (await oidc.refreshTokenGrant(config, token)).refresh_token!;
    vi.useFakeTimers({ toFake: ['Date'], now: start + 2 * REFRESH_TOKEN_TTL_MS - 3000 });
    token = (await oidc.refreshTokenGrant(config, token)).refresh_token!;
    vi.useFakeTimers({ toFake: ['Date'], now: start + 3 * REFRESH_TOKEN_TTL_MS });
    await expect(oidc.refreshTokenGrant(config, token)).rejects.toMatchObject({ error: 'invalid_grant' });
  });

  it('OP7: a public client proves itself with PKCE alone; a confidential one needs its secret', async () => {
    const made = await withAdmin();
    const native = await addClient(made, { name: 'Editor', public: true, redirectUris: [REDIRECT_URI] });
    const tokens = await signInAt(made, await relyingParty(made.app, native.client.id));
    expect(tokens.id_token).toBeTruthy();
    // A public client may send HTTP Basic with an empty password.
    const basicEmpty = await made.app.request('/auth/oidc/token', {
      ...form({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token! }),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${btoa(`${native.client.id}:`)}` },
    });
    expect(basicEmpty.status).toBe(200);

    const confidential = await addClient(made);
    const request = await authorizationRequest(await relyingParty(made.app, confidential.client.id, confidential.clientSecret));
    const code = new URL((await made.app.request(request.url.toString(), { headers: { Cookie: made.cookie } })).headers.get('location')!).searchParams.get('code')!;
    const exchange = (data: Record<string, string>, headers: Record<string, string> = {}) =>
      made.app.request('/auth/oidc/token', { ...form({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, code_verifier: request.verifier, ...data }), headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers } });
    // Without the secret, or with a wrong one: not the client.
    expect(await (await exchange({ client_id: confidential.client.id })).json()).toMatchObject({ error: 'invalid_client' });
    const wrong = await exchange({}, { Authorization: `Basic ${btoa(`${confidential.client.id}:mcs_wrong`)}` });
    expect(wrong.status).toBe(401);
    expect(wrong.headers.get('www-authenticate')).toContain('Basic');
    // Another client can't use the code up.
    const other = await addClient(made, { name: 'Other' });
    expect((await exchange({ client_id: other.client.id, client_secret: other.clientSecret! })).status).toBe(400);
    // In the form (client_secret_post), the secret works.
    const res = await exchange({ client_id: confidential.client.id, client_secret: confidential.clientSecret! });
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    // A code works once.
    expect(await (await exchange({ client_id: confidential.client.id, client_secret: confidential.clientSecret! })).json()).toMatchObject({ error: 'invalid_grant' });
  });

  it('OP8: PKCE is required, and the verifier must match', async () => {
    const made = await withAdmin();
    const { client, clientSecret } = await addClient(made);
    const config = await relyingParty(made.app, client.id, clientSecret);
    const plain = new URL(`${ISSUER}/auth/oidc/authorize?response_type=code&client_id=${client.id}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid&state=s1`);
    const refused = new URL((await made.app.request(plain.toString(), { headers: { Cookie: made.cookie } })).headers.get('location')!);
    expect(Object.fromEntries(refused.searchParams)).toMatchObject({ error: 'invalid_request', state: 's1', iss: ISSUER });

    const request = await authorizationRequest(config);
    const back = new URL((await made.app.request(request.url.toString(), { headers: { Cookie: made.cookie } })).headers.get('location')!);
    await expect(oidc.authorizationCodeGrant(config, back, { pkceCodeVerifier: oidc.randomPKCECodeVerifier(), expectedNonce: request.nonce, expectedState: request.state })).rejects.toMatchObject({ error: 'invalid_grant' });
  });

  it('OP9: an unknown client or redirect URI gets a page, never a redirect; this computer matches at any port', async () => {
    const made = await withAdmin();
    const { client } = await addClient(made, { public: true, redirectUris: ['http://127.0.0.1/callback', 'vscode://madauth.signin/cb'] });
    const config = await relyingParty(made.app, client.id);
    const at = async (redirectUri: string) => {
      const request = await authorizationRequest(config, { redirect_uri: redirectUri });
      return made.app.request(request.url.toString(), { headers: { Cookie: made.cookie } });
    };
    expect((await at('http://127.0.0.1:53127/callback')).headers.get('location')).toMatch(/^http:\/\/127\.0\.0\.1:53127\/callback\?code=/);
    expect((await at('vscode://madauth.signin/cb')).headers.get('location')).toMatch(/^vscode:\/\/madauth\.signin\/cb\?code=/);
    for (const wrong of ['http://127.0.0.1:53127/other', 'https://evil.example/callback']) {
      const res = await at(wrong);
      expect(res.status).toBe(400);
      expect(res.headers.get('location')).toBeNull();
    }
    const unknown = await made.app.request(`/auth/oidc/authorize?client_id=mc_nope&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`);
    expect(unknown.status).toBe(400);
  });

  it('OP10: without a session, the app’s login page signs the user in and sends them back', async () => {
    const made = await withAdmin();
    const { client, clientSecret } = await addClient(made);
    const config = await relyingParty(made.app, client.id, clientSecret);
    const request = await authorizationRequest(config);

    const toLogin = await made.app.request(request.url.toString());
    expect(toLogin.status).toBe(302);
    const login = new URL(toLogin.headers.get('location')!);
    expect(`${login.origin}${login.pathname}`).toBe(`${ISSUER}/`);
    const returnTo = login.searchParams.get('madauth_return')!;
    expect(returnTo).toBe(request.url.toString());

    // prompt=none can't show a login page.
    const none = await made.app.request((await authorizationRequest(config, { prompt: 'none' })).url.toString());
    expect(new URL(none.headers.get('location')!).searchParams.get('error')).toBe('login_required');

    // The admin's login page: a path, or a page of an allowed origin; anything else is refused.
    for (const outside of ['https://evil.example/login', '//evil.example/login', '/\\evil.example/login']) {
      expect((await admin(made, 'settings/set', { loginUrl: outside })).status).toBe(400);
    }
    expect((await (await admin(made, 'settings/set', { loginUrl: '/login?x=1' })).json()).loginUrl).toBe('/login?x=1');
    const custom = new URL((await made.app.request(request.url.toString())).headers.get('location')!);
    expect(`${custom.origin}${custom.pathname}`).toBe(`${ISSUER}/login`);
    expect(custom.searchParams.get('x')).toBe('1');
    expect((await (await admin(made, 'settings/get', {})).json()).loginUrl).toBe('/login?x=1');
    expect((await (await admin(made, 'settings/set', { loginUrl: `${APP_ORIGIN}/sign-in` })).json()).loginUrl).toBe(`${APP_ORIGIN}/sign-in`);
    expect((await (await admin(made, 'settings/set', { loginUrl: null })).json()).loginUrl).toBeNull();

    // Back with a session, the request goes on.
    const back = await made.app.request(returnTo, { headers: { Cookie: made.cookie } });
    expect(new URL(back.headers.get('location')!).searchParams.get('code')).toBeTruthy();
  });

  it('OP11: prompt=login and an old sign-in past max_age end the session and ask for a new sign-in', async () => {
    const made = await withAdmin();
    const { client, clientSecret } = await addClient(made);
    const config = await relyingParty(made.app, client.id, clientSecret);

    const again = await made.app.request((await authorizationRequest(config, { prompt: 'login' })).url.toString(), { headers: { Cookie: made.cookie } });
    expect(cookies(again).madauth_session.value).toBe('');
    const returnTo = new URL(new URL(again.headers.get('location')!).searchParams.get('madauth_return')!);
    // The way back asks for no new sign-in again.
    expect(returnTo.searchParams.has('prompt')).toBe(false);

    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 120_000 });
    const old = await made.app.request((await authorizationRequest(config, { max_age: '60' })).url.toString(), { headers: { Cookie: made.cookie } });
    expect(new URL(old.headers.get('location')!).origin + new URL(old.headers.get('location')!).pathname).toBe(`${ISSUER}/`);
    const recent = await made.app.request((await authorizationRequest(config, { max_age: '600' })).url.toString(), { headers: { Cookie: made.cookie } });
    expect(new URL(recent.headers.get('location')!).searchParams.get('code')).toBeTruthy();
  });

  it('OP12: ending the user’s sessions ends the refresh tokens and the user info', async () => {
    const made = await withAdmin();
    const { client, clientSecret } = await addClient(made);
    const config = await relyingParty(made.app, client.id, clientSecret);
    const tokens = await signInAt(made, config);
    // Another sign-in at the client, whose chain is never used again.
    const unused = await signInAt(made, config);
    const userId = tokens.claims()!.sub;

    // A password reset ends every session of the user (one e-mail a minute: the sign-up's was the last).
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 61_000 });
    await post(made.app, '/auth/password/send-reset', { email: 'grace@example.com', redirectTo: `${APP_ORIGIN}/reset` });
    const { token } = linkAndCode(made.hook.lastEmail());
    const reset = await post(made.app, '/auth/password/reset', { token, password: 'a new long passphrase' });
    expect(reset.status).toBe(200);

    await expect(oidc.refreshTokenGrant(config, tokens.refresh_token!)).rejects.toMatchObject({ error: 'invalid_grant' });
    await expect(oidc.fetchUserInfo(config, tokens.access_token, userId)).rejects.toThrow();

    // The next sign-in at a client removes the chains the reset ended, also those never used again.
    expect(await made.store.findMany('oidcRefreshToken', { userId })).toHaveLength(1);
    await signInAt({ ...made, cookie: `madauth_session=${cookies(reset).madauth_session.value}` }, config);
    expect(await made.store.findMany('oidcRefreshToken', { userId })).toHaveLength(1);
    await expect(oidc.refreshTokenGrant(config, unused.refresh_token!)).rejects.toMatchObject({ error: 'invalid_grant' });
  });

  it('OP13: resetting or deleting a user removes their codes and refresh tokens', async () => {
    const made = await withAdmin();
    const { client, clientSecret } = await addClient(made);
    const config = await relyingParty(made.app, client.id, clientSecret);
    const tokens = await signInAt(made, config);
    const userId = tokens.claims()!.sub;
    expect(await made.store.findMany('oidcRefreshToken', { userId })).toHaveLength(1);
    await new Users(made.store).resetSignIn(userId);
    expect(await made.store.findMany('oidcRefreshToken', { userId })).toHaveLength(0);

    const other = await withAdmin();
    const second = await addClient(other);
    const deleted = (await signInAt(other, await relyingParty(other.app, second.client.id, second.clientSecret))).claims()!.sub;
    // A code that was never exchanged goes too.
    await authorizationRequest(await relyingParty(other.app, second.client.id, second.clientSecret)).then((r) => other.app.request(r.url.toString(), { headers: { Cookie: other.cookie } }));
    expect(await other.store.findMany('oidcCode', { userId: deleted })).toHaveLength(1);
    await new Users(other.store).deleteById(deleted);
    expect(await other.store.findMany('oidcRefreshToken', { userId: deleted })).toHaveLength(0);
    expect(await other.store.findMany('oidcCode', { userId: deleted })).toHaveLength(0);
  });

  it('OP14: a client signs the user out with its ID token, back to a registered address', async () => {
    const made = await withAdmin();
    const { client, clientSecret } = await addClient(made);
    const config = await relyingParty(made.app, client.id, clientSecret);
    const tokens = await signInAt(made, config);

    const unregistered = oidc.buildEndSessionUrl(config, { id_token_hint: tokens.id_token!, post_logout_redirect_uri: 'https://evil.example/' });
    expect((await made.app.request(unregistered.toString(), { headers: { Cookie: made.cookie } })).status).toBe(400);
    expect((await made.app.request('/auth/oidc/logout', { headers: { Cookie: made.cookie } })).status).toBe(400);

    const url = oidc.buildEndSessionUrl(config, { id_token_hint: tokens.id_token!, post_logout_redirect_uri: LOGOUT_URI, state: 'bye' });
    const res = await made.app.request(url.toString(), { headers: { Cookie: made.cookie } });
    expect(res.headers.get('location')).toBe(`${LOGOUT_URI}?state=bye`);
    expect(cookies(res).madauth_session.value).toBe('');
    await expect(oidc.refreshTokenGrant(config, tokens.refresh_token!)).rejects.toMatchObject({ error: 'invalid_grant' });
  });

  it('OP15: removing a client ends its refresh tokens and its sign-ins', async () => {
    const made = await withAdmin();
    const { client, clientSecret } = await addClient(made);
    const config = await relyingParty(made.app, client.id, clientSecret);
    const tokens = await signInAt(made, config);
    expect((await (await admin(made, 'clients/remove', { id: client.id })).json()).client.id).toBe(client.id);
    expect(await made.store.findMany('oidcRefreshToken', { clientId: client.id })).toHaveLength(0);
    // An unknown client: 401 with a challenge.
    await expect(oidc.refreshTokenGrant(config, tokens.refresh_token!)).rejects.toMatchObject({ name: 'WWWAuthenticateChallengeError' });
    expect((await made.app.request((await authorizationRequest(config)).url.toString(), { headers: { Cookie: made.cookie } })).status).toBe(400);
    expect((await admin(made, 'clients/remove', { id: client.id })).status).toBe(404);
  });

  it('OP16: the token and user info endpoints take calls from any origin, without cookies', async () => {
    const made = await withAdmin();
    const preflight = await made.app.request('/auth/oidc/token', {
      method: 'OPTIONS',
      headers: { Origin: 'https://spa.example.org', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' },
    });
    expect(preflight.headers.get('access-control-allow-origin')).toBe('*');
    expect(preflight.headers.get('access-control-allow-credentials')).toBeNull();
    // A POST without an allowed Origin reaches the endpoint (the rest of /auth refuses it).
    const res = await made.app.request('/auth/oidc/token', { ...form({ grant_type: 'authorization_code' }), headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://spa.example.org' } });
    expect(await res.json()).toMatchObject({ error: 'invalid_client' });
  });
});

describe('the device authorization grant', () => {
  const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
  const postForm = (made: Made, path: string, data: Record<string, string>) =>
    made.app.request(path, { ...form(data), headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  /** A device asks for its codes. */
  const startDevice = async (made: Made, clientId: string, extra: Record<string, string> = {}) => {
    const res = await postForm(made, '/auth/oidc/device', { client_id: clientId, scope: 'openid email offline_access', ...extra });
    expect(res.status).toBe(200);
    return (await res.json()) as { device_code: string; user_code: string; verification_uri: string; verification_uri_complete: string; expires_in: number; interval: number };
  };
  const poll = async (made: Made, clientId: string, deviceCode: string) => {
    const res = await postForm(made, '/auth/oidc/token', { grant_type: DEVICE_GRANT, client_id: clientId, device_code: deviceCode });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  };
  const user = (made: Made, path: string, code: string) => post(made.app, `/auth/device/${path}`, { code }, { Cookie: made.cookie });
  const later = (ms: number) => vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });

  it('DG1: a TV signs its user in: codes, the lookup, the approval, the tokens', async () => {
    const made = await withAdmin();
    const { client } = await addClient(made, { name: 'Living room TV', public: true, deviceFlow: true });
    expect((await (await made.app.request('/.well-known/openid-configuration')).json()).device_authorization_endpoint).toBe(`${ISSUER}/auth/oidc/device`);

    const started = await startDevice(made, client.id);
    expect(started.user_code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    expect(started.verification_uri).toBe(`${ISSUER}/`);
    expect(started.verification_uri_complete).toBe(`${ISSUER}/?madauth_device=${started.user_code}`);
    expect(started).toMatchObject({ expires_in: 600, interval: 5 });

    // Not approved yet; polling faster than the interval is told to slow down, and such a poll doesn't delay the next.
    expect((await poll(made, client.id, started.device_code)).body.error).toBe('authorization_pending');
    expect((await poll(made, client.id, started.device_code)).body.error).toBe('slow_down');
    later(4000);
    expect((await poll(made, client.id, started.device_code)).body.error).toBe('slow_down');
    later(1500);
    expect((await poll(made, client.id, started.device_code)).body.error).toBe('authorization_pending');

    // The user types the code in any case, with or without the dash, and sees who asks.
    const typed = started.user_code.toLowerCase().replace('-', ' ');
    const looked = await user(made, 'lookup', typed);
    expect(looked.status).toBe(200);
    expect(await looked.json()).toMatchObject({ code: started.user_code, client: { id: client.id, name: 'Living room TV' }, scope: ['openid', 'email', 'offline_access'] });
    expect((await user(made, 'approve', typed)).status).toBe(200);
    // Once: the decision is made.
    expect((await user(made, 'approve', typed)).status).toBe(404);

    later(6000);
    const got = await poll(made, client.id, started.device_code);
    expect(got.status).toBe(200);
    expect(got.body).toMatchObject({ token_type: 'Bearer', expires_in: 900, scope: 'openid email offline_access' });
    const idToken = JSON.parse(Buffer.from((got.body.id_token as string).split('.')[1], 'base64url').toString());
    expect(idToken).toMatchObject({ aud: client.id, email: 'grace@example.com', amr: ['pwd'] });
    expect(typeof got.body.refresh_token).toBe('string');
    // The device code is used up.
    later(6000);
    expect((await poll(made, client.id, started.device_code)).body.error).toBe('invalid_grant');
    // The refresh token works like any other.
    const config = await relyingParty(made.app, client.id);
    expect((await oidc.refreshTokenGrant(config, got.body.refresh_token as string)).access_token).toBeTruthy();
  });

  it('DG2: only clients an admin allowed may use it; a confidential one proves its secret', async () => {
    const made = await withAdmin();
    const plain = await addClient(made, { public: true });
    expect(await (await postForm(made, '/auth/oidc/device', { client_id: plain.client.id })).json()).toMatchObject({ error: 'unauthorized_client' });
    expect((await (await admin(made, 'clients/update', { id: plain.client.id, deviceFlow: true })).json()).client.deviceFlow).toBe(true);
    expect((await postForm(made, '/auth/oidc/device', { client_id: plain.client.id })).status).toBe(200);

    const confidential = await addClient(made, { deviceFlow: true });
    expect((await postForm(made, '/auth/oidc/device', { client_id: confidential.client.id })).status).toBe(401);
    expect((await postForm(made, '/auth/oidc/device', { client_id: confidential.client.id, client_secret: confidential.clientSecret! })).status).toBe(200);
    expect((await admin(made, 'clients/add', { name: 'x', redirectUris: [REDIRECT_URI], deviceFlow: 'yes' })).status).toBe(400);
  });

  it('DG3: denied, expired, and without a refresh token when offline_access is not asked for', async () => {
    const made = await withAdmin();
    const { client } = await addClient(made, { public: true, deviceFlow: true });
    const denied = await startDevice(made, client.id);
    await user(made, 'lookup', denied.user_code);
    expect((await user(made, 'deny', denied.user_code)).status).toBe(200);
    expect((await poll(made, client.id, denied.device_code)).body.error).toBe('access_denied');
    expect((await poll(made, client.id, denied.device_code)).body.error).toBe('invalid_grant');

    const online = await startDevice(made, client.id, { scope: 'openid' });
    await user(made, 'lookup', online.user_code);
    await user(made, 'approve', online.user_code);
    const got = await poll(made, client.id, online.device_code);
    expect(got.status).toBe(200);
    expect(got.body.refresh_token).toBeUndefined();
    expect(got.body.id_token).toBeTruthy();

    const expired = await startDevice(made, client.id);
    later(601_000);
    expect((await user(made, 'lookup', expired.user_code)).status).toBe(404);
    expect((await poll(made, client.id, expired.device_code)).body.error).toBe('expired_token');
  });

  it('DG4: a code is bound to whoever looked it up; another user, or no session, gets nothing', async () => {
    const made = await withAdmin();
    const { client } = await addClient(made, { public: true, deviceFlow: true });
    const started = await startDevice(made, client.id);
    expect((await post(made.app, '/auth/device/lookup', { code: started.user_code })).status).toBe(401);
    expect((await user(made, 'lookup', started.user_code)).status).toBe(200);

    const other = { ...made, cookie: `madauth_session=${await signUpVerified(made.app, made.hook, 'ada@example.com')}` };
    expect((await user(other, 'lookup', started.user_code)).status).toBe(404);
    expect((await user(other, 'approve', started.user_code)).status).toBe(404);
    // Approving takes the lookup first.
    const fresh = await startDevice(made, client.id);
    expect((await user(made, 'approve', fresh.user_code)).status).toBe(404);
    expect((await user(made, 'lookup', fresh.user_code)).status).toBe(200);
    expect((await user(made, 'approve', fresh.user_code)).status).toBe(200);
  });

  it('DG5: five wrong codes in ten minutes, then the lookup waits', async () => {
    const made = await withAdmin();
    const { client } = await addClient(made, { public: true, deviceFlow: true });
    const started = await startDevice(made, client.id);
    for (let i = 0; i < 5; i++) {
      const res = await user(made, 'lookup', 'BBBB-BBBB');
      expect(res.status).toBe(404);
      expect((await res.json()).error).toBe('device_code_invalid');
    }
    const blocked = await user(made, 'lookup', started.user_code);
    expect(blocked.status).toBe(429);
    expect((await blocked.json()).error).toBe('too_many_attempts');
    later(601_000);
    // The device code expired meanwhile with the wait: a new one works, and a right code gives the tries back.
    const again = await startDevice(made, client.id);
    for (let i = 0; i < 4; i++) expect((await user(made, 'lookup', 'BBBB-BBBB')).status).toBe(404);
    expect((await user(made, 'lookup', again.user_code)).status).toBe(200);
    for (let i = 0; i < 4; i++) expect((await user(made, 'lookup', 'BBBB-BBBB')).status).toBe(404);
    expect((await user(made, 'lookup', again.user_code)).status).toBe(200);
  });

  it('DG6: a password reset ends what a device was granted, and removes a pending device code', async () => {
    const made = await withAdmin();
    const { client } = await addClient(made, { public: true, deviceFlow: true });
    const started = await startDevice(made, client.id);
    await user(made, 'lookup', started.user_code);
    await user(made, 'approve', started.user_code);
    const userId = (await (await made.app.request('/auth/session', { headers: { Cookie: made.cookie } })).json()).user.id;
    expect(await made.store.findMany('oidcDeviceCode', { userId })).toHaveLength(1);
    await new Users(made.store).resetSignIn(userId);
    expect(await made.store.findMany('oidcDeviceCode', { userId })).toHaveLength(0);
    expect((await poll(made, client.id, started.device_code)).body.error).toBe('invalid_grant');
  });
});

describe('the token exchange', () => {
  const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
  const ID_TOKEN = 'urn:ietf:params:oauth:token-type:id_token';
  const postForm = (made: Made, path: string, data: Record<string, string>) =>
    made.app.request(path, { ...form(data), headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  const nonceFor = async (made: Made, clientId: string) => {
    const res = await postForm(made, '/auth/oidc/nonce', { client_id: clientId });
    expect(res.status).toBe(200);
    return (await res.json()) as { nonce: string; google_client_id: string; expires_in: number };
  };
  const exchange = async (made: Made, clientId: string, idToken: string, extra: Record<string, string> = {}) => {
    const res = await postForm(made, '/auth/oidc/token', { grant_type: EXCHANGE, client_id: clientId, subject_token: idToken, subject_token_type: ID_TOKEN, scope: 'openid email offline_access', ...extra });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  };

  it('TX1: a native app exchanges a Google ID token with madAuth’s nonce for tokens; a new user is signed up', async () => {
    const made = await withAdmin();
    const { client } = await addClient(made, { name: 'Phone app', public: true, tokenExchange: true });
    expect((await (await made.app.request('/.well-known/openid-configuration')).json()).grant_types_supported).toContain(EXCHANGE);
    const { nonce, google_client_id } = await nonceFor(made, client.id);
    expect(google_client_id).toBe(CLIENT_ID);

    made.hook.calls.length = 0;
    const got = await exchange(made, client.id, await googleIdToken({ nonce }));
    expect(got.status).toBe(200);
    expect(got.body).toMatchObject({ token_type: 'Bearer', scope: 'openid email offline_access' });
    const claims = JSON.parse(Buffer.from((got.body.id_token as string).split('.')[1], 'base64url').toString());
    expect(claims).toMatchObject({ aud: client.id, email: 'ada@example.com', amr: ['google'] });
    expect(typeof got.body.refresh_token).toBe('string');
    // Ada is a new user: signed up and signed in, without cookies.
    expect(made.hook.calls.map((call) => call.type)).toEqual(['user.signing_up', 'user.signed_up', 'user.signed_in']);
    expect(await made.store.findOne('user', { emailNormalized: 'ada@example.com' })).toMatchObject({ emailVerified: true });
  });

  it('TX2: the nonce must be madAuth’s, for this client and fresh; the token must be for the server’s Google client', async () => {
    const made = await withAdmin();
    const { client } = await addClient(made, { public: true, tokenExchange: true });
    const other = await addClient(made, { public: true, tokenExchange: true });
    expect((await exchange(made, client.id, await googleIdToken({ nonce: 'random-nonce' }))).body.error).toBe('invalid_grant');
    expect((await exchange(made, client.id, await googleIdToken({ nonce: (await nonceFor(made, other.client.id)).nonce }))).body.error).toBe('invalid_grant');
    const { nonce } = await nonceFor(made, client.id);
    expect((await exchange(made, client.id, await googleIdToken({ nonce, aud: 'another-client' }))).body.error).toBe('invalid_grant');
    expect((await exchange(made, client.id, await googleIdToken({ nonce, email_verified: false }))).body.error).toBe('invalid_grant');
    expect((await exchange(made, client.id, 'not-a-jwt')).body.error).toBe('invalid_grant');
    expect((await exchange(made, client.id, await googleIdToken({ nonce }), { subject_token_type: 'urn:ietf:params:oauth:token-type:access_token' })).body.error).toBe('invalid_request');
    // A nonce works once, also when the exchange with it failed.
    expect((await exchange(made, client.id, await googleIdToken({ nonce }))).body.error).toBe('invalid_grant');
    const fresh = (await nonceFor(made, client.id)).nonce;
    const token = await googleIdToken({ nonce: fresh });
    expect((await exchange(made, client.id, token)).status).toBe(200);
    expect((await exchange(made, client.id, token)).body.error).toBe('invalid_grant');
    const expired = (await nonceFor(made, client.id)).nonce;
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 6 * 60 * 1000 });
    expect((await exchange(made, client.id, await googleIdToken({ nonce: expired }))).body.error).toBe('invalid_grant');
  });

  it('TX3: only clients an admin allowed; a user who signs in another way, or needs a second factor, is refused', async () => {
    const made = await withAdmin();
    const plain = await addClient(made, { public: true });
    expect((await postForm(made, '/auth/oidc/nonce', { client_id: plain.client.id })).status).toBe(400);
    expect((await (await admin(made, 'clients/update', { id: plain.client.id, tokenExchange: true })).json()).client.tokenExchange).toBe(true);
    const { nonce } = await nonceFor(made, plain.client.id);
    // Grace signs in with a password: Google can't take her account over.
    const taken = await exchange(made, plain.client.id, await googleIdToken({ nonce, email: 'grace@example.com' }));
    expect(taken.body).toMatchObject({ error: 'invalid_grant' });
    expect(taken.body.error_description).toContain('password');
    // A policy that asks for a second factor: the app finishes in a browser.
    await admin(made, 'settings/method', { method: 'authenticator', setting: { allowAsSignInMethod: false, secondFactor: 'none' } });
    await admin(made, 'settings/method', { method: 'google', setting: { allowAsSignInMethod: true, secondFactor: 'required' } });
    made.hook.calls.length = 0;
    const second = await exchange(made, plain.client.id, await googleIdToken({ nonce: (await nonceFor(made, plain.client.id)).nonce }));
    expect(second.status).toBe(400);
    expect(second.body).toMatchObject({ error: 'interaction_required', next: 'second-factor-setup' });
    // Nothing was signed in: no session cookies, no sign-in event.
    expect(made.hook.calls.map((call) => call.type)).not.toContain('user.signed_in');
  });
});
