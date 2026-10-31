// madAuth as an OpenID Connect provider, driven by a standard relying party (openid-client) where it can be.
// Behaviour described in "OpenID Connect provider" in docs/server.md; update the doc when changing it.
import * as oidc from 'openid-client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { REFRESH_TOKEN_TTL_MS } from '../oidc-clients.js';
import { APP_ORIGIN, ISSUER, cookies, passwordApp, post, setClaims, signUpVerified, linkAndCode } from '../test/helpers.js';
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
  const made = passwordApp({ allowedOrigins: [APP_ORIGIN, ISSUER] });
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
    scope: 'openid email profile',
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
    expect(tokens.scope).toBe('openid email profile');

    // The access token is a JWT for APIs (RFC 9068), meant for the client.
    const [header, payload] = tokens.access_token.split('.').slice(0, 2).map((part) => JSON.parse(Buffer.from(part, 'base64url').toString()));
    expect(header).toMatchObject({ typ: 'at+jwt', alg: 'ES256' });
    expect(payload).toMatchObject({ sub: claims.sub, aud: client.id, client_id: client.id, scope: 'openid email profile' });
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
