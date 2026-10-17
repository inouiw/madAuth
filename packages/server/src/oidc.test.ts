// Generic OpenID Connect providers: see "Providers" in docs/server.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { discover } from './oidc.js';
import { parseProviderFields, parseProviderKind } from './providers.js';
import { passwordApp, post, setClaims, signUpVerified } from './test/helpers.js';
import { fakeOidcProvider, type FakeOidcProvider } from './test/oidc.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const GITLAB = { kind: 'oidc', id: 'gitlab', name: 'GitLab', clientId: 'madauth-client', clientSecret: 'madauth-client-secret' };

/** A server whose OpenID Connect requests go to `idp`, with Ada, an admin who signed in just now. */
async function withAdmin(idp: FakeOidcProvider) {
  vi.useFakeTimers({ toFake: ['Date'], now: 1_700_000_000_000 });
  const made = passwordApp({ google: undefined, oidcFetch: idp.fetch });
  const cookie = `madauth_session=${await signUpVerified(made.app, made.hook, 'ada@example.com', 'the admins own password')}`;
  await setClaims(made.store, 'ada@example.com', { roles: ['admin'] });
  return { ...made, cookie };
}

const admin = (made: Awaited<ReturnType<typeof withAdmin>>, action: string, body: unknown) =>
  post(made.app, `/auth/admin/providers/${action}`, body, { Cookie: made.cookie }).then((res) => res.json() as Promise<Record<string, any>>);

describe('what an admin sends for an OpenID Connect provider', () => {
  it('OP1: an id of its own that is none of madAuth’s methods, an https issuer, a name, the secret, more scopes', () => {
    expect(parseProviderKind({ kind: 'oidc', id: 'gitlab' })).toEqual({ kind: 'oidc', id: 'gitlab' });
    for (const id of [undefined, 'GitLab', 'g', 'with space', '1st', 'a'.repeat(33), 'password', 'microsoft']) {
      expect(parseProviderKind({ kind: 'oidc', id })).toMatchObject({ error: 'invalid_provider' });
    }

    const fields = { name: 'GitLab', clientId: 'abc', clientSecret: 's', issuer: 'https://gitlab.com' };
    expect(parseProviderFields('oidc', { ...fields, scopes: 'read_user openid  read_user', trustEmail: true }, true)).toEqual({ ...fields, scopes: ['read_user'], trustEmail: true });
    expect(parseProviderFields('oidc', { ...fields, issuer: 'http://localhost:9000/realms/dev' }, true)).toMatchObject({ issuer: 'http://localhost:9000/realms/dev' });
    for (const wrong of [
      { ...fields, name: undefined },
      { ...fields, clientSecret: undefined },
      { ...fields, issuer: undefined },
      { ...fields, issuer: 'http://gitlab.com' },
      { ...fields, issuer: 'https://gitlab.com/?x=1' },
      { ...fields, scopes: 'a\\b' },
      { ...fields, trustEmail: 'yes' },
    ]) {
      expect(parseProviderFields('oidc', wrong, true)).toMatchObject({ error: 'invalid_provider' });
    }
    // The issuer stays: the accounts belong to it.
    expect(parseProviderFields('oidc', { issuer: 'https://other.example.com' }, false)).toMatchObject({ error: 'invalid_provider', message: expect.stringContaining("can't change") });
    expect(parseProviderFields('oidc', { trustEmail: true, scopes: '' }, false)).toEqual({ trustEmail: true, scopes: [] });
    // The other kinds have none of these fields.
    expect(parseProviderFields('github', { clientId: 'Ov23li', clientSecret: 's', issuer: 'https://github.com' }, true)).toMatchObject({ error: 'invalid_provider' });
  });
});

describe('finding a provider', () => {
  it('OP2: reads its discovery document, which must name the issuer exactly and https endpoints', async () => {
    const idp = await fakeOidcProvider();
    expect(await discover(idp.issuer, idp.fetch)).toEqual({
      endpoints: {
        issuer: idp.issuer,
        authorizationEndpoint: `${idp.issuer}/authorize`,
        tokenEndpoint: `${idp.issuer}/token`,
        jwksUri: `${idp.issuer}/jwks`,
        userinfoEndpoint: `${idp.issuer}/userinfo`,
        clientAuth: 'client_secret_basic',
      },
    });
    expect(await discover(`${idp.issuer}/`, idp.fetch)).toMatchObject({ problem: expect.stringContaining('names the issuer') });
    expect(await discover('https://nothing.example.com', idp.fetch)).toMatchObject({ problem: expect.stringContaining('HTTP 404') });
    const down = (async () => Promise.reject(new TypeError('fetch failed'))) as typeof fetch;
    expect(await discover(idp.issuer, down)).toMatchObject({ problem: expect.stringContaining('could not be read') });

    const postOnly = await fakeOidcProvider({ authMethods: ['client_secret_post'] });
    expect(await discover(postOnly.issuer, postOnly.fetch)).toMatchObject({ endpoints: { clientAuth: 'client_secret_post' } });
    const neither = await fakeOidcProvider({ authMethods: ['private_key_jwt'] });
    expect(await discover(neither.issuer, neither.fetch)).toMatchObject({ problem: expect.stringContaining('neither') });
  });
});

describe('admins add an OpenID Connect provider', () => {
  it('OP3: checks the issuer first, keeps its fields, and lets its scopes and e-mail switch change but not its issuer', async () => {
    const idp = await fakeOidcProvider();
    const made = await withAdmin(idp);

    expect(await admin(made, 'add', { ...GITLAB, issuer: 'https://nothing.example.com' })).toMatchObject({ error: 'invalid_provider', message: expect.stringContaining('HTTP 404') });
    const { provider } = await admin(made, 'add', { ...GITLAB, issuer: idp.issuer, scopes: 'read_user' });
    expect(provider).toMatchObject({ id: 'gitlab', kind: 'oidc', name: 'GitLab', issuer: idp.issuer, scopes: ['read_user'], trustEmail: false, callbackUrl: 'https://auth.example.com/auth/providers/gitlab/callback' });
    expect(await admin(made, 'add', { ...GITLAB, issuer: idp.issuer })).toMatchObject({ error: 'provider_exists' });

    expect((await admin(made, 'update', { id: 'gitlab', trustEmail: true })).provider).toMatchObject({ trustEmail: true, scopes: ['read_user'] });
    expect(await admin(made, 'update', { id: 'gitlab', issuer: 'https://other.example.com' })).toMatchObject({ error: 'invalid_provider' });
    expect(made.hook.calls.filter((c) => c.type.startsWith('provider.')).map((c) => [c.type, c.data.provider.trustEmail])).toEqual([
      ['provider.added', false],
      ['provider.changed', true],
    ]);
  });
});

describe("an OpenID Connect provider's method", () => {
  it('OP4: is switched on like the others, with a policy, and an id the server has no provider for is refused', async () => {
    const idp = await fakeOidcProvider();
    const made = await withAdmin(idp);
    await admin(made, 'add', { ...GITLAB, issuer: idp.issuer });
    const set = (methods: Record<string, unknown>) =>
      post(made.app, '/auth/admin/settings/set', { methods }, { Cookie: made.cookie }).then((res) => res.json() as Promise<Record<string, any>>);
    const on = { allowAsSignInMethod: true, secondFactor: 'none' };

    expect((await set({ password: on, gitlab: { ...on, secondFactor: 'optional' }, authenticator: { allowAsSignInMethod: false, secondFactor: 'none' } })).methods.gitlab).toEqual({
      configured: true,
      enabled: true,
      allowAsSignInMethod: true,
      secondFactor: 'optional',
    });
    // It always signs in, like Google.
    expect(await set({ password: on, gitlab: { allowAsSignInMethod: false, secondFactor: 'none' } })).toMatchObject({ error: 'invalid_settings' });
    expect(await set({ password: on, keycloak: on })).toMatchObject({ error: 'invalid_settings', message: expect.stringContaining('"keycloak" is no sign-in method of this server') });
    const config = (await (await made.app.request('/auth/config')).json()) as { providers: unknown[] };
    expect(config.providers).toContainEqual({ id: 'gitlab', kind: 'oidc', name: 'GitLab', secondFactor: 'optional' });
  });
});

describe('signing in with an OpenID Connect provider', () => {
  const APP = 'https://app.example.com';
  const ON = { allowAsSignInMethod: true, secondFactor: 'none' } as const;

  /** A server with GitLab added and on, next to e-mail & password; `extra` changes the provider. */
  async function withGitLab(options: Parameters<typeof fakeOidcProvider>[0] = {}, extra: Record<string, unknown> = {}) {
    const idp = await fakeOidcProvider(options);
    const made = await withAdmin(idp);
    expect((await admin(made, 'add', { ...GITLAB, issuer: idp.issuer, scopes: 'read_user', ...extra })).provider).toBeDefined();
    await post(made.app, '/auth/admin/settings/set', { methods: { password: ON, gitlab: ON } }, { Cookie: made.cookie });
    return { ...made, idp };
  }

  /** The sign-in as a browser makes it: start, the provider's page (approve), and back to the callback. */
  async function signIn(made: Awaited<ReturnType<typeof withGitLab>>, signedIn: Parameters<FakeOidcProvider['approve']>[1], extraQuery = '') {
    const start = await made.app.request(`/auth/providers/gitlab/start?return_to=${encodeURIComponent(`${APP}/page`)}${extraQuery}`, { headers: extraQuery ? { Cookie: made.cookie } : {} });
    expect(start.status).toBe(302);
    const authorize = start.headers.get('location')!;
    const state = start.headers.getSetCookie().find((cookie) => cookie.startsWith('madauth_oauth='))!.split(';')[0]!;
    const callback = await made.app.request(`/auth/providers/gitlab/callback?${made.idp.approve(authorize, signedIn)}`, { headers: { Cookie: extraQuery ? `${state}; ${made.cookie}` : state } });
    const session = callback.headers.getSetCookie().find((cookie) => cookie.startsWith('madauth_session='))?.split(';')[0];
    return { authorize: new URL(authorize), callback, location: callback.headers.get('location'), session };
  }

  it('OP5: a new user signs up: the request asks for the scopes with PKCE and a nonce, the code exchange authenticates the client', async () => {
    const made = await withGitLab();
    const { authorize, location, session } = await signIn(made, { idToken: { sub: 'gl-1', email: 'linus@example.com', email_verified: true, name: 'Linus' } });

    expect(authorize.origin + authorize.pathname).toBe(`${made.idp.issuer}/authorize`);
    expect(Object.fromEntries(authorize.searchParams)).toMatchObject({
      client_id: 'madauth-client',
      redirect_uri: 'https://auth.example.com/auth/providers/gitlab/callback',
      response_type: 'code',
      scope: 'openid email profile read_user',
      code_challenge_method: 'S256',
      nonce: expect.any(String),
      state: expect.any(String),
    });
    expect(location).toBe(`${APP}/page`);
    const user = (await (await made.app.request('/auth/session', { headers: { Cookie: session! } })).json()) as { user: Record<string, unknown> };
    expect(user.user).toMatchObject({ email: 'linus@example.com', name: 'Linus', amr: ['gitlab'] });
    expect(made.idp.calls.find((call) => call.url.endsWith('/token'))?.authorization).toMatch(/^Basic /);
    expect(made.hook.calls.filter((call) => call.type === 'user.signed_up').at(-1)?.data).toMatchObject({ user: { email: 'linus@example.com' }, method: 'gitlab' });
    // The same account signs in again, also with a new address at the provider.
    const again = await signIn(made, { idToken: { sub: 'gl-1', email: 'linus@new.example.com', email_verified: true } });
    expect(again.location).toBe(`${APP}/page`);
    expect(((await (await made.app.request('/auth/session', { headers: { Cookie: again.session! } })).json()) as { user: { email: string } }).user.email).toBe('linus@example.com');
  });

  it('OP6: the address comes from userinfo when the ID token has none, and counts only verified, unless the provider is trusted', async () => {
    const made = await withGitLab();
    expect((await signIn(made, { idToken: { sub: 'gl-2' }, userinfo: { sub: 'gl-2', email: 'mia@example.com', email_verified: true } })).location).toBe(`${APP}/page`);
    expect((await signIn(made, { idToken: { sub: 'gl-3' }, userinfo: { sub: 'someone-else', email: 'x@example.com', email_verified: true } })).location).toBe(`${APP}/page#madauth_error=verification_failed&madauth_method=gitlab`);
    // A signed userinfo answer (a JWT, not JSON) fails, and the log says why.
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect((await signIn(made, { idToken: { sub: 'gl-3' }, userinfo: 'eyJ.signed.jwt' })).location).toBe(`${APP}/page#madauth_error=verification_failed&madauth_method=gitlab`);
    expect(logged).toHaveBeenCalledWith(expect.stringContaining('answered no JSON'));
    expect((await signIn(made, { idToken: { sub: 'gl-4', email: 'eve@example.com', email_verified: false } })).location).toBe(`${APP}/page#madauth_error=email_unverified&madauth_method=gitlab`);
    expect((await signIn(made, { idToken: { sub: 'gl-5', email: 'cognito@example.com', email_verified: 'true' } })).location).toBe(`${APP}/page`);

    await admin(made, 'update', { id: 'gitlab', trustEmail: true });
    expect((await signIn(made, { idToken: { sub: 'gl-4', email: 'eve@example.com' } })).location).toBe(`${APP}/page`);
  });

  it('OP7: an ID token with another nonce or for another client is refused; one for several clients needs azp', async () => {
    const made = await withGitLab();
    const refused = `${APP}/page#madauth_error=verification_failed&madauth_method=gitlab`;
    const claims = { sub: 'gl-6', email: 'kim@example.com', email_verified: true };
    expect((await signIn(made, { idToken: { ...claims, nonce: 'another' } })).location).toBe(refused);
    expect((await signIn(made, { idToken: claims, audience: 'another-client' })).location).toBe(refused);
    expect((await signIn(made, { idToken: claims, audience: ['madauth-client', 'another-client'] })).location).toBe(refused);
    expect((await signIn(made, { idToken: { ...claims, azp: 'madauth-client' }, audience: ['madauth-client', 'another-client'] })).location).toBe(`${APP}/page`);
    // azp, when there, names this client also with one audience.
    expect((await signIn(made, { idToken: { ...claims, azp: 'another-client' } })).location).toBe(refused);
  });

  it('OP8: never joins a user who signs in another way, and is off, missing or not OpenID Connect as the settings say', async () => {
    const made = await withGitLab();
    expect((await signIn(made, { idToken: { sub: 'gl-7', email: 'ada@example.com', email_verified: true } })).location).toBe(`${APP}/page#madauth_error=other_method&madauth_method=gitlab`);

    await post(made.app, '/auth/admin/settings/set', { methods: { password: ON } }, { Cookie: made.cookie });
    const off = await made.app.request(`/auth/providers/gitlab/start?return_to=${encodeURIComponent(`${APP}/page`)}`);
    expect(off.headers.get('location')).toBe(`${APP}/page#madauth_error=method_disabled&madauth_method=gitlab`);
    expect((await made.app.request(`/auth/providers/keycloak/start?return_to=${encodeURIComponent(`${APP}/page`)}`)).status).toBe(404);
  });

  it('OP9: a provider that takes the secret only in the form gets it there', async () => {
    const made = await withGitLab({ authMethods: ['client_secret_post'] });
    expect((await signIn(made, { idToken: { sub: 'gl-8', email: 'pat@example.com', email_verified: true } })).location).toBe(`${APP}/page`);
    const exchange = made.idp.calls.find((call) => call.url.endsWith('/token'))!;
    expect(exchange.authorization).toBeNull();
    expect(new URLSearchParams(exchange.body).get('client_secret')).toBe('madauth-client-secret');
  });

  it('OP11: its id comes back only with its issuer, whose users its accounts are, and off until switched on', async () => {
    const idp = await fakeOidcProvider();
    const other = await fakeOidcProvider({ issuer: 'https://other-idp.example.com' });
    const both = ((input: string | URL | Request, init?: RequestInit) =>
      (String(input instanceof Request ? input.url : input).startsWith(other.issuer) ? other.fetch : idp.fetch)(input, init)) as typeof fetch;
    const made = { ...(await withAdmin({ ...idp, fetch: both })), idp };
    const add = (issuer: string) => admin(made, 'add', { ...GITLAB, issuer });
    const switchOn = () => post(made.app, '/auth/admin/settings/set', { methods: { password: ON, gitlab: ON } }, { Cookie: made.cookie });
    const userOf = async (session: string | undefined) => ((await (await made.app.request('/auth/session', { headers: { Cookie: session! } })).json()) as { user: { id: string } }).user.id;
    const linus = { idToken: { sub: 'gl-9', email: 'linus@example.com', email_verified: true } };
    expect((await add(idp.issuer)).provider).toBeDefined();
    await switchOn();
    const first = await signIn(made, linus);

    expect((await admin(made, 'remove', { id: 'gitlab' })).usersWithoutSignIn).toBe(1);
    // Another issuer under the id would sign its users in to these accounts, by their sub.
    expect(await add(other.issuer)).toMatchObject({ error: 'invalid_provider', message: expect.stringContaining(`belongs to the issuer "${idp.issuer}"`) });
    expect((await add(idp.issuer)).provider).toBeDefined();
    const settings = (await (await post(made.app, '/auth/admin/settings/get', {}, { Cookie: made.cookie })).json()) as { methods: Record<string, { enabled: boolean }> };
    expect(settings.methods.gitlab).toMatchObject({ configured: true, enabled: false });
    await switchOn();
    const again = await signIn(made, linus);
    expect(await userOf(again.session)).toBe(await userOf(first.session));
  });

  it('OP10: a signed-in user adds the provider to their methods, sees its address there, and removes it', async () => {
    const made = await withGitLab();
    const { location } = await signIn(made, { idToken: { sub: 'gl-ada', email: 'ada@gitlab.example.com', email_verified: true } }, '&link=1');
    expect(location).toBe(`${APP}/page#madauth_linked=gitlab`);
    const list = async () => ((await (await made.app.request('/auth/methods', { headers: { Cookie: made.cookie } })).json()) as { methods: { id: string; method: string }[] }).methods;
    const gitlab = (await list()).find((m) => m.method === 'gitlab');
    expect(gitlab).toMatchObject({ signIn: true, removable: true, email: 'ada@gitlab.example.com' });
    expect((await post(made.app, '/auth/methods/remove', { id: gitlab!.id }, { Cookie: made.cookie })).status).toBe(200);
    expect((await list()).map((m) => m.method)).not.toContain('gitlab');
  });
});
