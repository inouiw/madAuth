// GitLab, LinkedIn and Slack (OpenID Connect presets), Facebook and X: see "Providers" in docs/server.md and
// docs/social-security.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PRESET_RULES } from './oidc-presets.js';
import { parseProviderFields, parseProviderKind } from './providers.js';
import { passwordApp, post, setClaims, signUpVerified } from './test/helpers.js';
import { fakeOidcProvider, type FakeOidcProvider, type FakeSignIn } from './test/oidc.js';
import { FACEBOOK_APP_ID, FACEBOOK_APP_SECRET, X_CLIENT_ID, X_CLIENT_SECRET, fakeSocial, type FakeProfile } from './test/social.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const APP = 'https://app.example.com';
const ON = { allowAsSignInMethod: true, secondFactor: 'none' } as const;

describe('what an admin sends for a preset, Facebook or X', () => {
  it('SP1: a preset names the provider and fills in its issuer; only GitLab’s issuer can be another', () => {
    expect(parseProviderKind({ kind: 'oidc', preset: 'linkedin' })).toEqual({ kind: 'oidc', id: 'linkedin' });
    expect(parseProviderKind({ kind: 'oidc', preset: 'gitlab', id: 'gitlab-corp' })).toEqual({ kind: 'oidc', id: 'gitlab-corp' });
    expect(parseProviderKind({ kind: 'oidc' })).toMatchObject({ error: 'invalid_provider' });

    const secret = { clientId: 'client', clientSecret: 'secret' };
    expect(parseProviderFields('oidc', { ...secret, preset: 'linkedin' }, true)).toEqual({ ...secret, preset: 'linkedin', issuer: 'https://www.linkedin.com/oauth' });
    expect(parseProviderFields('oidc', { ...secret, preset: 'slack', issuer: 'https://slack.com' }, true)).toEqual({ ...secret, preset: 'slack', issuer: 'https://slack.com' });
    expect(parseProviderFields('oidc', { ...secret, preset: 'slack', issuer: 'https://evil.example.com' }, true)).toMatchObject({ message: expect.stringContaining('leave issuer out') });
    expect(parseProviderFields('oidc', { ...secret, preset: 'gitlab' }, true)).toMatchObject({ issuer: 'https://gitlab.com', preset: 'gitlab' });
    expect(parseProviderFields('oidc', { ...secret, preset: 'gitlab', issuer: 'https://gitlab.example.com', name: 'Our GitLab' }, true)).toMatchObject({ issuer: 'https://gitlab.example.com', name: 'Our GitLab' });
    expect(parseProviderFields('oidc', { ...secret, preset: 'discord' }, true)).toMatchObject({ message: expect.stringContaining('preset must be one of gitlab, linkedin, slack') });
    expect(parseProviderFields('oidc', { preset: 'gitlab' }, false)).toMatchObject({ message: expect.stringContaining("preset can't change") });
    expect(parseProviderFields('github', { preset: 'gitlab' }, false)).toMatchObject({ message: '"preset" is a field of OpenID Connect providers only.' });
    // Without a preset, the name and the issuer are still needed.
    expect(parseProviderFields('oidc', { ...secret, issuer: 'https://idp.example.com' }, true)).toMatchObject({ error: 'invalid_provider' });
  });

  it('SP2: Facebook and X have their kind as their id, need a client ID of their form and the secret', () => {
    expect(parseProviderKind({ kind: 'facebook' })).toEqual({ kind: 'facebook', id: 'facebook' });
    expect(parseProviderKind({ kind: 'x' })).toEqual({ kind: 'x', id: 'x' });
    expect(parseProviderKind({ kind: 'x', id: 'twitter' })).toMatchObject({ error: 'invalid_provider' });
    expect(parseProviderKind({ kind: 'oidc', id: 'facebook' })).toMatchObject({ error: 'invalid_provider', message: expect.stringContaining('madAuth') });
    expect(parseProviderFields('facebook', { clientId: FACEBOOK_APP_ID, clientSecret: FACEBOOK_APP_SECRET }, true)).toEqual({ clientId: FACEBOOK_APP_ID, clientSecret: FACEBOOK_APP_SECRET });
    expect(parseProviderFields('facebook', { clientId: 'app-name', clientSecret: 's' }, true)).toMatchObject({ message: expect.stringContaining('App ID') });
    expect(parseProviderFields('facebook', { clientId: FACEBOOK_APP_ID }, true)).toMatchObject({ message: 'A Facebook provider needs its clientSecret.' });
    expect(parseProviderFields('x', { clientId: X_CLIENT_ID, clientSecret: X_CLIENT_SECRET }, true)).toEqual({ clientId: X_CLIENT_ID, clientSecret: X_CLIENT_SECRET });
    expect(parseProviderFields('x', { clientId: 'has space', clientSecret: 's' }, true)).toMatchObject({ message: expect.stringContaining('OAuth 2.0 Client ID') });
    expect(parseProviderFields('x', { clientId: X_CLIENT_ID, clientSecret: 's', issuer: 'https://x.com' }, true)).toMatchObject({ error: 'invalid_provider' });
  });
});

/** Several stand-ins as one `fetch`: the first that knows the URL answers. */
const fetchOf =
  (...fakes: { fetch: typeof fetch }[]): typeof fetch =>
  async (input, init) => {
    for (const fake of fakes) {
      const res = await fake.fetch(input, init);
      if (res.status !== 404) return res;
    }
    return new Response('not found', { status: 404 });
  };

/** A server with e-mail & password, the stand-ins, and Ada, an admin who signed in just now. */
async function server(fetchFn: typeof fetch) {
  vi.useFakeTimers({ toFake: ['Date'], now: 1_700_000_000_000 });
  const made = passwordApp({ google: undefined, oidcFetch: fetchFn });
  const cookie = `madauth_session=${await signUpVerified(made.app, made.hook, 'ada@example.com', 'the admins own password')}`;
  await setClaims(made.store, 'ada@example.com', { roles: ['admin'] });
  /** Adds a provider and switches it on; resolves to the admin API's answer. */
  const add = async (provider: Record<string, unknown>) => {
    const added = await post(made.app, '/auth/admin/providers/add', provider, { Cookie: cookie });
    const answer = (await added.json()) as { provider: { id: string } & Record<string, unknown> };
    expect(added.status, JSON.stringify(answer)).toBe(200);
    expect((await post(made.app, '/auth/admin/settings/set', { methods: { password: ON, [answer.provider.id]: ON } }, { Cookie: cookie })).status).toBe(200);
    return answer.provider;
  };
  return { ...made, cookie, add };
}
type Server = Awaited<ReturnType<typeof server>>;

/** The sign-in as a browser makes it: start, the provider's page (`approve`), and back to the callback. */
async function signIn(made: Server, id: string, approve: (authorizeUrl: string) => string) {
  const start = await made.app.request(`/auth/providers/${id}/start?return_to=${encodeURIComponent(`${APP}/page`)}`);
  expect(start.status).toBe(302);
  const authorize = start.headers.get('location')!;
  const state = start.headers.getSetCookie().find((cookie) => cookie.startsWith('madauth_oauth='))!.split(';')[0]!;
  const callback = await made.app.request(`/auth/providers/${id}/callback?${approve(authorize)}`, { headers: { Cookie: state } });
  const cookieOf = (name: string) => callback.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))?.split(';')[0];
  return { authorize: new URL(authorize), location: callback.headers.get('location'), session: cookieOf('madauth_session'), pending: cookieOf('madauth_pending_account') };
}
const userOf = async (made: Server, session: string | undefined) =>
  ((await (await made.app.request('/auth/session', { headers: { Cookie: session ?? '' } })).json()) as { user?: Record<string, unknown> }).user;
const accountKeys = async (made: Server) => ((await made.store.findMany('account', {})) as { key: string }[]).map((account) => account.key);

describe('the OpenID Connect presets', () => {
  const viaOidc = (idp: FakeOidcProvider, signedIn: FakeSignIn) => (authorizeUrl: string) => idp.approve(authorizeUrl, signedIn);

  it('SP3: LinkedIn: its issuer, no PKCE, the secret in the form, and an ID token without the nonce', async () => {
    const linkedin = await fakeOidcProvider({ issuer: PRESET_RULES.linkedin.issuer, authMethods: ['client_secret_post'], pkce: false, echoNonce: false });
    const made = await server(linkedin.fetch);
    const added = await made.add({ kind: 'oidc', preset: 'linkedin', clientId: linkedin.clientId, clientSecret: linkedin.clientSecret });
    expect(added).toMatchObject({ id: 'linkedin', name: 'LinkedIn', preset: 'linkedin', issuer: 'https://www.linkedin.com/oauth', callbackUrl: 'https://auth.example.com/auth/providers/linkedin/callback' });

    const { authorize, location, session } = await signIn(made, 'linkedin', viaOidc(linkedin, { idToken: { sub: 'li-1', email: 'grace@example.com', email_verified: true, name: 'Grace' } }));
    expect(authorize.href.startsWith('https://www.linkedin.com/oauth/authorize?')).toBe(true);
    expect(authorize.searchParams.get('scope')).toBe('openid email profile');
    expect(authorize.searchParams.has('code_challenge')).toBe(false);
    expect(authorize.searchParams.get('nonce')).toBeTruthy();
    expect(location).toBe(`${APP}/page`);
    expect(await userOf(made, session)).toMatchObject({ email: 'grace@example.com', name: 'Grace', amr: ['linkedin'] });
    expect(await accountKeys(made)).toContain('oidc:linkedin:li-1');
    // The button's logo follows the preset.
    const config = (await (await made.app.request('/auth/config')).json()) as { providers: unknown[] };
    expect(config.providers).toContainEqual({ id: 'linkedin', kind: 'oidc', name: 'LinkedIn', preset: 'linkedin', secondFactor: 'none' });
  });

  it('SP3b: a nonce LinkedIn does send must be the sign-in’s', async () => {
    const linkedin = await fakeOidcProvider({ issuer: PRESET_RULES.linkedin.issuer, authMethods: ['client_secret_post'], pkce: false, echoNonce: false });
    const made = await server(linkedin.fetch);
    await made.add({ kind: 'oidc', preset: 'linkedin', clientId: linkedin.clientId, clientSecret: linkedin.clientSecret });
    const { location } = await signIn(made, 'linkedin', viaOidc(linkedin, { idToken: { sub: 'li-2', email: 'eve@example.com', email_verified: true, nonce: 'another sign-in' } }));
    expect(location).toBe(`${APP}/page#madauth_error=verification_failed&madauth_method=linkedin`);
  });

  it('SP4: Slack: no PKCE, but the nonce is required; an unverified address is confirmed by e-mail', async () => {
    const slack = await fakeOidcProvider({ issuer: 'https://slack.com', authMethods: ['client_secret_post', 'client_secret_basic'], pkce: false });
    const made = await server(slack.fetch);
    await made.add({ kind: 'oidc', preset: 'slack', clientId: slack.clientId, clientSecret: slack.clientSecret });
    const { authorize, location } = await signIn(made, 'slack', viaOidc(slack, { idToken: { sub: 'U1', email: 'linus@example.com', email_verified: false } }));
    expect(authorize.searchParams.has('code_challenge')).toBe(false);
    expect(location).toBe(`${APP}/page#madauth_next=email-confirmation&madauth_email=l%E2%80%A2%E2%80%A2%E2%80%A2%40example.com&madauth_method=slack`);
    expect(made.hook.lastEmail()).toMatchObject({ type: 'email.send_verification', data: { to: 'linus@example.com' } });

    const noNonce = await fakeOidcProvider({ issuer: 'https://slack.com', authMethods: ['client_secret_basic'], pkce: false, echoNonce: false });
    const strict = await server(noNonce.fetch);
    await strict.add({ kind: 'oidc', preset: 'slack', clientId: noNonce.clientId, clientSecret: noNonce.clientSecret });
    expect((await signIn(strict, 'slack', viaOidc(noNonce, { idToken: { sub: 'U2', email: 'a@example.com', email_verified: true } }))).location).toBe(
      `${APP}/page#madauth_error=verification_failed&madauth_method=slack`,
    );
  });

  it('SP5: a self-hosted GitLab: its own issuer and id, the standard flow with PKCE; an account without an address types one', async () => {
    const gitlab = await fakeOidcProvider({ issuer: 'https://gitlab.example.com' });
    const made = await server(gitlab.fetch);
    const added = await made.add({ kind: 'oidc', preset: 'gitlab', id: 'gitlab-corp', name: 'Corp GitLab', issuer: gitlab.issuer, clientId: gitlab.clientId, clientSecret: gitlab.clientSecret });
    expect(added).toMatchObject({ id: 'gitlab-corp', name: 'Corp GitLab', preset: 'gitlab', issuer: 'https://gitlab.example.com' });
    // gitlab.com's discovery isn't asked: the issuer is the instance's.
    expect(gitlab.calls[0]?.url).toBe('https://gitlab.example.com/.well-known/openid-configuration');

    const { authorize, location } = await signIn(made, 'gitlab-corp', viaOidc(gitlab, { idToken: { sub: '42', name: 'Hedy' }, userinfo: { sub: '42' } }));
    expect(authorize.searchParams.get('code_challenge_method')).toBe('S256');
    expect(location).toBe(`${APP}/page#madauth_next=email-address&madauth_method=gitlab-corp`);
    // The preset can't change, and the issuer stays.
    expect((await post(made.app, '/auth/admin/providers/update', { id: 'gitlab-corp', preset: 'slack' }, { Cookie: made.cookie })).status).toBe(400);
  });
});

describe('Facebook', () => {
  const ada = { id: '10158000000000001', name: 'Grace Hopper', email: 'grace@example.com', picture: { data: { url: 'https://platform-lookaside.fbsbx.com/grace.jpg', is_silhouette: false } } };

  async function withFacebook() {
    const social = fakeSocial();
    const made = await server(social.fetch);
    const added = await made.add({ kind: 'facebook', clientId: FACEBOOK_APP_ID, clientSecret: FACEBOOK_APP_SECRET });
    expect(added).toMatchObject({ id: 'facebook', kind: 'facebook', name: 'Facebook', callbackUrl: 'https://auth.example.com/auth/providers/facebook/callback' });
    return { made, social, as: (profile: FakeProfile) => (authorizeUrl: string) => social.approve(authorizeUrl, profile) };
  }

  it('SP6: the login dialog with the state and the email permission; the address is confirmed by e-mail once, then the account signs in by itself', async () => {
    const { made, social, as } = await withFacebook();
    const first = await signIn(made, 'facebook', as(ada));
    expect(first.authorize.origin + first.authorize.pathname).toBe('https://www.facebook.com/v26.0/dialog/oauth');
    expect(Object.fromEntries(first.authorize.searchParams)).toMatchObject({
      client_id: FACEBOOK_APP_ID,
      redirect_uri: 'https://auth.example.com/auth/providers/facebook/callback',
      response_type: 'code',
      scope: 'email,public_profile',
    });
    expect(first.authorize.searchParams.has('code_challenge')).toBe(false);
    // Facebook doesn't say it confirmed the address: the confirmation e-mail proves it.
    expect(first.location).toBe(`${APP}/page#madauth_next=email-confirmation&madauth_email=g%E2%80%A2%E2%80%A2%E2%80%A2%40example.com&madauth_method=facebook`);
    expect(first.session).toBeUndefined();
    const code = String(made.hook.lastEmail()?.data.code);
    const confirmed = await post(made.app, '/auth/email/verify', { email: 'grace@example.com', code });
    expect(((await confirmed.json()) as { user: Record<string, unknown> }).user).toMatchObject({ email: 'grace@example.com', name: 'Grace Hopper', amr: ['facebook'] });
    expect(await accountKeys(made)).toContain(`facebook:${ada.id}`);
    // The profile call carries the token as a header and the app secret proof, never the secret itself.
    const me = social.calls.find((call) => call.url.startsWith('https://graph.facebook.com/v26.0/me'))!;
    expect(me.authorization).toMatch(/^Bearer token-/);
    expect(me.url).not.toContain(FACEBOOK_APP_SECRET);

    const again = await signIn(made, 'facebook', as(ada));
    expect(again.location).toBe(`${APP}/page`);
    expect(await userOf(made, again.session)).toMatchObject({ email: 'grace@example.com', picture: ada.picture.data.url, amr: ['facebook'] });
  });

  it('SP7: without an address the user types one; a refused exchange or profile is verification_failed; cancelling is cancelled', async () => {
    const { made, as } = await withFacebook();
    expect((await signIn(made, 'facebook', as({ id: '2001', name: 'Phone Only' }))).location).toBe(`${APP}/page#madauth_next=email-address&madauth_method=facebook`);
    expect((await signIn(made, 'facebook', as({ name: 'No id' }))).location).toBe(`${APP}/page#madauth_error=verification_failed&madauth_method=facebook`);
    expect((await signIn(made, 'facebook', (url) => `code=unknown&state=${new URL(url).searchParams.get('state')}`)).location).toBe(
      `${APP}/page#madauth_error=verification_failed&madauth_method=facebook`,
    );
    const denied = await signIn(made, 'facebook', (url) => `error=access_denied&error_reason=user_denied&state=${new URL(url).searchParams.get('state')}`);
    expect(denied.location).toBe(`${APP}/page#madauth_error=cancelled&madauth_method=facebook`);
  });
});

describe('X', () => {
  async function withX() {
    const social = fakeSocial();
    const made = await server(fetchOf(social));
    await made.add({ kind: 'x', clientId: X_CLIENT_ID, clientSecret: X_CLIENT_SECRET });
    return { made, social, as: (profile: FakeProfile) => (authorizeUrl: string) => social.approve(authorizeUrl, profile) };
  }

  it('SP8: PKCE and the users.email scope; a confirmed address signs up at once, the secret as HTTP Basic', async () => {
    const { made, social, as } = await withX();
    const { authorize, location, session } = await signIn(made, 'x', as({ id: '1500000000000000001', name: 'Ada', username: 'ada', confirmed_email: 'ada.x@example.com', profile_image_url: 'https://pbs.twimg.com/ada.jpg' }));
    expect(authorize.origin + authorize.pathname).toBe('https://x.com/i/oauth2/authorize');
    expect(Object.fromEntries(authorize.searchParams)).toMatchObject({ client_id: X_CLIENT_ID, scope: 'tweet.read users.read users.email', code_challenge_method: 'S256', response_type: 'code' });
    expect(location).toBe(`${APP}/page`);
    const user = (await userOf(made, session)) as { id: string; sessionId: string };
    expect(user).toMatchObject({ email: 'ada.x@example.com', name: 'Ada', picture: 'https://pbs.twimg.com/ada.jpg', amr: ['x'] });
    // Like every sign-in, it starts a session with its record.
    expect(await made.store.findOne('session', { id: user.sessionId })).toMatchObject({ userId: user.id, amr: 'x' });
    expect(await accountKeys(made)).toContain('x:1500000000000000001');
    const exchange = social.calls.find((call) => call.url === 'https://api.x.com/2/oauth2/token')!;
    expect(exchange.authorization).toMatch(/^Basic /);
    expect(exchange.body).not.toContain(X_CLIENT_SECRET);
  });

  it('SP9: an account without a confirmed address types one; the username stands in for a missing name', async () => {
    const { made, as } = await withX();
    const { location, pending } = await signIn(made, 'x', as({ id: '1500000000000000002', username: 'phoneonly' }));
    expect(location).toBe(`${APP}/page#madauth_next=email-address&madauth_method=x`);
    made.hook.calls.length = 0;
    expect((await post(made.app, '/auth/providers/x/address', { email: 'phone@example.com', redirectTo: `${APP}/page` }, { Cookie: pending! })).status).toBe(202);
    const confirmed = await post(made.app, '/auth/email/verify', { email: 'phone@example.com', code: String(made.hook.lastEmail()?.data.code) });
    expect(((await confirmed.json()) as { user: Record<string, unknown> }).user).toMatchObject({ email: 'phone@example.com', name: 'phoneonly', amr: ['x'] });
  });

  it('SP10: the settings, /auth/config and the admin API name Facebook and X; removing one leaves its accounts', async () => {
    const { made } = await withX();
    const config = (await (await made.app.request('/auth/config')).json()) as { providers: unknown[] };
    expect(config.providers).toContainEqual({ id: 'x', kind: 'x', name: 'X', secondFactor: 'none' });
    const settings = (await (await post(made.app, '/auth/admin/settings/get', {}, { Cookie: made.cookie })).json()) as { methods: Record<string, unknown> };
    expect(settings.methods.x).toMatchObject({ configured: true, enabled: true });
    expect((await post(made.app, '/auth/admin/settings/set', { methods: { facebook: ON } }, { Cookie: made.cookie })).status).toBe(400);
    expect((await post(made.app, '/auth/admin/providers/remove', { id: 'x' }, { Cookie: made.cookie })).status).toBe(200);
    expect((await made.app.request(`/auth/providers/x/start?return_to=${encodeURIComponent(APP)}`)).status).toBe(404);
  });
});
