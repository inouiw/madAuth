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
