// Microsoft sign-in: see "Microsoft" in docs/server.md and docs/microsoft-security.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CONSUMER_TENANT } from './microsoft.js';
import { parseProviderFields, parseProviderKind } from './providers.js';
import { setupToken } from './setup.js';
import { ISSUER, keyService, passwordApp, post, setClaims, signUpVerified } from './test/helpers.js';
import { CONTOSO_TENANT, MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET, fakeMicrosoft, type FakeMicrosoft, type FakeMicrosoftSignIn } from './test/microsoft.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const APP = 'https://app.example.com';
const ON = { allowAsSignInMethod: true, secondFactor: 'none' } as const;
const MICROSOFT = { kind: 'microsoft', clientId: MICROSOFT_CLIENT_ID, clientSecret: MICROSOFT_CLIENT_SECRET };

describe('what an admin sends for the Microsoft provider', () => {
  it('MS1: its id is its kind; a GUID client ID, the secret and a tenant are needed, and only Microsoft has a tenant', () => {
    expect(parseProviderKind({ kind: 'microsoft' })).toEqual({ kind: 'microsoft', id: 'microsoft' });
    expect(parseProviderKind({ kind: 'microsoft', id: 'entra' })).toMatchObject({ error: 'invalid_provider' });
    for (const tenant of ['common', 'organizations', 'consumers', CONTOSO_TENANT, CONTOSO_TENANT.toUpperCase()]) {
      expect(parseProviderFields('microsoft', { ...MICROSOFT, tenant }, true)).toEqual({ clientId: MICROSOFT_CLIENT_ID, clientSecret: MICROSOFT_CLIENT_SECRET, tenant: tenant.toLowerCase() });
    }
    for (const tenant of [undefined, '', 'contoso.onmicrosoft.com', 'Common', 42]) {
      expect(parseProviderFields('microsoft', { ...MICROSOFT, tenant }, true)).toMatchObject({ error: 'invalid_provider', message: expect.stringContaining('tenant') });
    }
    expect(parseProviderFields('microsoft', { ...MICROSOFT, clientId: 'not-a-guid', tenant: 'common' }, true)).toMatchObject({ message: expect.stringContaining('application (client) ID') });
    expect(parseProviderFields('microsoft', { clientId: MICROSOFT_CLIENT_ID, tenant: 'common' }, true)).toMatchObject({ message: 'A Microsoft provider needs its clientSecret.' });
    expect(parseProviderFields('microsoft', { ...MICROSOFT, tenant: 'common', issuer: 'https://login.microsoftonline.com' }, true)).toMatchObject({ error: 'invalid_provider' });
    expect(parseProviderFields('github', { tenant: 'common' }, false)).toMatchObject({ message: '"tenant" is a field of the Microsoft provider only.' });
    // An update may leave the tenant as it is, or change it.
    expect(parseProviderFields('microsoft', { name: 'Work account' }, false)).toEqual({ name: 'Work account' });
    expect(parseProviderFields('microsoft', { tenant: 'organizations' }, false)).toEqual({ tenant: 'organizations' });
  });
});

describe('signing in with Microsoft', () => {
  /** A server with Microsoft added for `tenant` and on, next to e-mail & password, with Ada, an admin who signed in just now. */
  async function withMicrosoft(tenant = 'common') {
    vi.useFakeTimers({ toFake: ['Date'], now: 1_700_000_000_000 });
    const ms = await fakeMicrosoft();
    const made = passwordApp({ google: undefined, oidcFetch: ms.fetch });
    const cookie = `madauth_session=${await signUpVerified(made.app, made.hook, 'ada@example.com', 'the admins own password')}`;
    await setClaims(made.store, 'ada@example.com', { roles: ['admin'] });
    const added = await post(made.app, '/auth/admin/providers/add', { ...MICROSOFT, tenant }, { Cookie: cookie });
    expect(added.status).toBe(200);
    expect((await post(made.app, '/auth/admin/settings/set', { methods: { password: ON, microsoft: ON } }, { Cookie: cookie })).status).toBe(200);
    return { ...made, ms, cookie };
  }
  type Made = Pick<Awaited<ReturnType<typeof withMicrosoft>>, 'app' | 'store' | 'cookie'> & { ms: FakeMicrosoft };

  /** The sign-in as a browser makes it: start, Microsoft's page, and back to the callback; `link` adds it to Ada's methods. */
  async function signIn(made: Made, signedIn: FakeMicrosoftSignIn, link = false) {
    const start = await made.app.request(`/auth/providers/microsoft/start?return_to=${encodeURIComponent(`${APP}/page`)}${link ? '&link=1' : ''}`, { headers: link ? { Cookie: made.cookie } : {} });
    expect(start.status).toBe(302);
    const authorize = start.headers.get('location')!;
    const state = start.headers.getSetCookie().find((cookie) => cookie.startsWith('madauth_oauth='))!.split(';')[0]!;
    const callback = await made.app.request(`/auth/providers/microsoft/callback?${made.ms.approve(authorize, signedIn)}`, { headers: { Cookie: link ? `${state}; ${made.cookie}` : state } });
    const cookieOf = (name: string) => callback.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))?.split(';')[0];
    return { authorize: new URL(authorize), callback, location: callback.headers.get('location'), session: cookieOf('madauth_session'), pending: cookieOf('madauth_pending_account') };
  }
  const userOf = async (made: Made, session: string | undefined) =>
    ((await (await made.app.request('/auth/session', { headers: { Cookie: session ?? '' } })).json()) as { user?: Record<string, unknown> }).user;
  const accountKeys = async (made: Made) => ((await made.store.findMany('account', {})) as { key: string }[]).map((account) => account.key);
  const codeOf = (email: { data: Record<string, unknown> } | undefined) => String(email?.data.code);

  const grace = { idToken: { tid: CONTOSO_TENANT, oid: 'oid-grace', email: 'grace@contoso.example.com', xms_edov: true, name: 'Grace Hopper' } };

  it('MS2: a new user signs up with a verified address: Microsoft’s own endpoints, the secret in the form, the account by tenant and object id', async () => {
    const made = await withMicrosoft();
    const { authorize, location, session } = await signIn(made, grace);

    expect(authorize.origin + authorize.pathname).toBe('https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
    expect(Object.fromEntries(authorize.searchParams)).toMatchObject({
      client_id: MICROSOFT_CLIENT_ID,
      redirect_uri: 'https://auth.example.com/auth/providers/microsoft/callback',
      response_type: 'code',
      scope: 'openid email profile',
      code_challenge_method: 'S256',
    });
    expect(location).toBe(`${APP}/page`);
    expect(await userOf(made, session)).toMatchObject({ email: 'grace@contoso.example.com', name: 'Grace Hopper', amr: ['microsoft'] });
    const exchange = made.ms.calls.find((call) => call.url === 'https://login.microsoftonline.com/common/oauth2/v2.0/token');
    expect(exchange?.authorization).toBeNull();
    expect(made.hook.calls.filter((call) => call.type === 'user.signed_up').at(-1)?.data).toMatchObject({ method: 'microsoft' });
    expect(await accountKeys(made)).toContain(`microsoft:${CONTOSO_TENANT}:oid-grace`);

    // A new app registration gives the account another `sub`; the tenant and object id still find it.
    const again = await signIn(made, { idToken: { ...grace.idToken, sub: 'another-pairwise-sub' } });
    expect((await userOf(made, again.session))?.id).toBe((await userOf(made, session))?.id);
  });

  it('MS3: the token must come from the tenant it names, one the provider’s tenant admits, and carry the object id', async () => {
    const failed = `${APP}/page#madauth_error=verification_failed&madauth_method=microsoft`;
    const made = await withMicrosoft();
    expect((await signIn(made, { ...grace, issuer: `https://login.microsoftonline.com/${CONSUMER_TENANT}/v2.0` })).location).toBe(failed);
    expect((await signIn(made, { ...grace, issuer: 'https://sts.windows.net/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/' })).location).toBe(failed);
    expect((await signIn(made, { idToken: { ...grace.idToken, oid: undefined } })).location).toBe(failed);
    expect((await signIn(made, { idToken: { ...grace.idToken, tid: 'not-a-tenant' } })).location).toBe(failed);

    const personal = { idToken: { tid: CONSUMER_TENANT, oid: 'oid-linus', email: 'linus@outlook.example.com', xms_edov: true } };
    const consumers = await withMicrosoft('consumers');
    expect((await signIn(consumers, grace)).location).toBe(failed);
    expect((await signIn(consumers, personal)).location).toBe(`${APP}/page`);
    const organizations = await withMicrosoft('organizations');
    expect((await signIn(organizations, personal)).location).toBe(failed);
    expect((await signIn(organizations, grace)).location).toBe(`${APP}/page`);
    const contoso = await withMicrosoft(CONTOSO_TENANT);
    expect((await signIn(contoso, { idToken: { ...grace.idToken, tid: 'ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee' } })).location).toBe(failed);
    expect((await signIn(contoso, grace)).location).toBe(`${APP}/page`);
    expect(contoso.ms.calls.some((call) => call.url === `https://login.microsoftonline.com/${CONTOSO_TENANT}/oauth2/v2.0/token`)).toBe(true);
  });

  it('MS4: without xms_edov the address is confirmed by e-mail first, since a tenant’s admin can give anyone any address', async () => {
    const made = await withMicrosoft();
    const { location, session } = await signIn(made, { idToken: { ...grace.idToken, xms_edov: false } });
    expect(location).toBe(`${APP}/page#madauth_next=email-confirmation&madauth_email=g%E2%80%A2%E2%80%A2%E2%80%A2%40contoso.example.com&madauth_method=microsoft`);
    expect(session).toBeUndefined();
    expect(made.hook.lastEmail()).toMatchObject({ type: 'email.send_verification', data: { to: 'grace@contoso.example.com' } });
    // An address that signs in another way is refused, and nothing is sent.
    made.hook.calls.length = 0;
    expect((await signIn(made, { idToken: { oid: 'oid-mallory', email: 'ada@example.com' } })).location).toBe(`${APP}/page#madauth_error=other_method&madauth_method=microsoft`);
    expect(made.hook.emails()).toEqual([]);
  });

  it('MS5: without an address the user types one: the page gets the hint, the e-mail proves the address, and from then on the account signs in by itself', async () => {
    const made = await withMicrosoft();
    const phoneOnly = { idToken: { oid: 'oid-phone', preferred_username: 'linus@outlook.example.com', name: 'Linus' } };
    const { location, session, pending, callback } = await signIn(made, phoneOnly);
    expect(location).toBe(`${APP}/page#madauth_next=email-address&madauth_method=microsoft`);
    expect(session).toBeUndefined();
    expect(callback.headers.getSetCookie().find((c) => c.startsWith('madauth_pending_account='))).toMatch(/Path=\/auth\/providers\/microsoft; HttpOnly; Secure; SameSite=Strict/);

    const hint = await made.app.request('/auth/providers/microsoft/address', { headers: { Cookie: pending! } });
    expect(await hint.json()).toEqual({ suggestion: 'linus@outlook.example.com' });
    expect((await made.app.request('/auth/providers/microsoft/address')).status).toBe(400);

    made.hook.calls.length = 0;
    const typed = { email: 'linus@example.com', redirectTo: `${APP}/page` };
    expect((await post(made.app, '/auth/providers/microsoft/address', typed)).status).toBe(400);
    expect(await (await post(made.app, '/auth/providers/microsoft/address', { ...typed, email: 'no address' }, { Cookie: pending! })).json()).toMatchObject({ error: 'invalid_email' });
    const sent = await post(made.app, '/auth/providers/microsoft/address', typed, { Cookie: pending! });
    expect(sent.status).toBe(202);
    expect(sent.headers.getSetCookie().find((c) => c.startsWith('madauth_pending_account='))).toMatch(/Max-Age=0/);
    expect(made.hook.lastEmail()).toMatchObject({ type: 'email.send_verification', data: { to: 'linus@example.com' } });

    const confirmed = await post(made.app, '/auth/email/verify', { email: 'linus@example.com', code: codeOf(made.hook.lastEmail()) });
    expect(((await confirmed.json()) as { user: Record<string, unknown> }).user).toMatchObject({ email: 'linus@example.com', name: 'Linus', amr: ['microsoft'] });
    // The account is the user's now: the next sign-in needs no address.
    made.hook.calls.length = 0;
    const again = await signIn(made, phoneOnly);
    expect(again.location).toBe(`${APP}/page`);
    expect((await userOf(made, again.session))?.email).toBe('linus@example.com');
    expect(made.hook.emails()).toEqual([]);
  });

  it('MS5b: an address typed again replaces one whose confirmation never came, e.g. with a typo', async () => {
    const made = await withMicrosoft();
    const phoneOnly = { idToken: { oid: 'oid-typo' } };
    const first = await signIn(made, phoneOnly);
    expect((await post(made.app, '/auth/providers/microsoft/address', { email: 'linus@exmaple.com', redirectTo: `${APP}/page` }, { Cookie: first.pending! })).status).toBe(202);
    // Signing in again, the account still waits for its address; the corrected one gets the e-mail.
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 61_000 });
    const again = await signIn(made, phoneOnly);
    expect(again.location).toBe(`${APP}/page#madauth_next=email-address&madauth_method=microsoft`);
    made.hook.calls.length = 0;
    expect((await post(made.app, '/auth/providers/microsoft/address', { email: 'linus@example.com', redirectTo: `${APP}/page` }, { Cookie: again.pending! })).status).toBe(202);
    expect(made.hook.emails().map((e) => e.data.to)).toEqual(['linus@example.com']);
    const confirmed = await post(made.app, '/auth/email/verify', { email: 'linus@example.com', code: codeOf(made.hook.lastEmail()) });
    expect(((await confirmed.json()) as { user: Record<string, unknown> }).user).toMatchObject({ email: 'linus@example.com', amr: ['microsoft'] });
  });

  it('MS6: the answer is the same for an address that signs in another way: its owner is told, and nothing is linked', async () => {
    const made = await withMicrosoft();
    const { pending } = await signIn(made, { idToken: { oid: 'oid-mallory', preferred_username: '+15551234567' } });
    expect(await (await made.app.request('/auth/providers/microsoft/address', { headers: { Cookie: pending! } })).json()).toEqual({ suggestion: null });
    made.hook.calls.length = 0;
    // A minute after Ada's own e-mail: one per minute goes to an address.
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 61_000 });
    const answer = await post(made.app, '/auth/providers/microsoft/address', { email: 'ada@example.com', redirectTo: `${APP}/page` }, { Cookie: pending! });
    expect(answer.status).toBe(202);
    expect(made.hook.emails().map((e) => [e.type, e.data.to])).toEqual([['email.send_already_registered', 'ada@example.com']]);
    expect(await accountKeys(made)).not.toContain('microsoft:9188040d-6c67-4c5b-b112-36a304b66dad:oid-mallory');
  });

  it('MS7: without the webhook’s e-mails an account without an address is refused', async () => {
    const ms = await fakeMicrosoft();
    const quiet = { ...passwordApp({ google: undefined, password: undefined, oidcFetch: ms.fetch, webhook: undefined }), ms, cookie: '' };
    const bearer = { Authorization: `Bearer ${await setupToken(keyService, ISSUER)}` };
    expect((await post(quiet.app, '/auth/admin/providers/add', { ...MICROSOFT, tenant: 'common' }, bearer)).status).toBe(200);
    expect((await post(quiet.app, '/auth/admin/settings/set', { methods: { microsoft: ON } }, bearer)).status).toBe(200);
    expect((await signIn(quiet, { idToken: { oid: 'oid-quiet' } })).location).toBe(`${APP}/page#madauth_error=email_unverified&madauth_method=microsoft`);
    expect((await signIn(quiet, grace)).location).toBe(`${APP}/page`);
  });

  it('MS8: a signed-in user adds Microsoft, also an account without an address; the settings, /auth/config and the admin API name it', async () => {
    const made = await withMicrosoft();
    expect((await signIn(made, { idToken: { oid: 'oid-ada' } }, true)).location).toBe(`${APP}/page#madauth_linked=microsoft`);
    const methods = ((await (await made.app.request('/auth/methods', { headers: { Cookie: made.cookie } })).json()) as { methods: { method: string; email?: string | null }[] }).methods;
    expect(methods.find((m) => m.method === 'microsoft')).toBeDefined();
    // Ada signs in with it from now on, without an address.
    expect((await userOf(made, (await signIn(made, { idToken: { oid: 'oid-ada' } })).session))?.email).toBe('ada@example.com');

    const config = (await (await made.app.request('/auth/config')).json()) as { providers: unknown[] };
    expect(config.providers).toContainEqual({ id: 'microsoft', kind: 'microsoft', name: 'Microsoft', secondFactor: 'none' });
    const listed = (await (await post(made.app, '/auth/admin/providers/list', {}, { Cookie: made.cookie })).json()) as { providers: Record<string, unknown>[] };
    expect(listed.providers.find((p) => p.id === 'microsoft')).toMatchObject({ kind: 'microsoft', tenant: 'common', clientId: MICROSOFT_CLIENT_ID, hasClientSecret: true });
    const settings = (await (await post(made.app, '/auth/admin/settings/get', {}, { Cookie: made.cookie })).json()) as { methods: Record<string, unknown> };
    expect(settings.methods.microsoft).toMatchObject({ configured: true, enabled: true });
    // The tenant changes; the accounts stay.
    expect((await post(made.app, '/auth/admin/providers/update', { id: 'microsoft', tenant: 'organizations' }, { Cookie: made.cookie })).status).toBe(200);
    expect((await signIn(made, grace)).location).toBe(`${APP}/page`);
  });
});
