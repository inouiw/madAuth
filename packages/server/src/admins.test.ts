// The role admin: INITIAL_ADMIN_EMAIL makes the first admin, and no admin takes the role from themselves. See
// "The first admin" in docs/server.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { INITIAL_ADMIN_SETTING } from './admins.js';
import type { MadauthConfig } from './config.js';
import { Settings } from './settings.js';
import { base32Decode, stepOf, totp } from './authenticator.js';
import {
  REDIRECT_TO,
  cookies,
  linkAndCode,
  passwordApp,
  post,
  signInResponse,
  setMethods,
  signUpVerified,
  testApp,
  type RecordingWebhook,
} from './test/helpers.js';

afterEach(() => {
  vi.restoreAllMocks();
});

type App = ReturnType<typeof testApp>;
const GRACE = 'grace@example.com';
const ADA = 'ada@example.com';
const password = 'correct horse battery';

const withSession = (session: string) => ({ Cookie: `madauth_session=${session}` });
const setClaimsOf = (app: App, session: string, email: string, claims: object) => post(app, '/auth/admin/claims/set', { email, claims }, withSession(session));
const sessionUser = async (app: App, session: string) => (await (await app.request('/auth/session', { headers: withSession(session) })).json()).user;
const signInWithPassword = async (app: App, email: string, secret = email === ADA ? 'adas password!' : password) =>
  cookies(await post(app, '/auth/password/signin', { email, password: secret })).madauth_session.value;
/** The `user.claims_changed` calls INITIAL_ADMIN_EMAIL caused. */
const initialAdminCalls = (hook: RecordingWebhook) => hook.calls.filter((call) => call.type === 'user.claims_changed' && call.data.by === 'INITIAL_ADMIN_EMAIL');

/** An app whose INITIAL_ADMIN_EMAIL is Grace's; with `overrides`, on the store of an earlier one. */
const appFor = (initialAdminEmail: string | undefined, overrides: Partial<MadauthConfig> = {}) => passwordApp({ initialAdminEmail, ...overrides });

describe('INITIAL_ADMIN_EMAIL', () => {
  it('gives the role to the user who signs up with the address, once it is confirmed, and tells the webhook', async () => {
    const { app, hook, store } = appFor(GRACE);
    await post(app, '/auth/password/signup', { email: 'Grace@Example.com', password, name: 'Grace Hopper', redirectTo: REDIRECT_TO });

    // An unfinished sign-up gets nothing: nobody has proven the address yet.
    expect((await post(app, '/auth/password/signin', { email: GRACE, password })).status).toBe(403);
    expect(await new Settings(store).get(INITIAL_ADMIN_SETTING)).toBeUndefined();
    const confirmed = await post(app, '/auth/email/verify', { token: linkAndCode(hook.lastEmail()).token });

    const { user } = await confirmed.json();
    expect(user.claims).toEqual({ roles: ['admin'] });
    expect(initialAdminCalls(hook)).toEqual([
      { type: 'user.claims_changed', data: { user: { id: user.id, email: 'Grace@Example.com', name: 'Grace Hopper', claims: { roles: ['admin'] } }, claims: { roles: ['admin'] }, by: 'INITIAL_ADMIN_EMAIL' } },
    ]);
    // After user.signed_up, which carries the role as well: the receiver hears of the user first.
    expect(hook.types().slice(-3)).toEqual(['user.signed_up', 'user.claims_changed', 'user.signed_in']);
    expect(await new Settings(store).get(INITIAL_ADMIN_SETTING)).toEqual([{ email: GRACE, userId: user.id }]);
    // The session works for the admin API at once.
    const session = cookies(confirmed).madauth_session.value;
    expect((await post(app, '/auth/admin/claims/get', { email: GRACE }, withSession(session))).status).toBe(200);
  });

  it('a Google sign-in with the address gets it too: Google verified it', async () => {
    const { app, hook } = appFor(ADA);

    const res = await signInResponse(app);

    expect((await res.json()).user.claims).toEqual({ roles: ['admin'] });
    expect(initialAdminCalls(hook)).toHaveLength(1);
  });

  it('applies once per value: a role taken away stays away, and a new value applies again, to the claims a user has', async () => {
    const first = appFor(GRACE);
    const grace = await signUpVerified(first.app, first.hook);
    await signUpVerified(first.app, first.hook, ADA, 'adas password!');
    await setClaimsOf(first.app, grace, ADA, { plan: 'pro', roles: ['editor'] });
    expect((await sessionUser(first.app, await signInWithPassword(first.app, GRACE))).claims).toEqual({ roles: ['admin'] });

    // The operator names Ada now: the new value applies at her next sign-in, next to the claims she has.
    const second = appFor(ADA, { store: first.store, webhookFetch: first.hook.fetch });
    const ada = cookies(await post(second.app, '/auth/password/signin', { email: ADA, password: 'adas password!' })).madauth_session.value;
    expect((await sessionUser(second.app, ada)).claims).toEqual({ plan: 'pro', roles: ['admin', 'editor'] });
    // Ada takes Grace's role away. Grace's value was applied, so her next sign-in leaves it away, also on an
    // instance that still has her value (as while a deployment replaces its instances).
    expect((await setClaimsOf(second.app, ada, GRACE, {})).status).toBe(200);
    expect((await sessionUser(first.app, await signInWithPassword(first.app, GRACE))).claims).toBeUndefined();

    expect(initialAdminCalls(first.hook).map((call) => call.data.user.email)).toEqual([GRACE, ADA]);
  });

  it('of two sign-ins at once, one applies it', async () => {
    const before = appFor(undefined);
    await signInResponse(before.app);
    const { app, hook } = appFor(ADA, { store: before.store });

    const results = await Promise.all([1, 2].map(() => signInResponse(app)));

    expect(results.map((res) => res.status)).toEqual([200, 200]);
    expect(initialAdminCalls(hook)).toHaveLength(1);
    expect((await sessionUser(app, cookies(results[0]).madauth_session.value)).claims).toEqual({ roles: ['admin'] });
  });

  it('does nothing for another address, or without the variable', async () => {
    const { app, hook } = appFor(ADA);

    const session = await signUpVerified(app, hook);

    expect((await sessionUser(app, session)).claims).toBeUndefined();
    expect(initialAdminCalls(hook)).toEqual([]);
  });
});

describe("an admin's own role", () => {
  /** Grace is the admin (by INITIAL_ADMIN_EMAIL), Ada a user; returns both sessions. */
  async function withAdmin() {
    const made = appFor(GRACE);
    const grace = await signUpVerified(made.app, made.hook);
    const ada = await signUpVerified(made.app, made.hook, ADA, 'adas password!');
    return { ...made, grace, ada };
  }

  it("an admin can't take the role from themselves; another admin can", async () => {
    const { app, grace, ada } = await withAdmin();

    const refused = await setClaimsOf(app, grace, GRACE, { plan: 'pro' });

    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: 'own_admin_role' });
    expect((await sessionUser(app, grace)).claims).toEqual({ roles: ['admin'] });
    // Their other claims are theirs to change, as long as the role stays.
    expect((await setClaimsOf(app, grace, GRACE, { plan: 'pro', roles: ['admin'] })).status).toBe(200);
    expect((await setClaimsOf(app, grace, ADA, { roles: ['admin'] })).status).toBe(200);
    expect((await setClaimsOf(app, ada, GRACE, { plan: 'pro' })).status).toBe(200);
    expect((await sessionUser(app, grace)).claims).toEqual({ plan: 'pro' });
    expect(await (await setClaimsOf(app, ada, ADA, {})).json()).toMatchObject({ error: 'own_admin_role' });
  });

  it("an admin can't delete their own account while they have the role", async () => {
    const { app, store, grace, ada } = await withAdmin();
    const deleteAccount = () => post(app, '/auth/account/delete', {}, withSession(grace));

    const refused = await deleteAccount();

    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: 'own_admin_role' });
    expect(await store.findOne('user', { emailNormalized: GRACE })).not.toBeNull();
    // Another admin takes the role from her first.
    await setClaimsOf(app, grace, ADA, { roles: ['admin'] });
    await setClaimsOf(app, ada, GRACE, {});
    expect((await deleteAccount()).status).toBe(204);
  });

  it('a refused deletion leaves the code from the authenticator app unused', async () => {
    const { app, store, grace } = await withAdmin();
    const signIn = { allowAsSignInMethod: true, secondFactor: 'none' } as const;
    await setMethods(store, { google: signIn, password: signIn, authenticator: { allowAsSignInMethod: false, secondFactor: 'none' } });
    const setup = await post(app, '/auth/authenticator/setup', {}, withSession(grace));
    const secret = base32Decode((await setup.json()).secret)!;
    const confirm = await post(app, '/auth/authenticator/confirm', { code: totp(secret, stepOf(Date.now())) }, { Cookie: `madauth_session=${grace}; madauth_authenticator_setup=${cookies(setup).madauth_authenticator_setup.value}` });
    const [recoveryCode] = (await confirm.json()).recoveryCodes;

    const refused = await post(app, '/auth/account/delete', { recoveryCode }, withSession(grace));

    expect(await refused.json()).toMatchObject({ error: 'own_admin_role' });
    expect(await (await app.request('/auth/authenticator/status', { headers: withSession(grace) })).json()).toMatchObject({ recoveryCodesLeft: 10 });
  });
});
