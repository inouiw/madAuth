// Behaviour described in docs/email-link-security.md; update the doc when changing it.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { REDIRECT_TO, WEBHOOK_SECRET, WEBHOOK_URL, cookies, getNonce, googleIdToken, linkAndCode, passwordApp, post, signUpVerified, verify, setMethods } from '../test/helpers.js';
import { base32Decode, stepOf, totp } from '../totp.js';

type Made = ReturnType<typeof passwordApp>;

const LINDA = 'linda@example.com';
const START = 1_700_000_015_000;

afterEach(() => {
  vi.useRealTimers();
});

const startClock = () => vi.useFakeTimers({ toFake: ['Date'], now: START });
const advance = (ms: number) => vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + ms });

/** Which methods are on, written as an admin would. */

const send = (app: Made['app'], email = LINDA, more: Record<string, unknown> = {}) =>
  post(app, '/auth/email-link/send', { email, redirectTo: REDIRECT_TO, locale: 'de', ...more });
const verifyLink = (app: Made['app'], body: Record<string, unknown>) => post(app, '/auth/email-link/verify', body);

describe('e-mail link', () => {
  it('L1: the first link signs a new address up and in, and the address counts as confirmed', async () => {
    const { app, hook, store } = passwordApp();

    const sent = await send(app);

    expect(sent.status).toBe(202);
    // Nobody can sign in as Linda before the link is used: the user is not reported yet.
    expect(hook.types()).toEqual(['user.signing_up', 'email.send_signin_link']);
    expect(hook.calls[0].data).toEqual({ email: LINDA, locale: 'de', method: 'email-link' });
    const mail = hook.lastEmail()!;
    expect(mail.data).toMatchObject({
      to: LINDA,
      site: 'app.example.com',
      locale: 'de',
      code: expect.stringMatching(/^\d{6}$/),
      user: { id: expect.stringMatching(/^usr_/) },
    });
    const { link, token } = linkAndCode(mail);
    expect(link).toBe(`${REDIRECT_TO}#madauth_signin=${token}`);

    hook.calls.length = 0;
    const res = await verifyLink(app, { token });

    expect(res.status).toBe(200);
    expect((await res.json()).user).toMatchObject({ email: LINDA, amr: ['email'] });
    expect(cookies(res).madauth_session.value).toBeTruthy();
    expect(hook.types()).toEqual(['user.email_verified', 'user.signed_up', 'user.signed_in']);
    expect(hook.calls[0].data).toMatchObject({ via: 'link', user: { email: LINDA } });
    expect(hook.calls[1].data).toMatchObject({ method: 'email-link', user: { email: LINDA } });
    expect(hook.calls[2].data).toMatchObject({ method: 'email-link', user: { email: LINDA } });
    expect(hook.calls[1].data.user).not.toHaveProperty('amr');
    const [user] = await store.findMany('user', {});
    expect(user).toMatchObject({ emailVerified: true, name: null });
    expect((await store.findMany('account', { userId: user.id })).map((a) => a.key)).toEqual([`email-link:${user.id}`]);
    // A link works once.
    expect((await verifyLink(app, { token })).status).toBe(400);
  });

  it('L2: the code signs in too; a returning user just gets the e-mail; the link lives 15 minutes', async () => {
    startClock();
    const { app, hook } = passwordApp();
    await send(app);
    const { code } = linkAndCode(hook.lastEmail());
    hook.calls.length = 0;

    const res = await verifyLink(app, { email: LINDA, code: ` ${code.slice(0, 3)} ${code.slice(3)} ` });

    expect(res.status).toBe(200);
    expect(hook.calls[0]).toMatchObject({ type: 'user.email_verified', data: { via: 'code' } });

    advance(61_000);
    hook.calls.length = 0;
    expect((await send(app)).status).toBe(202);
    expect(hook.types()).toEqual(['email.send_signin_link']);
    expect(hook.lastEmail()!.data.expiresAt).toBe(Date.now() + 15 * 60 * 1000);
    const { token } = linkAndCode(hook.lastEmail());
    hook.calls.length = 0;
    advance(15 * 60 * 1000 + 1);
    const late = await verifyLink(app, { token });
    expect(late.status).toBe(400);
    expect(await late.json()).toMatchObject({ error: 'link_invalid' });
    // A returning user's address is confirmed already: no second user.email_verified.
    advance(61_000);
    await send(app);
    expect((await verifyLink(app, { token: linkAndCode(hook.lastEmail()).token })).status).toBe(200);
    expect(hook.types()).toEqual(['email.send_signin_link', 'user.signed_in']);
  });

  it('L3: a method signs in only users who have it: the owner of another kind of account is told so, both ways', async () => {
    startClock();
    const { app, hook } = passwordApp();
    await signUpVerified(app, hook, 'grace@example.com');
    advance(61_000);
    hook.calls.length = 0;

    const res = await send(app, 'grace@example.com');

    expect(res.status).toBe(202);
    expect(hook.types()).toEqual(['email.send_already_registered']);
    expect(hook.lastEmail()!.data).toMatchObject({ to: 'grace@example.com', methods: ['password'], link: REDIRECT_TO, locale: 'de' });
    // The password still signs Grace in, and only it.
    expect((await post(app, '/auth/password/signin', { email: 'grace@example.com', password: 'correct horse battery' })).status).toBe(200);

    await send(app);
    await verifyLink(app, { token: linkAndCode(hook.lastEmail()).token });
    advance(61_000);
    hook.calls.length = 0;
    await post(app, '/auth/password/signup', { email: LINDA, password: 'correct horse battery', redirectTo: REDIRECT_TO });
    expect(hook.types()).toEqual(['user.signing_up', 'email.send_already_registered']);
    expect(hook.lastEmail()!.data.methods).toEqual(['email-link']);
    // No password was added: "forgot password" says so.
    advance(61_000);
    hook.calls.length = 0;
    await post(app, '/auth/password/send-reset', { email: LINDA, redirectTo: REDIRECT_TO });
    expect(hook.types()).toEqual(['email.send_password_reset_no_password']);
  });

  it('L4: a sign-up nobody finished is taken over: its password goes; a password sign-up afterwards takes the user back', async () => {
    startClock();
    const { app, hook, store } = passwordApp();
    await post(app, '/auth/password/signup', { email: LINDA, password: 'correct horse battery', redirectTo: REDIRECT_TO });
    advance(61_000);
    hook.calls.length = 0;

    expect((await send(app)).status).toBe(202);

    // The user exists already: checked, but not created again.
    expect(hook.types()).toEqual(['user.signing_up', 'email.send_signin_link']);
    const [user] = await store.findMany('user', {});
    expect((await store.findMany('account', { userId: user.id })).map((a) => a.key)).toEqual([`email-link:${user.id}`]);
    const { token } = linkAndCode(hook.lastEmail());

    hook.calls.length = 0;

    const res = await verifyLink(app, { token });

    expect(res.status).toBe(200);
    // The link makes the sign-up nobody finished hers: her first session completes it.
    expect(hook.types()).toEqual(['user.email_verified', 'user.signed_up', 'user.signed_in']);
    expect(hook.calls[0].data).toMatchObject({ method: 'email-link', via: 'link' });
    expect((await store.findMany('account', { userId: user.id })).map((a) => a.key)).toEqual([`email-link:${user.id}`]);
    expect(await store.findMany('verification', { userId: user.id })).toEqual([]);
    expect((await post(app, '/auth/password/signin', { email: LINDA, password: 'correct horse battery' })).status).toBe(401);

    // Before the link is used, someone signs the address up with a password: the latest sign-up counts, as
    // between two password sign-ups, so the link account goes and the link with it.
    const again = passwordApp();
    await send(again.app);
    const unused = linkAndCode(again.hook.lastEmail()).token;
    advance(61_000);
    await post(again.app, '/auth/password/signup', { email: LINDA, password: 'another password', redirectTo: REDIRECT_TO });
    const [other] = await again.store.findMany('user', {});
    expect((await again.store.findMany('account', { userId: other.id })).map((a) => a.key)).toEqual([`password:${other.id}`]);
    expect(await (await verifyLink(again.app, { token: unused })).json()).toMatchObject({ error: 'link_invalid' });
  });

  it('L10: a link sign-up nobody finished is taken over by a password, by the app or by Google: the link account goes', async () => {
    startClock();
    const { app, hook, store } = passwordApp();
    await send(app);
    const { token } = linkAndCode(hook.lastEmail());
    advance(61_000);

    // A password sign-up with the address, confirmed with its own e-mail.
    await post(app, '/auth/password/signup', { email: LINDA, password: 'correct horse battery', redirectTo: REDIRECT_TO });
    const confirmed = await post(app, '/auth/email/verify', { token: linkAndCode(hook.lastEmail()).token });

    expect(confirmed.status).toBe(200);
    expect((await confirmed.json()).user).toMatchObject({ email: LINDA, amr: ['pwd'] });
    const [user] = await store.findMany('user', {});
    expect((await store.findMany('account', { userId: user.id })).map((a) => a.key)).toEqual([`password:${user.id}`]);
    // The link from before no longer signs in, and no new one is sent: the address signs in with the password.
    expect(await (await verifyLink(app, { token })).json()).toMatchObject({ error: 'link_invalid' });
    advance(61_000);
    hook.calls.length = 0;
    expect((await send(app)).status).toBe(202);
    expect(hook.types()).toEqual(['email.send_already_registered']);
    expect(hook.lastEmail()!.data.methods).toEqual(['password']);

    // A sign-up with the authenticator app drops the link account as well.
    const withApp = passwordApp();
    await setMethods(withApp.store, { google: {}, password: {}, totp: {}, 'email-link': { secondFactor: 'none' } });
    await send(withApp.app);
    advance(61_000);
    expect((await post(withApp.app, '/auth/totp/signup', { email: LINDA, redirectTo: REDIRECT_TO })).status).toBe(202);
    expect(await withApp.store.findMany('account', {})).toEqual([]);

    // Google takes over a link sign-up nobody finished, too.
    const other = passwordApp();
    await send(other.app, 'ada@example.com');
    const { nonce, cookie } = await getNonce(other.app);
    expect((await verify(other.app, await googleIdToken({ nonce }), cookie)).status).toBe(200);
    expect((await other.store.findMany('account', {})).map((a) => a.key)).toEqual(['google:1001']);
  });

  it('L5: the sign-up check decides for new addresses and fails closed; known users are not checked', async () => {
    startClock();
    const { app, hook, store } = passwordApp();
    hook.respond = (call) => (call.type === 'user.signing_up' ? { allow: false, message: 'Invited users only.' } : undefined);

    const refused = await send(app);

    expect(refused.status).toBe(403);
    expect(await refused.json()).toEqual({ error: 'signup_rejected', message: 'Invited users only.' });
    expect(await store.findMany('user', {})).toEqual([]);

    hook.respond = undefined;
    hook.fail = 500;
    hook.failOnly = (type) => type === 'user.signing_up';
    expect((await send(app)).status).toBe(503);
    expect(await store.findMany('user', {})).toEqual([]);

    hook.fail = undefined;
    await send(app);
    await verifyLink(app, { token: linkAndCode(hook.lastEmail()).token });
    advance(61_000);
    hook.calls.length = 0;
    hook.respond = () => ({ allow: false });
    expect((await send(app)).status).toBe(202);
    expect(hook.types()).toEqual(['email.send_signin_link']);
  });

  it('L6: one e-mail per minute; invalid input is refused; a webhook that fails is reported', async () => {
    startClock();
    const { app, hook } = passwordApp();
    await send(app);

    expect((await send(app)).status).toBe(202);
    expect(hook.emails().length).toBe(1);
    advance(60_000);
    expect((await send(app)).status).toBe(202);
    expect(hook.emails().length).toBe(2);

    expect((await send(app, 'not-an-address')).status).toBe(400);
    expect(await (await post(app, '/auth/email-link/send', { email: LINDA, redirectTo: 'https://evil.example/' })).json()).toMatchObject({ error: 'invalid_options' });
    expect((await verifyLink(app, {})).status).toBe(400);
    advance(60_000);
    hook.fail = 500;
    const failed = await send(app);
    expect(failed.status).toBe(503);
    expect(await failed.json()).toMatchObject({ error: 'temporarily_unavailable' });
  });

  it('L7: switched off, the routes answer 403 and a link keeps; not configured, they are not there', async () => {
    const { app, hook, store } = passwordApp();
    await send(app);
    const { token, code } = linkAndCode(hook.lastEmail());
    await setMethods(store, { google: {}, password: {} });

    expect((await send(app)).status).toBe(403);
    const byLink = await verifyLink(app, { token });
    expect(byLink.status).toBe(403);
    expect(await byLink.json()).toMatchObject({ error: 'method_disabled' });
    expect((await verifyLink(app, { email: LINDA, code })).status).toBe(403);
    expect(await (await app.request('/auth/config')).json()).toMatchObject({ emailLink: null });

    await setMethods(store, { google: {}, 'email-link': { secondFactor: 'none' } });
    expect((await verifyLink(app, { token })).status).toBe(200);
    expect(await (await app.request('/auth/config')).json()).toMatchObject({ emailLink: { secondFactor: 'none' } });

    // Without email.send_signin_link among the webhook's types, the method is not configured: no routes, and an admin can't list it.
    const without = passwordApp({ webhook: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET, events: new Set(['email.send_verification', 'email.send_password_reset']) } });
    expect((await send(without.app)).status).toBe(404);
    expect(await (await without.app.request('/auth/config')).json()).toMatchObject({ emailLink: null, password: { minLength: 8 } });
  });

  it('L8: the policy asks for the authenticator app after the link: set up during the sign-in, then a code', async () => {
    startClock();
    const { app, hook, store } = passwordApp();
    await setMethods(store, { google: {}, password: {}, 'email-link': { secondFactor: 'required' } });
    await send(app);

    const first = await verifyLink(app, { token: linkAndCode(hook.lastEmail()).token });

    expect(first.status).toBe(401);
    expect(await first.json()).toMatchObject({ error: 'totp_setup_required', method: 'email-link' });
    expect(cookies(first).madauth_session.value).toBe('');
    const challenge = `madauth_challenge=${cookies(first).madauth_challenge.value}`;
    const setup = await post(app, '/auth/totp/setup', {}, { Cookie: challenge });
    expect(setup.status).toBe(200);
    const secret = base32Decode(((await setup.json()) as { secret: string }).secret)!;
    const setupCookie = `madauth_totp_setup=${cookies(setup).madauth_totp_setup.value}`;
    const confirm = await post(app, '/auth/totp/confirm', { code: totp(secret, stepOf(Date.now())) }, { Cookie: `${challenge}; ${setupCookie}` });
    expect(confirm.status).toBe(200);
    expect((await confirm.json()).user).toMatchObject({ email: LINDA, amr: ['email', 'otp'] });
    expect(hook.calls.at(-1)).toMatchObject({ type: 'user.signed_in', data: { method: 'email-link', secondFactor: 'totp' } });

    // From then on: the code from the app.
    advance(61_000);
    await send(app);
    const again = await verifyLink(app, { token: linkAndCode(hook.lastEmail()).token });
    expect(again.status).toBe(401);
    expect(await again.json()).toMatchObject({ error: 'totp_required', method: 'email-link' });
    advance(30_000);
    const verify = await post(app, '/auth/totp/verify', { code: totp(secret, stepOf(Date.now())) }, { Cookie: `madauth_challenge=${cookies(again).madauth_challenge.value}` });
    expect(verify.status).toBe(200);
    expect((await verify.json()).user.amr).toEqual(['email', 'otp']);
  });

  it('L9: wrong codes: five per e-mail, ten per user until a link is used', async () => {
    startClock();
    const { app, hook } = passwordApp();
    await send(app);
    let { token, code } = linkAndCode(hook.lastEmail());
    const wrong = () => verifyLink(app, { email: LINDA, code: code === '000000' ? '111111' : '000000' });

    for (let i = 0; i < 4; i++) expect(await (await wrong()).json()).toMatchObject({ error: 'code_invalid' });
    // The fifth wrong code deletes the verification: the right code no longer works either.
    await wrong();
    expect((await verifyLink(app, { email: LINDA, code })).status).toBe(400);

    // Ten wrong codes in a row lock the user's codes; the link still works, and sets the count back.
    advance(61_000);
    await send(app);
    ({ code } = linkAndCode(hook.lastEmail()));
    for (let i = 0; i < 5; i++) await wrong();
    advance(61_000);
    await send(app);
    ({ token, code } = linkAndCode(hook.lastEmail()));
    const locked = await verifyLink(app, { email: LINDA, code });
    expect(locked.status).toBe(429);
    expect(await locked.json()).toMatchObject({ error: 'codes_locked' });
    expect((await verifyLink(app, { token })).status).toBe(200);
    advance(61_000);
    await send(app);
    ({ code } = linkAndCode(hook.lastEmail()));
    expect((await verifyLink(app, { email: LINDA, code })).status).toBe(200);
  });
});
