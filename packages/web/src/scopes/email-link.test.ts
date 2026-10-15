import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { EmailLink } from '../providers/email-link.js';
import { GoogleFedcm } from '../providers/google-fedcm.js';
import { Password } from '../providers/password.js';
import { CODE, SERVER, SIGNIN_TOKEN, fakeGis, fakeServer, resetAll } from '../test-helpers.js';

let warnLog: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  warnLog = vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(resetAll);

const init = (options: Partial<Parameters<typeof Madauth.initialize>[0]> = {}) =>
  Madauth.initialize({ serverUrl: SERVER, providers: [new Password(), new EmailLink()], ...options });

const linda = { id: 'usr_linda', email: 'linda@example.com' };

/** Linda has signed up with the link before, and the fake server has sent her one. */
function lindaWithLink(server: ReturnType<typeof fakeServer>, verified = true) {
  server.accounts.set(linda.email, { password: '', verified, link: true });
  server.mails.push({ purpose: 'signin', to: linda.email, redirectTo: 'x' });
}

describe('Madauth.emailLink', () => {
  it('H27: send asks for the e-mail with the current page as the link’s target and the locale, for any address', async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    await init({ locale: 'de' });

    const result = await Madauth.emailLink.send({ email: linda.email });

    expect(result).toEqual({ isSuccess: true });
    expect(server.requests.at(-1)).toMatchObject({
      method: 'POST',
      url: `${SERVER}/auth/email-link/send`,
      credentials: 'include',
      body: { email: linda.email, redirectTo: expect.stringMatching(/\/page$/), locale: 'de' },
    });
    expect(server.mails.at(-1)).toMatchObject({ purpose: 'signin', to: linda.email });
    expect(await Madauth.emailLink.send({ email: 'ada@example.com', redirectTo: 'https://app.example.com/welcome' })).toEqual({ isSuccess: true });
    expect(server.mails.at(-1)).toMatchObject({ purpose: 'signin', to: 'ada@example.com', redirectTo: 'https://app.example.com/welcome' });
    // The owner of a password account is told so instead; the answer is the same.
    expect(await Madauth.emailLink.send({ email: 'grace@example.com' })).toEqual({ isSuccess: true });
    expect(server.mails.at(-1)).toMatchObject({ purpose: 'registered', to: 'grace@example.com' });

    expect(await Madauth.emailLink.send({ email: 'nope' })).toMatchObject({ isSuccess: false, error: { code: 'invalid_email' } });
    server.rejectSignUp = 'Invited users only.';
    expect(await Madauth.emailLink.send({ email: 'new@example.com' })).toMatchObject({ isSuccess: false, error: { code: 'signup_rejected', message: 'Invited users only.' } });
    server.rejectSignUp = undefined;
    server.emailsDown = true;
    expect(await Madauth.emailLink.send({ email: linda.email })).toMatchObject({ isSuccess: false, error: { code: 'temporarily_unavailable' } });
    server.emailsDown = false;
    server.methods['email-link'] = false;
    expect(await Madauth.emailLink.send({ email: linda.email })).toMatchObject({ isSuccess: false, error: { code: 'method_disabled' } });
  });

  it('H28: verify signs in with the code from the e-mail', async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    await init();
    await Madauth.emailLink.send({ email: linda.email });

    expect(await Madauth.emailLink.verify({ email: linda.email, code: '000000' })).toMatchObject({ isSuccess: false, error: { code: 'code_invalid' } });
    expect(Madauth.currentUser).toBeNull();
    const result = await Madauth.emailLink.verify({ email: linda.email, code: CODE });

    expect(result).toEqual({ isSuccess: true, user: linda });
    expect(listener).toHaveBeenLastCalledWith(linda);
    expect(Madauth.currentUser).toEqual(linda);
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/email-link/verify`, body: { email: linda.email, code: CODE } });
    server.locked = true;
    expect(await Madauth.emailLink.verify({ email: linda.email, code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'codes_locked' } });
  });

  it('H29: the link in the hash signs in on initialize and leaves the address bar tidy', async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    lindaWithLink(server, false);
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    history.replaceState(null, '', `/page?x=1#other=1&madauth_signin=${SIGNIN_TOKEN}`);

    const result = await init({ ui: 'custom' });

    expect(result).toEqual({ isSuccess: true, leftOut: [] });
    expect(Madauth.currentUser).toEqual(linda);
    expect(listener).toHaveBeenLastCalledWith(linda);
    expect(location.href).toMatch(/\/page\?x=1#other=1$/);
    expect(server.requests.find((r) => r.path === '/auth/email-link/verify')).toMatchObject({ method: 'POST', body: { token: SIGNIN_TOKEN } });
    expect(server.accounts.get(linda.email)).toMatchObject({ verified: true });
  });

  it('H29: an invalid link is reported by initialize; without the provider the token is dropped with a warning', async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    history.replaceState(null, '', '/page#madauth_signin=stale');

    const result = await init({ ui: 'custom' });

    expect(result).toMatchObject({ isSuccess: false, error: { code: 'link_invalid' }, leftOut: [] });
    expect(Madauth.currentUser).toBeNull();
    expect(location.hash).toBe('');
    // madAuth is usable all the same.
    expect(await Madauth.emailLink.send({ email: linda.email })).toEqual({ isSuccess: true });

    history.replaceState(null, '', `/page#madauth_signin=${SIGNIN_TOKEN}`);
    expect(await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()], ui: 'custom' })).toEqual({ isSuccess: true, leftOut: [] });
    expect(location.hash).toBe('');
    expect(warnLog).toHaveBeenCalledWith('[madauth]', expect.stringContaining('EmailLink'));
    expect(server.requests.filter((r) => r.path === '/auth/email-link/verify')).toHaveLength(1);
  });

  it('H30: the link goes on with the authenticator app when the policy asks for it, by link and by code', async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    server.policy['email-link'] = 'optional';
    lindaWithLink(server);
    server.authenticators.add(linda.email);
    history.replaceState(null, '', `/page#madauth_signin=${SIGNIN_TOKEN}`);

    const result = await init({ ui: 'custom' });

    expect(result).toEqual({ isSuccess: true, leftOut: [] });
    expect(Madauth.currentUser).toBeNull();
    expect(Madauth.authenticator.pendingStep).toEqual({ step: 'code', method: 'email-link', factors: ['authenticator'] });
    expect(Madauth.authenticator.policy?.secondFactorFor).toEqual(['email-link']);
    expect(await Madauth.authenticator.verify({ code: CODE })).toEqual({ isSuccess: true, user: linda });
    expect(Madauth.authenticator.pendingStep).toBeNull();

    server.policy['email-link'] = 'required';
    await Madauth.emailLink.send({ email: 'new@example.com' });
    expect(await Madauth.emailLink.verify({ email: 'new@example.com', code: CODE })).toMatchObject({
      isSuccess: false,
      error: { code: 'second_factor_setup_required', method: 'email-link' },
    });
    expect(Madauth.authenticator.pendingStep).toEqual({ step: 'setup', method: 'email-link', factors: ['authenticator'] });
  });

  it('H31: left out when the server does not offer the e-mail link; without the provider the scope says so', async () => {
    const server = fakeServer();

    expect(await init()).toEqual({ isSuccess: true, leftOut: ['email-link'] });

    expect(warnLog).toHaveBeenCalledWith('[madauth]', 'flow_not_enabled', expect.stringContaining('"email-link" is left out'));
    expect(Madauth.emailLink.policy).toBeNull();
    expect(await Madauth.emailLink.send({ email: linda.email })).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });

    server.methods['email-link'] = true;
    expect(await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] })).toEqual({ isSuccess: true, leftOut: [] });
    expect(await Madauth.emailLink.send({ email: linda.email })).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
    expect(await Madauth.emailLink.verify({ email: linda.email, code: CODE })).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
    expect(server.requests.filter((r) => r.path.startsWith('/auth/email-link'))).toHaveLength(0);

    server.policy['email-link'] = 'optional';
    await init();
    expect(Madauth.emailLink.policy).toEqual({ secondFactor: 'optional' });
  });

  it('H32: a sign-in link does not get One Tap prompted on top of it', async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    lindaWithLink(server);
    const gis = fakeGis();
    history.replaceState(null, '', `/page#madauth_signin=${SIGNIN_TOKEN}`);

    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm(), new EmailLink()], ui: 'custom' });

    expect(Madauth.currentUser).toEqual(linda);
    expect(gis.id.prompt).not.toHaveBeenCalled();
  });
});
