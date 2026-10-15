import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { Passkey } from '../providers/passkey.js';
import { Password } from '../providers/password.js';
import { CODE, SERVER, VERIFY_TOKEN, fakeServer, grace, resetAll, stubWebAuthn } from '../test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(resetAll);

const init = (providers = [new Password(), new Passkey()]) => Madauth.initialize({ serverUrl: SERVER, providers });
const credentials = { email: 'grace@example.com', password: 'correct horse battery' };

/** A server with passkeys that sign in on their own. */
function passkeyServer(signIn = true) {
  const server = fakeServer();
  server.passkey = { signIn, secondFactor: 'none' };
  return server;
}

/** A server where people sign up with a passkey alone. */
function signUpServer() {
  const server = fakeServer();
  server.passkey = { signIn: true, signUp: true, secondFactor: 'none' };
  return server;
}

const newUser = { id: 'usr_new', email: 'new@example.com', name: 'New User' };

describe('Madauth.passkey', () => {
  it('PW1: add creates a passkey in the browser and stores it; signIn signs in with it', async () => {
    const server = passkeyServer();
    server.user = grace;
    const { credentials: browser } = stubWebAuthn({ id: 'cred-1' });
    await init();

    expect(Madauth.passkey.available).toBe(true);
    expect(Madauth.passkey.signInAvailable).toBe(true);
    const added = await Madauth.passkey.add({ name: 'Laptop' });

    expect(added).toEqual({ isSuccess: true, passkey: { id: 'acc_1', name: 'Laptop', createdAt: 1, lastUsedAt: 0 } });
    expect(browser.create).toHaveBeenCalledOnce();
    expect(browser.create.mock.calls[0][0].publicKey).toMatchObject({ challenge: 'cmVnaXN0ZXI', rp: { id: 'localhost' } });
    expect(server.requests.at(-1)).toMatchObject({ path: '/auth/passkey/register/verify', body: { response: { id: 'cred-1', response: { kind: 'create' } }, name: 'Laptop' } });

    await Madauth.signOut();
    server.user = null;
    const signedIn = await Madauth.passkey.signIn();
    expect(signedIn).toEqual({ isSuccess: true, user: grace });
    expect(Madauth.currentUser).toEqual(grace);
    expect(browser.get.mock.calls[0][0]).toMatchObject({ publicKey: { challenge: 'c2lnbmlu', userVerification: 'required' } });
  });

  it('PW2: the browser dialog closed is cancelled; an unknown passkey is passkey_unknown, and the browser is told to forget it', async () => {
    passkeyServer();
    const browser = stubWebAuthn({ outcome: 'cancel' });
    await init();

    expect(await Madauth.passkey.signIn()).toMatchObject({ isSuccess: false, error: { code: 'cancelled' } });
    browser.state.outcome = 'ok';
    browser.state.id = 'gone';
    expect(await Madauth.passkey.signIn()).toMatchObject({ isSuccess: false, error: { code: 'passkey_unknown' } });
    expect((PublicKeyCredential as unknown as { signalUnknownCredential: ReturnType<typeof vi.fn> }).signalUnknownCredential).toHaveBeenCalledWith({
      rpId: 'localhost',
      credentialId: 'gone',
    });
  });

  it('PW3: signing in alone needs the Passkey provider and a server that allows it; adding one needs neither', async () => {
    const server = passkeyServer(false);
    server.user = grace;
    stubWebAuthn();
    await init([new Password()]);

    expect(Madauth.passkey.signInAvailable).toBe(false);
    expect(await Madauth.passkey.signIn()).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
    expect(await Madauth.passkey.add()).toMatchObject({ isSuccess: true });
    // The provider is left out when the server does not let passkeys sign in.
    expect(await init()).toEqual({ isSuccess: true, leftOut: ['passkey'] });
  });

  it('PW4: without passkeys in the browser, or on the server, nothing is offered', async () => {
    const server = fakeServer();
    server.user = grace;
    stubWebAuthn();
    await init([new Password()]);
    expect(Madauth.passkey.available).toBe(false);
    expect(await Madauth.passkey.add()).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });

    resetAll();
    passkeyServer().user = grace;
    await init([new Password()]);
    expect(Madauth.passkey.available).toBe(false);
    expect(await Madauth.passkey.add()).toMatchObject({ isSuccess: false, error: { code: 'passkey_unsupported' } });
  });

  it('PW5: a passkey as the second step: the password sign-in ends with passkey_required, verify finishes it', async () => {
    const server = passkeyServer();
    server.policy.password = 'optional';
    server.passkeys.set('cred-1', { email: grace.email!, id: 'acc_1', name: 'Laptop' });
    stubWebAuthn({ id: 'cred-1' });
    await init();

    const first = await Madauth.password.signIn(credentials);
    expect(first).toMatchObject({ isSuccess: false, error: { code: 'passkey_required', factors: ['passkey'] } });
    expect(Madauth.passkey.pendingStep).toEqual({ step: 'passkey', method: 'password', factors: ['passkey'] });

    expect(await Madauth.passkey.verify()).toEqual({ isSuccess: true, user: grace });
    expect(Madauth.currentUser).toEqual(grace);
    expect(Madauth.passkey.pendingStep).toBeNull();
  });

  it('PW6: a required policy lets the sign-in add a passkey as its setup, which signs in', async () => {
    const server = passkeyServer();
    server.policy.password = 'required';
    stubWebAuthn({ id: 'cred-9' });
    await init();

    expect(await Madauth.password.signIn(credentials)).toMatchObject({ isSuccess: false, error: { code: 'totp_setup_required', factors: ['passkey', 'totp'] } });
    const added = await Madauth.passkey.add();

    expect(added).toMatchObject({ isSuccess: true, user: grace, passkey: { name: 'Passkey' } });
    expect(Madauth.currentUser).toEqual(grace);
  });

  it('PW7: adding one needs a recent sign-in; a device that holds one already is already_added', async () => {
    const server = passkeyServer();
    server.user = grace;
    server.staleSignIn = true;
    const browser = stubWebAuthn();
    await init();

    expect(await Madauth.passkey.add()).toMatchObject({ isSuccess: false, error: { code: 'reauth_required' } });
    server.staleSignIn = false;
    browser.state.outcome = 'exists';
    expect(await Madauth.passkey.add()).toMatchObject({ isSuccess: false, error: { code: 'already_added' } });
  });
});

describe('Madauth.passkey.signUp', () => {
  it('PW9: signUp creates an account with a passkey alone; confirming the address leads to the passkey, which signs in', async () => {
    const server = signUpServer();
    stubWebAuthn({ id: 'cred-new' });
    await init();

    expect(Madauth.passkey.policy).toEqual({ signIn: true, signUp: true, secondFactor: 'none' });
    expect(await Madauth.passkey.signUp({ email: 'new@example.com', name: 'New User' })).toEqual({ isSuccess: true });
    expect(server.requests.at(-1)).toMatchObject({
      url: `${SERVER}/auth/passkey/signup`,
      body: { email: 'new@example.com', name: 'New User', redirectTo: 'https://app.example.com/page' },
    });
    expect(server.mails.at(-1)).toMatchObject({ purpose: 'verify', to: 'new@example.com' });
    expect(await Madauth.passkey.sendVerificationEmail({ email: 'new@example.com' })).toEqual({ isSuccess: true });
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/email/send-verification` });

    expect(await Madauth.passkey.verifyEmail({ email: 'new@example.com', code: CODE })).toMatchObject({
      isSuccess: false,
      error: { code: 'passkey_setup_required', method: 'passkey', factors: ['passkey'] },
    });
    expect(Madauth.passkey.pendingStep).toEqual({ step: 'setup', method: 'passkey', factors: ['passkey'] });
    expect(await Madauth.passkey.add()).toMatchObject({ isSuccess: true, user: newUser, passkey: { name: 'Passkey' } });
    expect(Madauth.currentUser).toEqual(newUser);
    expect(Madauth.passkey.pendingStep).toBeNull();
  });

  it('PW10: a policy that asks for a second factor after a passkey: the new passkey leads to its setup', async () => {
    const server = signUpServer();
    server.passkey = { signIn: true, signUp: true, secondFactor: 'required' };
    server.accounts.set('new@example.com', { password: '', verified: false, name: 'New User', passkey: true });
    server.mails.push({ purpose: 'verify', to: 'new@example.com', redirectTo: 'https://app.example.com/page' });
    stubWebAuthn({ id: 'cred-new' });
    history.replaceState(null, '', `/page#madauth_verify=${VERIFY_TOKEN}`);
    await init([new Password(), new Passkey()]);
    await Madauth.sessionReady();

    // The link opened the page: the passkey is next.
    expect(Madauth.passkey.pendingStep).toEqual({ step: 'setup', method: 'passkey', factors: ['passkey'] });
    const added = await Madauth.passkey.add();

    expect(added).toMatchObject({ isSuccess: false, error: { code: 'totp_setup_required', method: 'passkey', factors: ['totp'] } });
    expect(Madauth.passkey.pendingStep).toEqual({ step: 'setup', method: 'passkey', factors: ['totp'] });
    expect(Madauth.currentUser).toBeNull();
  });

  it('PW12: a redirect that returns with the passkey of a sign-up next (#madauth_next=passkey-setup) goes on with it', async () => {
    signUpServer();
    history.replaceState(null, '', '/page#madauth_next=passkey-setup&madauth_method=github');

    await init();

    expect(Madauth.passkey.pendingStep).toEqual({ step: 'setup', method: 'github', factors: ['passkey'] });
    expect(location.hash).toBe('');
  });

  it('PW11: signing up with a passkey alone needs the Passkey provider and a server that offers it', async () => {
    signUpServer();
    await init([new Password()]);
    expect(await Madauth.passkey.signUp({ email: 'new@example.com' })).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });

    resetAll();
    passkeyServer();
    stubWebAuthn();
    await init();
    expect(Madauth.passkey.policy?.signUp).toBe(false);
    expect(await Madauth.passkey.signUp({ email: 'new@example.com' })).toMatchObject({ isSuccess: false, error: { code: 'method_disabled' } });
  });
});

describe('Madauth.methods', () => {
  it('PW8: lists the signed-in user\'s methods and removes one; adds a password and the e-mail link', async () => {
    const server = passkeyServer();
    server.user = grace;
    server.passkeys.set('cred-1', { email: grace.email!, id: 'acc_1', name: 'Laptop' });
    await init();

    expect(await Madauth.methods.list()).toEqual({
      isSuccess: true,
      methods: [
        { id: 'acc_password', method: 'password', signIn: true, removable: true, createdAt: 1 },
        { id: 'acc_1', method: 'passkey', signIn: true, removable: true, createdAt: 1, name: 'Laptop', lastUsedAt: 0 },
      ],
    });
    expect(await Madauth.methods.remove('acc_1')).toEqual({ isSuccess: true });
    expect(await Madauth.methods.remove('acc_1')).toMatchObject({ isSuccess: false, error: { code: 'method_not_found' } });
    expect(await Madauth.password.add({ password: 'another one, please' })).toMatchObject({ isSuccess: false, error: { code: 'already_added' } });
    server.staleSignIn = true;
    expect(await Madauth.methods.remove('acc_password')).toMatchObject({ isSuccess: false, error: { code: 'reauth_required' } });

    server.user = null;
    expect(await Madauth.methods.list()).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
  });
});
