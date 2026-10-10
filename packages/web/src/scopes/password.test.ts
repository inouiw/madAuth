import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { GoogleFedcm } from '../providers/google-fedcm.js';
import { Password } from '../providers/password.js';
import { CODE, RESET_TOKEN, SERVER, VERIFY_TOKEN, fakeGis, fakeServer, grace, resetAll, settle } from '../test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

const init = (options: Partial<Parameters<typeof Madauth.initialize>[0]> = {}) =>
  Madauth.initialize({ serverUrl: SERVER, providers: [new Password()], ...options });

describe('Madauth.password', () => {
  it('H1: signIn signs in and notifies listeners', async () => {
    const server = fakeServer();
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    await init();

    const result = await Madauth.password.signIn({ email: 'grace@example.com', password: 'correct horse battery' });

    expect(result).toEqual({ isSuccess: true, user: grace });
    expect(listener).toHaveBeenLastCalledWith(grace);
    expect(Madauth.currentUser).toEqual(grace);
    expect(server.requests.at(-1)).toMatchObject({
      method: 'POST',
      url: `${SERVER}/auth/password/signin`,
      credentials: 'include',
      body: { email: 'grace@example.com', password: 'correct horse battery' },
    });
  });

  it('H1: a wrong password fails without notifying listeners', async () => {
    fakeServer();
    await init();
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    await settle();
    listener.mockClear();

    const result = await Madauth.password.signIn({ email: 'grace@example.com', password: 'wrong' });

    expect(result).toMatchObject({ isSuccess: false, error: { code: 'invalid_credentials' } });
    expect(listener).not.toHaveBeenCalled();
    expect(Madauth.currentUser).toBeNull();
  });

  it('H2: fails clearly without the Password provider, without asking the server', async () => {
    const server = fakeServer();
    fakeGis();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm({ autoPrompt: false })] });
    const before = server.requests.length;

    const result = await Madauth.password.signIn({ email: 'grace@example.com', password: 'x' });

    expect(result).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled', message: expect.stringContaining('new Password()') } });
    expect(server.requests).toHaveLength(before);
    expect(Madauth.password.policy).toBeNull();
  });

  it('H3: reports a server without e-mail & password sign-in', async () => {
    fakeServer().password = false;

    expect(await init()).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled', message: expect.stringContaining('DATABASE_URL') } });
  });

  it('H4: the e-mails link to the current page without its hash by default', async () => {
    const server = fakeServer();
    history.replaceState(null, '', '/a?b=1#x');
    await init();

    await Madauth.password.sendResetEmail({ email: 'grace@example.com' });
    await Madauth.password.signUp({ email: 'new@example.com', password: 'long enough', redirectTo: 'https://app.example.com/welcome' });

    expect(server.mails).toEqual([
      { purpose: 'reset', to: 'grace@example.com', redirectTo: 'https://app.example.com/a?b=1' },
      { purpose: 'verify', to: 'new@example.com', redirectTo: 'https://app.example.com/welcome' },
    ]);
    // The user's language goes along, so the e-mail can be written in it.
    expect(server.requests.at(-1)!.body).toMatchObject({ locale: navigator.language });
  });

  it('sends the configured locale with sign-up and the e-mail requests', async () => {
    const server = fakeServer();
    vi.spyOn(navigator, 'language', 'get').mockReturnValue('en-US');
    await init({ locale: 'de-CH' });
    const sentLocales = () => server.requests.filter((r) => r.method === 'POST').map((r) => (r.body as { locale?: string }).locale);

    await Madauth.password.signUp({ email: 'new@example.com', password: 'long enough' });
    await Madauth.password.sendVerificationEmail({ email: 'new@example.com' });
    await Madauth.password.sendResetEmail({ email: 'grace@example.com' });
    expect(sentLocales()).toEqual(['de-CH', 'de-CH', 'de-CH']);

    Madauth.setLocale('en-GB');
    await Madauth.password.sendResetEmail({ email: 'grace@example.com' });
    expect(sentLocales().at(-1)).toBe('en-GB');
  });

  it('without a configured locale, sends the page’s language, else the browser’s', async () => {
    const server = fakeServer();
    vi.spyOn(navigator, 'language', 'get').mockReturnValue('fr-FR');
    document.documentElement.lang = 'de';
    await init();

    await Madauth.password.sendResetEmail({ email: 'grace@example.com' });
    expect(server.requests.at(-1)!.body).toMatchObject({ locale: 'de' });

    document.documentElement.removeAttribute('lang');
    await Madauth.password.sendResetEmail({ email: 'grace@example.com' });
    expect(server.requests.at(-1)!.body).toMatchObject({ locale: 'fr-FR' });
  });

  it('reports a refused sign-up and e-mails that can not be sent', async () => {
    const server = fakeServer();
    await init();

    server.emailsDown = true;
    expect(await Madauth.password.signUp({ email: 'new@example.com', password: 'long enough' })).toMatchObject({
      error: { code: 'temporarily_unavailable' },
    });
    expect(await Madauth.password.sendResetEmail({ email: 'grace@example.com' })).toMatchObject({ error: { code: 'temporarily_unavailable' } });
    server.rejectSignUp = 'Company addresses only';
    expect(await Madauth.password.signUp({ email: 'new@example.com', password: 'long enough' })).toEqual({
      isSuccess: false,
      error: { code: 'signup_rejected', message: 'Company addresses only' },
    });
  });

  it('signUp reports an invalid address or a short password', async () => {
    fakeServer();
    await init();

    expect(await Madauth.password.signUp({ email: 'nope', password: 'long enough' })).toMatchObject({ error: { code: 'invalid_email' } });
    expect(await Madauth.password.signUp({ email: 'new@example.com', password: 'short' })).toMatchObject({ error: { code: 'weak_password' } });
    expect(await Madauth.password.signUp({ email: 'new@example.com', password: 'long enough' })).toEqual({ isSuccess: true });
  });

  it('H5: a verification link signs the user in when the page opens', async () => {
    const server = fakeServer();
    server.accounts.set('new@example.com', { password: 'long enough', verified: false });
    server.mails.push({ purpose: 'verify', to: 'new@example.com', redirectTo: '' });
    history.replaceState(null, '', `/page?x=1#madauth_verify=${VERIFY_TOKEN}`);
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);

    expect(await init()).toEqual({ isSuccess: true, leftOut: [] });

    expect(listener).toHaveBeenLastCalledWith(expect.objectContaining({ email: 'new@example.com' }));
    expect(location.href).toBe('https://app.example.com/page?x=1');
  });

  it('H5: an invalid verification link is reported by initialize', async () => {
    fakeServer();
    history.replaceState(null, '', '/page#madauth_verify=used-token');

    expect(await init()).toMatchObject({ isSuccess: false, error: { code: 'link_invalid' } });
    expect(location.hash).toBe('');
    // madAuth stays usable.
    expect(await Madauth.password.signIn({ email: 'grace@example.com', password: 'correct horse battery' })).toMatchObject({
      isSuccess: true,
    });
  });

  it('H6: with ui: custom, a reset link only sets pendingReset; confirmReset uses it', async () => {
    const server = fakeServer();
    history.replaceState(null, '', `/page#madauth_reset=${RESET_TOKEN}`);

    await init({ ui: 'custom' });
    await settle();

    expect(Madauth.password.pendingReset).toBe(true);
    expect(location.hash).toBe('');
    expect(document.querySelector('madauth-login')).toBeNull();

    const result = await Madauth.password.confirmReset({ newPassword: 'brand new password' });

    expect(result).toEqual({ isSuccess: true, user: grace });
    expect(server.requests.at(-1)!.body).toEqual({ password: 'brand new password', token: RESET_TOKEN });
    expect(Madauth.password.pendingReset).toBe(false);
    expect(Madauth.currentUser).toEqual(grace);
  });

  it('H6: a weak password keeps the pending reset for another try', async () => {
    fakeServer();
    history.replaceState(null, '', `/page#madauth_reset=${RESET_TOKEN}`);
    await init({ ui: 'custom' });

    expect(await Madauth.password.confirmReset({ newPassword: 'short' })).toMatchObject({ error: { code: 'weak_password' } });
    expect(Madauth.password.pendingReset).toBe(true);
  });

  it('H7: confirmReset takes an explicit token, or the e-mail and code', async () => {
    const server = fakeServer();
    await init({ ui: 'custom' });

    expect(await Madauth.password.confirmReset({ newPassword: 'brand new password' })).toMatchObject({ error: { code: 'link_invalid' } });
    await Madauth.password.confirmReset({ newPassword: 'brand new password', token: 'X' });
    expect(server.requests.at(-1)!.body).toEqual({ password: 'brand new password', token: 'X' });
    const result = await Madauth.password.confirmReset({ newPassword: 'brand new password', email: 'grace@example.com', code: CODE });
    expect(server.requests.at(-1)!.body).toEqual({ password: 'brand new password', email: 'grace@example.com', code: CODE });
    expect(result).toMatchObject({ isSuccess: true, user: grace });
  });

  it('H8: verifyEmail with the code signs in', async () => {
    const server = fakeServer();
    await init();
    await Madauth.password.signUp({ email: 'new@example.com', password: 'long enough' });

    expect(await Madauth.password.verifyEmail({ email: 'new@example.com', code: '000000' })).toMatchObject({
      error: { code: 'code_invalid' },
    });
    const result = await Madauth.password.verifyEmail({ email: 'new@example.com', code: CODE });

    expect(result).toMatchObject({ isSuccess: true, user: { email: 'new@example.com' } });
    expect(server.requests.at(-1)!.body).toEqual({ email: 'new@example.com', code: CODE });
  });

  it('sendVerificationEmail asks for the confirmation e-mail again', async () => {
    const server = fakeServer();
    await init();

    expect(await Madauth.password.sendVerificationEmail({ email: 'new@example.com' })).toEqual({ isSuccess: true });
    expect(server.mails).toEqual([{ purpose: 'verify', to: 'new@example.com', redirectTo: 'https://app.example.com/page' }]);
  });

  it('H9: with the default UI, a reset link opens the dialog on its new-password form', async () => {
    fakeServer();
    history.replaceState(null, '', `/page#madauth_reset=${RESET_TOKEN}`);

    await init();
    await settle();

    const dialog = document.querySelector('madauth-login')!;
    expect(dialog.shadowRoot!.querySelector('dialog')!.open).toBe(true);
    expect(dialog.shadowRoot!.querySelector('form.reset input[autocomplete="new-password"]')).not.toBeNull();
  });

  it('H11: signIn() refuses to open the dialog with ui: custom', async () => {
    fakeServer();
    await init({ ui: 'custom' });

    expect(await Madauth.signIn()).toMatchObject({ isSuccess: false, error: { code: 'invalid_options' } });
    expect(document.querySelector('madauth-login')).toBeNull();
  });

  it('rejects an unknown ui option', async () => {
    fakeServer();

    // @ts-expect-error: not a valid ui
    expect(await init({ ui: 'modal' })).toMatchObject({ isSuccess: false, error: { code: 'invalid_options' } });
  });

  it('exposes the password policy once initialized', async () => {
    fakeServer();
    void init();
    expect(Madauth.password.policy).toBeNull();

    await settle();

    expect(Madauth.password.policy).toEqual({ minLength: 8 });
  });

  it('methods wait for initialize and fail with not_initialized without it', async () => {
    fakeServer();

    expect(await Madauth.password.signIn({ email: 'grace@example.com', password: 'x' })).toMatchObject({
      error: { code: 'not_initialized' },
    });
    void init();
    expect(await Madauth.password.signIn({ email: 'grace@example.com', password: 'correct horse battery' })).toMatchObject({
      isSuccess: true,
    });
  });

  it('signing in with a password closes a showing One Tap prompt', async () => {
    fakeServer();
    const gis = fakeGis();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm(), new Password()] });
    await settle();
    expect(gis.id.prompt).toHaveBeenCalledOnce();

    await Madauth.password.signIn({ email: 'grace@example.com', password: 'correct horse battery' });

    expect(gis.id.cancel).toHaveBeenCalled();
  });
});
