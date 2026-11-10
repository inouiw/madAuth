// Sign in with Apple in the web library: the button madAuth adds when the server offers it, and `Madauth.apple` for a
// native app's identity token. See "Providers" in docs/custom-ui.md.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { SERVER, ada, fakeServer, resetAll, settle, type FakeServer } from '../test-helpers.js';
import { Password } from './password.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(resetAll);

const shadow = () => document.querySelector('madauth-login')!.shadowRoot!;
const $ = <T extends HTMLElement = HTMLElement>(selector: string) => shadow().querySelector<T>(selector);
const $$ = (selector: string) => [...shadow().querySelectorAll<HTMLElement>(selector)];

/** A server with Apple on next to e-mail & password. */
function appleServer(): FakeServer {
  const server = fakeServer();
  server.oidc = [{ id: 'apple', kind: 'apple', name: 'Apple', secondFactor: 'none', teamId: 'TEAM123456', keyId: 'KEY1234567', bundleIds: ['com.example.app'] }];
  return server;
}

describe('Apple', () => {
  it('AW1: the dialog shows "Continue with Apple" with the Apple logo, which starts the redirect', async () => {
    appleServer();
    const assign = vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    history.replaceState(null, '', '/page');

    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    void Madauth.showSignInDialog();
    await settle();

    expect($$('.button-slot').map((slot) => slot.dataset.button)).toEqual(['apple']);
    const button = $<HTMLButtonElement>('.apple-slot button')!;
    expect(button.textContent).toBe('Continue with Apple');
    expect(button.querySelector('svg path')?.getAttribute('fill')).toBe('currentColor');
    expect(button.style.background).toBe('#000000');
    button.click();
    expect(assign).toHaveBeenCalledExactlyOnceWith(
      `${SERVER}/auth/providers/apple/start?return_to=${encodeURIComponent('https://app.example.com/page')}&locale=${encodeURIComponent(navigator.language)}`,
    );
  });

  it('AW2: the page comes back from Apple with the result, named as Apple', async () => {
    appleServer();
    history.replaceState(null, '', '/page#madauth_error=cancelled&madauth_method=apple');
    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()], ui: 'custom' });
    expect(result).toMatchObject({ isSuccess: false, error: { code: 'cancelled', message: expect.stringContaining('Apple') } });
    expect(Madauth.authenticator.pendingStep).toBeNull();
    expect(location.hash).toBe('');
  });

  it('AW3: Madauth.apple signs in with a native app’s identity token after the nonce, with the name and the code, and links one', async () => {
    const server = appleServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [], ui: 'custom' });
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);

    expect(await Madauth.apple.nonce()).toEqual({ isSuccess: true, nonce: 'nonce-1' });
    expect(server.requests.at(-1)).toMatchObject({ method: 'POST', path: '/auth/providers/apple/nonce' });
    const signedIn = await Madauth.apple.signIn({ credential: 'apple-id-token', name: { firstName: 'Ada', lastName: 'Byron' }, authorizationCode: 'c0de' });
    expect(signedIn).toEqual({ isSuccess: true, user: ada });
    expect(server.requests.at(-1)).toMatchObject({
      path: '/auth/providers/apple/verify',
      body: { credential: 'apple-id-token', name: { firstName: 'Ada', lastName: 'Byron' }, authorizationCode: 'c0de', locale: navigator.language },
    });
    expect(listener).toHaveBeenLastCalledWith(ada);

    expect(await Madauth.apple.signIn({ credential: 'apple-id-token', purpose: 'link' })).toEqual({ isSuccess: true, user: ada });
    expect(server.requests.at(-1)).toMatchObject({ path: '/auth/providers/apple/link', body: { credential: 'apple-id-token' } });
    expect(server.linked.get(ada.email!)?.has('apple')).toBe(true);

    server.verifyError = 'verification_failed';
    expect(await Madauth.apple.signIn({ credential: 'bad' })).toMatchObject({ isSuccess: false, error: { code: 'verification_failed' } });

    // Without an Apple provider on the server, nothing is asked.
    server.oidc = [];
    await Madauth.initialize({ serverUrl: SERVER, providers: [], ui: 'custom' });
    expect(await Madauth.apple.nonce()).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
  });

  it('AW4: Madauth.apple.renderButton renders the button for a custom screen; the token exchange takes Apple’s token', async () => {
    const server = appleServer();
    server.clients.push({ id: 'mc_1', name: 'Phone app', public: true, redirectUris: [], postLogoutRedirectUris: [], deviceFlow: false, tokenExchange: true, idTokenAlg: 'ES256', createdAt: 1, updatedAt: 1 });
    const assign = vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    await Madauth.initialize({ serverUrl: SERVER, providers: [], ui: 'custom' });
    const el = document.createElement('div');
    document.body.append(el);
    const rendered = Madauth.apple.renderButton(el, { theme: 'dark' });
    await settle();
    expect(rendered.isSuccess).toBe(true);
    const button = el.querySelector('button')!;
    expect(button.textContent).toBe('Continue with Apple');
    expect(button.style.background).toBe('#ffffff');
    button.click();
    expect(assign).toHaveBeenCalledOnce();
    if (rendered.isSuccess) rendered.remove();
    el.remove();

    expect(await Madauth.tokens.nonce({ clientId: 'mc_1' })).toEqual({ isSuccess: true, nonce: 'nonce-token', googleClientId: 'google-client', apple: true, expiresIn: 300 });
    const tokens = await Madauth.tokens.exchange({ clientId: 'mc_1', credential: 'apple-id-token', name: { firstName: 'Ada' }, authorizationCode: 'c0de' });
    expect(tokens).toMatchObject({ isSuccess: true, accessToken: 'at' });
    expect(server.requests.at(-1)!.body).toMatchObject({ subject_token: 'apple-id-token', name: '{"firstName":"Ada"}', authorization_code: 'c0de' });
  });
});
