import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { GoogleFedcm } from '../providers/google-fedcm.js';
import { GoogleRedirect } from '../providers/google-redirect.js';
import { Password } from '../providers/password.js';
import { CLIENT_ID, CODE, SERVER, ada, fakeGis, fakeServer, gisScripts, grace, resetAll, settle } from '../test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

function container(): HTMLElement {
  const el = document.createElement('div');
  document.body.append(el);
  return el;
}

describe('Madauth.google.renderButton', () => {
  it('H10: renders the FedCM button for a custom screen and reports the sign-in', async () => {
    fakeServer();
    const gis = fakeGis();
    void Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm({ autoPrompt: false })] });
    const onResult = vi.fn();
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    const el = container();

    // Works before initialize has finished.
    const rendered = Madauth.google.renderButton(el, { theme: 'dark', onResult });
    await settle();

    expect(rendered.isSuccess).toBe(true);
    expect(gis.id.renderButton).toHaveBeenCalledOnce();
    // Inside a light wrapper, so Google's iframe gets no opaque background on a dark page.
    const target = gis.id.renderButton.mock.lastCall![0];
    expect(target.parentElement).toBe(el);
    expect(target.style.colorScheme).toBe('light');
    expect(gis.id.renderButton.mock.lastCall![1].theme).toBe('filled_black');

    gis.signIn();
    await settle();

    expect(onResult).toHaveBeenCalledExactlyOnceWith({ isSuccess: true, user: ada });
    expect(listener).toHaveBeenLastCalledWith(ada);

    el.append(document.createElement('iframe'));
    if (rendered.isSuccess) rendered.remove();
    expect(el.childElementCount).toBe(0);
  });

  it('H10: renders a button that starts the redirect with GoogleRedirect', async () => {
    fakeServer().codeFlow = true;
    const assign = vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()] });
    const el = container();

    Madauth.google.renderButton(el);
    await settle();
    el.querySelector('button')!.click();

    expect(el.querySelector('button')!.textContent).toBe('Continue with Google');
    expect(assign).toHaveBeenCalledExactlyOnceWith(
      `${SERVER}/auth/providers/google/start?return_to=${encodeURIComponent('https://app.example.com/page')}&locale=${encodeURIComponent(navigator.language)}`,
    );
  });

  it('labels the redirect button in the configured language until it is removed', async () => {
    fakeServer().codeFlow = true;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()], locale: 'de-CH', ui: 'custom' });
    const el = container();

    const rendered = Madauth.google.renderButton(el);
    await settle();
    const button = el.querySelector('button')!;
    expect(button.textContent).toBe('Weiter mit Google');

    Madauth.setLocale('en');
    expect(button.textContent).toBe('Continue with Google');

    if (rendered.isSuccess) rendered.remove();
    Madauth.setLocale('de');
    expect(button.textContent).toBe('Continue with Google');
  });

  it('H10: fails without a Google provider or before initialize', async () => {
    fakeServer();

    expect(Madauth.google.renderButton(container())).toMatchObject({ isSuccess: false, error: { code: 'not_initialized' } });
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    expect(Madauth.google.renderButton(container())).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
  });

  it('reports a failed initialize through onResult', async () => {
    fakeServer().down = true;
    fakeGis();
    void Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm()] });
    const onResult = vi.fn();

    Madauth.google.renderButton(container(), { onResult });
    await settle();

    expect(onResult).toHaveBeenCalledWith(expect.objectContaining({ isSuccess: false, error: expect.objectContaining({ code: 'network' }) }));
  });

  it('renders nothing when removed before initialize has finished', async () => {
    fakeServer();
    const gis = fakeGis();
    void Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm({ autoPrompt: false })] });

    const rendered = Madauth.google.renderButton(container());
    if (rendered.isSuccess) rendered.remove();
    await settle();

    expect(gis.id.renderButton).not.toHaveBeenCalled();
  });
});

describe('Madauth.google.nonce and signIn: an ID token the app obtained itself', () => {
  it('H11: signs in with the token, without a Google provider in initialize and without Google’s script', async () => {
    const server = fakeServer();
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    void Madauth.initialize({ serverUrl: SERVER, providers: [new Password()], ui: 'custom' });

    // Works before initialize has finished.
    const start = await Madauth.google.nonce();
    expect(start).toEqual({ isSuccess: true, nonce: 'nonce-1', clientId: CLIENT_ID });
    const result = await Madauth.google.signIn({ credential: 'native-id-token' });

    expect(result).toEqual({ isSuccess: true, user: ada });
    expect(server.requests.find((r) => r.path === '/auth/providers/google/nonce')).toMatchObject({ method: 'POST', credentials: 'include' });
    expect(server.requests.find((r) => r.path === '/auth/providers/google/verify')).toMatchObject({
      method: 'POST',
      body: { credential: 'native-id-token', locale: navigator.language },
      credentials: 'include',
    });
    expect(Madauth.currentUser).toEqual(ada);
    expect(listener).toHaveBeenLastCalledWith(ada);
    expect(gisScripts()).toHaveLength(0);
  });

  it('H11: fails before initialize, and when the server has no Google provider that is on', async () => {
    expect(await Madauth.google.nonce()).toMatchObject({ isSuccess: false, error: { code: 'not_initialized' } });
    const server = fakeServer();
    server.google = false;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });

    expect(await Madauth.google.nonce()).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
    expect(await Madauth.google.signIn({ credential: 'native-id-token' })).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
    expect(server.requests.some((r) => r.path.startsWith('/auth/providers/google'))).toBe(false);
  });

  it('H11: returns the server’s error and signs nobody in', async () => {
    const server = fakeServer();
    server.verifyError = 'other_method';
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    await settle();
    listener.mockClear();

    const result = await Madauth.google.signIn({ credential: 'native-id-token' });

    expect(result).toEqual({ isSuccess: false, error: { code: 'other_method', message: 'rejected in test' } });
    expect(Madauth.currentUser).toBeNull();
    expect(listener).not.toHaveBeenCalled();
  });

  it('H11: goes on with the second step when the policy asks for one, like a password sign-in', async () => {
    const server = fakeServer();
    server.policy.google = 'optional';
    server.authenticators.add(ada.email!);
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()], ui: 'custom' });

    const first = await Madauth.google.signIn({ credential: 'native-id-token' });

    expect(first).toMatchObject({ isSuccess: false, error: { code: 'authenticator_required', method: 'google', factors: ['authenticator'] } });
    expect(Madauth.authenticator.pendingStep).toEqual({ step: 'code', method: 'google', factors: ['authenticator'] });
    expect(Madauth.currentUser).toBeNull();

    expect(await Madauth.authenticator.verify({ code: CODE })).toEqual({ isSuccess: true, user: ada });
    expect(Madauth.authenticator.pendingStep).toBeNull();
    expect(Madauth.currentUser).toEqual(ada);
  });

  it('H11: with purpose link, adds the Google account to the signed-in user and resolves with them as they are', async () => {
    const server = fakeServer();
    server.user = grace;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });

    expect(await Madauth.google.signIn({ credential: 'native-id-token', purpose: 'link' })).toEqual({ isSuccess: true, user: grace });

    expect(server.requests.find((r) => r.path === '/auth/providers/google/link')?.body).toEqual({ credential: 'native-id-token' });
    expect(server.requests.some((r) => r.path === '/auth/providers/google/verify')).toBe(false);
    expect(server.linked.get(grace.email!)).toContain('google');
    expect(Madauth.currentUser).toEqual(grace);
  });

  it('H11: linking fails with reauth_required after two minutes, no_session for nobody, and account_taken', async () => {
    const server = fakeServer();
    server.user = grace;
    server.staleSignIn = true;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    expect(await Madauth.google.signIn({ credential: 'native-id-token', purpose: 'link' })).toMatchObject({ isSuccess: false, error: { code: 'reauth_required' } });

    server.staleSignIn = false;
    server.verifyError = 'account_taken';
    expect(await Madauth.google.signIn({ credential: 'native-id-token', purpose: 'link' })).toMatchObject({ isSuccess: false, error: { code: 'account_taken' } });

    server.verifyError = undefined;
    await Madauth.signOut();
    expect(await Madauth.google.signIn({ credential: 'native-id-token', purpose: 'link' })).toEqual({ isSuccess: false, error: { code: 'no_session', message: 'Nobody is signed in.' } });
    expect(server.linked.get(grace.email!)).toBeUndefined();
  });
});
