import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import type { MadauthLogin } from '../madauth-login.js';
import { CLIENT_ID, SERVER, ada, fakeGis, fakeServer, gisScripts, resetAll, settle } from '../test-helpers.js';
import { GoogleFedcm } from './google-fedcm.js';
import { GoogleRedirect } from './google-redirect.js';
import { Password } from './password.js';

let errorLog: ReturnType<typeof vi.spyOn>;
let warnLog: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  resetAll();
  errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
  warnLog = vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(resetAll);

function dialogElement(): MadauthLogin {
  return document.querySelector('madauth-login')!;
}

function shadow<T extends Element>(selector: string): T | null {
  return dialogElement().shadowRoot!.querySelector<T>(selector);
}

describe('GoogleFedcm', () => {
  it('G1: initialize reports when Google Identity Services cannot be loaded', async () => {
    fakeServer();
    // No window.google: the script "loads" but provides nothing.

    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm()] });

    expect(result).toMatchObject({ isSuccess: false, error: { code: 'gis_load_failed' } });
    expect(gisScripts()).toHaveLength(0);
  });

  it('G2: passes the server’s client ID and a fresh nonce to GIS, with the FedCM button', async () => {
    fakeServer();
    const gis = fakeGis();

    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm()] });
    await settle();

    expect(gis.id.initialize).toHaveBeenCalledWith(
      expect.objectContaining({ client_id: CLIENT_ID, nonce: 'nonce-1', use_fedcm_for_button: true, context: 'signin' }),
    );
  });

  it('G3: prompts One Tap on load only when nobody is signed in and autoPrompt is on', async () => {
    const server = fakeServer();
    const gis = fakeGis();

    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm()] });
    await settle();
    expect(gis.id.prompt).toHaveBeenCalledOnce();

    server.user = ada;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm()] });
    await settle();
    expect(gis.id.prompt).toHaveBeenCalledOnce();

    server.user = null;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm({ autoPrompt: false })] });
    await settle();
    expect(gis.id.prompt).toHaveBeenCalledOnce();
  });

  it('G4: a One Tap sign-in signs the user in without the app doing anything', async () => {
    const server = fakeServer();
    const gis = fakeGis();
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm()] });
    await settle();

    gis.signIn('one-tap-token');
    await settle();

    expect(server.requests.find((r) => r.path === '/auth/google/verify')?.body).toEqual({ credential: 'one-tap-token' });
    expect(listener).toHaveBeenLastCalledWith(ada);
    expect(Madauth.currentUser).toEqual(ada);
  });

  it('logs a failed One Tap sign-in and shows it when the dialog opens', async () => {
    const server = fakeServer();
    const gis = fakeGis();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm()] });
    await settle();
    server.verifyError = 'verification_failed';

    gis.signIn();
    await settle();
    expect(errorLog).toHaveBeenCalledWith('[madauth]', 'verification_failed', 'rejected in test');

    void Madauth.signIn();
    await settle();
    expect(shadow('.error')?.getAttribute('data-code')).toBe('verification_failed');
  });

  it('G5 / W3: the dialog always offers the FedCM button, even while One Tap is held back', async () => {
    fakeServer();
    const gis = fakeGis();
    gis.id.prompt.mockImplementation(() => {}); // Chrome's cooldown: nothing is shown.
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm()] });

    void Madauth.signIn();
    await settle();

    expect(gis.id.cancel).toHaveBeenCalled();
    expect(gis.id.renderButton).toHaveBeenCalledOnce();
    const [target, options] = gis.id.renderButton.mock.lastCall!;
    expect(target.parentElement).toBe(shadow('.google-slot'));
    expect(options).toMatchObject({ text: 'continue_with', size: 'large' });
    // The button got its own nonce.
    expect(gis.id.initialize.mock.lastCall![0].nonce).toBe('nonce-2');
  });

  it('renders Google’s dark button when the dialog is dark', async () => {
    fakeServer();
    const gis = fakeGis();
    let scheme = 'dark';
    vi.spyOn(window, 'getComputedStyle').mockImplementation(() => ({ colorScheme: scheme }) as CSSStyleDeclaration);
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm({ autoPrompt: false })] });

    void Madauth.signIn();
    await settle();
    expect(gis.id.renderButton.mock.lastCall![1].theme).toBe('filled_black');

    dialogElement().close();
    scheme = 'light';
    void Madauth.signIn();
    await settle();
    expect(gis.id.renderButton.mock.lastCall![1].theme).toBe('outline');
  });

  it('W4: a sign-in with the dialog’s button fires madauth-signed-in and closes the dialog', async () => {
    fakeServer();
    const gis = fakeGis();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm({ autoPrompt: false })] });
    void Madauth.signIn();
    await settle();
    const onSignedIn = vi.fn();
    dialogElement().addEventListener('madauth-signed-in', (e) => onSignedIn(e.detail));

    gis.signIn();
    await settle();

    expect(onSignedIn).toHaveBeenCalledExactlyOnceWith({ method: 'google', user: ada });
    expect(shadow<HTMLDialogElement>('dialog')!.open).toBe(false);
  });

  it('W5: a failed sign-in shows an error, keeps the dialog open and renders a fresh button', async () => {
    const server = fakeServer();
    const gis = fakeGis();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm({ autoPrompt: false })] });
    void Madauth.signIn();
    await settle();
    const onError = vi.fn();
    const onSignedIn = vi.fn();
    dialogElement().addEventListener('madauth-error', (e) => onError(e.detail));
    dialogElement().addEventListener('madauth-signed-in', onSignedIn);
    server.verifyError = 'verification_failed';

    gis.signIn();
    await settle();

    expect(onError).toHaveBeenCalledWith({ method: 'google', code: 'verification_failed', message: 'rejected in test' });
    expect(onSignedIn).not.toHaveBeenCalled();
    expect(shadow<HTMLDialogElement>('dialog')!.open).toBe(true);
    expect(shadow('.error')!.textContent).toContain('could not be verified');
    expect(gis.id.renderButton).toHaveBeenCalledTimes(2);
    expect(gis.id.initialize.mock.lastCall![0].nonce).toBe('nonce-2');
  });

  it('W2: loads the GIS script only once', async () => {
    fakeServer();
    fakeGis();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm()] });

    void Madauth.signIn();
    await settle();
    dialogElement().close();
    void Madauth.signIn();
    await settle();

    expect(gisScripts()).toHaveLength(1);
  });

  it('G6: signing out disables Google’s automatic sign-in', async () => {
    fakeServer().user = ada;
    const gis = fakeGis();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm()] });

    await Madauth.signOut();

    expect(gis.id.disableAutoSelect).toHaveBeenCalledOnce();
  });
});

describe('GoogleRedirect', () => {
  it('D1: is left out, with a warning, when the server has no client secret; the other methods work', async () => {
    fakeServer().codeFlow = false;

    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect(), new Password()] });

    // The page learns from the result which method it has to do without.
    expect(result).toEqual({ isSuccess: true, leftOut: ['google'] });
    expect(warnLog).toHaveBeenCalledWith('[madauth]', 'flow_not_enabled', expect.stringContaining('left out'));
    expect(errorLog).not.toHaveBeenCalled();
    // The page behaves as if GoogleRedirect had not been passed.
    expect(Madauth.google.renderButton(document.createElement('div'))).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
    void Madauth.signIn();
    await settle();
    expect(shadow('.google-slot')).toBeNull();
    expect(shadow('form.signin')).not.toBeNull();
  });

  it('D1b: initialize fails when no sign-in method is left', async () => {
    fakeServer().codeFlow = false;

    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()] });

    expect(result).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled', message: expect.stringContaining('No sign-in method') } });
    expect(errorLog).toHaveBeenCalledWith('[madauth]', 'flow_not_enabled', expect.stringContaining('No sign-in method'));
  });

  it('D2 / W6: the dialog’s Google button starts the code flow', async () => {
    fakeServer().codeFlow = true;
    const assign = vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    history.replaceState(null, '', '/page?x=1#top');
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()] });

    void Madauth.signIn();
    await settle();
    shadow<HTMLButtonElement>('.google-slot button')!.click();

    expect(assign).toHaveBeenCalledExactlyOnceWith(
      `${SERVER}/auth/google/start?return_to=${encodeURIComponent('https://app.example.com/page?x=1')}`,
    );
    expect(shadow('.notice')).toBeNull();
  });

  it('D3: reports a failed redirect sign-in, tidies the URL and shows it in the dialog', async () => {
    fakeServer().codeFlow = true;
    history.replaceState(null, '', '/page?x=1#madauth_error=verification_failed');

    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()] });

    expect(result).toMatchObject({ isSuccess: false, error: { code: 'verification_failed' } });
    expect(location.href).toBe('https://app.example.com/page?x=1');
    // madAuth stays usable: the dialog opens and shows the error.
    void Madauth.signIn();
    await settle();
    expect(shadow('.error')?.getAttribute('data-code')).toBe('verification_failed');
  });

  it('labels the dialog’s button in the dialog’s language and follows setLocale', async () => {
    fakeServer().codeFlow = true;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()], locale: 'de' });

    void Madauth.signIn();
    await settle();
    const button = shadow<HTMLButtonElement>('.google-slot button')!;
    expect(button.textContent).toBe('Weiter mit Google');

    Madauth.setLocale('en');
    expect(button.textContent).toBe('Continue with Google');
    // The same button: it was not rendered again.
    expect(shadow('.google-slot button')).toBe(button);
  });

  it('reports a failed redirect sign-in in the configured language', async () => {
    fakeServer().codeFlow = true;
    history.replaceState(null, '', '/page#madauth_error=verification_failed');

    const german = await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()], locale: 'de' });

    expect(german).toEqual({
      isSuccess: false,
      error: { code: 'verification_failed', message: 'Die Anmeldung mit Google konnte nicht überprüft werden. Bitte versuchen Sie es erneut.' },
    });
    void Madauth.signIn();
    await settle();
    expect(shadow('.error')!.textContent).toContain('Die Anmeldung konnte nicht überprüft werden. Bitte versuchen Sie es erneut.');

    history.replaceState(null, '', '/page#madauth_error=server_error');
    const unknown = await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()], locale: 'de-AT' });
    expect(unknown).toEqual({
      isSuccess: false,
      error: { code: 'unknown', message: 'Die Anmeldung mit Google ist fehlgeschlagen (server_error).' },
    });

    history.replaceState(null, '', '/page#madauth_error=cancelled');
    const english = await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()] });
    expect(english).toEqual({ isSuccess: false, error: { code: 'cancelled', message: 'The Google sign-in was cancelled.' } });
  });

  it('D3: restores the session after a successful redirect sign-in', async () => {
    const server = fakeServer();
    server.codeFlow = true;
    server.user = ada;
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);

    expect(await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()] })).toEqual({ isSuccess: true, leftOut: [] });

    expect(listener).toHaveBeenCalledWith(ada);
  });

  it('D4: never loads Google Identity Services', async () => {
    fakeServer().codeFlow = true;

    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()] });
    void Madauth.signIn();
    await settle();

    expect(gisScripts()).toHaveLength(0);
  });
});
