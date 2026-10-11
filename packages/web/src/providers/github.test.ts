// GitHub sign-in in the web library: the provider, the dialog's button, the return from the redirect.
// See "GitHub" in docs/custom-ui.md and docs/github-security.md.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import type { MadauthLogin, SignedInDetail } from '../madauth-login.js';
import { CODE, SERVER, ada, fakeServer, gisScripts, resetAll, settle } from '../test-helpers.js';
import { GitHub } from './github.js';
import { GoogleRedirect } from './google-redirect.js';
import { Password } from './password.js';
import type { SignInProvider } from './provider.js';
import { Totp } from './totp.js';

let errorLog: ReturnType<typeof vi.spyOn>;
let warnLog: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  resetAll();
  errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
  warnLog = vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(resetAll);

function login(): MadauthLogin {
  return document.querySelector('madauth-login')!;
}

function $<T extends Element = HTMLElement>(selector: string): T | null {
  return login().shadowRoot!.querySelector<T>(selector);
}

function $$(selector: string): Element[] {
  return [...login().shadowRoot!.querySelectorAll(selector)];
}

/** Opens the dialog on a server with GitHub sign-in; resolves to the pending signIn() result. */
async function openDialog(providers: SignInProvider[], options: { locale?: string } = {}) {
  await Madauth.initialize({ serverUrl: SERVER, providers, ...options });
  const result = Madauth.signIn();
  await settle();
  return result;
}

describe('GitHub', () => {
  it('B1: is left out, with a warning, when the server has no GitHub sign-in; the other methods work', async () => {
    fakeServer();

    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [new GitHub(), new Password()] });

    expect(result).toEqual({ isSuccess: true, leftOut: ['github'] });
    expect(warnLog).toHaveBeenCalledWith('[madauth]', 'flow_not_enabled', expect.stringContaining('left out'));
    expect(errorLog).not.toHaveBeenCalled();
    expect(Madauth.github.renderButton(document.createElement('div'))).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
    void Madauth.signIn();
    await settle();
    expect($('.github-slot')).toBeNull();
    expect($('form.signin')).not.toBeNull();
  });

  it('B1: initialize fails when no sign-in method is left', async () => {
    fakeServer();

    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [new GitHub()] });

    expect(result).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled', message: expect.stringContaining('No sign-in method') }, leftOut: ['github'] });
  });

  it('B2: the dialog’s GitHub button starts the redirect', async () => {
    fakeServer().github = true;
    const assign = vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    history.replaceState(null, '', '/page?x=1#top');

    void openDialog([new GitHub()]);
    await settle();
    $<HTMLButtonElement>('.github-slot button')!.click();

    expect(assign).toHaveBeenCalledExactlyOnceWith(`${SERVER}/auth/github/start?return_to=${encodeURIComponent('https://app.example.com/page?x=1')}`);
    expect(gisScripts()).toHaveLength(0);
  });

  it('B3: a failed GitHub sign-in is reported as GitHub’s on the return, in the configured language, and the URL is tidied', async () => {
    fakeServer().github = true;
    history.replaceState(null, '', '/page?x=1#madauth_error=cancelled&madauth_method=github');

    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [new GitHub()] });

    expect(result).toEqual({ isSuccess: false, error: { code: 'cancelled', message: 'The GitHub sign-in was cancelled.' }, leftOut: [] });
    expect(location.href).toBe('https://app.example.com/page?x=1');
    void Madauth.signIn();
    await settle();
    expect($('.error')?.getAttribute('data-code')).toBe('cancelled');

    history.replaceState(null, '', '/page#madauth_error=email_unverified&madauth_method=github');
    const german = await Madauth.initialize({ serverUrl: SERVER, providers: [new GitHub()], locale: 'de' });
    expect(german).toMatchObject({ isSuccess: false, error: { code: 'email_unverified', message: 'Die E-Mail-Adresse Ihres GitHub-Kontos ist nicht bestätigt.' } });

    history.replaceState(null, '', '/page#madauth_error=server_error&madauth_method=github');
    const unknown = await Madauth.initialize({ serverUrl: SERVER, providers: [new GitHub()] });
    expect(unknown).toMatchObject({ isSuccess: false, error: { code: 'unknown', message: 'GitHub sign-in failed (server_error).' } });
  });

  it('B3: with both providers, the error is attributed by the method the server names, Google when it names none', async () => {
    const server = fakeServer();
    server.github = true;
    server.codeFlow = true;
    const providers = () => [new GoogleRedirect(), new GitHub()];

    history.replaceState(null, '', '/page#madauth_error=verification_failed&madauth_method=google');
    expect(await Madauth.initialize({ serverUrl: SERVER, providers: providers() })).toMatchObject({ error: { message: 'The Google sign-in could not be verified. Please try again.' } });
    history.replaceState(null, '', '/page#madauth_error=verification_failed&madauth_method=github');
    expect(await Madauth.initialize({ serverUrl: SERVER, providers: providers() })).toMatchObject({ error: { message: 'The GitHub sign-in could not be verified. Please try again.' } });
    // A server before 0.5 names no method: only Google had a redirect flow then.
    history.replaceState(null, '', '/page#madauth_error=verification_failed');
    expect(await Madauth.initialize({ serverUrl: SERVER, providers: providers() })).toMatchObject({ error: { message: 'The Google sign-in could not be verified. Please try again.' } });
    expect(location.href).toBe('https://app.example.com/page');
  });

  it('B4: the dialog shows the providers’ buttons first, Google before GitHub, then "or" and the form, then the other ways', async () => {
    const server = fakeServer();
    server.github = true;
    server.codeFlow = true;
    server.methods.totp = true;

    void openDialog([new Totp(), new Password(), new GitHub(), new GoogleRedirect()]);
    await settle();

    expect($$('.button-slot').map((slot) => slot.getAttribute('data-button'))).toEqual(['google', 'github']);
    expect($$('.button-slot button').map((button) => button.textContent)).toEqual(['Continue with Google', 'Continue with GitHub']);
    expect($$('.divider')).toHaveLength(1);
    expect($('form.signin')).not.toBeNull();
    expect($('.others h3')!.textContent).toBe('Other ways to sign in');
    expect($$('.others [data-method]').map((row) => row.getAttribute('data-method'))).toEqual(['totp']);
    expect($('.github-slot')!.getAttribute('title')).toBe('Use your GitHub account');
  });

  it('B4: GitHub alone has no divider, and the other ways get their heading only next to a button or the form', async () => {
    const server = fakeServer();
    server.github = true;

    void openDialog([new GitHub()]);
    await settle();
    expect($$('.button-slot')).toHaveLength(1);
    expect($('.divider')).toBeNull();
    expect($('form.signin')).toBeNull();
    expect($('.others')).toBeNull();
    login().close();

    server.methods.totp = true;
    void openDialog([new GitHub(), new Totp()]);
    await settle();
    expect($('.divider')).toBeNull();
    expect($('.others h3')).not.toBeNull();
    login().close();

    void openDialog([new Totp()]);
    await settle();
    expect($('.others h3')).toBeNull();
  });

  it('B5: labels the button in the dialog’s language and follows setLocale', async () => {
    fakeServer().github = true;

    void openDialog([new GitHub()], { locale: 'de' });
    await settle();
    const button = $<HTMLButtonElement>('.github-slot button')!;
    expect(button.textContent).toBe('Weiter mit GitHub');

    Madauth.setLocale('en');
    expect(button.textContent).toBe('Continue with GitHub');
    expect($('.github-slot button')).toBe(button);
  });

  it('B6: the button shows GitHub’s mark in the text colour, on a white or a dark button', async () => {
    fakeServer().github = true;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GitHub()], ui: 'custom' });
    const light = document.createElement('div');
    const dark = document.createElement('div');
    document.body.append(light, dark);

    Madauth.github.renderButton(light, { theme: 'light' });
    Madauth.github.renderButton(dark, { theme: 'dark' });
    await settle();

    const lightButton = light.querySelector('button')!;
    const darkButton = dark.querySelector('button')!;
    expect(lightButton.querySelector('svg path')!.getAttribute('fill')).toBe('currentColor');
    expect(lightButton.style.background).not.toBe(darkButton.style.background);
    expect(lightButton.style.color).not.toBe(darkButton.style.color);
  });

  it('B8: back from the redirect with the first step done, the dialog goes on with the code as a GitHub sign-in', async () => {
    const server = fakeServer();
    server.github = true;
    server.policy.github = 'optional';
    server.authenticators.add('ada@example.com');
    server.challenge = { email: 'ada@example.com', next: 'totp', method: 'github', factors: ['totp'] };
    history.replaceState(null, '', '/page?x=1#madauth_next=totp&madauth_factors=totp&madauth_method=github');

    await Madauth.initialize({ serverUrl: SERVER, providers: [new GitHub(), new Totp()] });
    await settle();

    expect(location.href).toBe('https://app.example.com/page?x=1');
    expect($<HTMLDialogElement>('dialog')!.open).toBe(true);
    expect($('h2')!.textContent).toBe('Enter your code');
    let detail: SignedInDetail | undefined;
    login().addEventListener('madauth-signed-in', (e) => (detail = (e as CustomEvent<SignedInDetail>).detail));
    $<HTMLInputElement>('form input[name="code"]')!.value = CODE;
    $<HTMLFormElement>('form.totp-code')!.requestSubmit();
    await settle();
    expect(Madauth.currentUser).toEqual(ada);
    expect(detail).toEqual({ method: 'github', user: ada });
  });

  it('B8: a custom screen learns whose sign-in goes on; without a method in the hash (a server before 0.5) it is Google’s', async () => {
    const server = fakeServer();
    server.github = true;
    server.codeFlow = true;
    server.policy.google = 'required';
    server.policy.github = 'required';
    const providers = () => [new GoogleRedirect(), new GitHub(), new Totp()];

    history.replaceState(null, '', '/page#madauth_next=totp-setup&madauth_method=github');
    await Madauth.initialize({ serverUrl: SERVER, providers: providers(), ui: 'custom' });
    expect(Madauth.totp.pendingStep).toEqual({ step: 'setup', method: 'github' });

    history.replaceState(null, '', '/page#madauth_next=totp-setup');
    await Madauth.initialize({ serverUrl: SERVER, providers: providers(), ui: 'custom' });
    expect(Madauth.totp.pendingStep).toEqual({ step: 'setup', method: 'google' });
  });

  it('B9: GitHub takes a policy for the second factor, and its users are told they have no password to reset', async () => {
    const server = fakeServer();
    server.github = true;
    server.codeFlow = true;
    server.policy.github = 'required';

    void openDialog([new GoogleRedirect(), new GitHub(), new Password()]);
    await settle();

    expect(Madauth.totp.policy?.secondFactorFor).toEqual(['github']);
    $<HTMLButtonElement>('[data-action="forgot"]')!.click();
    await settle();
    expect($('.hint')!.textContent).toBe('Signed up with Google or GitHub? There is no password to reset: use that button instead.');
  });
});
