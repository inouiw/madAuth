// OpenID Connect providers in the web library: the button madAuth adds for each one the server offers,
// Madauth.provider(id), the return from the redirect, and the user's methods. See "Providers" in docs/custom-ui.md.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { SERVER, fakeServer, grace, resetAll, settle, type FakeServer } from '../test-helpers.js';
import { Authenticator } from './authenticator.js';
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

/** A server with GitLab, an OpenID Connect provider, on next to e-mail & password. */
function gitlabServer(): FakeServer {
  const server = fakeServer();
  server.oidc = [{ id: 'gitlab', name: 'GitLab', secondFactor: 'none' }];
  return server;
}

/** Where GitLab's sign-in starts from /page. */
const start = (link = '') => `${SERVER}/auth/providers/gitlab/start?return_to=${encodeURIComponent('https://app.example.com/page')}&locale=${encodeURIComponent(navigator.language)}${link}`;

describe('OpenID Connect providers', () => {
  it('O1: the dialog shows a neutral "Continue with <name>" button after Google and GitHub, which starts the redirect', async () => {
    const server = gitlabServer();
    server.github = true;
    server.codeFlow = true;
    const assign = vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    history.replaceState(null, '', '/page');

    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    void Madauth.showSignInDialog();
    await settle();

    expect($$('.button-slot').map((slot) => slot.dataset.button)).toEqual(['google', 'github', 'gitlab']);
    expect($('.gitlab-slot')!.title).toBe('Use your GitLab account');
    const button = $<HTMLButtonElement>('.gitlab-slot button')!;
    expect(button.textContent).toBe('Continue with GitLab');
    // madAuth's own sign-in mark: nothing is loaded from the provider.
    expect(button.querySelector('svg')).not.toBeNull();
    expect(button.querySelector('img')).toBeNull();
    button.click();
    expect(assign).toHaveBeenCalledExactlyOnceWith(start());
  });

  it('O2: Madauth.provider(id) renders the button also before initialize is done, and signs in or connects without one', async () => {
    gitlabServer();
    const assign = vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    history.replaceState(null, '', '/page');
    const container = document.createElement('div');
    document.body.append(container);

    const initialized = Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    expect(Madauth.provider('gitlab').renderButton(container)).toMatchObject({ isSuccess: true });
    await initialized;
    await settle();
    expect(container.querySelector('button')?.textContent).toBe('Continue with GitLab');

    expect(await Madauth.provider('gitlab').signIn()).toEqual({ isSuccess: true });
    expect(assign).toHaveBeenLastCalledWith(start());
    expect(await Madauth.provider('gitlab').signIn({ purpose: 'link' })).toEqual({ isSuccess: true });
    expect(assign).toHaveBeenLastCalledWith(start('&link=1'));
  });

  it('O3: a provider the server doesn’t offer fails, through onResult while initialize still asks the server', async () => {
    gitlabServer();
    const onResult = vi.fn();

    const initialized = Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    expect(Madauth.provider('keycloak').renderButton(document.createElement('div'), { onResult })).toMatchObject({ isSuccess: true });
    await initialized;
    await settle();

    expect(onResult).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ isSuccess: false, error: expect.objectContaining({ code: 'flow_not_enabled' }) }));
    expect(Madauth.provider('keycloak').renderButton(document.createElement('div'))).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
    expect(await Madauth.provider('keycloak').signIn()).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled', message: expect.stringContaining('"keycloak"') } });
  });

  it('O4: back from the redirect: an error names the provider, a connection says which, a second step goes on with it', async () => {
    const server = gitlabServer();
    server.methods.authenticator = true;

    history.replaceState(null, '', '/page#madauth_error=email_unverified&madauth_method=gitlab');
    expect(await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] })).toMatchObject({
      isSuccess: false,
      error: { code: 'email_unverified', message: 'Your GitLab account’s email address is not verified.' },
    });

    history.replaceState(null, '', '/page#madauth_linked=gitlab');
    expect(await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] })).toEqual({ isSuccess: true, leftOut: [], linked: 'gitlab' });
    expect(location.href).toBe('https://app.example.com/page');

    history.replaceState(null, '', '/page#madauth_next=authenticator&madauth_method=gitlab');
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password(), new Authenticator()] });
    expect(Madauth.authenticator.pendingStep).toEqual({ step: 'code', method: 'gitlab', factors: ['authenticator'] });
  });

  it('O5: the user’s methods offer to connect the provider, and list it by its name once connected', async () => {
    const server = gitlabServer();
    server.user = grace;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    void Madauth.showManageSignInMethodsDialog();
    await settle();

    expect($$('[data-purpose="link"]').map((slot) => slot.dataset.button)).toEqual(['gitlab']);
    expect($('.gitlab-slot button')?.textContent).toBe('Connect GitLab');

    resetAll();
    const connected = gitlabServer();
    connected.user = grace;
    connected.linked.set(grace.email!, new Set(['gitlab']));
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    void Madauth.showManageSignInMethodsDialog();
    await settle();

    expect($('.method[data-method="gitlab"] .label')?.textContent).toBe('GitLab');
    expect($('.method[data-method="gitlab"] .hint')?.textContent).toBe(grace.email);
    expect($('.method[data-method="gitlab"] svg')).not.toBeNull();
    expect($('[data-purpose="link"]')).toBeNull();
  });

  it('O6: the dialog names the provider where it names methods: what a second factor does, and the forgotten password', async () => {
    const server = gitlabServer();
    server.oidc[0]!.secondFactor = 'optional';
    server.methods.authenticator = true;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password(), new Authenticator()] });

    expect(Madauth.authenticator.policy?.secondFactorFor).toEqual(['gitlab']);
    void Madauth.showSignInDialog();
    await settle();
    $<HTMLButtonElement>('[data-action="forgot"]')!.click();
    await settle();
    expect($('p.hint')?.textContent).toBe('Signed up with GitLab? There is no password to reset: use that button instead.');
  });
});
