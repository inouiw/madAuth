import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as madauth from './index.js';
import { Madauth } from './madauth.js';
import { GoogleRedirect } from './providers/google-redirect.js';
import { SERVER, fakeServer, resetAll, settle } from './test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

describe('@madauth/web', () => {
  it('W7: exports exactly the public API', () => {
    expect(Object.keys(madauth).sort()).toEqual(
      ['GoogleFedcm', 'GoogleRedirect', 'Madauth', 'MadauthLogin', 'loginMethods'].sort(),
    );
    expect(Object.keys(madauth.Madauth).sort()).toEqual(
      ['currentUser', 'getSession', 'initialize', 'onAuthStateChanged', 'signIn', 'signOut'].sort(),
    );
    expect('tryOneTapSignIn' in madauth.Madauth).toBe(false);
  });
});

describe('<madauth-login> with madAuth', () => {
  async function open() {
    const login = document.createElement('madauth-login');
    document.body.append(login);
    await login.open();
    await settle();
    return login;
  }

  it('W1: offers Google only when a Google provider is registered', async () => {
    fakeServer().codeFlow = true;
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });
    let login = await open();
    login.shadowRoot!.querySelector<HTMLButtonElement>('[data-method="google"]')!.click();
    await login.updateComplete;
    expect(login.shadowRoot!.querySelector('.notice')!.textContent).toContain('coming soon');
    login.remove();

    vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()] });
    login = await open();
    login.shadowRoot!.querySelector<HTMLButtonElement>('[data-method="google"]')!.click();
    await login.updateComplete;
    expect(login.shadowRoot!.querySelector('.notice')).toBeNull();
    expect(window.location.assign).toHaveBeenCalledOnce();
    // Other methods have no provider yet.
    login.shadowRoot!.querySelector<HTMLButtonElement>('[data-method="sms"]')!.click();
    await login.updateComplete;
    expect(login.shadowRoot!.querySelector('.notice')!.textContent).toContain('coming soon');
  });

  it('W5: shows and fires an error when madAuth is not initialized', async () => {
    const login = document.createElement('madauth-login');
    const onError = vi.fn();
    login.addEventListener('madauth-error', (e) => onError(e.detail));
    document.body.append(login);

    await login.open();

    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ code: 'not_initialized' }));
    const error = login.shadowRoot!.querySelector('[part="error"]')!;
    expect(error.getAttribute('role')).toBe('alert');
    expect(error.textContent).toContain('Sign-in is not set up on this page.');
  });
});
