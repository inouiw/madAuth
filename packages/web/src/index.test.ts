import { afterEach, beforeEach, describe, expect, expectTypeOf, it, vi } from 'vitest';
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
      ['EmailLink', 'GitHub', 'GoogleFedcm', 'GoogleRedirect', 'Madauth', 'MadauthLogin', 'Password', 'Totp', 'loginMethods'].sort(),
    );
    expect(Object.keys(madauth.Madauth).sort()).toEqual(
      [
        'admin',
        'currentUser',
        'deleteAccount',
        'emailLink',
        'getSession',
        'github',
        'google',
        'initialize',
        'onAuthStateChanged',
        'password',
        'sessionReady',
        'setLocale',
        'setUpAuthenticator',
        'setUpSms',
        'signIn',
        'signOut',
        'sms',
        'totp',
      ].sort(),
    );
    expect('tryOneTapSignIn' in madauth.Madauth).toBe(false);
  });

  it('H12: scopes each sign-in method’s actions', () => {
    expect(Object.keys(madauth.Madauth.password).sort()).toEqual(
      ['confirmReset', 'loadRating', 'pendingReset', 'policy', 'sendResetEmail', 'sendVerificationEmail', 'signIn', 'signUp', 'verifyEmail'].sort(),
    );
    expect(Object.keys(madauth.Madauth.google)).toEqual(['renderButton']);
    expect(Object.keys(madauth.Madauth.github)).toEqual(['renderButton']);
    expect(Object.keys(madauth.Madauth.totp).sort()).toEqual(
      ['confirmSetup', 'newRecoveryCodes', 'pendingStep', 'policy', 'remove', 'sendVerificationEmail', 'signIn', 'signUp', 'startSetup', 'status', 'verify', 'verifyEmail'].sort(),
    );
    expect(Object.keys(madauth.Madauth.emailLink).sort()).toEqual(['policy', 'send', 'verify']);
    expect(Object.keys(madauth.Madauth.sms).sort()).toEqual(['available', 'confirmSetup', 'pendingStep', 'remove', 'send', 'setUp', 'status', 'verify']);
    expectTypeOf(madauth.Madauth.password).toEqualTypeOf<madauth.PasswordApi>();
    expectTypeOf(madauth.Madauth.emailLink).toEqualTypeOf<madauth.EmailLinkApi>();
    expectTypeOf(madauth.Madauth.sms).toEqualTypeOf<madauth.SmsApi>();
    expectTypeOf(madauth.Madauth.google).toEqualTypeOf<madauth.GoogleApi>();
    expectTypeOf(madauth.Madauth.github).toEqualTypeOf<madauth.GitHubApi>();
    expectTypeOf(madauth.Madauth.totp).toEqualTypeOf<madauth.TotpApi>();
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
    expect(login.shadowRoot!.querySelector('[data-method="google"], .google-slot')).toBeNull();
    login.remove();

    vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()] });
    login = await open();
    login.shadowRoot!.querySelector<HTMLButtonElement>('.google-slot button')!.click();
    await login.updateComplete;
    expect(login.shadowRoot!.querySelector('.notice')).toBeNull();
    expect(window.location.assign).toHaveBeenCalledOnce();
    // Methods without a provider are not listed.
    expect(login.shadowRoot!.querySelectorAll('[data-method]')).toHaveLength(0);
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
