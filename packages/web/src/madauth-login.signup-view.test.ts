import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth, type SignInOptions } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { EmailLink } from './providers/email-link.js';
import { GoogleRedirect } from './providers/google-redirect.js';
import { Password } from './providers/password.js';
import type { SignInProvider } from './providers/provider.js';
import { SERVER, fakeServer, resetAll, settle } from './test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

function login(): MadauthLogin {
  return document.querySelector('madauth-login')!;
}

function $<T extends Element = HTMLElement>(selector: string): T | null {
  return login().shadowRoot!.querySelector<T>(selector);
}

function text(selector: string): string {
  return $(selector)!.textContent.replace(/\s+/g, ' ').trim();
}

async function openDialog(options: SignInOptions, providers: SignInProvider[] = [new Password()]): Promise<void> {
  await Madauth.initialize({ serverUrl: SERVER, providers });
  void Madauth.showSignInDialog(options);
  await settle();
}

describe("showSignInDialog's view", () => {
  it("opens on the sign-in view by default and with 'signin'", async () => {
    fakeServer();
    await openDialog({});
    expect($('form.signin')).not.toBeNull();
    login().shadowRoot!.querySelector('dialog')!.close();
    await settle();

    void Madauth.showSignInDialog({ view: 'signin' });
    await settle();
    expect($('form.signin')).not.toBeNull();
  });

  it("opens on the \"Create account\" form with 'signup', with the e-mail address filled in", async () => {
    fakeServer();
    await openDialog({ view: 'signup', email: 'new@example.com' });

    expect(text('h2')).toBe('Create account');
    expect($('form.signup #new-password')).not.toBeNull();
    expect($<HTMLInputElement>('form.signup input[name="email"]')!.value).toBe('new@example.com');
    // The way back to the sign-in view is there, as after the link.
    expect($('[data-action="back"]')).not.toBeNull();
  });

  it('opens on the sign-in view again when reopened without the view', async () => {
    fakeServer();
    await openDialog({ view: 'signup' });
    login().shadowRoot!.querySelector('dialog')!.close();
    await settle();

    void Madauth.showSignInDialog();
    await settle();
    expect($('form.signin')).not.toBeNull();
  });

  it("stays on the sign-in view when only a provider's button makes accounts", async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    await openDialog({ view: 'signup' }, [new GoogleRedirect(), new EmailLink()]);

    expect($('form.signup')).toBeNull();
    expect($('[data-method="email-link"]')).not.toBeNull();
  });

  it('refuses a view it does not know', async () => {
    fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    const result = await Madauth.showSignInDialog({ view: 'register' as SignInOptions['view'] });
    expect(result).toMatchObject({ isSuccess: false, error: { code: 'invalid_options' } });
  });
});
