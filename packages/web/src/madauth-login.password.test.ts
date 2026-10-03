import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { GoogleFedcm } from './providers/google-fedcm.js';
import { Password } from './providers/password.js';
import type { SignInProvider } from './providers/provider.js';
import { CODE, SERVER, fakeGis, fakeServer, grace, resetAll, settle } from './test-helpers.js';

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

async function fill(values: Record<string, string>): Promise<void> {
  for (const [name, value] of Object.entries(values)) {
    const input = $<HTMLInputElement>(`form input[name="${name}"]`);
    if (!input) throw new Error(`No field ${name}`);
    input.value = value;
  }
}

async function submit(form: string): Promise<void> {
  $<HTMLFormElement>(`form.${form}`)!.requestSubmit();
  await settle();
}

async function click(selector: string): Promise<void> {
  $<HTMLButtonElement>(selector)!.click();
  await settle();
}

/** Opens the dialog with the password provider; resolves to the pending signIn() result. */
async function openDialog(providers: SignInProvider[] = [new Password()]) {
  await Madauth.initialize({ serverUrl: SERVER, providers });
  const result = Madauth.signIn();
  await settle();
  return result;
}

describe('<madauth-login> with e-mail & password', () => {
  it('D1: offers the form, "Forgot password?" and "Create account" only with the provider', async () => {
    fakeServer();
    fakeGis();
    void openDialog([new GoogleFedcm({ autoPrompt: false })]);
    await settle();
    expect($('[data-action="forgot"]')).toBeNull();
    await click('[data-method="password"]');
    expect($('.notice')!.textContent).toContain('coming soon');
    login().close();

    void openDialog();
    await settle();
    expect($('form.signin input[name="email"]')).not.toBeNull();
    expect($('[data-action="forgot"]')).not.toBeNull();
    expect($('[data-action="signup"]')).not.toBeNull();
  });

  it('D2: signs in through the form and closes', async () => {
    fakeServer();
    const result = openDialog();
    const onSignedIn = vi.fn();
    await settle();
    login().addEventListener('madauth-signed-in', (e) => onSignedIn(e.detail));

    await fill({ email: 'grace@example.com', password: 'correct horse battery' });
    await submit('signin');

    expect(await result).toEqual({ isSuccess: true, user: grace });
    expect(onSignedIn).toHaveBeenCalledWith({ method: 'password', user: grace });
    expect($<HTMLDialogElement>('dialog')!.open).toBe(false);
  });

  it('D2: a wrong password shows an error and keeps the dialog open', async () => {
    fakeServer();
    void openDialog();
    await settle();

    await fill({ email: 'grace@example.com', password: 'wrong' });
    await submit('signin');

    expect($('[part="error"]')!.dataset.code).toBe('invalid_credentials');
    expect($('[part="error"]')!.textContent).toContain('E-mail or password is wrong.');
    expect($<HTMLDialogElement>('dialog')!.open).toBe(true);
  });

  it('D3: creating an account leads to the check-inbox view; back leads to sign-in', async () => {
    const server = fakeServer();
    void openDialog();
    await settle();
    await fill({ email: 'new@example.com' });

    await click('[data-action="signup"]');
    expect($('h2')!.textContent).toBe('Create account');
    // The address typed on the sign-in view is kept.
    expect($<HTMLInputElement>('input[name="email"]')!.value).toBe('new@example.com');
    expect($('.hint')!.textContent).toContain('At least 8 characters');
    await fill({ name: 'New Person', password: 'long enough' });
    await submit('signup');

    expect($('h2')!.textContent).toBe('Check your inbox');
    expect($('.lead')!.textContent).toContain('new@example.com');
    expect(server.mails).toEqual([{ purpose: 'verify', to: 'new@example.com', redirectTo: 'https://app.example.com/page' }]);

    await click('[data-action="back"]');
    expect($('h2')!.textContent).toBe('Sign in');
  });

  it('D3: a short password on sign-up shows the rule', async () => {
    fakeServer();
    void openDialog();
    await settle();
    await click('[data-action="signup"]');

    await fill({ email: 'new@example.com', password: 'short' });
    await submit('signup');

    expect($('[part="error"]')!.textContent).toContain('at least 8 characters');
    expect($('h2')!.textContent).toBe('Create account');
  });

  it('K8: tells the user when sign-up or e-mails are not available', async () => {
    const server = fakeServer();
    server.emailsDown = true;
    void openDialog();
    await settle();
    await click('[data-action="signup"]');

    await fill({ email: 'new@example.com', password: 'long enough' });
    await submit('signup');

    expect($('[part="error"]')!.dataset.code).toBe('temporarily_unavailable');
    expect($('[part="error"]')!.textContent).toContain('E-mail & password sign-up is not available right now. Please try again later.');
    expect($('h2')!.textContent).toBe('Create account');

    await click('[data-action="back"]');
    await click('[data-action="forgot"]');
    await fill({ email: 'grace@example.com' });
    await submit('forgot');
    expect($('[part="error"]')!.textContent).toContain('Sending e-mails is not available right now.');
  });

  it('K8: shows the message of a refused sign-up', async () => {
    fakeServer().rejectSignUp = 'Only addresses at example.org can sign up.';
    void openDialog();
    await settle();
    await click('[data-action="signup"]');

    await fill({ email: 'new@example.com', password: 'long enough' });
    await submit('signup');

    expect($('[part="error"]')!.dataset.code).toBe('signup_rejected');
    expect($('[part="error"]')!.textContent).toContain('Only addresses at example.org can sign up.');
  });

  it('D4: the code from the e-mail confirms the address and signs in', async () => {
    fakeServer();
    const result = openDialog();
    await settle();
    await click('[data-action="signup"]');
    await fill({ email: 'new@example.com', password: 'long enough' });
    await submit('signup');

    await fill({ code: '123 456' });
    await submit('code');

    expect(await result).toMatchObject({ isSuccess: true, user: { email: 'new@example.com' } });
  });

  it('D4: forgot password → code → new password signs in', async () => {
    const server = fakeServer();
    const result = openDialog();
    await settle();

    await click('[data-action="forgot"]');
    expect($('h2')!.textContent).toBe('Reset password');
    await fill({ email: 'grace@example.com' });
    await submit('forgot');
    expect(server.mails.at(-1)).toMatchObject({ purpose: 'reset', to: 'grace@example.com' });
    expect($('h2')!.textContent).toBe('Check your inbox');

    await fill({ code: CODE });
    await submit('code');
    expect($('h2')!.textContent).toBe('Choose a new password');
    await fill({ password: 'brand new password' });
    await submit('reset');

    expect(await result).toEqual({ isSuccess: true, user: grace });
    expect(server.requests.at(-1)!.body).toEqual({ password: 'brand new password', email: 'grace@example.com', code: CODE });
  });

  it('D4: a wrong reset code leads back to the code field', async () => {
    fakeServer();
    void openDialog();
    await settle();
    await click('[data-action="forgot"]');
    await fill({ email: 'grace@example.com' });
    await submit('forgot');
    await fill({ code: '000000' });
    await submit('code');

    await fill({ password: 'brand new password' });
    await submit('reset');

    expect($('h2')!.textContent).toBe('Check your inbox');
    expect($('[part="error"]')!.dataset.code).toBe('code_invalid');
  });

  it('D5: an unconfirmed address can ask for the e-mail again', async () => {
    const server = fakeServer();
    server.accounts.set('new@example.com', { password: 'long enough', verified: false });
    void openDialog();
    await settle();
    await fill({ email: 'new@example.com', password: 'long enough' });
    await submit('signin');
    expect($('[part="error"]')!.dataset.code).toBe('email_unverified');

    await click('[data-action="resend-verification"]');

    expect(server.mails).toEqual([{ purpose: 'verify', to: 'new@example.com', redirectTo: 'https://app.example.com/page' }]);
    expect($('h2')!.textContent).toBe('Check your inbox');
    expect($('.notice[role="status"]')!.textContent).toContain('We sent the e-mail again.');
  });

  it('D6: uses only the public Madauth API', async () => {
    fakeServer();
    const spies = (['signIn', 'signUp', 'sendResetEmail', 'confirmReset'] as const).map((name) => vi.spyOn(Madauth.password, name));
    void openDialog();
    await settle();

    await fill({ email: 'grace@example.com', password: 'wrong' });
    await submit('signin');
    await click('[data-action="signup"]');
    await fill({ email: 'x@example.com', password: 'long enough' });
    await submit('signup');
    await click('[data-action="back"]');
    await click('[data-action="forgot"]');
    await fill({ email: 'grace@example.com' });
    await submit('forgot');
    await fill({ code: CODE });
    await submit('code');
    await fill({ password: 'brand new password' });
    await submit('reset');

    for (const spy of spies) expect(spy).toHaveBeenCalled();
    // Vitest runs in the package directory; import.meta.url is not a file URL under happy-dom.
    const source = readFileSync('src/madauth-login.ts', 'utf8');
    expect(source).not.toMatch(/from '\.\/http\.js'/);
    expect(source).not.toMatch(/\brequest\(/);
  });

  it('D7: sets autocomplete so password managers and one-time codes work', async () => {
    fakeServer();
    void openDialog();
    await settle();
    const autocomplete = (name: string) => $<HTMLInputElement>(`form input[name="${name}"]`)!.getAttribute('autocomplete');

    expect([autocomplete('email'), autocomplete('password')]).toEqual(['email', 'current-password']);
    await click('[data-action="signup"]');
    expect([autocomplete('name'), autocomplete('email'), autocomplete('password')]).toEqual(['name', 'email', 'new-password']);
    await fill({ email: 'x@example.com', password: 'long enough' });
    await submit('signup');
    expect(autocomplete('code')).toBe('one-time-code');
  });

  it('signIn({ email }) fills the e-mail field and focuses the password field', async () => {
    const server = fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });

    const result = Madauth.signIn({ email: ' grace@example.com ' });
    await settle();

    expect($<HTMLInputElement>('form.signin input[name="email"]')!.value).toBe('grace@example.com');
    expect(login().shadowRoot!.activeElement).toBe($('form.signin input[name="password"]'));

    await fill({ password: 'correct horse battery' });
    await submit('signin');
    expect(await result).toEqual({ isSuccess: true, user: grace });
    expect(server.requests.at(-1)!.body).toEqual({ email: 'grace@example.com', password: 'correct horse battery' });
  });

  it('signIn({ email }) keeps the address on the other views', async () => {
    fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    void Madauth.signIn({ email: 'new@example.com' });
    await settle();

    await click('[data-action="signup"]');
    expect($<HTMLInputElement>('form.signup input[name="email"]')!.value).toBe('new@example.com');

    await click('[data-action="back"]');
    await click('[data-action="forgot"]');
    expect($<HTMLInputElement>('form.forgot input[name="email"]')!.value).toBe('new@example.com');
  });

  it('signIn({ email }) replaces an address from an earlier visit', async () => {
    fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    void Madauth.signIn({ email: 'grace@example.com' });
    await settle();
    // Typed over the prefilled address, then closed without sending the form.
    await fill({ email: 'typed@example.com' });
    login().close();

    void Madauth.signIn({ email: 'grace@example.com' });
    await settle();
    expect($<HTMLInputElement>('form.signin input[name="email"]')!.value).toBe('grace@example.com');
    login().close();

    void Madauth.signIn({ email: 'ada@example.com' });
    await settle();
    expect($<HTMLInputElement>('form.signin input[name="email"]')!.value).toBe('ada@example.com');
  });

  it('open({ email }) on the element fills the e-mail field too', async () => {
    fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    const element = document.createElement('madauth-login');
    document.body.append(element);

    await element.open({ email: 'grace@example.com' });

    expect($<HTMLInputElement>('form.signin input[name="email"]')!.value).toBe('grace@example.com');
    expect(element.shadowRoot!.activeElement).toBe($('form.signin input[name="password"]'));
  });

  it('signIn({ email }) fills the field without the Password provider, but leaves the focus alone', async () => {
    fakeServer();
    fakeGis();

    void openDialog([new GoogleFedcm({ autoPrompt: false })]);
    await settle();
    login().close();
    void Madauth.signIn({ email: 'grace@example.com' });
    await settle();

    expect($<HTMLInputElement>('form.signin input[name="email"]')!.value).toBe('grace@example.com');
    expect(login().shadowRoot!.activeElement).not.toBe($('form.signin input[name="password"]'));
  });

  it('signIn() without an e-mail leaves the field and the focus alone', async () => {
    fakeServer();
    void openDialog();
    await settle();

    expect($<HTMLInputElement>('form.signin input[name="email"]')!.value).toBe('');
    expect(login().shadowRoot!.activeElement).not.toBe($('form.signin input[name="password"]'));

    await fill({ email: 'typed@example.com' });
    login().close();
    void Madauth.signIn({});
    await settle();
    expect($<HTMLInputElement>('form.signin input[name="email"]')!.value).toBe('typed@example.com');
    expect(login().shadowRoot!.activeElement).not.toBe($('form.signin input[name="password"]'));
  });

  it('starts over on the sign-in view when reopened', async () => {
    fakeServer();
    void openDialog();
    await settle();
    await click('[data-action="forgot"]');

    $<HTMLButtonElement>('.close')!.click();
    void Madauth.signIn();
    await settle();

    expect($('h2')!.textContent).toBe('Sign in');
    expect($('[part="error"]')).toBeNull();
  });
});
