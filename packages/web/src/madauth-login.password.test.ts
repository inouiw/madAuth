import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { GoogleFedcm } from './providers/google-fedcm.js';
import { GoogleRedirect } from './providers/google-redirect.js';
import { Password } from './providers/password.js';
import type { SignInProvider } from './providers/provider.js';
import { CODE, SERVER, ada, fakeGis, fakeServer, grace, resetAll, settle } from './test-helpers.js';

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
  const result = Madauth.showSignInDialog();
  await settle();
  return result;
}

describe('<madauth-login> with e-mail & password', () => {
  it('opened from a confirmation link that failed, the dialog opens by itself with the error', async () => {
    fakeServer();
    history.replaceState(null, '', '/page#madauth_verify=used-up');

    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    await settle();

    expect($<HTMLDialogElement>('dialog')!.open).toBe(true);
    expect($('.error')?.getAttribute('data-code')).toBe('link_invalid');
  });

  it('opened from a used-up confirmation link while signed in, the dialog stays closed', async () => {
    fakeServer().user = ada;
    history.replaceState(null, '', '/page#madauth_verify=used-up');
    const signIn = vi.spyOn(Madauth, 'showSignInDialog');

    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    await settle();

    expect(signIn).not.toHaveBeenCalled();
    expect(Madauth.currentUser).toEqual(ada);
  });

  it('D1: offers the form, "Forgot password?" and "Create account" only with the provider', async () => {
    fakeServer();
    fakeGis();
    void openDialog([new GoogleFedcm({ autoPrompt: false })]);
    await settle();
    expect($('form.signin')).toBeNull();
    expect($('[data-action="forgot"]')).toBeNull();
    expect($('[data-action="signup"]')).toBeNull();
    login().close();

    void openDialog();
    await settle();
    expect($('form.signin input[name="email"]')).not.toBeNull();
    expect($('[data-action="forgot"]')).not.toBeNull();
    expect($('[data-action="signup"]')).not.toBeNull();
  });

  it('D1: opened while madAuth gets ready, the dialog shows up with the form already in place', async () => {
    const server = fakeServer();
    let answer!: () => void;
    server.held = new Promise((resolve) => (answer = resolve));
    void Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    document.body.append(document.createElement('madauth-login'));
    const opened = login().open();
    await settle();
    expect($<HTMLDialogElement>('dialog')!.open).toBe(false);

    answer();
    await opened;

    expect($<HTMLDialogElement>('dialog')!.open).toBe(true);
    expect($('form.signin')).not.toBeNull();
  });

  it('D1: offers no form when madAuth could not get ready, only the error', async () => {
    const server = fakeServer();
    server.down = true;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    document.body.append(document.createElement('madauth-login'));
    await login().open();
    await settle();

    expect($('[part="error"]')!.dataset.code).toBe('network');
    expect($('form.signin')).toBeNull();
    expect($('[data-method]')).toBeNull();
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
    expect($('[part="error"]')!.textContent).toContain('Email or password is wrong.');
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

  it('rates the new password as it is typed, against the server’s minimum score', async () => {
    fakeServer();
    void openDialog();
    await settle();
    await click('[data-action="signup"]');
    const type = (password: string) => {
      const input = $<HTMLInputElement>('input[name="password"]')!;
      input.value = password;
      input.dispatchEvent(new Event('input', { bubbles: true }));
    };
    const meter = () => $('[part="strength"]');

    expect(meter()).toBeNull();
    type('password1234');
    await vi.waitFor(() => expect(meter()?.dataset.score).toBe('1'));
    expect(meter()!.hasAttribute('data-too-easy')).toBe(true);
    expect(meter()!.textContent).toContain('Weak: too easy to guess');
    expect($('[role="meter"]')!.getAttribute('aria-valuetext')).toBe('Weak: too easy to guess');

    type('correct horse battery');
    await vi.waitFor(() => expect(meter()?.dataset.score).toBe('4'));
    expect(meter()!.hasAttribute('data-too-easy')).toBe(false);
    expect(meter()!.textContent).toContain('Strong');

    // The user's own name and address count as easy to guess, as on the server.
    await fill({ name: 'Grace Hopper', email: 'grace@example.com' });
    type('Grace Hopper 1');
    await vi.waitFor(() => expect(meter()?.dataset.score).toBe('0'));

    type('');
    await settle();
    expect(meter()).toBeNull();
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
    expect($('[part="error"]')!.textContent).toContain('Email & password sign-up is not available right now. Please try again later.');
    expect($('h2')!.textContent).toBe('Create account');

    await click('[data-action="back"]');
    await click('[data-action="forgot"]');
    await fill({ email: 'grace@example.com' });
    await submit('forgot');
    expect($('[part="error"]')!.textContent).toContain('Sending emails is not available right now.');
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

  it('D4: the "forgot password" form tells Google users to use the Google button, only when Google is offered', async () => {
    fakeServer();
    fakeGis();
    void openDialog([new GoogleFedcm({ autoPrompt: false }), new Password()]);
    await settle();
    await click('[data-action="forgot"]');
    expect($('.hint')!.textContent).toContain('Google');
    login().close();

    void openDialog();
    await settle();
    await click('[data-action="forgot"]');
    expect($('h2')!.textContent).toBe('Reset password');
    expect($('.hint')).toBeNull();
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
    expect($('.notice[role="status"]')!.textContent).toContain('We sent the email again.');

    login().close();
    void openDialog();
    await settle();
    expect($('.notice')).toBeNull();
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

    // `username` on the address: password managers save and fill it together with the password.
    expect([autocomplete('email'), autocomplete('password')]).toEqual(['username', 'current-password']);
    await click('[data-action="signup"]');
    expect([autocomplete('name'), autocomplete('email'), autocomplete('password')]).toEqual(['name', 'username', 'new-password']);
    await fill({ email: 'x@example.com', password: 'long enough' });
    await submit('signup');
    // The code from the e-mail: Safari and iOS fill it from Mail and Messages.
    expect(autocomplete('code')).toBe('one-time-code');
  });

  it('moves the focus into each new view, so it is not left behind on the page', async () => {
    fakeServer();
    void openDialog();
    await settle();
    const focused = () => login().shadowRoot!.activeElement;

    await click('[data-action="signup"]');
    expect(focused()).toBe($('form.signup input[name="email"]'));
    await click('[data-action="back"]');
    expect(focused()).toBe($('form.signin input[name="email"]'));
    await click('[data-action="forgot"]');
    expect(focused()).toBe($('form.forgot input[name="email"]'));
    await fill({ email: 'grace@example.com' });
    await submit('forgot');
    expect($('h2')!.textContent).toBe('Check your inbox');
    expect(focused()).toBe($('form.code input[name="code"]'));
  });

  it('D7: uses `email`, not `username`, on an address field without a password', async () => {
    fakeServer();
    void openDialog();
    await settle();

    await click('[data-action="forgot"]');
    // On a `username` field the iCloud Passwords extension opens its panel, with nothing to fill.
    expect($('form.forgot input[name="email"]')!.getAttribute('autocomplete')).toBe('email');
  });

  it('offers Google on the sign-up view too, since it signs up a new user as well', async () => {
    const server = fakeServer();
    server.codeFlow = true;
    void openDialog([new GoogleRedirect(), new Password()]);
    await settle();

    await click('[data-action="signup"]');
    expect($('h2')!.textContent).toBe('Create account');
    expect($('.google-slot button')).not.toBeNull();
    expect($('.divider')!.textContent).toBe('or');
    // The address and the password first; the optional name last.
    expect([...login().shadowRoot!.querySelectorAll('form.signup input')].map((input) => input.getAttribute('name'))).toEqual([
      'email',
      'password',
      'name',
    ]);
  });

  it('links between sign-in and sign-up with a question, of which only the action is underlined', async () => {
    fakeServer();
    void openDialog();
    await settle();

    expect($('[data-action="signup"]')!.textContent).toBe('No account? Create one');
    expect($('[data-action="signup"] span')!.textContent).toBe('Create one');
    await click('[data-action="signup"]');
    expect($('[data-action="back"]')!.textContent).toBe('Already have an account? Sign in');
    expect($('[data-action="back"] span')!.textContent).toBe('Sign in');
  });

  it('shows and hides the password with the eye button', async () => {
    fakeServer();
    void openDialog();
    await settle();
    const field = $<HTMLInputElement>('#password')!;
    const eye = $<HTMLButtonElement>('form.signin .reveal')!;

    expect(eye.getAttribute('aria-label')).toBe('Show password');
    expect(eye.getAttribute('aria-controls')).toBe('password');
    expect([field.type, eye.getAttribute('aria-pressed')]).toEqual(['password', 'false']);
    await click('form.signin .reveal');
    expect([field.type, eye.getAttribute('aria-pressed')]).toEqual(['text', 'true']);
    await click('form.signin .reveal');
    expect([field.type, eye.getAttribute('aria-pressed')]).toEqual(['password', 'false']);

    await click('[data-action="signup"]');
    expect($('form.signup .reveal')!.getAttribute('aria-controls')).toBe('new-password');
  });

  it('hides a shown password when the form is sent, and when the dialog closes', async () => {
    fakeServer();
    void openDialog();
    await settle();
    const field = () => $<HTMLInputElement>('#password')!;

    await click('form.signin .reveal');
    await fill({ email: 'grace@example.com', password: 'wrong password' });
    await submit('signin');
    // Sent as a password field, so password managers offer to save it.
    expect([field().type, $('form.signin .reveal')!.getAttribute('aria-pressed')]).toEqual(['password', 'false']);

    await click('form.signin .reveal');
    $<HTMLButtonElement>('.close')!.click();
    void Madauth.showSignInDialog();
    await settle();
    // The sign-in view's fields stay for the next opening; the password is not shown there.
    expect([field().type, $('form.signin .reveal')!.getAttribute('aria-pressed')]).toEqual(['password', 'false']);
  });

  it('reads the rule for a new password out with the field', async () => {
    fakeServer();
    void openDialog();
    await settle();
    expect($('#password')!.hasAttribute('aria-describedby')).toBe(false);

    await click('[data-action="signup"]');
    expect($('#new-password')!.getAttribute('aria-describedby')).toBe('new-password-hint');
    expect($('#new-password-hint')!.textContent).toBe('At least 8 characters.');
  });

  it('signIn({ email }) fills the e-mail field and focuses the password field', async () => {
    const server = fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });

    const result = Madauth.showSignInDialog({ email: ' grace@example.com ' });
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
    void Madauth.showSignInDialog({ email: 'new@example.com' });
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
    void Madauth.showSignInDialog({ email: 'grace@example.com' });
    await settle();
    // Typed over the prefilled address, then closed without sending the form.
    await fill({ email: 'typed@example.com' });
    login().close();

    void Madauth.showSignInDialog({ email: 'grace@example.com' });
    await settle();
    expect($<HTMLInputElement>('form.signin input[name="email"]')!.value).toBe('grace@example.com');
    login().close();

    void Madauth.showSignInDialog({ email: 'ada@example.com' });
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

  it('signIn({ email }) opens the dialog without the Password provider, which has no e-mail field then', async () => {
    fakeServer();
    fakeGis();

    void openDialog([new GoogleFedcm({ autoPrompt: false })]);
    await settle();
    login().close();
    void Madauth.showSignInDialog({ email: 'grace@example.com' });
    await settle();

    expect($<HTMLDialogElement>('dialog')!.open).toBe(true);
    expect($('input[name="email"]')).toBeNull();
  });

  it('signIn() without an e-mail leaves the field and the focus alone', async () => {
    fakeServer();
    void openDialog();
    await settle();

    expect($<HTMLInputElement>('form.signin input[name="email"]')!.value).toBe('');
    expect(login().shadowRoot!.activeElement).not.toBe($('form.signin input[name="password"]'));

    await fill({ email: 'typed@example.com' });
    login().close();
    void Madauth.showSignInDialog({});
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
    void Madauth.showSignInDialog();
    await settle();

    expect($('h2')!.textContent).toBe('Sign in');
    expect($('[part="error"]')).toBeNull();
  });
});
