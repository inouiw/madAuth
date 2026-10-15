import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { EmailLink } from './providers/email-link.js';
import { Passkey } from './providers/passkey.js';
import { Password } from './providers/password.js';
import type { SignInProvider } from './providers/provider.js';
import { Totp } from './providers/totp.js';
import { CODE, SERVER, VERIFY_TOKEN, fakeServer, grace, resetAll, settle, stubWebAuthn } from './test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(resetAll);

function login(): MadauthLogin {
  return document.querySelector('madauth-login')!;
}

function $<T extends Element = HTMLElement>(selector: string): T | null {
  return login().shadowRoot!.querySelector<T>(selector);
}

function $$(selector: string): HTMLElement[] {
  return [...login().shadowRoot!.querySelectorAll<HTMLElement>(selector)];
}

/** The text of an element, with the whitespace of the template collapsed. */
function text(selector: string): string {
  return $(selector)!.textContent.replace(/\s+/g, ' ').trim();
}

function fill(values: Record<string, string>): void {
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
  const element = $<HTMLButtonElement>(selector);
  if (!element) throw new Error(`No ${selector}`);
  element.click();
  await settle();
}

const credentials = { email: 'grace@example.com', password: 'correct horse battery' };
const providers = (): SignInProvider[] => [new Password(), new Totp(), new EmailLink(), new Passkey()];

/** A server with passkeys that sign in on their own. */
function passkeyServer() {
  const server = fakeServer();
  server.passkey = { signIn: true, secondFactor: 'none' };
  server.methods['email-link'] = true;
  return server;
}

async function openDialog() {
  await Madauth.initialize({ serverUrl: SERVER, providers: providers() });
  const result = Madauth.signIn();
  await settle();
  return result;
}

describe('<madauth-login> and passkeys', () => {
  it('DP1: the sign-in view offers a passkey first; it signs in, and closing the browser dialog shows no error', async () => {
    const server = passkeyServer();
    server.passkeys.set('cred-1', { email: grace.email!, id: 'acc_1', name: 'Laptop' });
    const browser = stubWebAuthn({ outcome: 'cancel' });
    const result = openDialog();
    await settle();

    // A button above the password form, not a row under "Other ways to sign in".
    expect($('.buttons > :first-child')!.dataset.method).toBe('passkey');
    expect(text('[data-method="passkey"]')).toBe('Sign in with a passkey');
    expect($$('[data-method="passkey"] svg')).toHaveLength(2);
    expect($$('.others [data-method]').map((row) => row.dataset.method)).toEqual(['email-link']);
    await click('[data-method="passkey"]');
    expect($('.error')).toBeNull();
    expect(login().shadowRoot!.querySelector('dialog')!.open).toBe(true);

    browser.state.outcome = 'ok';
    await click('[data-method="passkey"]');
    expect(await result).toEqual({ isSuccess: true, user: grace });
  });

  it('DP2: with autofill, the e-mail field offers the passkeys; the wait ends with the view', async () => {
    passkeyServer();
    const browser = stubWebAuthn({ conditional: true });
    void openDialog();
    await settle();

    expect($<HTMLInputElement>('form.signin input[name="email"]')!.getAttribute('autocomplete')).toBe('username webauthn');
    const conditional = browser.credentials.get.mock.calls.find(([request]) => request.mediation === 'conditional');
    expect(conditional).toBeDefined();
    const signal = conditional![0].signal!;
    expect(signal.aborted).toBe(false);
    await click('[data-action="forgot"]');
    expect(signal.aborted).toBe(true);
  });

  it('DP3: the second step with a passkey, and the switch to the app', async () => {
    const server = passkeyServer();
    server.policy.password = 'optional';
    server.passkeys.set('cred-1', { email: grace.email!, id: 'acc_1', name: 'Laptop' });
    server.authenticators.add(grace.email!);
    stubWebAuthn({ id: 'cred-1' });
    const result = openDialog();
    await settle();

    fill(credentials);
    await submit('signin');
    expect(text('h2')).toBe('Confirm with your passkey');
    expect($('[data-action="use-app"]')).not.toBeNull();
    await click('[data-action="use-app"]');
    expect(text('h2')).toBe('Enter your code');
    await click('[data-action="use-passkey"]');
    await click('[data-action="verify-passkey"]');

    expect(await result).toEqual({ isSuccess: true, user: grace });
  });

  it('DP4: a required policy offers a passkey first in the setup, the app instead, and the passkey signs in', async () => {
    const server = passkeyServer();
    server.policy.password = 'required';
    stubWebAuthn({ id: 'cred-7' });
    const result = openDialog();
    await settle();

    fill(credentials);
    await submit('signin');
    expect(text('h2')).toBe('Create a passkey');
    expect(text('p.lead')).toContain('Signing in requires a second factor');
    await click('[data-action="use-app-setup"]');
    expect(text('h2')).toBe('Set up authenticator app');
    await click('[data-action="use-passkey-setup"]');
    fill({ name: 'Phone' });
    await submit('passkey-setup');

    expect(await result).toEqual({ isSuccess: true, user: grace });
    expect(server.passkeys.get('cred-7')).toMatchObject({ email: grace.email, name: 'Phone' });
  });

  it('DP5: Madauth.setUpPasskey() adds one for the signed-in user; long after signing in, the user signs in again first', async () => {
    const server = passkeyServer();
    server.user = grace;
    server.staleSignIn = true;
    stubWebAuthn({ id: 'cred-3' });
    await Madauth.initialize({ serverUrl: SERVER, providers: providers() });
    const result = Madauth.setUpPasskey();
    await settle();

    expect(text('h2')).toBe('Create a passkey');
    await submit('passkey-setup');
    expect($('.error')!.dataset.code).toBe('reauth_required');
    await click('[data-action="sign-in-again"]');
    expect(text('h2')).toBe('Sign in');
    server.staleSignIn = false;
    fill(credentials);
    await submit('signin');
    // Back to the passkey: the browser's dialog needs the user's click.
    expect(text('h2')).toBe('Create a passkey');
    await submit('passkey-setup');

    expect(await result).toEqual({ isSuccess: true, passkey: { id: 'acc_1', name: 'Passkey', createdAt: 1, lastUsedAt: 0 } });
  });

  it('DP5: the setup names the other methods that can ask for the passkey as in a sentence, not as their buttons', async () => {
    const server = passkeyServer();
    server.passkey = { signIn: true, secondFactor: 'optional' };
    server.policy.google = 'optional';
    server.policy.password = 'optional';
    server.user = grace;
    stubWebAuthn();
    await Madauth.initialize({ serverUrl: SERVER, providers: providers() });

    void Madauth.setUpPasskey();
    await settle();
    // The passkey's own sign-in asks for a second factor too, but not for itself.
    expect($$('p.hint').map((hint) => hint.textContent.replace(/\s+/g, ' ').trim())).toContain(
      'From then on, signing in with Google or a password can also ask for your passkey.',
    );
  });

  it('DP6: Madauth.manageSignInMethods() lists the methods, removes one, and adds a passkey and the e-mail link', async () => {
    const server = passkeyServer();
    server.user = grace;
    server.passkeys.set('cred-1', { email: grace.email!, id: 'acc_1', name: 'Laptop' });
    stubWebAuthn({ id: 'cred-2' });
    await Madauth.initialize({ serverUrl: SERVER, providers: providers() });
    const result = Madauth.manageSignInMethods();
    await settle();

    expect(text('h2')).toBe('Sign-in methods');
    expect($$('.method').map((li) => li.dataset.method)).toEqual(['password', 'passkey']);
    expect(text('.method[data-method="passkey"] .label')).toBe('Laptop');
    // The key and the fingerprint, as on the sign-in view's button.
    expect($$('.method[data-method="passkey"] .icons svg')).toHaveLength(2);
    expect($$('[data-add="passkey"] .icons svg')).toHaveLength(2);
    // A password is there already: it is not offered.
    expect($('[data-add="password"]')).toBeNull();

    await click('.method[data-method="passkey"] [data-action="remove"]');
    expect($$('.method').map((li) => li.dataset.method)).toEqual(['password']);
    expect(text('.notice')).toBe('Removed.');
    // The password is her last way in now: it has no button to remove it.
    expect($('.method[data-method="password"] [data-action="remove"]')).toBeNull();

    await click('[data-add="email-link"]');
    expect($$('.method').map((li) => li.dataset.method)).toEqual(['password', 'email-link']);
    expect($('[data-add="email-link"]')).toBeNull();

    await click('[data-add="passkey"]');
    expect(text('h2')).toBe('Create a passkey');
    await submit('passkey-setup');
    expect(text('h2')).toBe('Sign-in methods');
    expect(text('.notice')).toBe('Added.');
    expect($$('.method').map((li) => li.dataset.method)).toEqual(['password', 'email-link', 'passkey']);

    await click('[data-action="done"]');
    expect(await result).toEqual({ isSuccess: true });
  });

  it('DP7: a Google user adds a password from the list', async () => {
    const server = passkeyServer();
    server.user = { id: 'usr_ada', email: 'ada@example.com', name: 'Ada' };
    await Madauth.initialize({ serverUrl: SERVER, providers: providers() });
    void Madauth.manageSignInMethods();
    await settle();

    await click('[data-add="password"]');
    expect(text('h2')).toBe('Add a password');
    expect($<HTMLInputElement>('form.add-password input[name="username"]')!.value).toBe('ada@example.com');
    fill({ password: 'adas own password!' });
    await submit('add-password');

    expect(text('h2')).toBe('Sign-in methods');
    expect(server.accounts.get('ada@example.com')).toMatchObject({ password: 'adas own password!' });
  });

  it('DP8: the autofill starts over before the server\'s ceremony expires, and ends before a passkey button\'s request', async () => {
    passkeyServer();
    const browser = stubWebAuthn({ conditional: true });
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      await Madauth.initialize({ serverUrl: SERVER, providers: providers() });
      void Madauth.signIn();
      await vi.advanceTimersByTimeAsync(50);
      const conditional = () => browser.credentials.get.mock.calls.filter(([request]) => request.mediation === 'conditional').map(([request]) => request.signal!);
      expect(conditional()).toHaveLength(1);

      await vi.advanceTimersByTimeAsync(4 * 60_000 + 50);
      expect(conditional()).toHaveLength(2);
      expect(conditional()[0].aborted).toBe(true);
      expect(conditional()[1].aborted).toBe(false);

      // The passkey button waits for the autofill's request to end, so the browser takes the new one.
      browser.state.outcome = 'cancel';
      $<HTMLButtonElement>('[data-method="passkey"]')!.click();
      await vi.advanceTimersByTimeAsync(50);
      const explicit = browser.credentials.get.mock.calls.findIndex(([request]) => request.mediation !== 'conditional');
      expect(explicit).toBeGreaterThan(-1);
      expect(conditional()[1].aborted).toBe(true);
      // No autofill request starts while the button's runs.
      expect(browser.credentials.get.mock.calls.slice(0, explicit)).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('DP12: a passkey button sign-in closes the dialog without starting the autofill again', async () => {
    const server = passkeyServer();
    server.passkeys.set('cred-1', { email: grace.email!, id: 'acc_1', name: 'Laptop' });
    stubWebAuthn({ conditional: true });
    // Each start of the autofill asks the browser first.
    const starts = vi.spyOn(PublicKeyCredential, 'isConditionalMediationAvailable');
    const result = openDialog();
    await settle();
    expect(starts).toHaveBeenCalledOnce();

    await click('[data-method="passkey"]');
    expect(await result).toEqual({ isSuccess: true, user: grace });
    expect(starts).toHaveBeenCalledOnce();
  });

  it('DP11: an autofill that fails is not asked again until the view changes', async () => {
    const server = passkeyServer();
    stubWebAuthn({ conditional: true });
    await Madauth.initialize({ serverUrl: SERVER, providers: providers() });
    // The server switched passkeys off since initialize: the autofill's request fails.
    server.passkey = { signIn: false, secondFactor: 'none' };
    void Madauth.signIn();
    await settle();
    await settle();
    const asked = () => server.requests.filter((r) => r.path === '/auth/passkey/signin/options').length;

    expect(asked()).toBe(1);
    expect($('.error')!.dataset.code).toBe('method_disabled');
    await click('[data-action="forgot"]');
    await click('[data-action="back"]');
    expect(asked()).toBe(2);
  });

  it('DP9: a setup step that only a passkey can finish, in a browser without passkeys, says so', async () => {
    const server = passkeyServer();
    server.policy.password = 'required';
    const result = openDialog();
    await settle();
    // The server offers only a passkey to set up.
    server.methods.sms = false;
    const realFetch = fetch;
    vi.stubGlobal('fetch', async (input: string | URL, init?: RequestInit) => {
      const res = await realFetch(input, init);
      if (!String(input).endsWith('/auth/password/signin') || res.status !== 401) return res;
      const body = (await res.json()) as Record<string, unknown>;
      return new Response(JSON.stringify({ ...body, factors: ['passkey'] }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    });

    fill(credentials);
    await submit('signin');

    expect($('.error')!.dataset.code).toBe('passkey_unsupported');
    expect(text('h2')).toBe('Sign in');
    void result;
  });

  it('DP10: signing in again through the app\'s setup goes back to the methods, and manageSignInMethods() resolves only when the dialog closes', async () => {
    const server = passkeyServer();
    server.user = grace;
    server.staleSignIn = true;
    server.linked.set(grace.email!, new Set(['email-link']));
    // The next sign-in sets the app up first.
    server.policy.password = 'required';
    await Madauth.initialize({ serverUrl: SERVER, providers: providers() });
    let resolved = false;
    const result = Madauth.manageSignInMethods().then((r) => ((resolved = true), r));
    await settle();

    await click('.method[data-method="email-link"] [data-action="remove"]');
    expect($('.error')!.dataset.code).toBe('reauth_required');
    await click('[data-action="sign-in-again"]');
    server.staleSignIn = false;
    fill(credentials);
    await submit('signin');
    expect(text('h2')).toBe('Set up authenticator app');
    await settle();
    fill({ code: CODE });
    await submit('totp-setup');
    await click('[data-action="saved"]');

    expect(text('h2')).toBe('Sign-in methods');
    expect(resolved).toBe(false);
    await click('[data-action="done"]');
    expect(await result).toEqual({ isSuccess: true });
  });
});

describe('<madauth-login> and the sign-up with a passkey alone', () => {
  /** A server where people sign up with a passkey alone. */
  function signUpServer() {
    const server = passkeyServer();
    server.passkey = { signIn: true, signUp: true, secondFactor: 'none' };
    return server;
  }
  const newUser = { id: 'usr_new', email: 'new@example.com', name: 'New User' };

  it('DP13: "Create account" offers a passkey instead of a password: the address is confirmed, then the passkey is created and signs in', async () => {
    const server = signUpServer();
    stubWebAuthn({ id: 'cred-new' });
    const result = openDialog();
    const onSignedIn = vi.fn();
    await settle();
    login().addEventListener('madauth-signed-in', (e) => onSignedIn(e.detail));
    await click('[data-action="signup"]');
    expect($('form.signup input[name="password"]')).not.toBeNull();
    await click('[data-action="use-passkey-signup"]');

    expect(text('h2')).toBe('Create account');
    expect($('form.signup input[name="password"]')).toBeNull();
    expect(text('.hint')).toContain('You will create your passkey after confirming your email address.');
    expect($('[data-action="use-password-signup"]')).not.toBeNull();
    fill({ email: 'new@example.com', name: 'New User' });
    await submit('signup');
    expect(text('h2')).toBe('Check your inbox');
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/passkey/signup`, body: { email: 'new@example.com', name: 'New User' } });
    await click('[data-action="resend"]');
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/email/send-verification` });
    fill({ code: CODE });
    await submit('code');

    expect(text('h2')).toBe('Create a passkey');
    expect(text('p.lead')).toContain('Your email address is confirmed');
    // Only a passkey: no switch to another factor.
    expect($('[data-action="use-app-setup"]')).toBeNull();
    await submit('passkey-setup');

    expect(await result).toEqual({ isSuccess: true, user: newUser });
    expect(onSignedIn).toHaveBeenCalledWith({ method: 'passkey', user: newUser });
    expect(server.passkeys.get('cred-new')).toMatchObject({ email: 'new@example.com' });
  });

  it('DP14: without the password form, the sign-in view offers the sign-up with a passkey under the buttons', async () => {
    signUpServer();
    stubWebAuthn();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Passkey()] });
    void Madauth.signIn();
    await settle();

    await click('[data-action="signup"]');

    expect(text('h2')).toBe('Create account');
    expect($('form.signup input[name="password"]')).toBeNull();
    expect($('[data-action="use-password-signup"]')).toBeNull();
    // Only where the server lets people sign up with a passkey.
    resetAll();
    passkeyServer();
    stubWebAuthn();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Passkey()] });
    void Madauth.signIn();
    await settle();
    expect($('[data-action="signup"]')).toBeNull();
  });

  it('DP15: the link in the e-mail opens the dialog on the passkey; a policy that asks for a second factor sets it up next', async () => {
    const server = signUpServer();
    server.passkey = { signIn: true, signUp: true, secondFactor: 'required' };
    server.accounts.set('new@example.com', { password: '', verified: false, name: 'New User', passkey: true });
    server.mails.push({ purpose: 'verify', to: 'new@example.com', redirectTo: 'https://app.example.com/page' });
    stubWebAuthn({ id: 'cred-new' });
    history.replaceState(null, '', `/page#madauth_verify=${VERIFY_TOKEN}`);
    await Madauth.initialize({ serverUrl: SERVER, providers: providers() });
    await settle();

    expect(text('h2')).toBe('Create a passkey');
    expect(text('p.lead')).toContain('Your email address is confirmed');
    await submit('passkey-setup');

    expect(text('h2')).toBe('Set up authenticator app');
    expect(server.passkeys.get('cred-new')).toMatchObject({ email: 'new@example.com' });
  });
});
