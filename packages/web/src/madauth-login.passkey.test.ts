import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { EmailLink } from './providers/email-link.js';
import { Passkey } from './providers/passkey.js';
import { Password } from './providers/password.js';
import type { SignInProvider } from './providers/provider.js';
import { Totp } from './providers/totp.js';
import { CODE, SERVER, fakeServer, grace, resetAll, settle, stubWebAuthn } from './test-helpers.js';

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
  it('DP1: the sign-in view offers a passkey; it signs in, and closing the browser dialog shows no error', async () => {
    const server = passkeyServer();
    server.passkeys.set('cred-1', { email: grace.email!, id: 'acc_1', name: 'Laptop' });
    const browser = stubWebAuthn({ outcome: 'cancel' });
    const result = openDialog();
    await settle();

    expect($('[data-method="passkey"]')!.textContent).toContain('Passkey');
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
