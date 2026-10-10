import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { GoogleFedcm } from './providers/google-fedcm.js';
import { GoogleRedirect } from './providers/google-redirect.js';
import { Password } from './providers/password.js';
import type { SignInProvider } from './providers/provider.js';
import { Totp } from './providers/totp.js';
import { CODE, RECOVERY_CODES, SERVER, ada, fakeGis, fakeServer, grace, resetAll, settle } from './test-helpers.js';

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

function $$(selector: string): Element[] {
  return [...login().shadowRoot!.querySelectorAll(selector)];
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
  $<HTMLButtonElement>(selector)!.click();
  await settle();
}

const credentials = { email: 'grace@example.com', password: 'correct horse battery' };

/** Opens the dialog; resolves to the pending signIn() result. */
async function openDialog(providers: SignInProvider[] = [new Password(), new Totp()]) {
  await Madauth.initialize({ serverUrl: SERVER, providers });
  const result = Madauth.signIn();
  await settle();
  return result;
}

describe('<madauth-login> and the authenticator app on its own', () => {
  it('D8: lists the app only when it signs in on its own, and shows its form', async () => {
    const server = fakeServer();
    server.policy.password = 'optional';
    // With the provider, but the app as a second factor only: not a way to sign in.
    void openDialog();
    await settle();
    expect($('[data-method="totp"]')).toBeNull();
    login().close();
    // Without the provider: coming soon, as for every method without one.
    void openDialog([new Password()]);
    await settle();
    await click('[data-method="totp"]');
    expect($('.notice')!.textContent).toContain('coming soon');
    login().close();
    await settle();

    server.methods.totp = true;
    void openDialog();
    await settle();
    fill({ email: 'grace@example.com' });
    await click('[data-method="totp"]');

    expect(text('h2')).toBe('Authenticator app');
    expect($<HTMLInputElement>('form.totp input[name="email"]')!.value).toBe('grace@example.com');
    const code = $<HTMLInputElement>('form.totp input[name="code"]')!;
    expect(code.getAttribute('autocomplete')).toBe('one-time-code');
    expect(code.getAttribute('inputmode')).toBe('numeric');
    expect(text('form.totp .hint')).toBe('Enter the 6-digit code from your authenticator app.');
    expect(text('form.totp .submit')).toBe('Sign in');
    await click('[data-action="toggle-recovery"]');
    expect($('form.totp input[name="recoveryCode"]')).not.toBeNull();
    expect($('form.totp input[name="code"]')).toBeNull();
    expect(text('[data-action="toggle-recovery"]')).toBe('Use the authenticator app instead');
    await click('[data-action="back"]');
    expect(text('h2')).toBe('Sign in');
    expect($<HTMLInputElement>('form.signin input[name="email"]')!.value).toBe('grace@example.com');
  });

  it('D9: signs in with the e-mail address and the code, and shows the errors', async () => {
    const server = fakeServer();
    server.methods.totp = true;
    server.authenticators.add('grace@example.com');
    server.recoveryCodes.set('grace@example.com', [...RECOVERY_CODES]);
    const result = openDialog();
    const onSignedIn = vi.fn();
    await settle();
    login().addEventListener('madauth-signed-in', (e) => onSignedIn(e.detail));
    await click('[data-method="totp"]');

    fill({ email: 'grace@example.com', code: '000000' });
    await submit('totp');
    expect($('[part="error"]')!.dataset.code).toBe('invalid_credentials');
    expect(text('[part="error"]')).toContain('E-mail or code is wrong. To sign in with an authenticator app, set it up first');
    expect($<HTMLDialogElement>('dialog')!.open).toBe(true);
    server.locked = true;
    await submit('totp');
    expect(text('[part="error"]')).toContain('Try again in 30 seconds');
    server.locked = false;

    fill({ email: 'grace@example.com', code: '123 456' });
    await submit('totp');

    expect(await result).toEqual({ isSuccess: true, user: grace });
    expect(onSignedIn).toHaveBeenCalledWith({ method: 'totp', user: grace });
    expect($<HTMLDialogElement>('dialog')!.open).toBe(false);
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/totp/signin`, body: { email: 'grace@example.com', code: CODE } });

    // A recovery code, next time.
    const again = Madauth.signIn();
    await settle();
    await click('[data-method="totp"]');
    await click('[data-action="toggle-recovery"]');
    fill({ email: 'grace@example.com', recoveryCode: RECOVERY_CODES[0] });
    await submit('totp');
    expect(await again).toEqual({ isSuccess: true, user: grace });
  });

  it('D15: creates an account with the app alone: the address is confirmed, the app set up, the codes shown', async () => {
    const server = fakeServer();
    server.methods.totp = true;
    const result = openDialog();
    const onSignedIn = vi.fn();
    await settle();
    login().addEventListener('madauth-signed-in', (e) => onSignedIn(e.detail));
    await click('[data-method="totp"]');
    await click('[data-action="signup"]');

    expect(text('h2')).toBe('Create account');
    expect($('form.signup input[name="password"]')).toBeNull();
    expect(text('.hint')).toBe('You will set up your authenticator app after confirming your e-mail address.');
    fill({ email: 'new@example.com', name: 'New User' });
    await submit('signup');
    expect(text('h2')).toBe('Check your inbox');
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/totp/signup`, body: { email: 'new@example.com', name: 'New User' } });
    await click('[data-action="resend"]');
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/email/send-verification` });
    fill({ code: CODE });
    await submit('code');

    expect(text('h2')).toBe('Set up authenticator app');
    expect(text('.lead')).toContain('Signing in requires an authenticator app');
    expect($('[part="qr"]')).not.toBeNull();
    fill({ code: CODE });
    await submit('totp-setup');
    expect(text('h2')).toBe('Save your recovery codes');
    expect($$('[part="codes"] li').map((li) => li.textContent!.trim())).toEqual(RECOVERY_CODES);
    await click('[data-action="saved"]');

    const user = { id: 'usr_new', email: 'new@example.com', name: 'New User' };
    expect(await result).toEqual({ isSuccess: true, user });
    expect(onSignedIn).toHaveBeenCalledWith({ method: 'totp', user });
    expect($<HTMLDialogElement>('dialog')!.open).toBe(false);
  });
});

describe('<madauth-login> and the second step', () => {
  it('D10: a password sign-in goes on with the code from the app, or a recovery code', async () => {
    const server = fakeServer();
    server.policy.password = 'optional';
    server.authenticators.add('grace@example.com');
    server.recoveryCodes.set('grace@example.com', [...RECOVERY_CODES]);
    const result = openDialog();
    const onSignedIn = vi.fn();
    await settle();
    login().addEventListener('madauth-signed-in', (e) => onSignedIn(e.detail));

    fill(credentials);
    await submit('signin');

    expect(text('h2')).toBe('Enter your code');
    expect(text('.lead')).toBe('Enter the code from your authenticator app to finish signing in.');
    expect($('[part="error"]')).toBeNull();
    expect(Madauth.currentUser).toBeNull();
    fill({ code: '000000' });
    await submit('totp-code');
    expect($('[part="error"]')!.dataset.code).toBe('code_invalid');
    expect($<HTMLDialogElement>('dialog')!.open).toBe(true);
    await click('[data-action="toggle-recovery"]');
    fill({ recoveryCode: RECOVERY_CODES[2] });
    await submit('totp-code');

    expect(await result).toEqual({ isSuccess: true, user: grace });
    expect(onSignedIn).toHaveBeenCalledWith({ method: 'password', user: grace });
    expect($<HTMLDialogElement>('dialog')!.open).toBe(false);

    // The sign-in expired meanwhile: back to the start, with the reason.
    void Madauth.signIn();
    await settle();
    fill(credentials);
    await submit('signin');
    server.challenge = undefined;
    fill({ code: CODE });
    await submit('totp-code');
    expect(text('h2')).toBe('Sign in');
    expect($('[part="error"]')!.dataset.code).toBe('challenge_expired');
    expect(text('[part="error"]')).toBe('The sign-in took too long. Please sign in again.');
  });

  it('D11: a required policy makes the sign-in set the app up first, with the QR code and the recovery codes', async () => {
    const server = fakeServer();
    server.policy.password = 'required';
    const result = openDialog();
    const onSignedIn = vi.fn();
    await settle();
    login().addEventListener('madauth-signed-in', (e) => onSignedIn(e.detail));

    fill(credentials);
    await submit('signin');

    expect(text('h2')).toBe('Set up authenticator app');
    expect(text('.lead')).toContain('Signing in requires an authenticator app');
    const qr = $<SVGElement>('[part="qr"]')!;
    expect(qr.tagName.toLowerCase()).toBe('svg');
    expect(qr.querySelector('path')!.getAttribute('d')).toMatch(/^M0 0h1v1h-1z/);
    expect(qr.getAttribute('aria-label')).toBe('QR code for your authenticator app');
    expect(text('.secret')).toBe('JBSW Y3DP EHPK 3PXP');
    expect(login().shadowRoot!.activeElement).toBe($('form.totp-setup input[name="code"]'));
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/totp/setup` });

    fill({ code: '000000' });
    await submit('totp-setup');
    expect($('[part="error"]')!.dataset.code).toBe('code_invalid');
    expect($('[part="qr"]')).not.toBeNull();
    fill({ code: CODE });
    await submit('totp-setup');

    expect(text('h2')).toBe('Save your recovery codes');
    expect($$('[part="codes"] li')).toHaveLength(10);
    expect(onSignedIn).not.toHaveBeenCalled();
    await click('[data-action="saved"]');
    expect(await result).toEqual({ isSuccess: true, user: grace });
    expect(onSignedIn).toHaveBeenCalledWith({ method: 'password', user: grace });
    expect($<HTMLDialogElement>('dialog')!.open).toBe(false);
  });

  it('D16: Google asks for the code too, through the button, One Tap, and the redirect flow', async () => {
    const server = fakeServer();
    server.policy.google = 'optional';
    server.authenticators.add('ada@example.com');
    const gis = fakeGis();
    const result = openDialog([new GoogleFedcm({ autoPrompt: false }), new Totp()]);
    await settle();

    gis.signIn();
    await settle();

    expect(text('h2')).toBe('Enter your code');
    fill({ code: CODE });
    await submit('totp-code');
    expect(await result).toEqual({ isSuccess: true, user: ada });

    // One Tap, outside the dialog: the dialog opens by itself on the code step.
    await Madauth.signOut();
    login().remove();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm(), new Totp()] });
    await settle();
    gis.signIn();
    await settle();
    expect(document.querySelector('madauth-login')).not.toBeNull();
    expect($<HTMLDialogElement>('dialog')!.open).toBe(true);
    expect(text('h2')).toBe('Enter your code');
    fill({ code: CODE });
    await submit('totp-code');
    expect(Madauth.currentUser).toEqual(ada);

    // Back from the redirect flow with the first step done.
    await Madauth.signOut();
    login().remove();
    server.codeFlow = true;
    server.challenge = { email: 'ada@example.com', next: 'totp', method: 'google' };
    history.replaceState(null, '', '/page?x=1#madauth_next=totp');
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect(), new Totp()] });
    await settle();
    expect(location.href).toBe('https://app.example.com/page?x=1');
    expect($<HTMLDialogElement>('dialog')!.open).toBe(true);
    expect(text('h2')).toBe('Enter your code');
    fill({ code: CODE });
    await submit('totp-code');
    expect(Madauth.currentUser).toEqual(ada);
  });
});

describe('Madauth.setUpAuthenticator', () => {
  it('D12: shows the QR code and the key, turns the app on with the first code, and shows the recovery codes once', async () => {
    const server = fakeServer();
    server.policy.password = 'optional';
    server.user = grace;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password(), new Totp()] });
    const onEnabled = vi.fn();
    const onCancel = vi.fn();

    const result = Madauth.setUpAuthenticator();
    await settle();
    login().addEventListener('madauth-authenticator-enabled', (e) => onEnabled(e.detail));
    login().addEventListener('madauth-cancel', onCancel);

    expect($<HTMLDialogElement>('dialog')!.open).toBe(true);
    expect(text('h2')).toBe('Set up authenticator app');
    expect(text('.lead')).toBe('Scan this QR code with your authenticator app (e.g. Google Authenticator or 1Password), then enter the code it shows.');
    expect(text('.hint')).toBe('From then on, signing in with E-mail & password also asks for a code from the app.');
    expect($('[part="qr"] path')).not.toBeNull();
    expect(text('.secret')).toBe('JBSW Y3DP EHPK 3PXP');
    expect(server.requests.at(-1)).toMatchObject({ url: `${SERVER}/auth/totp/setup` });

    fill({ code: '000000' });
    await submit('totp-setup');
    expect($('[part="error"]')!.dataset.code).toBe('code_invalid');
    expect($('[part="qr"]')).not.toBeNull();
    // The setup expired: the key is gone, and "Start again" gets a new one.
    server.totpSetup = undefined;
    fill({ code: CODE });
    await submit('totp-setup');
    expect($('[part="error"]')!.dataset.code).toBe('setup_expired');
    expect($('[part="qr"]')).toBeNull();
    await click('[data-action="restart-setup"]');
    expect($('[part="error"]')).toBeNull();
    expect($('[part="qr"]')).not.toBeNull();

    fill({ code: CODE });
    await submit('totp-setup');
    expect(text('h2')).toBe('Save your recovery codes');
    expect($$('[part="codes"] li').map((li) => li.textContent!.trim())).toEqual(RECOVERY_CODES);
    await click('[data-action="saved"]');

    expect(await result).toEqual({ isSuccess: true, recoveryCodes: RECOVERY_CODES });
    expect(onEnabled).toHaveBeenCalledWith({ recoveryCodes: RECOVERY_CODES });
    expect(onCancel).not.toHaveBeenCalled();
    expect($<HTMLDialogElement>('dialog')!.open).toBe(false);
    expect(server.authenticators.has('grace@example.com')).toBe(true);
  });

  it('D12: closing the recovery codes counts as having seen them; the app is on either way', async () => {
    const server = fakeServer();
    server.policy.password = 'optional';
    server.methods.totp = true;
    server.user = grace;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password(), new Totp()] });

    const result = Madauth.setUpAuthenticator();
    await settle();
    expect(text('.hint')).toBe('From then on, signing in with E-mail & password also asks for a code from the app.');
    expect($$('.hint')[1].textContent!.trim()).toBe('You can then sign in with your e-mail address and a code from the app.');
    fill({ code: CODE });
    await submit('totp-setup');
    await click('.close');

    expect(await result).toEqual({ isSuccess: true, recoveryCodes: RECOVERY_CODES });
    // A later sign-in starts clean.
    void Madauth.signIn();
    await settle();
    expect(text('h2')).toBe('Sign in');
    expect($('[part="qr"]')).toBeNull();
    expect($('[part="error"]')).toBeNull();
  });

  it('D13: is cancelled by the link, the cross and the backdrop, and refuses when it can not open', async () => {
    const server = fakeServer();
    server.policy.password = 'optional';
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password(), new Totp()] });
    expect(await Madauth.setUpAuthenticator()).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
    expect(document.querySelector('madauth-login')).toBeNull();

    server.user = grace;
    await Madauth.getSession();
    const cancelled = Madauth.setUpAuthenticator();
    await settle();
    await click('[data-action="cancel"]');
    expect(await cancelled).toMatchObject({ isSuccess: false, error: { code: 'cancelled' } });
    const crossed = Madauth.setUpAuthenticator();
    await settle();
    await click('.close');
    expect(await crossed).toMatchObject({ isSuccess: false, error: { code: 'cancelled' } });

    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password(), new Totp()], ui: 'custom' });
    expect(await Madauth.setUpAuthenticator()).toMatchObject({ isSuccess: false, error: { code: 'invalid_options', message: expect.stringContaining('startSetup') } });
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    expect(await Madauth.setUpAuthenticator()).toMatchObject({ isSuccess: false, error: { code: 'flow_not_enabled' } });
  });

  it('D14: a session that ended meanwhile is reported in the dialog', async () => {
    const server = fakeServer();
    server.policy.password = 'optional';
    server.user = grace;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password(), new Totp()] });
    server.user = null;

    void Madauth.setUpAuthenticator();
    await settle();

    expect($('[part="error"]')!.dataset.code).toBe('no_session');
    expect(text('[part="error"]')).toBe('You are not signed in. Please sign in first.');
    expect($('[part="qr"]')).toBeNull();
  });
});
