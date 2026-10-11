import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { GoogleRedirect } from './providers/google-redirect.js';
import { Password } from './providers/password.js';
import type { SignInProvider } from './providers/provider.js';
import { Totp } from './providers/totp.js';
import { CODE, MASKED_PHONE, PHONE, SERVER, fakeServer, grace, resetAll, settle } from './test-helpers.js';

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
const sends = (server: ReturnType<typeof fakeServer>) => server.requests.filter((r) => r.path === '/auth/sms/send').length;

/** Opens the dialog; resolves to the pending signIn() result. */
async function openDialog(providers: SignInProvider[] = [new Password(), new Totp()]) {
  await Madauth.initialize({ serverUrl: SERVER, providers });
  const result = Madauth.signIn();
  await settle();
  return result;
}

/** A server with SMS codes on and Grace's phone added; password sign-in asks for a factor she has. */
function smsServer() {
  const server = fakeServer();
  server.methods.sms = true;
  server.policy.password = 'optional';
  server.phones.set(grace.email!, '+41791234567');
  return server;
}

describe('<madauth-login> and SMS codes', () => {
  it('D23: a user with only a phone gets the SMS step: one code is sent, and the code signs in', async () => {
    const server = smsServer();
    const onSignedIn = vi.fn();
    const result = openDialog();
    await settle();
    login().addEventListener('madauth-signed-in', (e) => onSignedIn(e.detail));

    fill(credentials);
    await submit('signin');

    expect(text('h2')).toBe('Enter the code from the SMS');
    expect(text('p.lead')).toBe(`Enter the code we sent to ${MASKED_PHONE} to finish signing in.`);
    expect(sends(server)).toBe(1);
    expect(server.texts).toEqual([{ to: '+41791234567', purpose: 'signin' }]);
    const field = $<HTMLInputElement>('form.sms-code input[name="code"]')!;
    expect(field.getAttribute('autocomplete')).toBe('one-time-code');
    expect(field.getAttribute('inputmode')).toBe('numeric');
    expect($('[data-action="use-app"]')).toBeNull();

    await click('[data-action="resend-sms"]');
    expect(sends(server)).toBe(2);
    expect(text('.notice[role="status"]')).toBe('We sent the code again.');
    server.smsTooSoon = true;
    await click('[data-action="resend-sms"]');
    expect(text('[part="error"]')).toBe('We sent a code less than a minute ago. Enter that one, or wait a minute for a new one.');

    fill({ code: '000000' });
    await submit('sms-code');
    expect($('[part="error"]')!.dataset.code).toBe('code_invalid');
    fill({ code: CODE });
    await submit('sms-code');

    expect(onSignedIn).toHaveBeenCalledWith({ method: 'password', user: grace });
    expect(await result).toEqual({ isSuccess: true, user: grace });
    expect($<HTMLDialogElement>('dialog')!.open).toBe(false);
  });

  it('D24: with the app and a phone, the app comes first and the user can switch to the SMS and back', async () => {
    const server = smsServer();
    server.authenticators.add(grace.email!);
    void openDialog();
    await settle();

    fill(credentials);
    await submit('signin');

    expect(text('h2')).toBe('Enter your code');
    expect(sends(server)).toBe(0);
    await click('[data-action="use-sms"]');
    expect(text('h2')).toBe('Enter the code from the SMS');
    expect(sends(server)).toBe(1);
    await click('[data-action="use-app"]');
    expect(text('h2')).toBe('Enter your code');
    expect(sends(server)).toBe(1);
    fill({ code: CODE });
    await submit('totp-code');
    expect(Madauth.currentUser).toEqual(grace);

    // Without a phone there is nothing to switch to.
    server.phones.clear();
    await Madauth.signOut();
    void openDialog();
    await settle();
    fill(credentials);
    await submit('signin');
    expect(text('h2')).toBe('Enter your code');
    expect($('[data-action="use-sms"]')).toBeNull();
  });

  it('D25: a required policy with neither factor offers the phone instead of the app, and the setup signs in', async () => {
    const server = smsServer();
    server.phones.clear();
    server.policy.password = 'required';
    const onSignedIn = vi.fn();
    const result = openDialog();
    await settle();
    login().addEventListener('madauth-signed-in', (e) => onSignedIn(e.detail));

    fill(credentials);
    await submit('signin');

    expect(text('h2')).toBe('Set up authenticator app');
    await click('[data-action="use-phone"]');
    expect(text('h2')).toBe('Add your phone number');
    expect(text('p.lead')).toContain('Signing in requires a second factor');
    const phone = $<HTMLInputElement>('form.sms-setup input[name="phone"]')!;
    expect(phone.getAttribute('type')).toBe('tel');
    expect(phone.getAttribute('autocomplete')).toBe('tel');
    // And back to the app, and to the phone again.
    await click('[data-action="use-app-setup"]');
    expect(text('h2')).toBe('Set up authenticator app');
    await click('[data-action="use-phone"]');
    fill({ phone: PHONE });
    await submit('sms-setup');

    expect(text('h2')).toBe('Add your phone number');
    expect(text('p.lead')).toBe(`Enter the code we sent to ${MASKED_PHONE}.`);
    expect(server.texts).toEqual([{ to: '+41791234567', purpose: 'setup' }]);
    fill({ code: CODE });
    await submit('sms-setup-code');

    expect(onSignedIn).toHaveBeenCalledWith({ method: 'password', user: grace });
    expect(await result).toEqual({ isSuccess: true, user: grace });
    expect($<HTMLDialogElement>('dialog')!.open).toBe(false);

    // Without SMS codes on, the app setup has no such link.
    server.methods.sms = false;
    server.phones.clear();
    await Madauth.signOut();
    void openDialog();
    await settle();
    fill(credentials);
    await submit('signin');
    expect(text('h2')).toBe('Set up authenticator app');
    expect($('[data-action="use-phone"]')).toBeNull();
  });

  it('D26: setUpSms() adds a phone for the signed-in user and resolves with the number', async () => {
    const server = smsServer();
    server.phones.clear();
    server.user = grace;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    const onEnabled = vi.fn();
    const onCancel = vi.fn();

    const result = Madauth.setUpSms();
    await settle();
    login().addEventListener('madauth-sms-enabled', (e) => onEnabled(e.detail));
    login().addEventListener('madauth-cancel', onCancel);

    expect(text('h2')).toBe('Add your phone number');
    expect(text('p.lead')).toBe('Enter your mobile number. We will send you a code to confirm it.');
    expect(text('p.hint')).toContain('signing in with E-mail & password can also ask for a code sent to your phone');
    expect($('[data-action="use-app-setup"]')).toBeNull();
    fill({ phone: 'nope' });
    await submit('sms-setup');
    expect(text('[part="error"]')).toBe('Please enter a valid mobile number with the country code, e.g. +41 79 123 45 67.');
    fill({ phone: PHONE });
    await submit('sms-setup');
    expect(text('p.lead')).toBe(`Enter the code we sent to ${MASKED_PHONE}.`);
    // The setup expired meanwhile: start again.
    server.smsSetup = undefined;
    fill({ code: CODE });
    await submit('sms-setup-code');
    expect($('[part="error"]')!.dataset.code).toBe('setup_expired');
    await click('[data-action="restart-sms-setup"]');
    expect(server.texts).toHaveLength(2);
    fill({ code: '000000' });
    await submit('sms-setup-code');
    expect($('[part="error"]')!.dataset.code).toBe('code_invalid');
    fill({ code: CODE });
    await submit('sms-setup-code');

    expect(await result).toEqual({ isSuccess: true, phone: MASKED_PHONE });
    expect(onEnabled).toHaveBeenCalledWith({ phone: MASKED_PHONE });
    expect(onCancel).not.toHaveBeenCalled();
    expect($<HTMLDialogElement>('dialog')!.open).toBe(false);
    expect(server.phones.get(grace.email!)).toBe('+41791234567');

    // Closing the dialog cancels; a session that ended fails it.
    const cancelled = Madauth.setUpSms();
    await settle();
    await click('[data-action="cancel"]');
    expect(await cancelled).toMatchObject({ isSuccess: false, error: { code: 'cancelled' } });
    server.user = null;
    const noSession = Madauth.setUpSms();
    await settle();
    fill({ phone: PHONE });
    await submit('sms-setup');
    expect(await noSession).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
    expect($('[part="error"]')!.dataset.code).toBe('no_session');
  });

  it('D27: replacing the number asks for a code sent to the current one first', async () => {
    const server = smsServer();
    server.user = grace;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });

    const result = Madauth.setUpSms();
    await settle();
    fill({ phone: '+41 79 000 00 99' });
    await submit('sms-setup');

    expect(text('h2')).toBe('Enter the code from the SMS');
    expect(text('p.lead')).toBe(`Enter the code we sent to ${MASKED_PHONE}, your current number, to replace it with a new one.`);
    expect(server.texts.at(-1)).toEqual({ to: '+41791234567', purpose: 'approve' });
    expect($('[data-action="use-app"]')).toBeNull();
    fill({ code: '000000' });
    await submit('sms-code');
    expect($('[part="error"]')!.dataset.code).toBe('code_invalid');
    fill({ code: CODE });
    await submit('sms-code');
    expect(text('p.lead')).toBe('Enter the code we sent to +41 ••••••• 99.');
    expect(server.texts.at(-1)).toEqual({ to: '+41790000099', purpose: 'setup' });
    fill({ code: CODE });
    await submit('sms-setup-code');

    expect(await result).toEqual({ isSuccess: true, phone: '+41 ••••••• 99' });
    expect(server.phones.get(grace.email!)).toBe('+41790000099');
  });

  it('D29: a sign-up with the app sets the app up, never a phone: its setup has no phone link', async () => {
    const server = smsServer();
    server.methods.totp = true;
    void openDialog();
    await settle();
    await click('[data-method="totp"]');
    await click('[data-action="signup"]');
    fill({ email: 'new@example.com', name: 'New User' });
    await submit('signup');
    fill({ code: CODE });
    await submit('code');

    expect(text('h2')).toBe('Set up authenticator app');
    expect($('[data-action="use-phone"]')).toBeNull();
  });

  it('D28: an expired step and the redirect flow with the SMS step', async () => {
    const server = smsServer();
    void openDialog();
    await settle();
    fill(credentials);
    await submit('signin');
    expect(text('h2')).toBe('Enter the code from the SMS');
    server.challenge = undefined;
    fill({ code: CODE });
    await submit('sms-code');
    expect(text('h2')).toBe('Sign in');
    expect($('[part="error"]')!.dataset.code).toBe('challenge_expired');
    login().remove();

    // Back from the redirect flow with the first step done, the SMS next.
    server.codeFlow = true;
    server.challenge = { email: 'ada@example.com', next: 'sms', method: 'google', factors: ['sms'] };
    server.phones.set('ada@example.com', '+41791234567');
    history.replaceState(null, '', '/page?x=1#madauth_next=sms&madauth_factors=sms');
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleRedirect()] });
    await settle();
    expect(location.href).toBe('https://app.example.com/page?x=1');
    expect(text('h2')).toBe('Enter the code from the SMS');
    expect(sends(server)).toBe(2);
    fill({ code: CODE });
    await submit('sms-code');
    expect(Madauth.currentUser).toMatchObject({ email: 'ada@example.com' });
  });
});
