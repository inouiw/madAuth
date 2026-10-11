import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { EmailLink } from './providers/email-link.js';
import { Password } from './providers/password.js';
import type { SignInProvider } from './providers/provider.js';
import { CODE, SERVER, SIGNIN_TOKEN, fakeServer, resetAll, settle } from './test-helpers.js';

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

const linda = { id: 'usr_linda', email: 'linda@example.com' };

/** Opens the dialog; resolves to the pending signIn() result. */
async function openDialog(providers: SignInProvider[] = [new Password(), new EmailLink()]) {
  await Madauth.initialize({ serverUrl: SERVER, providers });
  const result = Madauth.signIn();
  await settle();
  return result;
}

describe('<madauth-login> and the e-mail link', () => {
  it('D18: lists the e-mail link only with its provider and the server offering it', async () => {
    const server = fakeServer();
    void openDialog();
    await settle();
    expect($('[data-method="email-link"]')).toBeNull();

    server.methods['email-link'] = true;
    void openDialog([new Password()]);
    await settle();
    expect($('[data-method="email-link"]')).toBeNull();

    void openDialog();
    await settle();
    expect(text('[data-method="email-link"]')).toBe('Email link');
    expect(text('.others h3')).toBe('Other ways to sign in');
  });

  it('D19: sends the link, shows the inbox view, sends again, and signs in with the code', async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    const onSignedIn = vi.fn();
    const result = openDialog();
    await settle();
    login().addEventListener('madauth-signed-in', (e) => onSignedIn(e.detail));

    await click('[data-method="email-link"]');
    expect(text('h2')).toBe('Sign in with an email link');
    expect($('form.email-link input[name="email"]')).not.toBeNull();
    // `email`, not `username`: without a password, password managers have nothing to fill.
    expect($('form.email-link input[name="email"]')!.getAttribute('autocomplete')).toBe('email');
    // A new user learns that the link makes the account, and everyone what the code is for.
    expect(text('p.lead')).toBe('We’ll email you a link to sign in. New here? The link creates your account.');
    expect(text('p.hint')).toBe('The email also has a code, for when you open it on another device.');
    // The row that led here is gone: the focus moved to the address field, not to the page behind.
    expect(login().shadowRoot!.activeElement).toBe($('form.email-link input[name="email"]'));
    fill({ email: linda.email });
    await submit('email-link');

    expect(text('h2')).toBe('Check your inbox');
    expect(text('p.lead')).toBe(`We sent an email to ${linda.email}. Open the link in it to sign in, or enter the 6-digit code from the email.`);
    expect(server.mails.at(-1)).toMatchObject({ purpose: 'signin', to: linda.email });
    await click('[data-action="resend"]');
    expect(server.mails.filter((m) => m.purpose === 'signin')).toHaveLength(2);
    expect(text('.notice[role="status"]')).toBe('We sent the email again.');

    fill({ code: '000000' });
    await submit('code');
    expect($('[part="error"]')!.dataset.code).toBe('code_invalid');
    expect(text('h2')).toBe('Check your inbox');
    fill({ code: CODE });
    await submit('code');

    expect(onSignedIn).toHaveBeenCalledWith({ method: 'email-link', user: linda });
    expect(await result).toEqual({ isSuccess: true, user: linda });
    expect($<HTMLDialogElement>('dialog')!.open).toBe(false);
  });

  it('D20: shows what went wrong on the e-mail link view, and keeps the address on the way back', async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    void openDialog();
    await settle();
    await click('[data-method="email-link"]');

    server.rejectSignUp = 'Invited users only.';
    fill({ email: 'new@example.com' });
    await submit('email-link');
    expect(text('[part="error"]')).toBe('Invited users only.');
    server.rejectSignUp = undefined;
    server.emailsDown = true;
    await submit('email-link');
    expect(text('[part="error"]')).toBe('Sending emails is not available right now. Please try again later.');
    server.emailsDown = false;
    await submit('email-link');
    expect(text('h2')).toBe('Check your inbox');
    server.locked = true;
    fill({ code: CODE });
    await submit('code');
    expect(text('[part="error"]')).toBe('Too many wrong codes. Please ask for a new email and use the link in it.');

    await click('[data-action="back"]');
    expect(text('h2')).toBe('Sign in');
    expect($<HTMLInputElement>('form.signin input[name="email"]')!.value).toBe('new@example.com');
  });

  it('D21: opened from the link with a policy, the dialog goes on with the authenticator app by itself', async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    server.policy['email-link'] = 'optional';
    server.accounts.set(linda.email, { password: '', verified: true, link: true });
    server.mails.push({ purpose: 'signin', to: linda.email, redirectTo: 'x' });
    server.authenticators.add(linda.email);
    history.replaceState(null, '', `/page#madauth_signin=${SIGNIN_TOKEN}`);

    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password(), new EmailLink()] });
    await settle();

    expect(text('h2')).toBe('Enter your code');
    expect(Madauth.currentUser).toBeNull();
    fill({ code: CODE });
    await submit('totp-code');
    expect(Madauth.currentUser).toEqual(linda);
    expect($<HTMLDialogElement>('dialog')!.open).toBe(false);
  });
});
