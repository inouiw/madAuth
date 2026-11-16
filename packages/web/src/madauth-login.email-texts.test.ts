import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth, type EmailTexts } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { EmailLink } from './providers/email-link.js';
import { Password } from './providers/password.js';
import { CODE, SERVER, fakeServer, resetAll, settle } from './test-helpers.js';

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

async function openDialog(emailTexts?: EmailTexts, locale?: string) {
  await Madauth.initialize({ serverUrl: SERVER, providers: [new Password(), new EmailLink()], emailTexts, locale });
  const result = Madauth.showSignInDialog();
  await settle();
  return result;
}

describe("<madauth-login> with emailTexts: 'code-only'", () => {
  it('asks for the code of a confirmation e-mail without mentioning a link', async () => {
    fakeServer();
    const result = openDialog('code-only');
    await settle();
    await click('[data-action="signup"]');
    fill({ email: 'new@example.com', password: 'long enough' });
    await submit('signup');

    expect(text('h2')).toBe('Check your inbox');
    expect(text('p.lead')).toBe('We sent an email to new@example.com. Enter the 6-digit code from the email.');
    fill({ code: CODE });
    await submit('code');
    expect(await result).toMatchObject({ isSuccess: true, user: { email: 'new@example.com' } });
  });

  it('tells an unconfirmed address to enter the code', async () => {
    const server = fakeServer();
    server.accounts.set('new@example.com', { password: 'long enough', verified: false });
    void openDialog('code-only');
    await settle();
    fill({ email: 'new@example.com', password: 'long enough' });
    await submit('signin');

    expect($('[part="error"]')!.dataset.code).toBe('email_unverified');
    expect($('[part="error"]')!.textContent).toContain('Please confirm your email address first: enter the code from the email we sent you.');
  });

  it('calls the e-mail sign-in "Email code" and asks for its code', async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    void openDialog('code-only');
    await settle();

    expect(text('[data-method="email-link"]')).toBe('Email code');
    await click('[data-method="email-link"]');
    expect(text('h2')).toBe('Sign in with an email code');
    expect(text('p.lead')).toBe('We’ll email you a code to sign in. New here? The code creates your account.');
    expect(text('p.hint')).toBe('Keep this window open: you enter the code here.');
    expect(text('form.email-link .submit')).toBe('Send code');
    fill({ email: 'linda@example.com' });
    await submit('email-link');

    expect(text('p.lead')).toBe('We sent an email to linda@example.com. Enter the 6-digit code from the email to sign in.');
    server.locked = true;
    fill({ code: CODE });
    await submit('code');
    expect($('[part="error"]')!.dataset.code).toBe('codes_locked');
    expect($('[part="error"]')!.textContent).toContain('codes are paused for a while');
    expect($('[part="error"]')!.textContent).not.toContain('link');
  });

  it('keeps the link in the password reset texts, whose e-mail still has it', async () => {
    fakeServer();
    void openDialog('code-only');
    await settle();
    await click('[data-action="forgot"]');
    expect(text('p.lead')).toBe('Enter your email address. We will send you a link and a code to choose a new password.');
    fill({ email: 'grace@example.com' });
    await submit('forgot');

    expect(text('p.lead')).toBe('We sent an email to grace@example.com. Open the link in it, or enter the 6-digit code from the email.');
  });

  it('points to the reset link when the reset codes are locked', async () => {
    const server = fakeServer();
    void openDialog('code-only');
    await settle();
    await click('[data-action="forgot"]');
    fill({ email: 'grace@example.com' });
    await submit('forgot');
    server.locked = true;
    fill({ code: CODE });
    await submit('code');
    fill({ password: 'brand new password' });
    await submit('reset');

    expect($('[part="error"]')!.dataset.code).toBe('codes_locked');
    expect($('[part="error"]')!.textContent).toContain('Please use the link in the email to choose a new password.');
  });

  it('has the code-only texts in German', async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    void openDialog('code-only', 'de');
    await settle();

    expect(text('[data-method="email-link"]')).toBe('E-Mail-Code');
    await click('[data-method="email-link"]');
    expect(text('h2')).toBe('Mit E-Mail-Code anmelden');
    fill({ email: 'linda@example.com' });
    await submit('email-link');
    expect(text('p.lead')).toBe(
      'Wir haben eine E-Mail an linda@example.com gesendet. Geben Sie den 6-stelligen Bestätigungscode aus der E-Mail ein, um sich anzumelden.',
    );
  });

  it("mentions the link without the option, and with 'link-and-code'", async () => {
    const server = fakeServer();
    server.methods['email-link'] = true;
    for (const emailTexts of [undefined, 'link-and-code'] as const) {
      void openDialog(emailTexts);
      await settle();
      expect(text('[data-method="email-link"]')).toBe('Email link');
      await click('[data-method="email-link"]');
      fill({ email: 'linda@example.com' });
      await submit('email-link');
      expect(text('p.lead')).toContain('Open the link in it to sign in');
      login().close();
    }
  });

  it('refuses an unknown value', async () => {
    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()], emailTexts: 'code' as EmailTexts });

    expect(result).toMatchObject({ isSuccess: false, error: { code: 'invalid_options' } });
    expect(result.isSuccess || result.error.message).toContain("emailTexts must be 'link-and-code' or 'code-only'");
  });
});
