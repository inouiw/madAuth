import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth, type MadauthOptions } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { Password } from './providers/password.js';
import { Totp } from './providers/totp.js';
import { CODE, RESET_TOKEN, SERVER, fakeServer, grace, resetAll, settle } from './test-helpers.js';

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

/** The text of an element, with the whitespace of the template collapsed. */
function text(selector: string): string {
  return $(selector)!.textContent.replace(/\s+/g, ' ').trim();
}

function fill(values: Record<string, string>): void {
  for (const [name, value] of Object.entries(values)) $<HTMLInputElement>(`form input[name="${name}"]`)!.value = value;
}

async function submit(form: string): Promise<void> {
  $<HTMLFormElement>(`form.${form}`)!.requestSubmit();
  await settle();
}

async function click(selector: string): Promise<void> {
  $<HTMLButtonElement>(selector)!.click();
  await settle();
}

/** Opens the dialog with the password provider. */
async function openDialog(options: Partial<MadauthOptions> = {}): Promise<void> {
  await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()], ...options });
  void Madauth.signIn();
  await settle();
}

function browserLanguage(language: string): void {
  vi.spyOn(navigator, 'language', 'get').mockReturnValue(language);
}

describe('the language of <madauth-login>', () => {
  it('is the locale option, by its primary subtag', async () => {
    fakeServer();

    await openDialog({ locale: 'de-CH' });

    expect(text('h2')).toBe('Anmelden');
    expect($('dialog')!.getAttribute('lang')).toBe('de');
  });

  it('is the page’s language without the option', async () => {
    fakeServer();
    document.documentElement.lang = 'de';
    browserLanguage('en-US');

    await openDialog();

    expect(text('h2')).toBe('Anmelden');
  });

  it('is the browser’s language when the page has none', async () => {
    fakeServer();
    browserLanguage('de-DE');

    await openDialog();

    expect(text('h2')).toBe('Anmelden');
  });

  it('prefers the option to the page’s language', async () => {
    fakeServer();
    document.documentElement.lang = 'de';
    browserLanguage('de-DE');

    await openDialog({ locale: 'en' });

    expect(text('h2')).toBe('Sign in');
    expect($('dialog')!.getAttribute('lang')).toBe('en');
  });

  it('is English for a language without texts', async () => {
    fakeServer();
    browserLanguage('de-DE');

    await openDialog({ locale: 'fr' });

    expect(text('h2')).toBe('Sign in');
  });

  it('applies before madAuth is initialized', async () => {
    document.documentElement.lang = 'de';
    const element = document.createElement('madauth-login');
    document.body.append(element);

    await element.open();

    expect(text('[part="error"]')).toBe('Die Anmeldung ist auf dieser Seite nicht eingerichtet.');
  });

  it('rejects a locale that is not a string', async () => {
    fakeServer();

    // @ts-expect-error: not a language tag
    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [], locale: 5 });

    expect(result).toMatchObject({ isSuccess: false, error: { code: 'invalid_options', message: expect.stringContaining('locale') } });
  });
});

describe('<madauth-login> in German', () => {
  it('shows the sign-in view', async () => {
    fakeServer();
    await openDialog({ locale: 'de' });

    expect(text('h2')).toBe('Anmelden');
    expect($('.close')!.getAttribute('aria-label')).toBe('Schließen');
    expect(text('.google .label')).toBe('Weiter mit Google');
    expect(text('.divider')).toBe('oder');
    expect(text('label[for="email"]')).toBe('E-Mail-Adresse');
    expect(text('label[for="password"]')).toBe('Passwort');
    expect(text('form.signin .submit')).toBe('Anmelden');
    expect(text('[data-action="forgot"]')).toBe('Passwort vergessen?');
    expect(text('[data-action="signup"]')).toBe('Konto erstellen');
    expect(text('.others h3')).toBe('Weitere Anmeldemöglichkeiten');
    expect([...login().shadowRoot!.querySelectorAll('.row .label')].map((label) => label.textContent)).toEqual([
      'Authentifizierungs-App',
      'E-Mail-Link',
      'SMS-Code',
    ]);
    expect($('[data-method="sms"]')!.title).toBe('Einmalcode per SMS an Ihr Mobiltelefon');

    await click('[data-method="sms"]');
    expect(text('.notice')).toBe('„SMS-Code“ ist bald verfügbar.');
  });

  it('keeps a heading set by the page', async () => {
    fakeServer();
    const element = document.createElement('madauth-login');
    element.heading = 'Willkommen zurück';
    document.body.append(element);

    await openDialog({ locale: 'de' });

    expect(text('h2')).toBe('Willkommen zurück');
  });

  it('shows the views for creating an account', async () => {
    fakeServer();
    await openDialog({ locale: 'de' });

    await click('[data-action="signup"]');
    expect(text('h2')).toBe('Konto erstellen');
    expect(text('label[for="name"]')).toBe('Name (optional)');
    expect(text('label[for="new-password"]')).toBe('Passwort');
    expect(text('.hint')).toBe('Mindestens 8 Zeichen.');
    expect(text('form.signup .submit')).toBe('Konto erstellen');
    expect(text('[data-action="back"]')).toBe('Sie haben bereits ein Konto? Anmelden');

    fill({ email: 'new@example.com', password: 'long enough' });
    await submit('signup');
    expect(text('h2')).toBe('Posteingang prüfen');
    expect(text('.lead')).toBe(
      'Wir haben eine E-Mail an new@example.com gesendet. Öffnen Sie den Link darin oder geben Sie den 6-stelligen Bestätigungscode aus der E-Mail ein.',
    );
    expect(text('label[for="code"]')).toBe('Bestätigungscode');
    expect(text('form.code .submit')).toBe('Weiter');
    expect(text('[data-action="resend"]')).toBe('E-Mail erneut senden');
    expect(text('[data-action="back"]')).toBe('Zurück zur Anmeldung');

    await click('[data-action="resend"]');
    expect(text('.notice[role="status"]')).toBe('Wir haben die E-Mail erneut gesendet.');
  });

  it('shows the views for a forgotten password', async () => {
    fakeServer();
    await openDialog({ locale: 'de' });

    await click('[data-action="forgot"]');
    expect(text('h2')).toBe('Passwort zurücksetzen');
    expect(text('.lead')).toBe(
      'Geben Sie Ihre E-Mail-Adresse ein. Wir senden Ihnen einen Link und einen Bestätigungscode, mit denen Sie ein neues Passwort wählen können.',
    );
    expect(text('form.forgot .submit')).toBe('E-Mail senden');
    expect(text('[data-action="back"]')).toBe('Zurück zur Anmeldung');

    fill({ email: 'grace@example.com' });
    await submit('forgot');
    fill({ code: CODE });
    await submit('code');
    expect(text('h2')).toBe('Neues Passwort wählen');
    expect(text('label[for="new-password"]')).toBe('Neues Passwort');
    expect(text('.hint')).toBe('Mindestens 8 Zeichen.');
    expect(text('form.reset .submit')).toBe('Passwort festlegen');
  });

  it('shows its own texts for error codes', async () => {
    const server = fakeServer();
    server.accounts.set('new@example.com', { password: 'long enough', verified: false });
    await openDialog({ locale: 'de' });

    fill({ email: 'grace@example.com', password: 'wrong' });
    await submit('signin');
    expect(text('[part="error"]')).toBe('E-Mail-Adresse oder Passwort ist falsch.');

    fill({ email: 'new@example.com', password: 'long enough' });
    await submit('signin');
    expect(text('[part="error"]')).toBe(
      'Bitte bestätigen Sie zuerst Ihre E-Mail-Adresse: Öffnen Sie den Link in der E-Mail, die wir Ihnen gesendet haben. E-Mail erneut senden',
    );

    server.emailsDown = true;
    await click('[data-action="signup"]');
    fill({ email: 'other@example.com', password: 'long enough' });
    await submit('signup');
    expect(text('[part="error"]')).toBe(
      'Derzeit kann kein Konto mit E-Mail-Adresse und Passwort erstellt werden. Bitte versuchen Sie es später erneut.',
    );

    await click('[data-action="back"]');
    await click('[data-action="forgot"]');
    await submit('forgot');
    expect(text('[part="error"]')).toBe('Derzeit können keine E-Mails gesendet werden. Bitte versuchen Sie es später erneut.');

    server.down = true;
    await click('[data-action="back"]');
    await submit('signin');
    expect(text('[part="error"]')).toBe(
      'Der Anmeldedienst ist nicht erreichbar. Bitte prüfen Sie Ihre Internetverbindung und versuchen Sie es erneut.',
    );
  });

  it('shows the views of the authenticator app', async () => {
    const server = fakeServer();
    server.methods.totp = true;
    server.policy.password = 'optional';
    server.authenticators.add('grace@example.com');
    await openDialog({ providers: [new Password(), new Totp()], locale: 'de' });

    // Signing in with the app alone.
    await click('[data-method="totp"]');
    expect(text('h2')).toBe('Authentifizierungs-App');
    expect(text('label[for="code"]')).toBe('Code aus der App');
    expect(text('form.totp .hint')).toBe('Geben Sie den 6-stelligen Code aus Ihrer Authentifizierungs-App ein.');
    expect(text('[data-action="toggle-recovery"]')).toBe('Stattdessen einen Wiederherstellungscode verwenden');
    expect(text('form.totp .submit')).toBe('Anmelden');
    fill({ email: 'grace@example.com', code: '000000' });
    await submit('totp');
    expect(text('[part="error"]')).toContain('E-Mail-Adresse oder Code ist falsch.');
    await click('[data-action="toggle-recovery"]');
    expect(text('label[for="recovery-code"]')).toBe('Wiederherstellungscode');
    expect(text('[data-action="toggle-recovery"]')).toBe('Stattdessen die Authentifizierungs-App verwenden');

    // The second step after the password.
    await click('[data-action="back"]');
    fill({ email: 'grace@example.com', password: 'correct horse battery' });
    await submit('signin');
    expect(text('h2')).toBe('Code eingeben');
    expect(text('.lead')).toBe('Geben Sie den Code aus Ihrer Authentifizierungs-App ein, um die Anmeldung abzuschließen.');
    expect(text('form.totp-code .submit')).toBe('Weiter');
    login().close();

    // Setting the app up while signed in.
    server.user = grace;
    await Madauth.getSession();
    void Madauth.setUpAuthenticator();
    await settle();
    expect(text('h2')).toBe('Authentifizierungs-App einrichten');
    expect(text('.lead')).toBe(
      'Scannen Sie diesen QR-Code mit Ihrer Authentifizierungs-App (z. B. Google Authenticator oder 1Password) und geben Sie dann den Code ein, den sie anzeigt.',
    );
    expect(text('.hint')).toBe('Die Anmeldung mit E-Mail-Adresse und Passwort fragt dann zusätzlich nach einem Code aus der App.');
    expect($('[part="qr"]')!.getAttribute('aria-label')).toBe('QR-Code für Ihre Authentifizierungs-App');
    expect(text('form.totp-setup .submit')).toBe('Einschalten');
    expect(text('[data-action="cancel"]')).toBe('Abbrechen');
    server.totpSetup = undefined;
    fill({ code: CODE });
    await submit('totp-setup');
    expect(text('[part="error"]')).toBe('Die Einrichtung hat zu lange gedauert. Bitte beginnen Sie neu. Neu beginnen');
    await click('[data-action="restart-setup"]');
    fill({ code: CODE });
    await submit('totp-setup');
    expect(text('h2')).toBe('Wiederherstellungscodes speichern');
    expect(text('[data-action="saved"]')).toBe('Ich habe sie gespeichert');
  });
});

describe('errors with a message from the server', () => {
  it('weak_password: German explains a password that is too short', async () => {
    fakeServer();
    await openDialog({ locale: 'de' });
    await click('[data-action="signup"]');

    fill({ email: 'new@example.com', password: 'short' });
    await submit('signup');

    expect($('[part="error"]')!.dataset.code).toBe('weak_password');
    expect(text('[part="error"]')).toBe('Das Passwort muss mindestens 8 Zeichen lang sein.');
  });

  it('weak_password: German says that any other password is not allowed', async () => {
    fakeServer();
    await openDialog({ locale: 'de' });
    await click('[data-action="signup"]');

    fill({ email: 'new@example.com', password: 'x'.repeat(257) });
    await submit('signup');

    expect($('[part="error"]')!.dataset.code).toBe('weak_password');
    expect(text('[part="error"]')).toBe('Dieses Passwort ist nicht zulässig. Bitte wählen Sie ein anderes.');
  });

  it('weak_password: German explains a short password on the reset form too', async () => {
    fakeServer();
    history.replaceState(null, '', `/page#madauth_reset=${RESET_TOKEN}`);
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()], locale: 'de' });
    await settle();

    fill({ password: 'short' });
    await submit('reset');

    expect(text('[part="error"]')).toBe('Das Passwort muss mindestens 8 Zeichen lang sein.');
  });

  it('weak_password: English shows the server’s message', async () => {
    fakeServer();
    await openDialog({ locale: 'en' });
    await click('[data-action="signup"]');

    fill({ email: 'new@example.com', password: 'short' });
    await submit('signup');
    expect(text('[part="error"]')).toBe('The password must have at least 8 characters.');

    fill({ email: 'new@example.com', password: 'x'.repeat(257) });
    await submit('signup');
    expect(text('[part="error"]')).toBe('The password must have at most 256 characters.');
  });

  it('too_many_attempts: German shows its own text without the seconds, English the server’s message', async () => {
    fakeServer().locked = true;
    await openDialog({ locale: 'de' });

    fill({ email: 'grace@example.com', password: 'correct horse battery' });
    await submit('signin');

    expect($('[part="error"]')!.dataset.code).toBe('too_many_attempts');
    expect(text('[part="error"]')).toBe('Zu viele Versuche. Bitte warten Sie einen Moment und versuchen Sie es erneut.');

    Madauth.setLocale('en');
    await login().updateComplete;

    expect(text('[part="error"]')).toBe('Too many failed attempts. Try again in 30 seconds.');
  });

  it('signup_rejected: every language shows the server’s message as it is', async () => {
    fakeServer().rejectSignUp = 'Nur Adressen von example.org können ein Konto erstellen.';
    await openDialog({ locale: 'de' });
    await click('[data-action="signup"]');

    fill({ email: 'new@example.com', password: 'long enough' });
    await submit('signup');

    expect($('[part="error"]')!.dataset.code).toBe('signup_rejected');
    expect(text('[part="error"]')).toBe('Nur Adressen von example.org können ein Konto erstellen.');

    Madauth.setLocale('en');
    await login().updateComplete;

    expect(text('[part="error"]')).toBe('Nur Adressen von example.org können ein Konto erstellen.');
  });
});

describe('Madauth.setLocale', () => {
  it('shows an open dialog in the new language, with its notice', async () => {
    fakeServer();
    await openDialog();
    await click('[data-method="sms"]');
    expect(text('h2')).toBe('Sign in');
    expect(text('.notice')).toBe('“SMS code” is coming soon.');

    Madauth.setLocale('de');
    await login().updateComplete;

    expect(text('h2')).toBe('Anmelden');
    expect(text('label[for="email"]')).toBe('E-Mail-Adresse');
    expect(text('.notice')).toBe('„SMS-Code“ ist bald verfügbar.');
    expect($('dialog')!.getAttribute('lang')).toBe('de');
    expect($<HTMLDialogElement>('dialog')!.open).toBe(true);
  });

  it('shows an error in the new language and keeps what was typed', async () => {
    fakeServer();
    await openDialog({ locale: 'de' });
    fill({ email: 'grace@example.com', password: 'wrong' });
    await submit('signin');
    expect(text('[part="error"]')).toBe('E-Mail-Adresse oder Passwort ist falsch.');
    fill({ password: 'typed since' });

    Madauth.setLocale('en-GB');
    await login().updateComplete;

    expect(text('[part="error"]')).toBe('E-mail or password is wrong.');
    expect($<HTMLInputElement>('form input[name="email"]')!.value).toBe('grace@example.com');
    expect($<HTMLInputElement>('form input[name="password"]')!.value).toBe('typed since');
  });

  it('applies to a dialog that is opened later', async () => {
    fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()], locale: 'en' });

    Madauth.setLocale('de');
    void Madauth.signIn();
    await settle();

    expect(text('h2')).toBe('Anmelden');
  });

  it('ignores a value that is not a language tag', async () => {
    fakeServer();
    await openDialog({ locale: 'de' });

    Madauth.setLocale(['en'] as unknown as string);
    await login().updateComplete;

    expect(text('h2')).toBe('Anmelden');
    expect(console.error).toHaveBeenCalledWith('[madauth]', 'invalid_options', expect.stringContaining('locale must be'));
  });

  it('is not needed to follow a page that changes its <html lang>', async () => {
    fakeServer();
    await openDialog();
    expect(text('h2')).toBe('Sign in');

    document.documentElement.lang = 'de';
    await settle();

    expect(text('h2')).toBe('Anmelden');
  });

  it('is replaced by the locale of a later initialize', async () => {
    fakeServer();
    Madauth.setLocale('de');

    await openDialog();

    expect(text('h2')).toBe('Sign in');
  });
});
