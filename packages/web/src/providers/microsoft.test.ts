// Microsoft in the web library: the button madAuth adds when the server offers it, and the address step after a
// sign-in that told no address (also an OpenID Connect provider's). See "Providers" in docs/custom-ui.md.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../index.js';
import { Madauth } from '../madauth.js';
import { SERVER, fakeServer, resetAll, settle, type FakeServer } from '../test-helpers.js';
import { Password } from './password.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(resetAll);

const shadow = () => document.querySelector('madauth-login')!.shadowRoot!;
const $ = <T extends HTMLElement = HTMLElement>(selector: string) => shadow().querySelector<T>(selector);
const $$ = (selector: string) => [...shadow().querySelectorAll<HTMLElement>(selector)];

/** A server with Microsoft on next to e-mail & password. */
function microsoftServer(): FakeServer {
  const server = fakeServer();
  server.oidc = [{ id: 'microsoft', kind: 'microsoft', name: 'Microsoft', secondFactor: 'none', tenant: 'common' }];
  return server;
}

describe('Microsoft', () => {
  it('MW1: the dialog shows "Continue with Microsoft" with its four squares, which starts the redirect', async () => {
    microsoftServer();
    const assign = vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    history.replaceState(null, '', '/page');

    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    void Madauth.showSignInDialog();
    await settle();

    expect($$('.button-slot').map((slot) => slot.dataset.button)).toEqual(['microsoft']);
    const button = $<HTMLButtonElement>('.microsoft-slot button')!;
    expect(button.textContent).toBe('Continue with Microsoft');
    expect([...button.querySelectorAll('svg rect')].map((rect) => rect.getAttribute('fill'))).toEqual(['#f25022', '#7fba00', '#00a4ef', '#ffb900']);
    button.click();
    expect(assign).toHaveBeenCalledExactlyOnceWith(
      `${SERVER}/auth/providers/microsoft/start?return_to=${encodeURIComponent('https://app.example.com/page')}&locale=${encodeURIComponent(navigator.language)}`,
    );
  });
});

describe('a provider that told no address', () => {
  it('MW2: back from it, the dialog asks for the address, offers the hint, sends the e-mail to what is typed, and signs in with the code', async () => {
    const server = microsoftServer();
    server.addressPending = { method: 'microsoft', suggestion: 'linus@outlook.example.com' };
    history.replaceState(null, '', '/page#madauth_next=email-address&madauth_method=microsoft');

    expect(await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] })).toEqual({ isSuccess: true, leftOut: [] });
    expect(location.href).toBe('https://app.example.com/page');
    expect(Madauth.authenticator.pendingStep).toEqual({ step: 'email-address', method: 'microsoft' });
    await settle();

    expect($('h2')!.textContent).toBe('Your email address');
    expect($('.lead')!.textContent).toBe('Microsoft didn’t tell us your email address. Enter it, and we’ll send you a link and a code to confirm it.');
    const field = $<HTMLInputElement>('form.email-address input[name="email"]')!;
    expect(field.value).toBe('linus@outlook.example.com');
    field.value = 'linus@example.com';
    $<HTMLFormElement>('form.email-address')!.requestSubmit();
    await settle();
    expect(server.requests.at(-1)).toMatchObject({ path: '/auth/providers/microsoft/address', body: { email: 'linus@example.com', redirectTo: 'https://app.example.com/page' } });

    expect($('h2')!.textContent).toBe('Check your inbox');
    expect($('.lead')!.textContent!.replace(/\s+/g, ' ')).toContain('We sent an email to linus@example.com.');
    // Sent again, and confirmed, with the address the user typed.
    $<HTMLButtonElement>('[data-action="resend"]')!.click();
    await settle();
    expect(server.requests.at(-1)).toMatchObject({ path: '/auth/email/send-verification', body: { email: 'linus@example.com' } });
    $<HTMLInputElement>('form.code input[name="code"]')!.value = '123456';
    $<HTMLFormElement>('form.code')!.requestSubmit();
    await settle();
    expect(server.requests.at(-1)).toMatchObject({ path: '/auth/email/verify', body: { code: '123456', email: 'linus@example.com' } });
    expect(Madauth.currentUser).toMatchObject({ email: 'linus@example.com', amr: ['microsoft'] });
  });

  it('MW3: a custom screen reads the hint, sends the address and the code; a sign-in that expired says so', async () => {
    const server = microsoftServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()], ui: 'custom' });
    expect(await Madauth.provider('microsoft').addressSuggestion()).toMatchObject({ isSuccess: false, error: { code: 'challenge_expired' } });

    server.addressPending = { method: 'microsoft', suggestion: null };
    expect(await Madauth.provider('microsoft').addressSuggestion()).toEqual({ isSuccess: true, suggestion: null });
    expect(await Madauth.provider('microsoft').submitAddress({ email: 'no address' })).toMatchObject({ isSuccess: false, error: { code: 'invalid_email' } });
    expect(await Madauth.provider('microsoft').submitAddress({ email: 'linus@example.com' })).toEqual({ isSuccess: true });
    expect(await Madauth.provider('microsoft').verifyEmail({ code: '123456', email: 'linus@example.com' })).toMatchObject({ isSuccess: true, user: { email: 'linus@example.com' } });
  });
});
