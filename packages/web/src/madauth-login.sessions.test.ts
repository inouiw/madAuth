import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { Password } from './providers/password.js';
import type { SessionInfo } from './scopes/sessions.js';
import { SERVER, fakeServer, grace, resetAll, settle } from './test-helpers.js';

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

async function click(selector: string): Promise<void> {
  const element = $<HTMLButtonElement>(selector);
  if (!element) throw new Error(`No ${selector}`);
  element.click();
  await settle();
}

function fill(values: Record<string, string>): void {
  for (const [name, value] of Object.entries(values)) {
    const input = $<HTMLInputElement>(`form input[name="${name}"]`);
    if (!input) throw new Error(`No field ${name}`);
    input.value = value;
  }
}

const session = (id: string, overrides: Partial<SessionInfo> = {}): SessionInfo & { email: string } => ({
  email: grace.email!,
  id,
  current: false,
  browser: 'Firefox',
  os: 'macOS',
  ip: '203.0.113.7',
  signedInAt: 1,
  amr: ['pwd'],
  createdAt: 1,
  lastActiveAt: Date.UTC(2026, 9, 3, 12, 5),
  expiresAt: 2,
  ...overrides,
});

async function openMethods() {
  const server = fakeServer();
  server.user = grace;
  server.sessions = [
    session('ses_here', { current: true }),
    session('ses_phone', { browser: 'Safari', os: 'iOS', ip: '203.0.113.8' }),
    session('ses_old', { browser: null, os: null, ip: null }),
  ];
  await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
  const result = Madauth.showManageSignInMethodsDialog();
  await settle();
  return { server, result };
}

describe('<madauth-login> and the sessions', () => {
  it('DS1: lists the sessions under the methods, the current one marked and without a button, and ends one', async () => {
    const { server } = await openMethods();

    expect(text('.sessions h3')).toBe('Sessions');
    expect($$('.session').map((li) => [li.dataset.session, li.hasAttribute('data-current')])).toEqual([
      ['ses_here', true],
      ['ses_phone', false],
      ['ses_old', false],
    ]);
    expect(text('.session[data-session="ses_here"] .label')).toBe('Firefox on macOS');
    expect(text('.session[data-session="ses_here"] .hint')).toMatch(/^This browser · 203\.0\.113\.7 · Last active .*2026/);
    expect(text('.session[data-session="ses_old"] .label')).toBe('Unknown device');
    expect($('.session[data-session="ses_here"] [data-action="end-session"]')).toBeNull();
    expect($('.session[data-session="ses_phone"] [data-action="end-session"]')!.getAttribute('aria-label')).toBe('End the session on Safari on iOS');

    await click('.session[data-session="ses_phone"] [data-action="end-session"]');
    expect(text('.notice')).toBe('Session ended.');
    expect(server.sessions.map((s) => s.id)).toEqual(['ses_here', 'ses_old']);
    expect($$('.session').map((li) => li.dataset.session)).toEqual(['ses_here', 'ses_old']);
    // One other session left: no button for all of them.
    expect($('[data-action="end-other-sessions"]')).toBeNull();
  });

  it('DS2: ends all others at once; ending takes a recent sign-in, and the dialog comes back after it', async () => {
    const { server } = await openMethods();
    server.staleSignIn = true;

    await click('[data-action="end-other-sessions"]');
    expect($('.error')!.dataset.code).toBe('reauth_required');
    expect(text('.notice.error')).toContain('For your security, sign in again to end a session.');
    await click('[data-action="sign-in-again"]');
    expect(text('h2')).toBe('Sign in');
    server.staleSignIn = false;
    fill({ email: 'grace@example.com', password: 'correct horse battery' });
    $<HTMLFormElement>('form.signin')!.requestSubmit();
    await settle();

    expect(text('h2')).toBe('Sign-in methods');
    await click('[data-action="end-other-sessions"]');
    expect(text('.notice')).toBe('2 other sessions ended.');
    expect($$('.session').map((li) => li.dataset.session)).toEqual(['ses_here']);
  });

  it('DS3: a session that ended meanwhile says so; a server without sessions shows no section', async () => {
    const { server } = await openMethods();
    server.sessions = server.sessions.filter((s) => s.id !== 'ses_phone');

    await click('.session[data-session="ses_phone"] [data-action="end-session"]');
    expect(text('.notice.error')).toBe('This session has ended already.');
    expect($$('.session').map((li) => li.dataset.session)).toEqual(['ses_here', 'ses_old']);

    server.sessions = [];
    login().shadowRoot!.querySelector<HTMLButtonElement>('[data-action="done"]')!.click();
    await settle();
    void Madauth.showManageSignInMethodsDialog();
    await settle();
    expect($('.sessions')).toBeNull();
  });
});
