import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { Password } from './providers/password.js';
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

const tv = { code: 'BCDFGHJK', client: { id: 'mc_tv', name: 'Living room TV' }, scope: ['openid', 'email', 'offline_access'], expiresAt: 1_700_000_600_000 };

describe('<madauth-login> and a device’s sign-in', () => {
  it('DD1: the signed-in user types the code, sees who asks, approves, and the call resolves', async () => {
    const server = fakeServer();
    server.user = grace;
    server.devices.push({ ...tv });
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    const result = Madauth.showDeviceApprovalDialog();
    await settle();

    expect(text('h2')).toBe('Sign in a device');
    $<HTMLInputElement>('input[name="code"]')!.value = 'bcdf-ghjk';
    $<HTMLFormElement>('form.device-code')!.requestSubmit();
    await settle();
    expect(text('.lead')).toBe('Living room TV asks to sign in as you.');
    expect(text('.device-code-shown')).toBe('The device shows the code BCDF-GHJK.');
    await click('[data-action="approve"]');
    expect(server.requests.at(-1)).toMatchObject({ path: '/auth/device/approve', body: { code: 'BCDF-GHJK' } });
    expect(text('.lead')).toBe('The device is signed in. You can close this window.');
    expect(await result).toEqual({ isSuccess: true, approved: true });
    await click('[data-action="done"]');
    expect(login().shadowRoot!.querySelector('dialog')!.open).toBe(false);
  });

  it('DD2: with the code from the URL it goes straight to the decision; a wrong code and too many are told', async () => {
    const server = fakeServer();
    server.user = grace;
    server.devices.push({ ...tv });
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    const denied = Madauth.showDeviceApprovalDialog({ code: 'BCDF-GHJK' });
    await settle();
    expect(text('.lead')).toBe('Living room TV asks to sign in as you.');
    await click('[data-action="deny"]');
    expect(await denied).toEqual({ isSuccess: true, approved: false });
    expect(text('.lead')).toBe('The device was refused. You can close this window.');
    await click('[data-action="done"]');

    const wrong = Madauth.showDeviceApprovalDialog({ code: 'XXXX-XXXX' });
    await settle();
    expect(text('h2')).toBe('Sign in a device');
    expect(text('.error')).toBe('This code is unknown, has expired or was used already. Check it on the device.');
    server.deviceLookupBlocked = true;
    $<HTMLInputElement>('input[name="code"]')!.value = 'XXXX-XXXX';
    $<HTMLFormElement>('form.device-code')!.requestSubmit();
    await settle();
    expect(text('.error')).toBe('Too many wrong codes. Try again in a few minutes.');
    await click('[data-action="cancel"]');
    expect(await wrong).toMatchObject({ isSuccess: false, error: { code: 'cancelled' } });
  });

  it('DD3: a user who is not signed in signs in first, then approves', async () => {
    const server = fakeServer();
    server.devices.push({ ...tv });
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    const result = Madauth.showDeviceApprovalDialog({ code: 'BCDF-GHJK' });
    await settle();
    expect(text('h2')).toBe('Sign in');
    $<HTMLInputElement>('input[name="email"]')!.value = grace.email!;
    $<HTMLInputElement>('input[name="password"]')!.value = 'correct horse battery';
    $<HTMLFormElement>('form.signin')!.requestSubmit();
    await settle();
    expect(text('h2')).toBe('Sign in a device');
    expect(text('.lead')).toBe('Living room TV asks to sign in as you.');
    await click('[data-action="approve"]');
    expect(await result).toEqual({ isSuccess: true, approved: true });
  });
});
