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

async function submit(form: string): Promise<void> {
  $<HTMLFormElement>(`form.${form}`)!.requestSubmit();
  await settle();
}

/** Ticks a scope's checkbox, as a click does. */
function tick(scope: string): void {
  const box = $<HTMLInputElement>(`input[name="scope"][value="${scope}"]`)!;
  box.checked = true;
  box.dispatchEvent(new Event('change', { bubbles: true }));
}

async function openApiKeys(server = fakeServer()) {
  server.user ??= grace;
  await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
  const result = Madauth.showManageApiKeysDialog();
  await settle();
  return { server, result };
}

describe('<madauth-login> and API keys', () => {
  it('DK1: lists the keys, makes one that is shown once to copy, revokes one, and resolves when closed', async () => {
    const server = fakeServer();
    server.apiKeys.push({ id: 'key_0', email: grace.email!, key: 'madauth_old', name: 'Old script', scopes: ['orders:read'], createdAt: 1, expiresAt: null, lastUsedAt: 0 });
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const { result } = await openApiKeys(server);

    expect(text('h2')).toBe('API keys');
    expect($$('li.key-row').map((li) => li.textContent.replace(/\s+/g, ' ').trim())).toEqual(['Old script orders:read · Not used yet · Never expires Revoke']);

    await click('[data-action="create-api-key"]');
    expect(text('h2')).toBe('Create an API key');
    // Only the scopes Grace may give a key: none of madAuth's (she is no admin), nor orders:refund (no role staff).
    expect($$('input[name="scope"]').map((box) => (box as HTMLInputElement).value)).toEqual(['orders:read']);
    expect($<HTMLButtonElement>('form.api-key-create .submit')!.disabled).toBe(true);
    $<HTMLInputElement>('input[name="name"]')!.value = 'Deploy script';
    tick('orders:read');
    await settle();
    expect($<HTMLButtonElement>('form.api-key-create .submit')!.disabled).toBe(false);
    $<HTMLSelectElement>('select[name="expires"]')!.value = '30';
    await submit('api-key-create');

    expect(text('h2')).toBe('Your new API key');
    expect(text('.api-key')).toBe('madauth_secret2');
    const sent = server.requests.at(-1)!.body as { name: string; scopes: string[]; expiresAt: number };
    expect(sent).toMatchObject({ name: 'Deploy script', scopes: ['orders:read'] });
    expect(sent.expiresAt - Date.now()).toBeGreaterThan(29 * 24 * 60 * 60 * 1000);
    await click('[data-action="copy-api-key"]');
    expect(writeText).toHaveBeenCalledWith('madauth_secret2');
    expect(text('.notice')).toBe('Copied.');

    // Where the page may not use the clipboard, the key is selected to copy by hand.
    writeText.mockRejectedValueOnce(new DOMException('denied', 'NotAllowedError'));
    await click('[data-action="copy-api-key"]');
    expect(text('.notice')).toBe('It could not be copied here: copy the selected key yourself.');

    await click('[data-action="back-to-api-keys"]');
    expect($$('li.key-row').map((li) => li.dataset.key)).toEqual(['key_0', 'key_2']);
    // Gone from the dialog for good: only its list entry stays.
    expect(login().shadowRoot!.innerHTML).not.toContain('madauth_secret2');

    await click('li.key-row[data-key="key_0"] [data-action="revoke"]');
    expect(text('.notice')).toBe('Revoked.');
    expect($$('li.key-row').map((li) => li.dataset.key)).toEqual(['key_2']);

    await click('[data-action="done"]');
    expect(await result).toEqual({ isSuccess: true });
  });

  it('DK2: making a key long after signing in asks to sign in again, and goes back to the form', async () => {
    const server = fakeServer();
    server.staleSignIn = true;
    await openApiKeys(server);
    await click('[data-action="create-api-key"]');
    $<HTMLInputElement>('input[name="name"]')!.value = 'Deploy script';
    tick('orders:read');
    await submit('api-key-create');

    expect($('.error')!.dataset.code).toBe('reauth_required');
    expect(text('.error')).toContain('sign in again to create an API key');
    await click('[data-action="sign-in-again"]');
    expect(text('h2')).toBe('Sign in');
    server.staleSignIn = false;
    $<HTMLInputElement>('form.signin input[name="email"]')!.value = 'grace@example.com';
    $<HTMLInputElement>('form.signin input[name="password"]')!.value = 'correct horse battery';
    await submit('signin');

    expect(text('h2')).toBe('Create an API key');
    expect($$('input[name="scope"]')).toHaveLength(1);
  });

  it('DK3: without a scope the user may give, the form says so', async () => {
    const server = fakeServer();
    server.apiScopes = server.apiScopes.filter((scope) => scope.role);
    await openApiKeys(server);
    await click('[data-action="create-api-key"]');

    expect(text('.lead')).toBe('There is nothing you can allow an API key to do.');
    expect($('form.api-key-create')).toBeNull();
  });

  it("DK5: when the scopes can't be loaded, the form goes back to the list with the error", async () => {
    const { server } = await openApiKeys();
    server.down = true;
    await click('[data-action="create-api-key"]');

    expect(text('h2')).toBe('API keys');
    expect($('.error')!.dataset.code).toBe('network');
    server.down = false;
    await click('[data-action="create-api-key"]');
    expect(text('h2')).toBe('Create an API key');
  });

  it("DK4: needs someone signed in, and madAuth's dialog", async () => {
    fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
    expect(await Madauth.showManageApiKeysDialog()).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });

    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()], ui: 'custom' });
    expect(await Madauth.showManageApiKeysDialog()).toMatchObject({
      isSuccess: false,
      error: { code: 'invalid_options', message: "Madauth.showManageApiKeysDialog() opens madAuth's dialog, but initialize was called with ui: 'custom'. Use Madauth.apiKeys instead." },
    });
  });
});
