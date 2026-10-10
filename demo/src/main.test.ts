import { beforeAll, describe, expect, it, vi } from 'vitest';
import html from '../index.html?raw';

const ada = {
  id: 'usr_1',
  name: 'Ada Lovelace',
  email: 'ada@example.com',
  picture: 'https://example.com/ada.png',
  claims: { roles: ['admin'] },
};
let sessionUser: typeof ada | null = null;
let settings = { google: { available: true, enabled: true }, password: { available: true, enabled: false } };

const $ = <T extends HTMLElement = HTMLElement>(selector: string) => document.querySelector<T>(selector)!;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

// A minimal madAuth server and Google Identity Services.
vi.stubGlobal(
  'fetch',
  vi.fn(async (input: string, init: RequestInit = {}) => {
    const body = () => JSON.parse(String(init.body)) as Record<string, any>;
    switch (`${init.method ?? 'GET'} ${new URL(input).pathname}`) {
      case 'GET /auth/config':
        return json({ google: { clientId: 'cid.apps.googleusercontent.com', codeFlow: false }, password: { minLength: 8 } });
      case 'GET /auth/session':
        return sessionUser ? json({ user: sessionUser }) : json({ error: 'no_session' }, 401);
      case 'POST /auth/google/nonce':
        return json({ nonce: 'n' });
      case 'POST /auth/google/verify':
        sessionUser = ada;
        return json({ user: ada });
      case 'POST /auth/logout':
        sessionUser = null;
        return new Response(null, { status: 204 });
      case 'POST /auth/account/delete':
        sessionUser = null;
        return new Response(null, { status: 204 });
      case 'POST /auth/admin/claims/get':
        return json({ email: body().email, userId: ada.id, claims: ada.claims });
      case 'POST /auth/admin/claims/set':
        return json({ email: body().email, userId: ada.id, claims: body().claims });
      case 'POST /auth/admin/settings/get':
        return json({ methods: settings });
      case 'POST /auth/admin/settings/set': {
        const { methods } = body();
        settings = {
          google: { ...settings.google, enabled: methods.google ?? settings.google.enabled },
          password: { ...settings.password, enabled: methods.password ?? settings.password.enabled },
        };
        return json({ methods: settings });
      }
    }
    return json({}, 404);
  }),
);
// The page asks before deleting the account.
vi.stubGlobal('confirm', vi.fn(() => true));
// Records what the page does with Google Identity Services. (Plain counters: Vitest clears mock calls between tests.)
const gis = { prompts: 0, buttons: 0, callback: undefined as ((response: { credential: string }) => void) | undefined };
window.google = {
  accounts: {
    id: {
      initialize: (config) => (gis.callback = config.callback),
      prompt: () => gis.prompts++,
      renderButton: () => gis.buttons++,
      disableAutoSelect: () => {},
      cancel: () => {},
    },
  },
};

beforeAll(async () => {
  // Render the demo page's markup (without loading its script and stylesheet), then run main.ts.
  const template = document.createElement('template');
  template.innerHTML = html;
  template.content.querySelectorAll('script, link').forEach((el) => el.remove());
  document.body.replaceChildren(template.content);
  await import('./main.js');
});

describe('demo page', () => {
  it('shows only a sign-in button while signed out', () => {
    const buttons = [...document.querySelectorAll<HTMLButtonElement>('main button')].filter((b) => !b.closest('[hidden]'));
    expect(buttons).toHaveLength(1);
    expect(buttons[0].textContent).toBe('Sign in');
  });

  it('marks One Tap / FedCM as the current demo and links to the redirect demo', () => {
    const links = [...document.querySelectorAll<HTMLAnchorElement>('#flow a')];
    expect(links.map((a) => a.dataset.flow)).toEqual(['fedcm', 'redirect']);
    expect(links[0].getAttribute('aria-current')).toBe('page');
    expect(links[1].getAttribute('aria-current')).toBeNull();
    expect(new URL(links[1].href).search).toBe('?google=redirect');
    expect($('.flow-description[data-flow="fedcm"]').hidden).toBe(false);
    expect($('.flow-description[data-flow="redirect"]').hidden).toBe(true);
    expect($('#flow-note').hidden).toBe(true);
  });

  it('prompts Google One Tap on load', async () => {
    await expect.poll(() => gis.prompts).toBe(1);
  });

  it('opens the login dialog with the Google button when the sign-in button is clicked', async () => {
    $<HTMLButtonElement>('#sign-in').click();

    const login = await vi.waitFor(() => {
      const element = document.querySelector('madauth-login');
      if (!element) throw new Error('the dialog was not created');
      return element;
    });
    await expect.poll(() => login.shadowRoot!.querySelector('dialog')!.open).toBe(true);
    await expect.poll(() => gis.buttons).toBe(1);
  });

  it('shows the user, their claims and the API after signing in with Google, and the sign-in button after signing out', async () => {
    gis.callback!({ credential: 'token' });

    await expect.poll(() => $('#account').hidden).toBe(false);
    expect($('#sign-in').hidden).toBe(true);
    expect($('#user-name').textContent).toBe('Ada Lovelace');
    expect($('#user-email').textContent).toBe('ada@example.com');
    expect($<HTMLImageElement>('#avatar').src).toBe(ada.picture);
    expect($('#claims').textContent).toBe(JSON.stringify(ada.claims, null, 2));
    expect($('#api').hidden).toBe(false);
    // The admin fields start with the signed-in user's own address, and an admin's checkboxes with the
    // server's settings; only then can they be sent back.
    expect($<HTMLInputElement>('#claims-email').value).toBe('ada@example.com');
    await expect.poll(() => $<HTMLButtonElement>('[data-call="setSettings"]').disabled).toBe(false);
    expect($<HTMLInputElement>('#method-google').checked).toBe(true);
    expect($<HTMLInputElement>('#method-password').checked).toBe(false);

    $<HTMLButtonElement>('[data-call="getSession"]').click();
    await expect.poll(() => $('#output').hidden).toBe(false);
    $<HTMLInputElement>('#claims-email').value = 'someone@example.com';

    $<HTMLButtonElement>('#sign-out').click();

    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    expect($('#account').hidden).toBe(true);
    expect($('#api').hidden).toBe(true);
    // Nothing of the previous user stays for the next one.
    expect($<HTMLInputElement>('#claims-email').value).toBe('');
    expect($('#output').hidden).toBe(true);
    expect($('#output').textContent).toBe('');
    expect($<HTMLButtonElement>('[data-call="setSettings"]').disabled).toBe(true);
    expect($<HTMLInputElement>('#method-google').checked).toBe(false);
  });

  it('calls the session and admin API and shows each result', async () => {
    gis.callback!({ credential: 'token' });
    await expect.poll(() => $('#api').hidden).toBe(false);
    await expect.poll(() => $<HTMLButtonElement>('[data-call="setSettings"]').disabled).toBe(false);

    $<HTMLButtonElement>('[data-call="getSettings"]').click();
    await expect.poll(() => $('#output').textContent).toContain('Madauth.admin.getSettings()');
    expect($('#output').hidden).toBe(false);
    expect($('#output').textContent).toContain('"enabled": false');
    expect($<HTMLInputElement>('#method-google').checked).toBe(true);
    expect($<HTMLInputElement>('#method-password').checked).toBe(false);

    $<HTMLInputElement>('#method-password').checked = true;
    $<HTMLButtonElement>('[data-call="setSettings"]').click();
    await expect.poll(() => settings.password.enabled).toBe(true);
    await expect.poll(() => $('#output').textContent).toContain('Madauth.admin.setSettings({ methods })');
    expect($<HTMLButtonElement>('[data-call="setSettings"]').disabled).toBe(false);

    $<HTMLButtonElement>('[data-call="sessionReady"]').click();
    await expect.poll(() => $('#output').textContent).toBe('Madauth.sessionReady()\ntrue');

    $<HTMLTextAreaElement>('#claims-json').value = '{ "plan": "pro" }';
    $<HTMLButtonElement>('[data-call="setClaims"]').click();
    await expect.poll(() => $('#output').textContent).toContain('"plan": "pro"');
    const [, init] = vi.mocked(fetch).mock.calls.at(-1) as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual({ email: 'ada@example.com', claims: { plan: 'pro' } });

    $<HTMLTextAreaElement>('#claims-json').value = 'not json';
    $<HTMLButtonElement>('[data-call="setClaims"]').click();
    await expect.poll(() => $('#output').textContent).toContain('must be JSON');

    $<HTMLButtonElement>('[data-call="getClaims"]').click();
    await expect.poll(() => $('#output').textContent).toContain('Madauth.admin.getClaims(email)');
    expect($('#output').textContent).toContain('"userId": "usr_1"');

    $<HTMLButtonElement>('[data-call="getSession"]').click();
    await expect.poll(() => $('#output').textContent).toContain('Madauth.getSession()');
    expect($('#output').textContent).toContain('"isSuccess": true');
  });

  it('deletes the account only after a confirmation, and shows the result', async () => {
    vi.mocked(confirm).mockReturnValueOnce(false);
    $<HTMLButtonElement>('[data-call="deleteAccount"]').click();
    await expect.poll(() => $('#output').textContent).toBe('Madauth.deleteAccount()\nCancelled.');
    expect($('#sign-in').hidden).toBe(true);

    $<HTMLButtonElement>('[data-call="deleteAccount"]').click();

    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    expect($('#api').hidden).toBe(true);
    expect(sessionUser).toBeNull();
    expect($('#output').textContent).toContain('Madauth.deleteAccount()');
    expect($('#output').textContent).toContain('"isSuccess": true');
  });

  it('switches between light and dark theme when the theme button is clicked', () => {
    const root = document.documentElement;
    const toggle = $<HTMLButtonElement>('#theme-toggle');
    const initial = root.dataset.theme!;
    const other = initial === 'dark' ? 'light' : 'dark';
    expect(['light', 'dark']).toContain(initial);
    expect(toggle.getAttribute('aria-label')).toBe(`Switch to ${other} theme`);

    toggle.click();

    expect(root.dataset.theme).toBe(other);
    expect(toggle.getAttribute('aria-label')).toBe(`Switch to ${initial} theme`);

    toggle.click();

    expect(root.dataset.theme).toBe(initial);
  });
});
