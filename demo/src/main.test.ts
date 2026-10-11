import { beforeAll, describe, expect, it, vi } from 'vitest';
import html from '../index.html?raw';

interface DemoUser {
  id: string;
  name: string;
  email: string;
  picture: string;
  claims?: Record<string, unknown>;
}

const ada = {
  id: 'usr_1',
  name: 'Ada Lovelace',
  email: 'ada@example.com',
  picture: 'https://example.com/ada.png',
  claims: { roles: ['admin'] },
} satisfies DemoUser;
let sessionUser: DemoUser | null = null;
/** Who the next Google sign-in signs in as. */
let signInAs: DemoUser = ada;
let settings = {
  google: { configured: true, enabled: true, secondFactor: 'none' },
  password: { configured: true, enabled: false, secondFactor: 'optional' },
  totp: { configured: true, enabled: false },
};
/** When set, the fake server answers settings/get only once it resolves. */
let holdSettings: Promise<void> | undefined;
/** Whether the signed-in user has the authenticator app. */
let authenticator = false;

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
        return json({
          google: { clientId: 'cid.apps.googleusercontent.com', codeFlow: false, secondFactor: 'none' },
          password: { minLength: 8, secondFactor: 'optional' },
          totp: { signIn: false, signUp: false },
          email: { verification: true },
        });
      case 'GET /auth/session':
        return sessionUser ? json({ user: sessionUser }) : json({ error: 'no_session' }, 401);
      case 'GET /auth/totp/status':
        return sessionUser ? json({ enabled: authenticator, recoveryCodesLeft: authenticator ? 10 : 0 }) : json({ error: 'no_session' }, 401);
      case 'POST /auth/totp/remove':
        if (body().code !== '123456') return json({ error: 'code_invalid', message: 'wrong' }, 401);
        authenticator = false;
        return json({});
      case 'POST /auth/google/nonce':
        return json({ nonce: 'n' });
      case 'POST /auth/google/verify':
        sessionUser = signInAs;
        return json({ user: signInAs });
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
        await holdSettings;
        return json({ methods: settings });
      case 'POST /auth/admin/settings/set': {
        // The list replaces what was on: a method that is not in it (or false) is off.
        const { methods } = body();
        const on = (value: unknown) => value === true || (!!value && typeof value === 'object');
        if (!on(methods.google) && !on(methods.password) && !on(methods.totp)) {
          return json({ error: 'invalid_settings', message: 'At least one sign-in method must stay on.' }, 400);
        }
        const policy = (value: { secondFactor?: string } | boolean | undefined) => (typeof value === 'object' && value.secondFactor) || 'none';
        settings = {
          google: { configured: true, enabled: on(methods.google), secondFactor: policy(methods.google) },
          password: { configured: true, enabled: on(methods.password), secondFactor: policy(methods.password) },
          totp: { configured: true, enabled: on(methods.totp) },
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
    expect($('#admin-note').hidden).toBe(true);
    await expect.poll(() => $<HTMLButtonElement>('[data-call="setSettings"]').disabled).toBe(false);
    expect($<HTMLInputElement>('#method-google').checked).toBe(true);
    expect($<HTMLInputElement>('#method-password').checked).toBe(false);
    expect($<HTMLSelectElement>('#policy-password').value).toBe('optional');
    expect($<HTMLInputElement>('#method-totp').checked).toBe(false);
    // The authenticator app: not set up yet, so only the setup is offered.
    await expect.poll(() => $('#totp-status').textContent).toBe('Not set up.');
    expect($('[data-call="setUpAuthenticator"]').hidden).toBe(false);
    expect($('[data-call="removeAuthenticator"]').hidden).toBe(true);
    expect($('.authenticator .code-field').hidden).toBe(true);
    expect($('#amr').textContent).toBe('');

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
    $<HTMLSelectElement>('#policy-password').value = 'required';
    $<HTMLInputElement>('#method-totp').checked = true;
    $<HTMLButtonElement>('[data-call="setSettings"]').click();
    await expect.poll(() => settings.password.enabled).toBe(true);
    expect(settings.password.secondFactor).toBe('required');
    expect(settings.totp.enabled).toBe(true);
    const [, sent] = [...vi.mocked(fetch).mock.calls].reverse().find(([url]: [unknown, RequestInit?]) => String(url).endsWith('/auth/admin/settings/set')) as [string, RequestInit];
    expect(JSON.parse(String(sent.body))).toEqual({
      methods: { google: { secondFactor: 'none' }, password: { secondFactor: 'required' }, totp: true },
    });
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

  it('shows the authenticator app as set up, and removes it with a code', async () => {
    authenticator = true;
    $<HTMLButtonElement>('#sign-out').click();
    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    gis.callback!({ credential: 'token' });

    await expect.poll(() => $('#totp-status').textContent).toBe('Set up, 10 recovery codes left.');
    expect($('[data-call="removeAuthenticator"]').hidden).toBe(false);
    expect($('[data-call="newRecoveryCodes"]').hidden).toBe(false);
    expect($('.authenticator .code-field').hidden).toBe(false);

    $<HTMLInputElement>('#totp-code').value = '000000';
    $<HTMLButtonElement>('[data-call="removeAuthenticator"]').click();
    await expect.poll(() => $('#output').textContent).toContain('code_invalid');
    expect($('#totp-status').textContent).toBe('Set up, 10 recovery codes left.');

    $<HTMLInputElement>('#totp-code').value = '123 456';
    $<HTMLButtonElement>('[data-call="removeAuthenticator"]').click();
    await expect.poll(() => $('#totp-status').textContent).toBe('Not set up.');
    expect($('[data-call="removeAuthenticator"]').hidden).toBe(true);
    const [, sent] = [...vi.mocked(fetch).mock.calls].reverse().find(([url]: [unknown, RequestInit?]) => String(url).endsWith('/auth/totp/remove')) as [string, RequestInit];
    expect(JSON.parse(String(sent.body))).toEqual({ code: '123456' });
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

  it('tells a user without the role admin why the admin calls fail, and loads no settings for them', async () => {
    const { claims: _, ...bob } = { ...ada, id: 'usr_2', name: 'Bob', email: 'bob@example.com' };
    signInAs = bob;
    const requestsBefore = vi.mocked(fetch).mock.calls.length;
    gis.callback!({ credential: 'token' });

    await expect.poll(() => $('#api').hidden).toBe(false);
    expect($('#admin-note').hidden).toBe(false);
    expect($('#admin-note').textContent).toContain('forbidden');
    // The sentence about madauth.com is only for that host.
    expect($('#admin-note [data-hosted]').hidden).toBe(true);
    expect($<HTMLButtonElement>('[data-call="setSettings"]').disabled).toBe(true);
    const paths = vi.mocked(fetch).mock.calls.slice(requestsBefore).map(([url]) => new URL(String(url)).pathname);
    expect(paths).not.toContain('/auth/admin/settings/get');

    $<HTMLButtonElement>('#sign-out').click();
    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    signInAs = ada;
  });

  it('leaves the boxes as the user set them when setSettings is refused', async () => {
    gis.callback!({ credential: 'token' });
    await expect.poll(() => $<HTMLButtonElement>('[data-call="setSettings"]').disabled).toBe(false);

    $<HTMLInputElement>('#method-google').checked = false;
    $<HTMLInputElement>('#method-password').checked = false;
    $<HTMLInputElement>('#method-totp').checked = false;
    $<HTMLButtonElement>('[data-call="setSettings"]').click();

    await expect.poll(() => $('#output').textContent).toContain('invalid_settings');
    expect($<HTMLInputElement>('#method-google').checked).toBe(false);
    expect($<HTMLInputElement>('#method-password').checked).toBe(false);
    expect($<HTMLButtonElement>('[data-call="setSettings"]').disabled).toBe(false);

    $<HTMLButtonElement>('#sign-out').click();
    await expect.poll(() => $('#sign-in').hidden).toBe(false);
  });

  it('drops settings that arrive after the admin signed out', async () => {
    let release!: () => void;
    holdSettings = new Promise((resolve) => (release = resolve));
    gis.callback!({ credential: 'token' });
    await expect.poll(() => $('#api').hidden).toBe(false);

    $<HTMLButtonElement>('#sign-out').click();
    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    release();
    holdSettings = undefined;
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect($<HTMLInputElement>('#method-google').checked).toBe(false);
    expect($<HTMLButtonElement>('[data-call="setSettings"]').disabled).toBe(true);
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
