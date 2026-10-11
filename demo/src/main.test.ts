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
/** The same for claims/get and totp/remove: late responses, after the user changed. */
let holdClaims: Promise<void> | undefined;
let holdRemove: Promise<void> | undefined;
/** Whether the signed-in user has the authenticator app. */
let authenticator = false;

const $ = <T extends HTMLElement = HTMLElement>(selector: string) => document.querySelector<T>(selector)!;
// The API explorer: a row per method, opened to its parameters, the request and the response.
const row = (id: string) => $<HTMLLIElement>(`.api-method[data-call="${id}"]`);
const detail = (id: string) => row(id).querySelector<HTMLElement>('.api-detail')!;
/** Opens a row (a click on an open row would close it). */
const open = (id: string) => {
  if (detail(id).hidden) row(id).querySelector<HTMLButtonElement>('.api-row')!.click();
};
const execute = (id: string) => row(id).querySelector<HTMLButtonElement>('.api-execute')!;
const request = (id: string) => row(id).querySelector('.api-request')!.textContent;
const response = (id: string) => row(id).querySelector('.api-response')!.textContent;
const param = (id: string, name: string) => row(id).querySelector<HTMLInputElement>(`[data-param="${name}"]`)!;
/** Sets a field as a user would: the page keeps the request box in step through the input event. */
const type = (field: HTMLInputElement | HTMLTextAreaElement, value: string) => {
  field.value = value;
  field.dispatchEvent(new Event('input', { bubbles: true }));
};
const changed = (field: HTMLElement) => field.dispatchEvent(new Event('change', { bubbles: true }));

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
        await holdRemove;
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
        await holdClaims;
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
  it('shows only a sign-in button while signed out, besides the info buttons', () => {
    const buttons = [...document.querySelectorAll<HTMLButtonElement>('main button:not(.info)')].filter((b) => !b.closest('[hidden]'));
    expect(buttons).toHaveLength(1);
    expect(buttons[0].textContent).toBe('Sign in');
  });

  it('marks One Tap / FedCM as the current demo and links to the redirect demo', () => {
    const links = [...document.querySelectorAll<HTMLAnchorElement>('#flow a')];
    expect(links.map((a) => a.dataset.flow)).toEqual(['fedcm', 'redirect']);
    expect(links[0].getAttribute('aria-current')).toBe('page');
    expect(links[1].getAttribute('aria-current')).toBeNull();
    expect(new URL(links[1].href).search).toBe('?google=redirect');
    expect($('#flow-note').hidden).toBe(true);
    // The explanation of the two flows is behind the info button, with the current flow marked.
    expect($('#flow-info').hidden).toBe(true);
    const info = $<HTMLButtonElement>('.google-flow .info');
    info.click();
    expect($('#flow-info').hidden).toBe(false);
    expect(info.getAttribute('aria-expanded')).toBe('true');
    expect($('.flow-description[data-flow="fedcm"]').getAttribute('aria-current')).toBe('true');
    expect($('.flow-description[data-flow="fedcm"]').textContent).toContain('One Tap / FedCM (current)');
    expect($('.flow-description[data-flow="redirect"]').getAttribute('aria-current')).toBeNull();
    expect($('.flow-description[data-flow="redirect"]').textContent).not.toContain('(current)');
    expect($('#flow-info').textContent).toContain('new GoogleFedcm()');
    info.click();
    expect($('#flow-info').hidden).toBe(true);
    expect(info.getAttribute('aria-expanded')).toBe('false');
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
    // The claims explanation is behind its info button.
    expect($('#claims-info').hidden).toBe(true);
    $<HTMLButtonElement>('.claims .info').click();
    expect($('#claims-info').hidden).toBe(false);
    expect($('#claims-info').textContent).toContain('session token');
    expect($('#claims-info').textContent).toContain('admin');
    expect($('#api').hidden).toBe(false);
    // The admin fields start with the signed-in user's own address, and an admin's checkboxes with the
    // server's settings; only then can they be sent back.
    expect(param('getClaims', 'email').value).toBe('ada@example.com');
    expect(param('setClaims', 'email').value).toBe('ada@example.com');
    expect($('#admin-note').hidden).toBe(true);
    await expect.poll(() => execute('setSettings').disabled).toBe(false);
    expect($('#settings-unloaded').hidden).toBe(true);
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

    // A row opens to its request; executing it shows the response.
    expect(detail('getSession').hidden).toBe(true);
    open('getSession');
    expect(detail('getSession').hidden).toBe(false);
    expect(request('getSession')).toBe('Madauth.getSession()\n(no arguments)');
    execute('getSession').click();
    await expect.poll(() => response('getSession')).toContain('"isSuccess": true');
    type(param('getClaims', 'email'), 'someone@example.com');

    $<HTMLButtonElement>('#sign-out').click();

    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    expect($('#account').hidden).toBe(true);
    expect($('#api').hidden).toBe(true);
    // Nothing of the previous user stays for the next one: the rows are closed, the fields and responses empty.
    expect(param('getClaims', 'email').value).toBe('');
    expect(detail('getSession').hidden).toBe(true);
    expect(response('getSession')).toBe('');
    expect($('#totp-output').hidden).toBe(true);
    expect($('#output').textContent).toBe('');
    expect(execute('setSettings').disabled).toBe(true);
    expect($<HTMLInputElement>('#method-google').checked).toBe(false);
  });

  it('calls the session and admin API from the explorer: the request follows the parameters, the response is shown', async () => {
    gis.callback!({ credential: 'token' });
    await expect.poll(() => $('#api').hidden).toBe(false);
    await expect.poll(() => execute('setSettings').disabled).toBe(false);

    open('getSettings');
    expect(request('getSettings')).toBe('Madauth.admin.getSettings()\n(no arguments)');
    execute('getSettings').click();
    await expect.poll(() => response('getSettings')).toContain('"enabled": false');
    expect($<HTMLInputElement>('#method-google').checked).toBe(true);
    expect($<HTMLInputElement>('#method-password').checked).toBe(false);

    // The controls of setSettings are its parameters: the request changes with them, before anything is sent.
    open('setSettings');
    expect(request('setSettings')).toContain('"password": false');
    $<HTMLInputElement>('#method-password').checked = true;
    changed($('#method-password'));
    $<HTMLSelectElement>('#policy-password').value = 'required';
    changed($('#policy-password'));
    $<HTMLInputElement>('#method-totp').checked = true;
    changed($('#method-totp'));
    expect(request('setSettings')).toBe(
      `Madauth.admin.setSettings({ methods })\n${JSON.stringify({ methods: { google: { secondFactor: 'none' }, password: { secondFactor: 'required' }, totp: true } }, null, 2)}`,
    );
    execute('setSettings').click();
    await expect.poll(() => settings.password.enabled).toBe(true);
    expect(settings.password.secondFactor).toBe('required');
    expect(settings.totp.enabled).toBe(true);
    const [, sent] = [...vi.mocked(fetch).mock.calls].reverse().find(([url]: [unknown, RequestInit?]) => String(url).endsWith('/auth/admin/settings/set')) as [string, RequestInit];
    expect(JSON.parse(String(sent.body))).toEqual({
      methods: { google: { secondFactor: 'none' }, password: { secondFactor: 'required' }, totp: true },
    });
    await expect.poll(() => response('setSettings')).toContain('"secondFactor": "required"');
    expect(execute('setSettings').disabled).toBe(false);

    open('sessionReady');
    expect(request('sessionReady')).toBe('Madauth.sessionReady()\n(no arguments)');
    execute('sessionReady').click();
    await expect.poll(() => response('sessionReady')).toBe('true');

    open('setClaims');
    type(param('setClaims', 'claims'), '{ "plan": "pro" }');
    expect(request('setClaims')).toBe(`Madauth.admin.setClaims(email, claims)\n${JSON.stringify({ email: 'ada@example.com', claims: { plan: 'pro' } }, null, 2)}`);
    execute('setClaims').click();
    await expect.poll(() => response('setClaims')).toContain('"plan": "pro"');
    const [, init] = vi.mocked(fetch).mock.calls.at(-1) as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual({ email: 'ada@example.com', claims: { plan: 'pro' } });

    // Claims that are not JSON can't be sent: the request box says so, and Execute repeats it without a call.
    type(param('setClaims', 'claims'), 'not json');
    expect(request('setClaims')).toContain('must be JSON');
    const calls = vi.mocked(fetch).mock.calls.length;
    execute('setClaims').click();
    await expect.poll(() => response('setClaims')).toContain('must be JSON');
    expect(vi.mocked(fetch).mock.calls.length).toBe(calls);

    open('getClaims');
    expect(request('getClaims')).toBe(`Madauth.admin.getClaims(email)\n${JSON.stringify({ email: 'ada@example.com' }, null, 2)}`);
    execute('getClaims').click();
    await expect.poll(() => response('getClaims')).toContain('"userId": "usr_1"');

    // The two admin calls target the same address: typed into one, it is in the other as well.
    type(param('setClaims', 'claims'), '{ "plan": "pro" }');
    type(param('getClaims', 'email'), 'bob@example.com');
    expect(param('setClaims', 'email').value).toBe('bob@example.com');
    expect(request('setClaims')).toContain('"email": "bob@example.com"');
    type(param('setClaims', 'email'), 'ada@example.com');
    expect(param('getClaims', 'email').value).toBe('ada@example.com');
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
    // With the app, deleting the account takes a code: the open row says so right away.
    open('deleteAccount');
    expect($('[data-needs-authenticator]').hidden).toBe(false);
    expect(request('deleteAccount')).toContain('"code"');

    // Signing out forgets the app at once, before the next user's status arrives.
    $<HTMLButtonElement>('#sign-out').click();
    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    expect($('[data-needs-authenticator]').hidden).toBe(true);
    expect($('.authenticator .code-field').hidden).toBe(true);
    gis.callback!({ credential: 'token' });
    await expect.poll(() => $('#totp-status').textContent).toBe('Set up, 10 recovery codes left.');

    $<HTMLInputElement>('#totp-code').value = '000000';
    $<HTMLButtonElement>('[data-call="removeAuthenticator"]').click();
    await expect.poll(() => $('#output').textContent).toContain('code_invalid');
    expect($('#totp-output').hidden).toBe(false);
    expect($('#totp-status').textContent).toBe('Set up, 10 recovery codes left.');
    // Deleting the account then takes a code as well: the parameter appears.
    expect($('[data-needs-authenticator]').hidden).toBe(false);

    $<HTMLInputElement>('#totp-code').value = '123 456';
    $<HTMLButtonElement>('[data-call="removeAuthenticator"]').click();
    await expect.poll(() => $('#totp-status').textContent).toBe('Not set up.');
    expect($('[data-call="removeAuthenticator"]').hidden).toBe(true);
    // Without the app, deleteAccount's request follows at once.
    open('deleteAccount');
    expect($('[data-needs-authenticator]').hidden).toBe(true);
    expect(request('deleteAccount')).toBe('Madauth.deleteAccount()\n(no arguments)');
    const [, sent] = [...vi.mocked(fetch).mock.calls].reverse().find(([url]: [unknown, RequestInit?]) => String(url).endsWith('/auth/totp/remove')) as [string, RequestInit];
    expect(JSON.parse(String(sent.body))).toEqual({ code: '123456' });
  });

  it('deletes the account only after a confirmation, and shows the result below the sign-in button', async () => {
    open('deleteAccount');
    vi.mocked(confirm).mockReturnValueOnce(false);
    execute('deleteAccount').click();
    await expect.poll(() => response('deleteAccount')).toBe('Cancelled.');
    expect($('#sign-in').hidden).toBe(true);
    expect($('#last-response').hidden).toBe(true);

    execute('deleteAccount').click();

    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    expect($('#api').hidden).toBe(true);
    expect(sessionUser).toBeNull();
    // The API is gone with the session, so the result lands where the user can see it; the rows are clean.
    await expect.poll(() => $('#last-response').hidden).toBe(false);
    expect($('#last-response').textContent).toContain('Madauth.deleteAccount()');
    expect($('#last-response').textContent).toContain('"isSuccess": true');
    expect(response('deleteAccount')).toBe('');
  });

  it('tells a user without the role admin why the admin calls fail, and loads no settings for them', async () => {
    const { claims: _, ...bob } = { ...ada, id: 'usr_2', name: 'Bob', email: 'bob@example.com' };
    signInAs = bob;
    const requestsBefore = vi.mocked(fetch).mock.calls.length;
    gis.callback!({ credential: 'token' });

    await expect.poll(() => $('#api').hidden).toBe(false);
    // The previous user's deletion result is gone with the new sign-in.
    expect($('#last-response').hidden).toBe(true);
    expect($('#admin-note').hidden).toBe(false);
    expect($('#admin-note').textContent).toContain('forbidden');
    // The sentence about madauth.com is only for that host.
    expect($('#admin-note [data-hosted]').hidden).toBe(true);
    expect(execute('setSettings').disabled).toBe(true);
    open('setSettings');
    expect($('#settings-unloaded').hidden).toBe(false);
    expect(request('setSettings')).toContain('Call getSettings first.');
    const paths = vi.mocked(fetch).mock.calls.slice(requestsBefore).map(([url]) => new URL(String(url)).pathname);
    expect(paths).not.toContain('/auth/admin/settings/get');

    $<HTMLButtonElement>('#sign-out').click();
    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    signInAs = ada;
  });

  it('leaves the boxes as the user set them when setSettings is refused', async () => {
    gis.callback!({ credential: 'token' });
    await expect.poll(() => execute('setSettings').disabled).toBe(false);

    open('setSettings');
    $<HTMLInputElement>('#method-google').checked = false;
    $<HTMLInputElement>('#method-password').checked = false;
    $<HTMLInputElement>('#method-totp').checked = false;
    execute('setSettings').click();

    await expect.poll(() => response('setSettings')).toContain('invalid_settings');
    expect($<HTMLInputElement>('#method-google').checked).toBe(false);
    expect($<HTMLInputElement>('#method-password').checked).toBe(false);
    expect(execute('setSettings').disabled).toBe(false);

    $<HTMLButtonElement>('#sign-out').click();
    await expect.poll(() => $('#sign-in').hidden).toBe(false);
  });

  it('shows a late response below the sign-in button when nobody is signed in, and drops it once someone else is', async () => {
    gis.callback!({ credential: 'token' });
    await expect.poll(() => $('#api').hidden).toBe(false);
    let release!: () => void;
    holdClaims = new Promise((resolve) => (release = resolve));
    open('getClaims');
    execute('getClaims').click();
    expect(execute('getClaims').getAttribute('aria-disabled')).toBe('true');

    // Signed out before the answer: the user still sees it, below the sign-in button.
    $<HTMLButtonElement>('#sign-out').click();
    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    release();
    await expect.poll(() => $('#last-response').hidden).toBe(false);
    expect($('#last-response').textContent).toContain('Madauth.admin.getClaims(email)');
    expect($('#last-response').textContent).toContain('"userId": "usr_1"');
    expect(response('getClaims')).toBe('');
    expect(execute('getClaims').getAttribute('aria-disabled')).toBeNull();

    // Someone else signed in before the answer: it is not theirs, and it is dropped.
    gis.callback!({ credential: 'token' });
    await expect.poll(() => $('#api').hidden).toBe(false);
    expect($('#last-response').hidden).toBe(true);
    holdClaims = new Promise((resolve) => (release = resolve));
    open('getClaims');
    execute('getClaims').click();
    $<HTMLButtonElement>('#sign-out').click();
    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    const { claims: _, ...bob } = { ...ada, id: 'usr_2', name: 'Bob', email: 'bob@example.com' };
    signInAs = bob;
    gis.callback!({ credential: 'token' });
    await expect.poll(() => $('#api').hidden).toBe(false);
    release();
    holdClaims = undefined;
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect($('#last-response').hidden).toBe(true);
    expect(response('getClaims')).toBe('');

    // The account calls drop a late result the same way (it may hold recovery codes).
    authenticator = true;
    $<HTMLButtonElement>('#sign-out').click();
    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    signInAs = ada;
    gis.callback!({ credential: 'token' });
    await expect.poll(() => $('#totp-status').textContent).toBe('Set up, 10 recovery codes left.');
    holdRemove = new Promise((resolve) => (release = resolve));
    $<HTMLInputElement>('#totp-code').value = '123456';
    $<HTMLButtonElement>('[data-call="removeAuthenticator"]').click();
    $<HTMLButtonElement>('#sign-out').click();
    await expect.poll(() => $('#sign-in').hidden).toBe(false);
    release();
    holdRemove = undefined;
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect($('#totp-output').hidden).toBe(true);
    expect($('#output').textContent).toBe('');
    authenticator = false;
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
    expect(execute('setSettings').disabled).toBe(true);
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
