// The admin dialog, Madauth.showAdminDialog(): the server's sign-in providers. See "Providers" in docs/server.md.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import type { MadauthLogin } from './madauth-login.js';
import { Password } from './providers/password.js';
import { SERVER, fakeServer, grace, resetAll, settle, type FakeServer } from './test-helpers.js';

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});
afterEach(resetAll);

const login = (): MadauthLogin | null => document.querySelector('madauth-login');
const $ = <T extends HTMLElement = HTMLElement>(selector: string) => login()!.shadowRoot!.querySelector<T>(selector);
const $$ = (selector: string) => [...login()!.shadowRoot!.querySelectorAll<HTMLElement>(selector)];
/** The text of an element, with the whitespace of the template collapsed. */
const text = (selector: string) => $(selector)!.textContent.replace(/\s+/g, ' ').trim();

async function click(selector: string): Promise<void> {
  const element = $<HTMLButtonElement>(selector);
  if (!element) throw new Error(`No ${selector}`);
  element.click();
  await settle();
}

/** Types into a field of the form, as the admin does. */
async function type(name: string, value: string): Promise<void> {
  const field = $<HTMLInputElement>(`form.provider-form [name="${name}"]`)!;
  field.value = value;
  field.dispatchEvent(new Event('input', { bubbles: true }));
  await settle();
}

async function tick(name: string, checked: boolean): Promise<void> {
  const box = $<HTMLInputElement>(`form.provider-form input[name="${name}"]`)!;
  box.checked = checked;
  box.dispatchEvent(new Event('change', { bubbles: true }));
  await settle();
}

async function save(): Promise<void> {
  $<HTMLFormElement>('form.provider-form')!.requestSubmit();
  await settle();
}

const rows = () => $$('[data-provider]').map((row) => row.textContent.replace(/\s+/g, ' ').trim());
const sent = (server: FakeServer, path: string) => server.requests.filter((r) => r.path === path).map((r) => r.body);

/** Grace, an admin, signed in, on a server with Google and `oidc`; resolves to the pending call. */
async function openAdmin(server = fakeServer()) {
  server.user ??= { ...grace, claims: { roles: ['admin'] } };
  server.claims.set(grace.email!, { roles: ['admin'] });
  await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });
  const result = Madauth.showAdminDialog();
  await settle();
  return { server, result };
}

const GITLAB = { id: 'gitlab', name: 'GitLab', secondFactor: 'none' as const, on: true, issuer: 'https://gitlab.com', clientId: 'gl-client' };

describe('<madauth-login> for admins: the sign-in providers', () => {
  it('DA1: lists the providers with their state, adds an OpenID Connect provider with its callback URL, switched on, and resolves when closed', async () => {
    const { server, result } = await openAdmin();

    expect(text('h2')).toBe('Sign-in providers');
    expect(rows()).toEqual(['Google Google · On, no second factor']);
    await click('[data-action="add-provider"]');
    expect(text('h2')).toBe('Add a provider');
    // Google is there already: GitHub and OpenID Connect are left.
    expect($$('[data-kind]').map((row) => row.dataset.kind)).toEqual(['github', 'oidc']);
    await click('[data-kind="oidc"]');
    expect(text('h2')).toBe('Add OpenID Connect');

    // The callback URL to register at the provider follows the id as it is typed.
    expect(text('.callback-url')).toBe(`${SERVER}/auth/providers/<id>/callback`);
    await type('id', 'gitlab');
    expect(text('.callback-url')).toBe(`${SERVER}/auth/providers/gitlab/callback`);
    await type('name', 'GitLab');
    await type('issuer', 'https://gitlab.com');
    await type('clientId', 'gl-client');
    await type('clientSecret', 'gl-secret');
    await type('scopes', 'read_user');
    expect($('select[name="secondFactor"]')).toBeNull();
    await tick('on', true);
    $<HTMLSelectElement>('select[name="secondFactor"]')!.value = 'optional';
    $('select[name="secondFactor"]')!.dispatchEvent(new Event('change', { bubbles: true }));
    expect(text('form.provider-form .submit')).toBe('Add GitLab');
    await save();

    expect(text('h2')).toBe('Sign-in providers');
    expect(text('.notice')).toBe('Added.');
    expect(rows()).toEqual(['Google Google · On, no second factor', 'GitLab OpenID Connect · gitlab · On, second factor optional']);
    expect(sent(server, '/auth/admin/providers/add')).toEqual([
      { kind: 'oidc', id: 'gitlab', name: 'GitLab', issuer: 'https://gitlab.com', clientId: 'gl-client', clientSecret: 'gl-secret', scopes: 'read_user', trustEmail: false },
    ]);
    // The settings go back with every method as it was, and the new one on.
    expect(sent(server, '/auth/admin/settings/set').at(-1)).toMatchObject({
      methods: { google: { allowAsSignInMethod: true, secondFactor: 'none' }, password: { allowAsSignInMethod: true }, gitlab: { allowAsSignInMethod: true, secondFactor: 'optional' } },
    });

    await click('[data-action="done"]');
    expect(await result).toEqual({ isSuccess: true });
  });

  it('DA2: changes only what changed, keeps the secret when it is left empty, and switches the provider off', async () => {
    const server = fakeServer();
    server.oidc = [{ ...GITLAB }];
    await openAdmin(server);

    await click('[data-provider="gitlab"]');
    expect(text('h2')).toBe('GitLab');
    // The id and the issuer can't change.
    expect($('input[name="id"]')).toBeNull();
    expect(text('.issuer')).toBe('https://gitlab.com');
    expect(text('.callback-url')).toBe(`${SERVER}/auth/providers/gitlab/callback`);
    expect($<HTMLInputElement>('input[name="on"]')!.checked).toBe(true);
    await type('name', 'GitLab EE');
    await tick('on', false);
    await save();

    expect(text('.notice')).toBe('Saved.');
    expect(sent(server, '/auth/admin/providers/update')).toEqual([{ id: 'gitlab', name: 'GitLab EE' }]);
    expect(Object.keys((sent(server, '/auth/admin/settings/set').at(-1) as { methods: object }).methods)).not.toContain('gitlab');
    expect(rows()).toContain('GitLab EE OpenID Connect · gitlab · Off');

    // Nothing changed: nothing is sent.
    await click('[data-provider="gitlab"]');
    await save();
    expect(sent(server, '/auth/admin/providers/update')).toHaveLength(1);
    expect(sent(server, '/auth/admin/settings/set')).toHaveLength(1);
  });

  it('DA3: a removal is confirmed with how many users sign in with the provider alone, counted before anything is removed', async () => {
    const server = fakeServer();
    server.oidc = [{ ...GITLAB }];
    server.usersAlone.gitlab = 2;
    await openAdmin(server);

    await click('[data-provider="gitlab"]');
    await click('[data-action="remove-provider"]');
    expect(text('h2')).toBe('Remove GitLab?');
    expect(text('.lead')).toBe('2 users sign in with it alone and can’t sign in until it is back, or an admin resets their sign-in.');
    expect(sent(server, '/auth/admin/providers/remove')).toEqual([{ id: 'gitlab', dryRun: true }]);
    expect(server.oidc).toHaveLength(1);

    await click('[data-action="back-to-provider"]');
    expect(text('h2')).toBe('GitLab');
    await click('[data-action="remove-provider"]');
    await click('[data-action="confirm-remove"]');

    expect(text('.notice')).toBe('Removed.');
    expect(server.oidc).toEqual([]);
    expect(rows()).toEqual(['Google Google · On, no second factor']);
  });

  it('DA4: a user who is no admin, or nobody, gets the error and no dialog', async () => {
    const server = fakeServer();
    server.user = grace;
    await Madauth.initialize({ serverUrl: SERVER, providers: [new Password()] });

    expect(await Madauth.showAdminDialog()).toMatchObject({ isSuccess: false, error: { code: 'forbidden' } });
    expect(login()?.shadowRoot?.querySelector('dialog')?.open ?? false).toBe(false);
    await Madauth.signOut();
    expect(await Madauth.showAdminDialog()).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
  });

  it('DA5: a change that needs a recent sign-in goes through the sign-in and back to the form, with what was typed', async () => {
    const server = fakeServer();
    server.accounts.get(grace.email!)!.verified = true;
    server.staleSignIn = true;
    await openAdmin(server);
    await click('[data-action="add-provider"]');
    await click('[data-kind="github"]');
    await type('clientId', 'Ov23li');
    await type('clientSecret', 'gh-secret');
    await save();

    expect($('.error')!.dataset.code).toBe('reauth_required');
    expect(text('.error')).toContain('sign in again to change the providers');
    await click('[data-action="sign-in-again"]');
    server.staleSignIn = false;
    $<HTMLInputElement>('form.signin input[name="email"]')!.value = 'grace@example.com';
    $<HTMLInputElement>('form.signin input[name="password"]')!.value = 'correct horse battery';
    $<HTMLFormElement>('form.signin')!.requestSubmit();
    await settle();

    expect(text('h2')).toBe('Add GitHub');
    expect($<HTMLInputElement>('input[name="clientId"]')!.value).toBe('Ov23li');
    await save();
    expect(text('.notice')).toBe('Added.');
    expect(sent(server, '/auth/admin/providers/add').at(-1)).toEqual({ kind: 'github', clientId: 'Ov23li', clientSecret: 'gh-secret' });
  });

  it('DA6: shows what the server refused, and a provider added before its settings were refused is changed when saved again', async () => {
    const server = fakeServer();
    server.settingsRefused = 'A policy needs a second factor that is on: passkeys, the app or SMS codes.';
    await openAdmin(server);
    await click('[data-action="add-provider"]');
    await click('[data-kind="github"]');
    await type('clientId', 'Ov23li');
    await type('clientSecret', 'gh-secret');
    await tick('on', true);
    await save();

    expect(text('.error')).toBe('A policy needs a second factor that is on: passkeys, the app or SMS codes.');
    expect(text('h2')).toBe('GitHub');
    server.settingsRefused = undefined;
    await save();
    expect(text('.notice')).toBe('Saved.');
    expect(sent(server, '/auth/admin/providers/add')).toHaveLength(1);
    expect(rows()).toContain('GitHub GitHub · On, no second factor');
  });

  it('DA7: speaks the dialog’s language', async () => {
    const server = fakeServer();
    server.oidc = [{ ...GITLAB, on: false }];
    server.usersAlone.gitlab = 1;
    await openAdmin(server);
    Madauth.setLocale('de');
    await settle();

    expect(text('h2')).toBe('Anmeldeanbieter');
    expect(rows()).toContain('GitLab OpenID Connect · gitlab · Aus');
    await click('[data-provider="gitlab"]');
    await click('[data-action="remove-provider"]');
    expect(text('.lead')).toBe('1 Nutzer meldet sich nur damit an und kann sich nicht anmelden, bis er wieder da ist oder ein Admin seine Anmeldung zurücksetzt.');
  });
});
