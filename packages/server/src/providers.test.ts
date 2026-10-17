// Sign-in providers in the store: see "Providers" in docs/server.md.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createLocalKeyService } from './key-service.js';
import { generateSigningKey } from './keys.js';
import { PROVIDERS_SETTING, Providers, importProviders, parseProviderFields, parseProviderKind } from './providers.js';
import { Settings } from './settings.js';
import { createSqliteAdapter } from './store/sqlite.js';
import { CLIENT_ID, keyService, passwordApp, setMethods } from './test/helpers.js';

const GOOGLE_ID = '123-test.apps.googleusercontent.com';

afterEach(() => {
  vi.restoreAllMocks();
});

function providers(keys = keyService) {
  const store = createSqliteAdapter(':memory:');
  const settings = new Settings(store);
  return { store, settings, providers: new Providers(settings, keys) };
}

describe('checking what an admin sends', () => {
  it('PV1: Google and GitHub have their kind as their id', () => {
    expect(parseProviderKind({ kind: 'google' })).toEqual({ kind: 'google', id: 'google' });
    expect(parseProviderKind({ kind: 'github', id: 'github' })).toEqual({ kind: 'github', id: 'github' });
    expect(parseProviderKind({ kind: 'gitlab' })).toMatchObject({ error: 'invalid_provider' });
    expect(parseProviderKind({ kind: 'google', id: 'work' })).toMatchObject({ error: 'invalid_provider', message: expect.stringContaining('"google"') });
  });

  it("PV2: checks each kind's client ID and secret, and refuses fields it doesn't have", () => {
    expect(parseProviderFields('google', { clientId: GOOGLE_ID }, true)).toEqual({ clientId: GOOGLE_ID });
    expect(parseProviderFields('google', { clientId: GOOGLE_ID, clientSecret: 's', name: ' Google Workspace ' }, true)).toEqual({
      clientId: GOOGLE_ID,
      clientSecret: 's',
      name: 'Google Workspace',
    });
    expect(parseProviderFields('google', { clientSecret: null }, false)).toEqual({ clientSecret: null });
    expect(parseProviderFields('github', { clientId: 'Ov23liAbc', clientSecret: 'gh-secret' }, true)).toEqual({ clientId: 'Ov23liAbc', clientSecret: 'gh-secret' });

    for (const [kind, data, adding] of [
      ['google', {}, true],
      ['google', { clientId: 'nope' }, true],
      ['google', { clientId: GOOGLE_ID, name: '' }, true],
      ['google', { clientId: GOOGLE_ID, clientSecret: '' }, true],
      ['google', { clientId: GOOGLE_ID, scopes: 'email' }, true],
      ['github', { clientId: 'Ov23liAbc' }, true],
      ['github', { clientSecret: null }, false],
      ['github', { clientId: 'has space', clientSecret: 's' }, true],
    ] as const) {
      expect(parseProviderFields(kind, data, adding)).toMatchObject({ error: 'invalid_provider', message: expect.any(String) });
    }
  });
});

describe('the providers in the store', () => {
  it('PV3: adds, lists, changes and removes providers, once each', async () => {
    const { providers: p } = providers();
    expect(await p.list()).toEqual([]);

    const { provider: google } = (await p.add('google', 'google', { clientId: GOOGLE_ID }, 'ada@example.com')) as { provider: { id: string } };
    expect(google).toMatchObject({ id: 'google', kind: 'google', name: 'Google', clientId: GOOGLE_ID, secret: null });
    expect(await p.add('google', 'google', { clientId: GOOGLE_ID }, null)).toEqual({ error: 'provider_exists' });
    await p.add('github', 'github', { clientId: 'Ov23liAbc', clientSecret: 'gh-secret', name: 'GitHub Enterprise' }, null);
    expect((await p.list()).map((x) => x.id)).toEqual(['google', 'github']);

    const changed = await p.update('github', { name: 'GitHub' }, null);
    expect(changed).toMatchObject({ provider: { id: 'github', name: 'GitHub', clientId: 'Ov23liAbc' } });
    expect(await p.update('gitlab', { name: 'x' }, null)).toEqual({ error: 'provider_not_found' });

    expect(await p.remove('google', null)).toMatchObject({ provider: { id: 'google' } });
    expect(await p.remove('google', null)).toEqual({ error: 'provider_not_found' });
    expect((await p.list()).map((x) => x.id)).toEqual(['github']);
  });

  it('PV4: keeps the client secret encrypted by the key service, and reads it back', async () => {
    const { providers: p, store } = providers();
    await p.add('github', 'github', { clientId: 'Ov23liAbc', clientSecret: 'gh-secret' }, null);

    const record = await store.findOne('setting', { id: PROVIDERS_SETTING });
    expect(String(record?.value)).not.toContain('gh-secret');
    const [github] = await p.list();
    expect(await p.clientSecret(github!)).toBe('gh-secret');

    await p.update('github', { clientSecret: 'new-secret' }, null);
    expect(await p.clientSecret((await p.list())[0]!)).toBe('new-secret');
    await p.add('google', 'google', { clientId: GOOGLE_ID, clientSecret: 'g' }, null);
    await p.update('google', { clientSecret: null }, null);
    expect((await p.list())[1]!.secret).toBeNull();
  });

  it('PV5: moves a secret to the newest key at its next use, and says when no key opens it', async () => {
    const oldKey = await generateSigningKey();
    const newKey = await generateSigningKey();
    const store = createSqliteAdapter(':memory:');
    const settings = new Settings(store);
    await new Providers(settings, await createLocalKeyService([oldKey])).add('github', 'github', { clientId: 'Ov23liAbc', clientSecret: 'gh-secret' }, null);

    const rotated = new Providers(settings, await createLocalKeyService([newKey, oldKey]));
    const before = (await rotated.list())[0]!;
    expect(await rotated.clientSecret(before)).toBe('gh-secret');
    const after = (await rotated.list())[0]!;
    expect(after.secret).not.toBe(before.secret);
    // Only the newest key is needed now.
    expect(await new Providers(settings, await createLocalKeyService([newKey])).clientSecret(after)).toBe('gh-secret');

    vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await new Providers(settings, await createLocalKeyService([await generateSigningKey()])).clientSecret(after)).toBeNull();
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('"github"'));
  });

  it("PV6: leaves out a stored provider it doesn't know, and warns once", async () => {
    const { providers: p, settings } = providers();
    await p.add('google', 'google', { clientId: GOOGLE_ID }, null);
    await settings.set(PROVIDERS_SETTING, [...(await p.list()), { id: 'gitlab', kind: 'gitlab' }], null);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

    expect((await p.list()).map((x) => x.id)).toEqual(['google']);
    await p.list();
    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe('Google and GitHub from the environment, as before 0.7', () => {
  it('PV7: become providers once, and are ignored when the store has one; the log says to remove them', async () => {
    const { providers: p } = providers();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

    await importProviders(p, { google: { clientId: GOOGLE_ID, clientSecret: 'g-secret' }, github: { clientId: 'Ov23liAbc', clientSecret: 'gh-secret' } });
    const [google, github] = await p.list();
    expect(google).toMatchObject({ id: 'google', clientId: GOOGLE_ID });
    expect(await p.clientSecret(google!)).toBe('g-secret');
    expect(await p.clientSecret(github!)).toBe('gh-secret');
    expect(warn.mock.calls.map((call) => String(call[0]))).toEqual([
      expect.stringContaining('GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are now the Google provider in the store'),
      expect.stringContaining('GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET are now the GitHub provider in the store'),
    ]);

    // An admin changed it since: the variables don't count any more.
    await p.update('google', { name: 'Google Workspace' }, 'ada@example.com');
    warn.mockClear();
    await importProviders(p, { google: { clientId: 'other.apps.googleusercontent.com' } });
    expect((await p.list())[0]).toMatchObject({ clientId: GOOGLE_ID, name: 'Google Workspace' });
    expect(String(warn.mock.calls[0]![0])).toContain('GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are ignored');
  });

  it('PV9: a failed import is logged and leaves the requests working, without the providers', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const failing = { ...keyService, encrypt: async () => Promise.reject(new Error('KMS is down')) };
    const { app } = passwordApp({ keyService: failing, google: { clientId: CLIENT_ID, clientSecret: 'g-secret' } });

    const res = await app.request('/auth/config');
    expect(res.status).toBe(200);
    expect(((await res.json()) as { google: unknown }).google).toBeNull();
    expect(error).toHaveBeenCalledWith(expect.stringContaining('KMS is down'));
  });

  it('PV8: a provider in the store applies at the next request, on a server that started without it', async () => {
    const { app, store } = passwordApp({ google: undefined });
    const config = async () => (await (await app.request('/auth/config')).json()) as { google: { clientId: string; codeFlow: boolean } | null };
    expect((await config()).google).toBeNull();
    expect((await app.request('/auth/providers/google/start')).status).toBe(404);

    await new Providers(new Settings(store), keyService).add('google', 'google', { clientId: CLIENT_ID, clientSecret: 'g-secret' }, null);
    await setMethods(store, { google: { allowAsSignInMethod: true, secondFactor: 'none' }, password: { allowAsSignInMethod: true, secondFactor: 'none' } });

    expect((await config()).google).toEqual({ clientId: CLIENT_ID, codeFlow: true, secondFactor: 'none' });
    const start = await app.request(`/auth/providers/google/start?return_to=${encodeURIComponent('https://app.example.com/page')}`);
    expect(start.status).toBe(302);
    expect(new URL(start.headers.get('location')!).searchParams.get('client_id')).toBe(CLIENT_ID);
  });
});
