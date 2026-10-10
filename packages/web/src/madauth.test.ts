import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import type { SignInProvider } from './providers/provider.js';
import { GoogleFedcm } from './providers/google-fedcm.js';
import { GoogleRedirect } from './providers/google-redirect.js';
import { fail, ok, type MadauthUser } from './result.js';
import { SERVER, ada, fakeGis, fakeServer, resetAll, settle } from './test-helpers.js';

/** A provider without UI that reports what the core does with it. */
function stubProvider(overrides: Partial<SignInProvider> = {}) {
  const provider = {
    method: 'google' as const,
    setup: vi.fn(async () => ok()),
    onSignedOut: vi.fn(),
    ...overrides,
  };
  return provider;
}

let errorLog: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  resetAll();
  errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(resetAll);

describe('Madauth.initialize', () => {
  it('I1: reports invalid options instead of throwing', async () => {
    fakeServer();

    const badUrl = await Madauth.initialize({ serverUrl: 'not a url', providers: [] });
    expect(badUrl).toEqual({ isSuccess: false, error: { code: 'invalid_options', message: expect.stringContaining('serverUrl') } });

    const twoGoogle = await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm(), new GoogleRedirect()] });
    expect(twoGoogle).toMatchObject({ isSuccess: false, error: { code: 'invalid_options' } });

    // @ts-expect-error: missing providers
    expect(await Madauth.initialize({})).toMatchObject({ isSuccess: false, error: { code: 'invalid_options' } });
  });

  it('I2: logs failures to the console as well as returning them', async () => {
    const server = fakeServer();
    server.down = true;

    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    expect(result).toMatchObject({ isSuccess: false, error: { code: 'network' } });
    expect(errorLog).toHaveBeenCalledWith('[madauth]', 'network', expect.stringContaining(SERVER));
  });

  it('I2: reports a server URL that answers with a page instead of JSON', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<!doctype html>', { status: 200 })));

    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    expect(result).toMatchObject({ isSuccess: false, error: { code: 'unknown', message: expect.stringContaining(SERVER) } });
    expect(await Madauth.getSession()).toMatchObject({ isSuccess: false, error: { code: 'unknown' } });
  });

  it('I3: uses the page origin when serverUrl is omitted', async () => {
    const server = fakeServer();

    expect(await Madauth.initialize({ providers: [] })).toEqual({ isSuccess: true, leftOut: [] });

    expect(server.requests[0].url).toBe('https://app.example.com/auth/config');
  });

  it('I4: lets other methods wait for initialize', async () => {
    const server = fakeServer();
    server.user = ada;

    void Madauth.initialize({ serverUrl: SERVER, providers: [] });
    const session = await Madauth.getSession();

    expect(session).toEqual({ isSuccess: true, user: ada });
    expect(server.requests.map((r) => r.path)).toEqual(['/auth/config', '/auth/session', '/auth/session']);
  });

  it('I5: methods fail with not_initialized before initialize', async () => {
    fakeServer();

    expect(await Madauth.signIn()).toMatchObject({ isSuccess: false, error: { code: 'not_initialized' } });
    expect(await Madauth.getSession()).toMatchObject({ isSuccess: false, error: { code: 'not_initialized' } });
    expect(await Madauth.signOut()).toMatchObject({ isSuccess: false, error: { code: 'not_initialized' } });
  });

  it('I6: calling initialize again replaces the configuration', async () => {
    const server = fakeServer();
    await Madauth.initialize({ serverUrl: 'https://a.example.com', providers: [] });
    await Madauth.initialize({ serverUrl: 'https://b.example.com/', providers: [] });

    await Madauth.getSession();

    expect(server.requests.at(-1)!.url).toBe('https://b.example.com/auth/session');
  });

  it('I6: an initialize that was replaced does not set up its providers', async () => {
    fakeServer();
    const replaced = stubProvider();
    const current = stubProvider();

    const first = Madauth.initialize({ serverUrl: SERVER, providers: [replaced] });
    const second = Madauth.initialize({ serverUrl: SERVER, providers: [current] });

    expect(await first).toMatchObject({ isSuccess: false, error: { code: 'cancelled' } });
    expect(await second).toEqual({ isSuccess: true, leftOut: [] });
    expect(replaced.setup).not.toHaveBeenCalled();
    expect(current.setup).toHaveBeenCalledOnce();
  });

  it('I12: fails when a provider’s setup fails', async () => {
    fakeServer();
    const provider = stubProvider({ setup: async () => fail('gis_load_failed', 'boom') });

    const result = await Madauth.initialize({ serverUrl: SERVER, providers: [provider] });

    expect(result).toEqual({ isSuccess: false, error: { code: 'gis_load_failed', message: 'boom' } });
    expect(await Madauth.getSession()).toMatchObject({ isSuccess: false, error: { code: 'gis_load_failed' } });
  });
});

describe('auth state', () => {
  it('I7: notifies listeners registered before and after initialize, until they unsubscribe', async () => {
    const server = fakeServer();
    server.user = ada;
    const early = vi.fn();
    const late = vi.fn();
    Madauth.onAuthStateChanged(early);

    await Madauth.initialize({ serverUrl: SERVER, providers: [stubProvider()] });
    const unsubscribeLate = Madauth.onAuthStateChanged(late);
    await settle();

    expect(early).toHaveBeenCalledExactlyOnceWith(ada);
    expect(late).toHaveBeenCalledExactlyOnceWith(ada);

    unsubscribeLate();
    await Madauth.signOut();

    expect(early).toHaveBeenLastCalledWith(null);
    expect(late).toHaveBeenCalledOnce();
  });

  it('I8: currentUser follows the state', async () => {
    const server = fakeServer();
    server.user = ada;
    expect(Madauth.currentUser).toBeNull();

    await Madauth.initialize({ serverUrl: SERVER, providers: [] });
    expect(Madauth.currentUser).toEqual(ada);

    await Madauth.signOut();
    expect(Madauth.currentUser).toBeNull();
  });

  it('notifies listeners when a provider signs the user in outside the dialog', async () => {
    fakeServer();
    let signedIn!: (user: MadauthUser) => void;
    const provider = stubProvider({
      setup: async (ctx) => {
        signedIn = ctx.signedIn;
        return ok();
      },
    });
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    await Madauth.initialize({ serverUrl: SERVER, providers: [provider] });

    signedIn(ada);

    expect(listener).toHaveBeenLastCalledWith(ada);
    expect(Madauth.currentUser).toEqual(ada);
  });

  it('I11: getSession and signOut call the server with credentials', async () => {
    const server = fakeServer();
    const provider = stubProvider();
    await Madauth.initialize({ serverUrl: SERVER, providers: [provider] });

    expect(await Madauth.getSession()).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });
    server.user = ada;
    expect(await Madauth.getSession()).toEqual({ isSuccess: true, user: ada });
    expect(await Madauth.signOut()).toEqual({ isSuccess: true });

    const logout = server.requests.find((r) => r.path === '/auth/logout')!;
    expect(logout).toMatchObject({ method: 'POST', url: `${SERVER}/auth/logout`, credentials: 'include' });
    expect(server.requests.every((r) => r.credentials === 'include')).toBe(true);
    expect(provider.onSignedOut).toHaveBeenCalledOnce();
  });
});

describe('Madauth.deleteAccount', () => {
  it('deletes the account on the server and signs the user out', async () => {
    const server = fakeServer();
    server.user = ada;
    const provider = stubProvider();
    const listener = vi.fn();
    await Madauth.initialize({ serverUrl: SERVER, providers: [provider] });
    Madauth.onAuthStateChanged(listener);

    expect(await Madauth.deleteAccount()).toEqual({ isSuccess: true });

    expect(server.requests.at(-1)).toMatchObject({ method: 'POST', url: `${SERVER}/auth/account/delete`, credentials: 'include' });
    expect(Madauth.currentUser).toBeNull();
    expect(listener).toHaveBeenLastCalledWith(null);
    expect(provider.onSignedOut).toHaveBeenCalledOnce();
  });

  it('reports no_session when nobody is signed in, and keeps the user when the server can not be reached', async () => {
    const server = fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });
    expect(await Madauth.deleteAccount()).toMatchObject({ isSuccess: false, error: { code: 'no_session' } });

    server.user = ada;
    await Madauth.getSession();
    server.down = true;
    expect(await Madauth.deleteAccount()).toMatchObject({ isSuccess: false, error: { code: 'network' } });
    expect(Madauth.currentUser).toEqual(ada);
  });
});

describe('Madauth.signIn', () => {
  it('I9: creates the dialog when the page has none, and reuses it', async () => {
    fakeServer();
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    void Madauth.signIn();
    await settle();
    const dialog = document.querySelector('madauth-login')!;
    expect(document.querySelectorAll('madauth-login')).toHaveLength(1);
    expect(dialog.shadowRoot!.querySelector('dialog')!.open).toBe(true);

    dialog.close();
    void Madauth.signIn();
    await settle();
    expect(document.querySelectorAll('madauth-login')).toHaveLength(1);
  });

  it('I9: uses a <madauth-login> that is already on the page', async () => {
    fakeServer();
    const existing = document.createElement('madauth-login');
    existing.heading = 'Welcome back';
    document.body.append(existing);
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    void Madauth.signIn();
    await settle();

    expect(document.querySelectorAll('madauth-login')).toHaveLength(1);
    expect(existing.shadowRoot!.querySelector('dialog')!.open).toBe(true);
  });

  it('I10: resolves with the user, or with cancelled when the dialog is closed', async () => {
    const server = fakeServer();
    const gis = fakeGis();
    await Madauth.initialize({ serverUrl: SERVER, providers: [new GoogleFedcm({ autoPrompt: false })] });

    const cancelled = Madauth.signIn();
    await settle();
    document.querySelector('madauth-login')!.shadowRoot!.querySelector<HTMLButtonElement>('.close')!.click();
    expect(await cancelled).toMatchObject({ isSuccess: false, error: { code: 'cancelled' } });

    const signedIn = Madauth.signIn();
    await settle();
    gis.signIn();
    expect(await signedIn).toEqual({ isSuccess: true, user: ada });
    expect(server.user).toEqual(ada);
    expect(document.querySelector('madauth-login')!.shadowRoot!.querySelector('dialog')!.open).toBe(false);
  });

  it('returns the initialize error without opening the dialog', async () => {
    fakeServer().down = true;
    await Madauth.initialize({ serverUrl: SERVER, providers: [] });

    expect(await Madauth.signIn()).toMatchObject({ isSuccess: false, error: { code: 'network' } });
    expect(document.querySelector('madauth-login')).toBeNull();
  });
});
