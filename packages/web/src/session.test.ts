// Keeping the session fresh: Madauth.sessionReady and the renewal before the session expires.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import { SERVER, ada, fakeServer, resetAll, setExpiryCookie } from './test-helpers.js';

const HERE = 'https://app.example.com';
const sessionRequests = (server: ReturnType<typeof fakeServer>) => server.requests.filter((r) => r.path === '/auth/session').length;

function setVisibility(state: 'visible' | 'hidden') {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state });
  document.dispatchEvent(new Event('visibilitychange'));
}

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  vi.useRealTimers();
  setVisibility('visible');
  resetAll();
});

describe('Madauth.sessionReady', () => {
  it('resolves at once while the session is valid, without asking the server', async () => {
    const server = fakeServer();
    server.user = ada;
    await Madauth.initialize({ serverUrl: HERE, providers: [] });
    const before = sessionRequests(server);

    expect(await Madauth.sessionReady()).toBe(true);

    expect(sessionRequests(server)).toBe(before);
  });

  it('resolves at once when nobody is signed in', async () => {
    const server = fakeServer();
    void Madauth.initialize({ serverUrl: HERE, providers: [] });

    // Before initialize has even heard from the server: there is no cookie, so there is no session.
    expect(await Madauth.sessionReady()).toBe(false);
    expect(server.requests.every((r) => r.path !== '/auth/session' || r.method === 'GET')).toBe(true);
  });

  it('renews an expired session first, with one request for all who wait', async () => {
    const server = fakeServer();
    server.user = ada;
    await Madauth.initialize({ serverUrl: HERE, providers: [] });
    // The page was left open, or is opened again after hours: the session has expired but can be renewed.
    setExpiryCookie(Date.now() - 1000);
    const before = sessionRequests(server);

    const results = await Promise.all([Madauth.sessionReady(), Madauth.sessionReady(), Madauth.sessionReady()]);

    expect(results).toEqual([true, true, true]);
    expect(sessionRequests(server)).toBe(before + 1);
    // Renewed: the next call needs no request.
    expect(await Madauth.sessionReady()).toBe(true);
    expect(sessionRequests(server)).toBe(before + 1);
  });

  it('resolves to false and signs the user out here when the session could not be renewed', async () => {
    const server = fakeServer();
    server.user = ada;
    await Madauth.initialize({ serverUrl: HERE, providers: [] });
    const listener = vi.fn();
    Madauth.onAuthStateChanged(listener);
    setExpiryCookie(Date.now() - 1000);
    server.user = null;

    expect(await Madauth.sessionReady()).toBe(false);

    expect(Madauth.currentUser).toBeNull();
    expect(listener).toHaveBeenLastCalledWith(null);
  });

  it('asks a server on another origin, whose cookie this page may not see', async () => {
    const server = fakeServer();
    server.user = ada;
    void Madauth.initialize({ serverUrl: SERVER, providers: [] });
    setExpiryCookie(null);

    expect(await Madauth.sessionReady()).toBe(true);
  });

  it('is false before initialize', async () => {
    expect(await Madauth.sessionReady()).toBe(false);
  });
});

describe('renewal while the page is open', () => {
  it('renews the session a minute before it expires', async () => {
    vi.useFakeTimers();
    const server = fakeServer();
    server.user = ada;
    await Madauth.initialize({ serverUrl: HERE, providers: [] });
    const before = sessionRequests(server);

    await vi.advanceTimersByTimeAsync(58 * 60 * 1000);
    expect(sessionRequests(server)).toBe(before);

    await vi.advanceTimersByTimeAsync(2 * 60 * 1000);
    expect(sessionRequests(server)).toBe(before + 1);

    // And again before the renewed session expires.
    await vi.advanceTimersByTimeAsync(60 * 60 * 1000);
    expect(sessionRequests(server)).toBe(before + 2);
  });

  it('a hidden page does not renew; it catches up when it comes back into view', async () => {
    vi.useFakeTimers();
    const server = fakeServer();
    server.user = ada;
    await Madauth.initialize({ serverUrl: HERE, providers: [] });
    const before = sessionRequests(server);

    setVisibility('hidden');
    await vi.advanceTimersByTimeAsync(3 * 60 * 60 * 1000);
    expect(sessionRequests(server)).toBe(before);

    setVisibility('visible');
    await vi.advanceTimersByTimeAsync(0);
    expect(sessionRequests(server)).toBe(before + 1);
    expect(Madauth.currentUser).toEqual(ada);
  });

  it('asks only once for a session that the server does not renew', async () => {
    vi.useFakeTimers();
    const server = fakeServer();
    server.user = ada;
    await Madauth.initialize({ serverUrl: HERE, providers: [] });
    // E.g. the renewal cookie is gone: the server still knows the user but issues nothing new.
    const expiry = Date.now() + 30_000;
    const realFetch = globalThis.fetch;
    vi.stubGlobal('fetch', async (...args: Parameters<typeof fetch>) => {
      const response = await realFetch(...args);
      setExpiryCookie(expiry);
      return response;
    });
    setExpiryCookie(expiry);
    await Madauth.getSession();
    const before = sessionRequests(server);

    await vi.advanceTimersByTimeAsync(20_000);

    expect(sessionRequests(server)).toBe(before + 1);
  });

  it('stops after sign-out', async () => {
    vi.useFakeTimers();
    const server = fakeServer();
    server.user = ada;
    await Madauth.initialize({ serverUrl: HERE, providers: [] });
    await Madauth.signOut();
    const before = sessionRequests(server);

    await vi.advanceTimersByTimeAsync(3 * 60 * 60 * 1000);

    expect(sessionRequests(server)).toBe(before);
  });
});
