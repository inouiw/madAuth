// Keeping the session fresh: Madauth.sessionReady renews an expired session before the app uses it.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './index.js';
import { Madauth } from './madauth.js';
import { SERVER, ada, fakeServer, resetAll, setExpiryCookie } from './test-helpers.js';

const HERE = 'https://app.example.com';
const sessionRequests = (server: ReturnType<typeof fakeServer>) => server.requests.filter((r) => r.path === '/auth/session').length;

beforeEach(() => {
  resetAll();
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
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
