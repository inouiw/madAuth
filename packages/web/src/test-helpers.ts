import { vi, type Mocked } from 'vitest';
import { resetGisForTests, type GoogleAccountsId } from './gis.js';
import { resetMadauthForTests } from './madauth.js';
import type { MadauthUser } from './result.js';

export const SERVER = 'https://auth.example.com';
export const CLIENT_ID = 'cid.apps.googleusercontent.com';
export const ada: MadauthUser = { id: 'google:1001', email: 'ada@example.com', name: 'Ada Lovelace' };

export interface RecordedRequest {
  url: string;
  method: string;
  path: string;
  body?: unknown;
  credentials?: RequestCredentials;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

export interface FakeServer {
  codeFlow: boolean;
  user: MadauthUser | null;
  /** Error code that /auth/google/verify answers with, if set. */
  verifyError: string | undefined;
  /** Makes every request fail like an unreachable server. */
  down: boolean;
  nonces: number;
  requests: RecordedRequest[];
}

/** Replaces fetch with an in-memory madAuth server. Change its fields to change its answers. */
export function fakeServer(): FakeServer {
  const server: FakeServer = { codeFlow: false, user: null, verifyError: undefined, down: false, nonces: 0, requests: [] };
  const fetchMock = vi.fn(async (input: string | URL, init: RequestInit = {}) => {
    const url = new URL(input);
    const method = init.method ?? 'GET';
    server.requests.push({
      url: url.href,
      method,
      path: url.pathname,
      body: typeof init.body === 'string' ? JSON.parse(init.body) : undefined,
      credentials: init.credentials,
    });
    if (server.down) throw new TypeError('Failed to fetch');
    switch (`${method} ${url.pathname}`) {
      case 'GET /auth/config':
        return json({ google: { clientId: CLIENT_ID, codeFlow: server.codeFlow } });
      case 'GET /auth/session':
        return server.user ? json({ user: server.user }) : json({ error: 'no_session' }, 401);
      case 'POST /auth/google/nonce':
        return json({ nonce: `nonce-${++server.nonces}` });
      case 'POST /auth/google/verify':
        if (server.verifyError) return json({ error: server.verifyError, message: 'rejected in test' }, 401);
        server.user = ada;
        return json({ user: ada });
      case 'POST /auth/logout':
        server.user = null;
        return new Response(null, { status: 204 });
    }
    return json({ error: 'not_found' }, 404);
  });
  vi.stubGlobal('fetch', fetchMock);
  return server;
}

/** Installs a fake `window.google.accounts.id`. */
export function fakeGis(): { id: Mocked<GoogleAccountsId>; signIn(credential?: string): void } {
  const id: Mocked<GoogleAccountsId> = {
    initialize: vi.fn(),
    prompt: vi.fn(),
    renderButton: vi.fn(),
    disableAutoSelect: vi.fn(),
    cancel: vi.fn(),
  };
  window.google = { accounts: { id } };
  return {
    id,
    /** Simulates Google handing a credential to the callback of the latest initialize(). */
    signIn(credential = 'google-id-token') {
      id.initialize.mock.lastCall![0].callback({ credential });
    },
  };
}

export function gisScripts(): NodeListOf<HTMLScriptElement> {
  return document.querySelectorAll('script[src="https://accounts.google.com/gsi/client"]');
}

export function resetAll(): void {
  resetMadauthForTests();
  resetGisForTests();
  delete window.google;
  document.body.replaceChildren();
  history.replaceState(null, '', '/page');
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
}

/** Waits until all pending promises (and a few timers) have run. */
export function settle(): Promise<void> {
  return new Promise((r) => setTimeout(r, 20));
}
