import { vi, type Mocked } from 'vitest';
import { resetGisForTests, type GoogleAccountsId } from './gis.js';
import { resetMadauthForTests } from './madauth.js';
import type { MadauthUser } from './result.js';

export const SERVER = 'https://auth.example.com';
export const CLIENT_ID = 'cid.apps.googleusercontent.com';
export const ada: MadauthUser = { id: 'google:1001', email: 'ada@example.com', name: 'Ada Lovelace' };
export const grace: MadauthUser = { id: 'usr_grace', email: 'grace@example.com', name: 'Grace Hopper' };

/** The link token and code the fake server puts in its e-mails. */
export const VERIFY_TOKEN = 'verify-token';
export const RESET_TOKEN = 'reset-token';
export const CODE = '123456';

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

export interface FakeAccount {
  password: string;
  verified: boolean;
  name?: string;
}

export interface FakeServer {
  /** Whether the server offers Google and e-mail & password sign-in. */
  google: boolean;
  password: boolean;
  codeFlow: boolean;
  /** E-mail & password accounts by e-mail address; grace@example.com (verified) exists. */
  accounts: Map<string, FakeAccount>;
  /** E-mails "sent": what for, to whom and the link's page. */
  mails: { purpose: 'verify' | 'reset' | 'registered'; to: string; redirectTo: unknown }[];
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
  const server: FakeServer = {
    google: true,
    password: true,
    codeFlow: false,
    accounts: new Map([['grace@example.com', { password: 'correct horse battery', verified: true, name: 'Grace Hopper' }]]),
    mails: [],
    user: null,
    verifyError: undefined,
    down: false,
    nonces: 0,
    requests: [],
  };
  const userFor = (email: string): MadauthUser => {
    const account = server.accounts.get(email);
    return email === grace.email ? grace : { id: `usr_${email.split('@')[0]}`, email, ...(account?.name ? { name: account.name } : {}) };
  };
  const lastMailTo = (purpose: 'verify' | 'reset') => [...server.mails].reverse().find((m) => m.purpose === purpose)?.to;
  const signedIn = (email: string) => {
    server.user = userFor(email);
    return json({ user: server.user });
  };
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
    const body = (typeof init.body === 'string' ? JSON.parse(init.body) : {}) as Record<string, string>;
    const email = body.email?.trim().toLowerCase();
    switch (`${method} ${url.pathname}`) {
      case 'GET /auth/config':
        return json({
          google: server.google ? { clientId: CLIENT_ID, codeFlow: server.codeFlow } : null,
          password: server.password ? { minLength: 8 } : null,
        });
      case 'POST /auth/password/signin': {
        const account = server.accounts.get(email);
        if (!account || account.password !== body.password) return json({ error: 'invalid_credentials', message: 'wrong' }, 401);
        if (!account.verified) return json({ error: 'email_unverified', message: 'unverified' }, 403);
        return signedIn(email);
      }
      case 'POST /auth/password/signup':
        if (!email?.includes('@')) return json({ error: 'invalid_email', message: 'invalid' }, 400);
        if ((body.password ?? '').length < 8) return json({ error: 'weak_password', message: 'The password must have at least 8 characters.' }, 400);
        if (server.accounts.get(email)?.verified) {
          server.mails.push({ purpose: 'registered', to: email, redirectTo: body.redirectTo });
        } else {
          server.accounts.set(email, { password: body.password, verified: false, name: body.name });
          server.mails.push({ purpose: 'verify', to: email, redirectTo: body.redirectTo });
        }
        return json({}, 202);
      case 'POST /auth/password/send-verification':
        server.mails.push({ purpose: 'verify', to: email, redirectTo: body.redirectTo });
        return json({}, 202);
      case 'POST /auth/password/send-reset':
        server.mails.push({ purpose: 'reset', to: email, redirectTo: body.redirectTo });
        return json({}, 202);
      case 'POST /auth/password/verify-email': {
        const target = body.token === VERIFY_TOKEN ? lastMailTo('verify') : body.code === CODE ? email : undefined;
        const account = target && server.accounts.get(target);
        if (!account) {
          return body.token ? json({ error: 'link_invalid', message: 'bad link' }, 400) : json({ error: 'code_invalid', message: 'bad code' }, 400);
        }
        account.verified = true;
        return signedIn(target);
      }
      case 'POST /auth/password/reset': {
        if ((body.password ?? '').length < 8) return json({ error: 'weak_password', message: 'The password must have at least 8 characters.' }, 400);
        const target = body.token === RESET_TOKEN ? (lastMailTo('reset') ?? grace.email) : body.code === CODE ? email : undefined;
        const account = target && server.accounts.get(target);
        if (!account) {
          return body.token ? json({ error: 'link_invalid', message: 'bad link' }, 400) : json({ error: 'code_invalid', message: 'bad code' }, 400);
        }
        account.password = body.password;
        account.verified = true;
        return signedIn(target);
      }
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
