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
  /** The webhook can't take e-mails over: sign-up and the e-mail requests answer 503. */
  emailsDown: boolean;
  /** The sign-up check (signup.before) refuses with this message. */
  rejectSignUp: string | undefined;
  /** Sign-in is locked after too many failed attempts: it answers 429. */
  locked: boolean;
  /** E-mails "sent": what for, to whom and the link's page. */
  mails: { purpose: 'verify' | 'reset' | 'registered'; to: string; redirectTo: unknown }[];
  user: MadauthUser | null;
  /** Error code that /auth/google/verify answers with, if set. */
  verifyError: string | undefined;
  /** Makes every request fail like an unreachable server. */
  down: boolean;
  nonces: number;
  requests: RecordedRequest[];
  /** Roles by e-mail address, as set through the admin API. */
  roles: Map<string, string[]>;
  /** Lifetime of a session in seconds; the server's expiry cookie is set from it. */
  sessionTtl: number;
}

/** Sets or clears the cookie in which the real server tells when the session expires. */
export function setExpiryCookie(expiresAt: number | null): void {
  document.cookie =
    expiresAt === null
      ? 'madauth_session_expires=; path=/; max-age=0'
      : `madauth_session_expires=${Math.floor(expiresAt / 1000)}; path=/; max-age=2592000`;
}

/** Replaces fetch with an in-memory madAuth server. Change its fields to change its answers. */
export function fakeServer(): FakeServer {
  const server: FakeServer = {
    google: true,
    password: true,
    codeFlow: false,
    accounts: new Map([['grace@example.com', { password: 'correct horse battery', verified: true, name: 'Grace Hopper' }]]),
    mails: [],
    emailsDown: false,
    rejectSignUp: undefined,
    locked: false,
    user: null,
    verifyError: undefined,
    down: false,
    nonces: 0,
    requests: [],
    roles: new Map(),
    sessionTtl: 3600,
  };
  const userFor = (email: string): MadauthUser => {
    const account = server.accounts.get(email);
    return email === grace.email ? grace : { id: `usr_${email.split('@')[0]}`, email, ...(account?.name ? { name: account.name } : {}) };
  };
  const lastMailTo = (purpose: 'verify' | 'reset') => [...server.mails].reverse().find((m) => m.purpose === purpose)?.to;
  /** What the real server does with every session it issues or renews. */
  const issued = () => setExpiryCookie(Date.now() + server.sessionTtl * 1000);
  const signedIn = (email: string) => {
    server.user = userFor(email);
    issued();
    return json({ user: server.user });
  };
  /** Why the server refuses a password, like its length-only policy. */
  const weakPassword = (password = ''): string | undefined => {
    if (password.length < 8) return 'The password must have at least 8 characters.';
    if (password.length > 256) return 'The password must have at most 256 characters.';
    return undefined;
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
        if (server.locked) return json({ error: 'too_many_attempts', message: 'Too many failed attempts. Try again in 30 seconds.' }, 429);
        const account = server.accounts.get(email);
        if (!account || account.password !== body.password) return json({ error: 'invalid_credentials', message: 'wrong' }, 401);
        if (!account.verified) return json({ error: 'email_unverified', message: 'unverified' }, 403);
        return signedIn(email);
      }
      case 'POST /auth/password/signup':
        if (server.rejectSignUp) return json({ error: 'signup_rejected', message: server.rejectSignUp }, 403);
        if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
        if (!email?.includes('@')) return json({ error: 'invalid_email', message: 'invalid' }, 400);
        if (weakPassword(body.password)) return json({ error: 'weak_password', message: weakPassword(body.password) }, 400);
        if (server.accounts.get(email)?.verified) {
          server.mails.push({ purpose: 'registered', to: email, redirectTo: body.redirectTo });
        } else {
          server.accounts.set(email, { password: body.password, verified: false, name: body.name });
          server.mails.push({ purpose: 'verify', to: email, redirectTo: body.redirectTo });
        }
        return json({}, 202);
      case 'POST /auth/password/send-verification':
        if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
        server.mails.push({ purpose: 'verify', to: email, redirectTo: body.redirectTo });
        return json({}, 202);
      case 'POST /auth/password/send-reset':
        if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
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
        if (weakPassword(body.password)) return json({ error: 'weak_password', message: weakPassword(body.password) }, 400);
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
        if (!server.user) {
          setExpiryCookie(null);
          return json({ error: 'no_session' }, 401);
        }
        issued();
        return json({ user: server.user });
      case 'POST /auth/google/nonce':
        return json({ nonce: `nonce-${++server.nonces}` });
      case 'POST /auth/google/verify':
        if (server.verifyError) return json({ error: server.verifyError, message: 'rejected in test' }, 401);
        server.user = ada;
        return json({ user: ada });
      case 'POST /auth/logout':
        server.user = null;
        setExpiryCookie(null);
        return new Response(null, { status: 204 });
      case 'POST /auth/admin/roles/get':
      case 'POST /auth/admin/roles/set': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (!server.user.roles?.includes('admin')) return json({ error: 'forbidden', message: 'admins only' }, 403);
        if (!email?.includes('@')) return json({ error: 'invalid_email', message: 'invalid' }, 400);
        if (url.pathname.endsWith('/set')) {
          const roles = (body as { roles?: unknown }).roles;
          if (!Array.isArray(roles)) return json({ error: 'invalid_roles', message: 'invalid' }, 400);
          server.roles.set(email, [...roles].sort());
        }
        return json({ email, roles: server.roles.get(email) ?? [] });
      }
      case 'POST /auth/account/delete':
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (server.user.email) server.accounts.delete(server.user.email);
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
  document.documentElement.removeAttribute('lang');
  setExpiryCookie(null);
  history.replaceState(null, '', '/page');
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
}

/** Waits until all pending promises (and a few timers) have run. */
export function settle(): Promise<void> {
  return new Promise((r) => setTimeout(r, 20));
}
