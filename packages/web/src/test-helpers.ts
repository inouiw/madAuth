import { vi, type Mocked } from 'vitest';
import { resetGisForTests, type GoogleAccountsId } from './gis.js';
import { resetMadauthForTests } from './madauth.js';
import type { SecondFactorPolicy } from './providers/provider.js';
import type { MadauthUser } from './result.js';

export const SERVER = 'https://auth.example.com';
export const CLIENT_ID = 'cid.apps.googleusercontent.com';
export const ada: MadauthUser = { id: 'google:1001', email: 'ada@example.com', name: 'Ada Lovelace' };
export const grace: MadauthUser = { id: 'usr_grace', email: 'grace@example.com', name: 'Grace Hopper' };

/** The link token and code the fake server puts in its e-mails. */
export const VERIFY_TOKEN = 'verify-token';
export const RESET_TOKEN = 'reset-token';
export const CODE = '123456';
/** The key the fake server hands out for the authenticator app, and the recovery codes it gives. */
export const TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
export const RECOVERY_CODES = ['abcde-fghij', 'klmno-pqrst', 'uvwxy-z2345', '67abc-defgh', 'ijklm-nopqr', 'stuvw-xyz23', '4567a-bcdef', 'ghijk-lmnop', 'qrstu-vwxyz', '23456-7abcd'];

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
  /** A sign-up with the authenticator app alone: no password, the app is set up after the confirmation. */
  app?: boolean;
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
  /** Claims by e-mail address, as set through the admin API. */
  claims: Map<string, Record<string, unknown>>;
  /** Which sign-in methods are on (the list an admin sets); `totp` is the app on its own. */
  methods: { google: boolean; password: boolean; totp: boolean };
  /** Whether Google and password ask for the authenticator app as a second factor. */
  policy: { google: SecondFactorPolicy; password: SecondFactorPolicy };
  /** The addresses whose users have set up the authenticator app, and their recovery codes left. */
  authenticators: Set<string>;
  recoveryCodes: Map<string, string[]>;
  /** A sign-in whose first step is done, waiting for the app's code or its setup (the challenge cookie). */
  challenge: { email: string; next: 'totp' | 'totp-setup'; method: 'google' | 'password' | 'totp' } | undefined;
  /** A setup under way (the setup cookie); set to undefined to simulate its expiry. */
  totpSetup: { email: string } | undefined;
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
    claims: new Map(),
    methods: { google: true, password: true, totp: false },
    policy: { google: 'none', password: 'none' },
    authenticators: new Set(),
    recoveryCodes: new Map(),
    challenge: undefined,
    totpSetup: undefined,
    sessionTtl: 3600,
  };
  const userFor = (email: string): MadauthUser => {
    const account = server.accounts.get(email);
    return email === grace.email ? grace : email === ada.email ? ada : { id: `usr_${email.split('@')[0]}`, email, ...(account?.name ? { name: account.name } : {}) };
  };
  const lastMailTo = (purpose: 'verify' | 'reset') => [...server.mails].reverse().find((m) => m.purpose === purpose)?.to;
  /** What the real server does with every session it issues or renews. */
  const issued = () => setExpiryCookie(Date.now() + server.sessionTtl * 1000);
  const signedIn = (email: string) => {
    server.user = userFor(email);
    issued();
    return json({ user: server.user });
  };
  /** The authenticator app is in use at all: on its own, or as the second factor of a method. */
  const totpOn = () => server.methods.totp || server.policy.google !== 'none' || server.policy.password !== 'none';
  /** What follows a primary method that succeeded: the session, or the app's code or setup. */
  const afterPrimary = (email: string, method: 'google' | 'password') => {
    const policy = server.policy[method];
    const enrolled = server.authenticators.has(email);
    const next = policy === 'none' ? undefined : enrolled ? 'totp' : policy === 'required' ? 'totp-setup' : undefined;
    if (!next) return signedIn(email);
    server.challenge = { email, next, method };
    return json({ error: next === 'totp' ? 'totp_required' : 'totp_setup_required', message: 'the app is next', method }, 401);
  };
  /** Checks a code from the app (`CODE`) or uses up a recovery code. */
  const codeOk = (email: string, body: Record<string, string>): boolean => {
    if (body.code !== undefined) return body.code === CODE;
    const codes = server.recoveryCodes.get(email) ?? [];
    const index = codes.indexOf(String(body.recoveryCode ?? '').trim().toLowerCase());
    if (index < 0) return false;
    codes.splice(index, 1);
    return true;
  };
  const isAdmin = () => !!(server.user?.claims?.roles as string[] | undefined)?.includes('admin');
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
    /** The user a setup belongs to: the signed-in one, or the one whose sign-in waits for it. */
    const whoSetsUp = () => server.user?.email ?? (server.challenge?.next === 'totp-setup' ? server.challenge.email : undefined);
    switch (`${method} ${url.pathname}`) {
      case 'GET /auth/config':
        return json({
          google: server.google && server.methods.google ? { clientId: CLIENT_ID, codeFlow: server.codeFlow, secondFactor: server.policy.google } : null,
          password: server.password && server.methods.password ? { minLength: 8, secondFactor: server.policy.password } : null,
          totp: totpOn() ? { signIn: server.methods.totp, signUp: server.methods.totp && server.password } : null,
          email: { verification: server.password },
        });
      case 'POST /auth/password/signin': {
        if (server.locked) return json({ error: 'too_many_attempts', message: 'Too many failed attempts. Try again in 30 seconds.' }, 429);
        const account = server.accounts.get(email);
        if (!account || account.app || account.password !== body.password) return json({ error: 'invalid_credentials', message: 'wrong' }, 401);
        if (!account.verified) return json({ error: 'email_unverified', message: 'unverified' }, 403);
        return afterPrimary(email, 'password');
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
      case 'POST /auth/totp/signup':
        if (!server.methods.totp) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (server.rejectSignUp) return json({ error: 'signup_rejected', message: server.rejectSignUp }, 403);
        if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
        if (!email?.includes('@')) return json({ error: 'invalid_email', message: 'invalid' }, 400);
        if (server.accounts.get(email)?.verified) {
          server.mails.push({ purpose: 'registered', to: email, redirectTo: body.redirectTo });
        } else {
          server.accounts.set(email, { password: '', verified: false, name: body.name, app: true });
          server.mails.push({ purpose: 'verify', to: email, redirectTo: body.redirectTo });
        }
        return json({}, 202);
      case 'POST /auth/email/send-verification':
        if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
        server.mails.push({ purpose: 'verify', to: email, redirectTo: body.redirectTo });
        return json({}, 202);
      case 'POST /auth/password/send-reset':
        if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
        server.mails.push({ purpose: 'reset', to: email, redirectTo: body.redirectTo });
        return json({}, 202);
      case 'POST /auth/email/verify': {
        const target = body.token === VERIFY_TOKEN ? lastMailTo('verify') : body.code === CODE ? email : undefined;
        const account = target && server.accounts.get(target);
        if (!account) {
          return body.token ? json({ error: 'link_invalid', message: 'bad link' }, 400) : json({ error: 'code_invalid', message: 'bad code' }, 400);
        }
        account.verified = true;
        if (account.app) {
          // A sign-up with the app: it is set up now.
          server.challenge = { email: target, next: 'totp-setup', method: 'totp' };
          return json({ error: 'totp_setup_required', message: 'set it up', method: 'totp' }, 401);
        }
        return afterPrimary(target, 'password');
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
        return afterPrimary(target, 'password');
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
        return afterPrimary(ada.email!, 'google');
      case 'POST /auth/logout':
        server.user = null;
        setExpiryCookie(null);
        return new Response(null, { status: 204 });
      // --- The authenticator app ---
      case 'POST /auth/totp/signin': {
        if (!totpOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (!server.methods.totp) return json({ error: 'method_disabled', message: 'not on its own' }, 403);
        if (server.locked) return json({ error: 'too_many_attempts', message: 'Too many failed attempts. Try again in 30 seconds.' }, 429);
        if (!server.authenticators.has(email) || !codeOk(email, body)) return json({ error: 'invalid_credentials', message: 'wrong' }, 401);
        return signedIn(email);
      }
      case 'POST /auth/totp/verify': {
        if (!totpOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        const challenge = server.challenge;
        if (!challenge || challenge.next !== 'totp' || !server.authenticators.has(challenge.email)) {
          return json({ error: 'challenge_expired', message: 'sign in again' }, 401);
        }
        if (server.locked) return json({ error: 'too_many_attempts', message: 'Too many failed attempts. Try again in 30 seconds.' }, 429);
        if (!codeOk(challenge.email, body)) return json({ error: 'code_invalid', message: 'wrong' }, 401);
        server.challenge = undefined;
        return signedIn(challenge.email);
      }
      case 'POST /auth/totp/setup': {
        if (!totpOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        const who = whoSetsUp();
        if (!who) return json({ error: 'no_session' }, 401);
        server.totpSetup = { email: who };
        return json({ secret: TOTP_SECRET, uri: `otpauth://totp/app.example.com:${encodeURIComponent(who)}?secret=${TOTP_SECRET}&issuer=app.example.com&algorithm=SHA1&digits=6&period=30` });
      }
      case 'POST /auth/totp/confirm': {
        if (!totpOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        const who = whoSetsUp();
        if (!who) return json({ error: 'no_session' }, 401);
        if (server.totpSetup?.email !== who) return json({ error: 'setup_expired', message: 'start again' }, 400);
        if (body.code !== CODE) return json({ error: 'code_invalid', message: 'wrong' }, 400);
        server.totpSetup = undefined;
        server.authenticators.add(who);
        server.recoveryCodes.set(who, [...RECOVERY_CODES]);
        if (server.user) return json({ recoveryCodes: [...RECOVERY_CODES] });
        // The setup finished a sign-in.
        server.challenge = undefined;
        server.user = userFor(who);
        issued();
        return json({ user: server.user, recoveryCodes: [...RECOVERY_CODES] });
      }
      case 'POST /auth/totp/remove': {
        if (!totpOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (!server.user?.email) return json({ error: 'no_session' }, 401);
        if (server.policy.google === 'required' || server.policy.password === 'required') return json({ error: 'required_by_policy', message: 'required' }, 403);
        if (!server.authenticators.has(server.user.email)) return json({});
        if (!codeOk(server.user.email, body)) return json({ error: 'code_invalid', message: 'wrong' }, 401);
        server.authenticators.delete(server.user.email);
        server.recoveryCodes.delete(server.user.email);
        return json({});
      }
      case 'POST /auth/totp/recovery-codes': {
        if (!totpOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (!server.user?.email) return json({ error: 'no_session' }, 401);
        if (!server.authenticators.has(server.user.email)) return json({ error: 'no_authenticator', message: 'none' }, 400);
        if (!codeOk(server.user.email, body)) return json({ error: 'code_invalid', message: 'wrong' }, 401);
        const fresh = RECOVERY_CODES.map((code) => code.split('').reverse().join(''));
        server.recoveryCodes.set(server.user.email, fresh);
        return json({ recoveryCodes: [...fresh] });
      }
      case 'GET /auth/totp/status': {
        if (!totpOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (!server.user?.email) return json({ error: 'no_session' }, 401);
        const enabled = server.authenticators.has(server.user.email);
        return json({ enabled, recoveryCodesLeft: enabled ? (server.recoveryCodes.get(server.user.email)?.length ?? 0) : 0 });
      }
      // --- Admin ---
      case 'POST /auth/admin/claims/get':
      case 'POST /auth/admin/claims/set': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (!isAdmin()) return json({ error: 'forbidden', message: 'admins only' }, 403);
        if (!email?.includes('@')) return json({ error: 'invalid_email', message: 'invalid' }, 400);
        if (!server.accounts.has(email)) return json({ error: 'user_not_found', message: 'no user' }, 404);
        if (url.pathname.endsWith('/set')) {
          const claims = (body as { claims?: unknown }).claims;
          if (!claims || typeof claims !== 'object' || Array.isArray(claims)) return json({ error: 'invalid_claims', message: 'invalid' }, 400);
          server.claims.set(email, claims as Record<string, unknown>);
        }
        return json({ email, userId: userFor(email).id, claims: server.claims.get(email) ?? {} });
      }
      case 'POST /auth/admin/settings/get':
      case 'POST /auth/admin/settings/set': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (!isAdmin()) return json({ error: 'forbidden', message: 'admins only' }, 403);
        if (url.pathname.endsWith('/set')) {
          const methods = (body as { methods?: Record<string, unknown> }).methods;
          if (!methods || typeof methods !== 'object') return json({ error: 'invalid_settings', message: 'invalid' }, 400);
          const on = (value: unknown) => value === true || (!!value && typeof value === 'object');
          const policyOf = (value: unknown): SecondFactorPolicy =>
            value && typeof value === 'object' && 'secondFactor' in value ? ((value as { secondFactor: SecondFactorPolicy }).secondFactor ?? 'none') : 'none';
          server.methods = { google: on(methods.google), password: on(methods.password), totp: on(methods.totp) };
          server.policy = { google: policyOf(methods.google), password: policyOf(methods.password) };
        }
        return json({
          methods: {
            google: { configured: server.google, enabled: server.google && server.methods.google, secondFactor: server.policy.google },
            password: { configured: server.password, enabled: server.password && server.methods.password, secondFactor: server.policy.password },
            totp: { configured: true, enabled: server.methods.totp },
          },
        });
      }
      case 'POST /auth/admin/totp/remove': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (!isAdmin()) return json({ error: 'forbidden', message: 'admins only' }, 403);
        if (!email?.includes('@')) return json({ error: 'invalid_email', message: 'invalid' }, 400);
        if (!server.accounts.has(email)) return json({ error: 'user_not_found', message: 'no user' }, 404);
        server.authenticators.delete(email);
        server.recoveryCodes.delete(email);
        return json({ email, userId: userFor(email).id, enabled: false });
      }
      case 'POST /auth/account/delete': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        const own = server.user.email;
        if (own && server.authenticators.has(own)) {
          if (body.code === undefined && body.recoveryCode === undefined) return json({ error: 'code_required', message: 'a code, please' }, 401);
          if (!codeOk(own, body)) return json({ error: 'code_invalid', message: 'wrong' }, 401);
          server.authenticators.delete(own);
        }
        if (own) server.accounts.delete(own);
        server.user = null;
        return new Response(null, { status: 204 });
      }
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
