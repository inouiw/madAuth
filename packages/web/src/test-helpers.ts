import { vi, type Mocked } from 'vitest';
import { resetGisForTests, type GoogleAccountsId } from '@madauth/google-identity';
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
export const SIGNIN_TOKEN = 'signin-token';
/** The phone the tests add, and how the fake server shows it. */
export const PHONE = '+41 79 123 45 67';
export const MASKED_PHONE = '+41 ••••••• 67';
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

/** Whether a challenge waits for a setup: a second factor a policy requires, or the app or passkey a sign-up with it creates. */
const isSetup = (next: string | undefined) => next === 'second-factor-setup' || next === 'authenticator-setup' || next === 'passkey-setup';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

export interface FakeAccount {
  password: string;
  verified: boolean;
  name?: string;
  /** A sign-up with the authenticator app alone: no password, the app is set up after the confirmation. */
  app?: boolean;
  /** A user of the e-mail link: no password, the link or its code sign in. */
  link?: boolean;
  /** A sign-up with a passkey alone: no password, the passkey is created after the confirmation. */
  passkey?: boolean;
}

export interface FakeServer {
  /** Whether the server offers Google, GitHub, e-mail & password sign-in and the e-mail link. */
  google: boolean;
  github: boolean;
  password: boolean;
  emailLink: boolean;
  codeFlow: boolean;
  /** The names admins gave the providers, as GET /auth/config lists them. */
  providerNames: { google: string; github: string };
  /** E-mail & password accounts by e-mail address; grace@example.com (verified) exists. */
  accounts: Map<string, FakeAccount>;
  /** The webhook can't take e-mails over: sign-up and the e-mail requests answer 503. */
  emailsDown: boolean;
  /** The sign-up check (user.signing_up) refuses with this message. */
  rejectSignUp: string | undefined;
  /** The rules for new passwords, as an admin set them. */
  passwordRules: { minLength: number; minScore: number };
  /** Sign-in is locked after too many failed attempts: it answers 429. */
  locked: boolean;
  /** E-mails "sent": what for, to whom and the link's page. */
  mails: { purpose: 'verify' | 'reset' | 'signin' | 'registered'; to: string; redirectTo: unknown }[];
  user: MadauthUser | null;
  /** Error code that /auth/providers/google/verify and /link answer with, if set. */
  verifyError: string | undefined;
  /** Makes every request fail like an unreachable server. */
  down: boolean;
  /** Every request waits for this before it is answered, if set: a slow server. */
  held: Promise<void> | undefined;
  nonces: number;
  requests: RecordedRequest[];
  /** Claims by e-mail address, as set through the admin API. */
  claims: Map<string, Record<string, unknown>>;
  /** Which sign-in methods are on (the list an admin sets); `authenticator` is the app on its own, `sms` SMS codes as a second factor. */
  methods: { google: boolean; github: boolean; password: boolean; authenticator: boolean; 'email-link': boolean; sms: boolean };
  /** Whether Google, GitHub, password and the e-mail link ask for the authenticator app as a second factor. */
  policy: { google: SecondFactorPolicy; github: SecondFactorPolicy; password: SecondFactorPolicy; 'email-link': SecondFactorPolicy };
  /** The addresses whose users have set up the authenticator app, and their recovery codes left. */
  authenticators: Set<string>;
  recoveryCodes: Map<string, string[]>;
  /** A sign-in whose first step is done, waiting for a second factor or a setup (the challenge cookie), with the factors that can finish it. */
  challenge:
    | { email: string; next: 'passkey' | 'authenticator' | 'sms' | 'second-factor-setup' | 'authenticator-setup' | 'passkey-setup'; method: 'google' | 'github' | 'password' | 'authenticator' | 'email-link' | 'passkey'; factors: ('passkey' | 'authenticator' | 'sms')[] }
    | undefined;
  /** Passkeys, when the server has them on: whether they sign in on their own (and sign people up), and that sign-in's policy. */
  passkey: { signIn: boolean; signUp?: boolean; secondFactor: SecondFactorPolicy } | null;
  /** The passkeys, by credential id: whose, their account id and name. */
  passkeys: Map<string, { email: string; id: string; name: string }>;
  /** Google, GitHub, OpenID Connect providers and the e-mail link the users added while signed in, by e-mail address. */
  linked: Map<string, Set<string>>;
  /**
   * The OpenID Connect providers, with their names and policies; on unless `on` is false. The rest is what the
   * admin API answers about them.
   */
  oidc: { id: string; name: string; secondFactor: SecondFactorPolicy; on?: boolean; issuer?: string; clientId?: string; scopes?: string[]; trustEmail?: boolean }[];
  /** How many users sign in with a provider alone, by its id, as a removal counts them. */
  usersAlone: Record<string, number>;
  /** The settings refuse to be set, with this message (`invalid_settings`). */
  settingsRefused: string | undefined;
  /**
   * A sign-up through a provider that doesn't vouch for the address, waiting for its confirmation e-mail: the
   * browser's confirmation cookie names it, so the code comes without an address.
   */
  confirmation: { email: string; method: string } | undefined;
  /** The user signed in more than ten minutes ago: changing a method answers `reauth_required`. */
  staleSignIn: boolean;
  /** The app's status can't be read: GET /auth/authenticator/status fails. */
  statusDown: boolean;
  /** The second factor each user wants to be asked for first, by e-mail address. */
  preferredFactors: Map<string, string>;
  /** A setup under way (the setup cookie); set to undefined to simulate its expiry. */
  authenticatorSetup: { email: string } | undefined;
  /** The phone numbers of the users who added one, by e-mail address. */
  phones: Map<string, string>;
  /** The SMS "sent": to which number, and what for. */
  texts: { to: string; purpose: 'setup' | 'signin' | 'approve' }[];
  /** A phone setup under way (the setup cookie); set to undefined to simulate its expiry. */
  smsSetup: { email: string; phone: string } | undefined;
  /** The last SMS went less than a minute ago: sending answers 429. */
  smsTooSoon: boolean;
  /** Lifetime of a session in seconds; the server's expiry cookie is set from it. */
  sessionTtl: number;
  /** The scopes API keys can have: one of madAuth's and the app's. */
  apiScopes: { name: string; description: string; role: string | null; endpoints: string[] }[];
  /** The API keys the users made, with the key and whose it is. */
  apiKeys: { id: string; email: string; key: string; name: string; scopes: string[]; createdAt: number; expiresAt: number | null; lastUsedAt: number }[];
  /** The app's login page an admin set; null: `/`. */
  loginUrl: string | null;
  /** The OpenID Connect clients an admin registered. */
  clients: { id: string; name: string; public: boolean; redirectUris: string[]; postLogoutRedirectUris: string[]; deviceFlow: boolean; tokenExchange: boolean; idTokenAlg: 'ES256' | 'RS256'; createdAt: number; updatedAt: number }[];
  /** The devices waiting for a user's approval, by their user code without the dash. */
  devices: { code: string; client: { id: string; name: string }; scope: string[]; expiresAt: number; boundTo?: string; decided?: 'approved' | 'denied' }[];
  /** Whether the user typed too many wrong device codes. */
  deviceLookupBlocked: boolean;
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
    github: false,
    password: true,
    emailLink: true,
    codeFlow: false,
    providerNames: { google: 'Google', github: 'GitHub' },
    accounts: new Map([['grace@example.com', { password: 'correct horse battery', verified: true, name: 'Grace Hopper' }]]),
    mails: [],
    emailsDown: false,
    rejectSignUp: undefined,
    passwordRules: { minLength: 8, minScore: 2 },
    locked: false,
    user: null,
    verifyError: undefined,
    down: false,
    held: undefined,
    nonces: 0,
    requests: [],
    claims: new Map(),
    methods: { google: true, github: true, password: true, authenticator: false, 'email-link': false, sms: false },
    policy: { google: 'none', github: 'none', password: 'none', 'email-link': 'none' },
    authenticators: new Set(),
    recoveryCodes: new Map(),
    challenge: undefined,
    authenticatorSetup: undefined,
    phones: new Map(),
    texts: [],
    smsSetup: undefined,
    smsTooSoon: false,
    sessionTtl: 3600,
    passkey: null,
    passkeys: new Map(),
    linked: new Map(),
    oidc: [],
    usersAlone: {},
    settingsRefused: undefined,
    confirmation: undefined,
    staleSignIn: false,
    statusDown: false,
    preferredFactors: new Map(),
    apiScopes: [
      { name: 'madauth:claims:read', description: "Read a user's claims and roles", role: 'admin', endpoints: ['POST /auth/admin/claims/get'] },
      { name: 'orders:read', description: 'Read your orders', role: null, endpoints: ['GET /api/orders'] },
      { name: 'orders:refund', description: 'Refund orders', role: 'staff', endpoints: [] },
    ],
    apiKeys: [],
    loginUrl: null,
    clients: [],
    devices: [],
    deviceLookupBlocked: false,
  };
  const mask = (phone: string) => `${phone.slice(0, 3)} ${'•'.repeat(Math.max(0, phone.length - 5))} ${phone.slice(-2)}`;
  const normalizePhone = (value: unknown) => {
    const digits = String(value ?? '').replace(/[\s().-]/g, '');
    return /^\+[1-9]\d{6,14}$/.test(digits) ? digits : undefined;
  };
  const userFor = (email: string): MadauthUser => {
    const account = server.accounts.get(email);
    const user = email === grace.email ? grace : email === ada.email ? ada : { id: `usr_${email.split('@')[0]}`, email, ...(account?.name ? { name: account.name } : {}) };
    // The claims an admin set for the address come with the session, as on the real server.
    const claims = server.claims.get(email);
    return claims ? { ...user, claims } : user;
  };
  const lastMailTo = (purpose: 'verify' | 'reset' | 'signin') => [...server.mails].reverse().find((m) => m.purpose === purpose)?.to;
  /** What the real server does with every session it issues or renews. */
  const issued = () => setExpiryCookie(Date.now() + server.sessionTtl * 1000);
  const signedIn = (email: string) => {
    server.user = userFor(email);
    issued();
    return json({ user: server.user });
  };
  /** The authenticator app is in use at all: on its own, or as the second factor of a method. */
  const authenticatorOn = () => server.methods.authenticator || server.policy.google !== 'none' || server.policy.github !== 'none' || server.policy.password !== 'none' || server.policy['email-link'] !== 'none';
  /** What follows a primary method that succeeded: the session, or a code (from the app, or by SMS) or the app's setup. */
  const passkeysOf = (email: string) => [...server.passkeys.values()].filter((p) => p.email === email);
  /** The second factors a user has, in the usual order. */
  const factorsOf = (email: string) => [
    ...(passkeysOf(email).length ? ['passkey'] : []),
    ...(server.authenticators.has(email) ? ['authenticator'] : []),
    ...(server.phones.has(email) ? ['sms'] : []),
  ];
  const afterPrimary = (email: string, method: 'google' | 'github' | 'password' | 'email-link' | 'passkey') => {
    const policy = method === 'passkey' ? (server.passkey?.secondFactor ?? 'none') : server.policy[method];
    const app = server.authenticators.has(email);
    const phone = server.methods.sms && server.phones.has(email);
    const passkey = !!server.passkey && method !== 'passkey' && passkeysOf(email).length > 0;
    const factors: ('passkey' | 'authenticator' | 'sms')[] = [...(passkey ? (['passkey'] as const) : []), ...(app ? (['authenticator'] as const) : []), ...(phone ? (['sms'] as const) : [])];
    const next: 'passkey' | 'authenticator' | 'sms' | 'second-factor-setup' | undefined =
      policy === 'none' ? undefined : factors.length ? factors[0] : policy === 'required' ? 'second-factor-setup' : undefined;
    if (!next) return signedIn(email);
    // As the real server: a sign-in that goes on with a second step ends the session there was.
    server.user = null;
    server.challenge = { email, next, method, factors };
    const error = { passkey: 'passkey_required', authenticator: 'authenticator_required', sms: 'sms_required', 'second-factor-setup': 'second_factor_setup_required' }[next];
    // For the setup, the factors that can be set up: a passkey when they are on, the app, and a phone when SMS codes are on.
    const named = next === 'second-factor-setup' ? [...(server.passkey && method !== 'passkey' ? ['passkey'] : []), 'authenticator', ...(server.methods.sms ? ['sms'] : [])] : factors;
    return json({ error, message: 'the second step is next', method, factors: named }, 401);
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
  /** A method as the admin API answers it. */
  const setting = (configured: boolean, listed: boolean, signIn: boolean, secondFactor: SecondFactorPolicy) => {
    const enabled = configured && listed;
    return { configured, enabled, allowAsSignInMethod: enabled && signIn, secondFactor: enabled ? secondFactor : 'none' };
  };
  const isAdmin = () => !!(server.user?.claims?.roles as string[] | undefined)?.includes('admin');
  /** The server's answer to a password that breaks its rules; a few common ones stand for "too easy to guess". */
  const weakPassword = (password = ''): Response | undefined => {
    const { minLength, minScore } = server.passwordRules;
    const weak = (message: string, details: object = {}) => json({ error: 'weak_password', message, ...details }, 400);
    if (password.length > 256) return weak('The password must have at most 256 characters.');
    if (password.length < minLength) return weak(`The password must have at least ${minLength} characters.`, { minLength });
    if (minScore > 0 && ['password1', 'password123', '12345678', 'qwertzuiop'].includes(password)) {
      return weak('This password is too easy to guess. Add another word or two, or choose less common ones.', { minScore });
    }
    return undefined;
  };
  const fetchMock = vi.fn(async (input: string | URL, init: RequestInit = {}) => {
    const url = new URL(input);
    const method = init.method ?? 'GET';
    server.requests.push({
      url: url.href,
      method,
      path: url.pathname,
      body: typeof init.body === 'string' ? JSON.parse(init.body) : init.body instanceof URLSearchParams ? Object.fromEntries(init.body) : undefined,
      credentials: init.credentials,
    });
    if (server.held) await server.held;
    if (server.down) throw new TypeError('Failed to fetch');
    const body = (typeof init.body === 'string' ? JSON.parse(init.body) : init.body instanceof URLSearchParams ? Object.fromEntries(init.body) : {}) as Record<string, string>;
    const email = body.email?.trim().toLowerCase();
    /** The user a setup belongs to: the signed-in one, or the one whose sign-in waits for it. */
    const whoSetsUp = () => server.user?.email ?? (isSetup(server.challenge?.next) ? server.challenge?.email : undefined);
    switch (`${method} ${url.pathname}`) {
      case 'GET /auth/config':
        return json({
          google: server.google && server.methods.google ? { clientId: CLIENT_ID, codeFlow: server.codeFlow, secondFactor: server.policy.google } : null,
          github: server.github && server.methods.github ? { secondFactor: server.policy.github } : null,
          password: server.password && server.methods.password ? { ...server.passwordRules, secondFactor: server.policy.password } : null,
          authenticator: authenticatorOn() ? { signIn: server.methods.authenticator, signUp: server.methods.authenticator && server.password } : null,
          email: { verification: server.password },
          emailLink: server.emailLink && server.methods['email-link'] ? { secondFactor: server.policy['email-link'] } : null,
          sms: server.methods.sms,
          passkey: server.passkey ? { signUp: false, ...server.passkey } : null,
          providers: [
            ...(['google', 'github'] as const).filter((kind) => server[kind] && server.methods[kind]).map((kind) => ({ id: kind, kind, name: server.providerNames[kind], secondFactor: server.policy[kind] })),
            ...server.oidc.filter((provider) => provider.on !== false).map(({ id, name, secondFactor }) => ({ id, name, secondFactor, kind: 'oidc' })),
          ],
        });
      // --- Passkeys ---
      case 'POST /auth/passkey/signin/options':
        if (!server.passkey?.signIn) return json({ error: 'method_disabled', message: 'off' }, 403);
        return json({ challenge: 'c2lnbmlu', rpId: 'localhost', userVerification: 'required' });
      case 'POST /auth/passkey/signin/verify': {
        const id = (body as unknown as { response?: { id?: string } }).response?.id ?? '';
        const passkey = server.passkeys.get(id);
        if (!passkey) return json({ error: 'passkey_unknown', message: 'unknown' }, 401);
        return afterPrimary(passkey.email, 'passkey');
      }
      case 'POST /auth/passkey/register/options': {
        if (!server.passkey) return json({ error: 'method_disabled', message: 'off' }, 403);
        const who = whoSetsUp();
        if (!who) return json({ error: 'no_session', message: 'sign in' }, 401);
        if (server.user && server.staleSignIn) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        return json({
          challenge: 'cmVnaXN0ZXI',
          rp: { id: 'localhost', name: 'localhost' },
          user: { id: 'dXNy', name: who, displayName: who },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
          excludeCredentials: passkeysOf(who).map(() => ({ id: 'b2xk', type: 'public-key' })),
        });
      }
      case 'POST /auth/passkey/register/verify': {
        const who = whoSetsUp();
        if (!who) return json({ error: 'no_session', message: 'sign in' }, 401);
        const credential = (body as unknown as { response?: { id?: string } }).response?.id ?? '';
        const passkey = { email: who, id: `acc_${server.passkeys.size + 1}`, name: (body as { name?: string }).name || 'Passkey' };
        server.passkeys.set(credential, passkey);
        const info = { id: passkey.id, name: passkey.name, createdAt: 1, lastUsedAt: 0 };
        if (!server.user && isSetup(server.challenge?.next)) {
          // A sign-up with a passkey alone: it signs in as a passkey would, its policy may ask for a second factor.
          const signUp = server.challenge?.next === 'passkey-setup';
          server.challenge = undefined;
          const res = signUp ? afterPrimary(who, 'passkey') : signedIn(who);
          if (res.status !== 200) return res;
          const { user } = (await res.json()) as { user: MadauthUser };
          return json({ passkey: info, user });
        }
        return json({ passkey: info });
      }
      case 'POST /auth/passkey/signup':
        if (!server.passkey?.signIn || !server.passkey.signUp) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (server.rejectSignUp) return json({ error: 'signup_rejected', message: server.rejectSignUp }, 403);
        if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
        if (!email?.includes('@')) return json({ error: 'invalid_email', message: 'invalid' }, 400);
        if (server.accounts.get(email)?.verified) {
          server.mails.push({ purpose: 'registered', to: email, redirectTo: body.redirectTo });
        } else {
          server.accounts.set(email, { password: '', verified: false, name: body.name, passkey: true });
          server.mails.push({ purpose: 'verify', to: email, redirectTo: body.redirectTo });
        }
        return json({}, 202);
      case 'POST /auth/passkey/verify/options': {
        const challenge = server.challenge;
        if (!challenge?.factors.includes('passkey')) return json({ error: 'challenge_expired', message: 'sign in again' }, 401);
        return json({ challenge: 'dmVyaWZ5', rpId: 'localhost', allowCredentials: [{ id: 'b2xk', type: 'public-key' }], userVerification: 'required' });
      }
      case 'POST /auth/passkey/verify': {
        const challenge = server.challenge;
        if (!challenge?.factors.includes('passkey')) return json({ error: 'challenge_expired', message: 'sign in again' }, 401);
        const id = (body as unknown as { response?: { id?: string } }).response?.id ?? '';
        if (server.passkeys.get(id)?.email !== challenge.email) return json({ error: 'verification_failed', message: 'wrong passkey' }, 401);
        server.challenge = undefined;
        return signedIn(challenge.email);
      }
      // --- API keys ---
      case 'GET /auth/api-keys/scopes': {
        const roles = (server.user?.claims?.roles as string[] | undefined) ?? [];
        return json({ scopes: server.apiScopes.map((scope) => ({ ...scope, allowed: !scope.role || roles.includes(scope.role) })) });
      }
      case 'GET /auth/api-keys': {
        const user = server.user?.email;
        if (!user) return json({ error: 'no_session', message: 'sign in' }, 401);
        return json({ apiKeys: server.apiKeys.filter((k) => k.email === user).map(({ key: _, email: __, ...info }) => info) });
      }
      case 'POST /auth/api-keys/create': {
        const user = server.user;
        if (!user?.email) return json({ error: 'no_session', message: 'sign in' }, 401);
        if (server.staleSignIn) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        const { name, scopes, expiresAt = null } = body as unknown as { name: string; scopes: string[]; expiresAt?: number };
        if (!scopes.every((scope) => server.apiScopes.some((s) => s.name === scope))) return json({ error: 'invalid_scopes', message: 'unknown' }, 400);
        const roles = (user.claims?.roles as string[] | undefined) ?? [];
        const allowed = (scope: string) => {
          const role = server.apiScopes.find((s) => s.name === scope)!.role;
          return !role || roles.includes(role);
        };
        if (!scopes.every(allowed)) return json({ error: 'scope_not_allowed', message: 'not yours' }, 403);
        const made = { id: `key_${server.apiKeys.length + 1}`, email: user.email, key: `madauth_secret${server.apiKeys.length + 1}`, name, scopes, createdAt: 1, expiresAt, lastUsedAt: 0 };
        server.apiKeys.push(made);
        const { key, email: _, ...apiKey } = made;
        return json({ key, apiKey });
      }
      case 'POST /auth/api-keys/revoke': {
        const user = server.user?.email;
        if (!user) return json({ error: 'no_session', message: 'sign in' }, 401);
        const index = server.apiKeys.findIndex((k) => k.id === (body as { id?: string }).id && k.email === user);
        if (index < 0) return json({ error: 'api_key_not_found', message: 'gone' }, 404);
        server.apiKeys.splice(index, 1);
        return json({});
      }
      // --- The user's methods ---
      case 'GET /auth/methods': {
        const user = server.user?.email;
        if (!user) return json({ error: 'no_session', message: 'sign in' }, 401);
        const account = server.accounts.get(user);
        const methods = [
          ...(account?.password ? [{ id: 'acc_password', method: 'password', signIn: true, removable: true, createdAt: 1 }] : []),
          ...[...(server.linked.get(user) ?? [])].map((method) => ({ id: `acc_${method}`, method, signIn: true, removable: true, createdAt: 1, ...(method === 'email-link' ? {} : { email: user }) })),
          ...(server.authenticators.has(user) ? [{ id: 'acc_authenticator', method: 'authenticator', signIn: server.methods.authenticator, removable: false, createdAt: 1 }] : []),
          ...passkeysOf(user).map((p) => ({ id: p.id, method: 'passkey', signIn: !!server.passkey?.signIn, removable: true, createdAt: 1, name: p.name, lastUsedAt: 0 })),
        ];
        const has = factorsOf(user);
        const preferred = has.find((factor) => factor === server.preferredFactors.get(user)) ?? null;
        return json({ methods, secondFactors: preferred ? [preferred, ...has.filter((f) => f !== preferred)] : has, preferredSecondFactor: preferred });
      }
      case 'POST /auth/second-factor/preferred': {
        const user = server.user?.email;
        if (!user) return json({ error: 'no_session', message: 'sign in' }, 401);
        const factor = (body as { factor?: unknown }).factor;
        if (factor === null) server.preferredFactors.delete(user);
        else if (typeof factor === 'string' && factorsOf(user).includes(factor)) server.preferredFactors.set(user, factor);
        else return json({ error: 'method_not_found', message: 'none' }, 404);
        return json({});
      }
      case 'POST /auth/methods/remove': {
        const user = server.user?.email;
        if (!user) return json({ error: 'no_session', message: 'sign in' }, 401);
        if (server.staleSignIn) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        const id = (body as { id?: string }).id;
        const passkey = [...server.passkeys.entries()].find(([, p]) => p.id === id && p.email === user);
        if (passkey) server.passkeys.delete(passkey[0]);
        else if (id === 'acc_password' && server.accounts.get(user)?.password) server.accounts.get(user)!.password = '';
        else if (id?.startsWith('acc_') && server.linked.get(user)?.delete(id.slice(4))) {
          // removed
        } else return json({ error: 'method_not_found', message: 'gone' }, 404);
        return json({});
      }
      case 'POST /auth/password/add':
      case 'POST /auth/email-link/add': {
        const user = server.user?.email;
        if (!user) return json({ error: 'no_session', message: 'sign in' }, 401);
        if (server.staleSignIn) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        if (url.pathname === '/auth/password/add') {
          const weak = weakPassword(body.password);
          if (weak) return weak;
          const account = server.accounts.get(user) ?? { password: '', verified: true };
          if (account.password) return json({ error: 'already_added', message: 'has one' }, 409);
          server.accounts.set(user, { ...account, password: body.password });
        } else {
          const linked = server.linked.get(user) ?? new Set();
          if (linked.has('email-link')) return json({ error: 'already_added', message: 'has it' }, 409);
          server.linked.set(user, linked.add('email-link'));
        }
        return json({});
      }
      case 'POST /auth/password/change': {
        const user = server.user?.email;
        if (!user) return json({ error: 'no_session', message: 'sign in' }, 401);
        const weak = weakPassword(body.password);
        if (weak) return weak;
        const account = server.accounts.get(user);
        if (!account?.password) return json({ error: 'method_not_found', message: 'no password' }, 404);
        if (account.password !== body.current) return json({ error: 'invalid_credentials', message: 'wrong' }, 401);
        account.password = body.password as string;
        return json({});
      }
      // --- The e-mail link ---
      case 'POST /auth/email-link/send': {
        if (!server.emailLink) break;
        if (!server.methods['email-link']) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (!email?.includes('@')) return json({ error: 'invalid_email', message: 'invalid' }, 400);
        const account = server.accounts.get(email);
        if (account?.verified && !account.link) {
          if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
          server.mails.push({ purpose: 'registered', to: email, redirectTo: body.redirectTo });
          return json({}, 202);
        }
        if (!account?.link && server.rejectSignUp) return json({ error: 'signup_rejected', message: server.rejectSignUp }, 403);
        if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
        if (!account?.link) server.accounts.set(email, { password: '', verified: false, link: true });
        server.mails.push({ purpose: 'signin', to: email, redirectTo: body.redirectTo });
        return json({}, 202);
      }
      case 'POST /auth/email-link/verify': {
        if (!server.emailLink) break;
        if (!server.methods['email-link']) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (server.locked) return json({ error: 'codes_locked', message: 'locked' }, 429);
        const target = body.token === SIGNIN_TOKEN ? lastMailTo('signin') : body.code === CODE ? email : undefined;
        const account = target && server.accounts.get(target);
        if (!account || !account.link) {
          return body.token ? json({ error: 'link_invalid', message: 'bad link' }, 400) : json({ error: 'code_invalid', message: 'bad code' }, 400);
        }
        account.verified = true;
        return afterPrimary(target, 'email-link');
      }
      case 'POST /auth/password/signin': {
        if (server.locked) return json({ error: 'too_many_attempts', message: 'Too many failed attempts. Try again in 30 seconds.' }, 429);
        const account = server.accounts.get(email);
        // A user without a password (one whose sign-in an admin reset) has none to sign in with.
        if (!account?.password || account.app || account.password !== body.password) return json({ error: 'invalid_credentials', message: 'wrong' }, 401);
        if (!account.verified) return json({ error: 'email_unverified', message: 'unverified' }, 403);
        return afterPrimary(email, 'password');
      }
      case 'POST /auth/password/signup':
        if (server.rejectSignUp) return json({ error: 'signup_rejected', message: server.rejectSignUp }, 403);
        if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
        if (!email?.includes('@')) return json({ error: 'invalid_email', message: 'invalid' }, 400);
        if (weakPassword(body.password)) return weakPassword(body.password)!;
        if (server.accounts.get(email)?.verified) {
          server.mails.push({ purpose: 'registered', to: email, redirectTo: body.redirectTo });
        } else {
          server.accounts.set(email, { password: body.password, verified: false, name: body.name });
          server.mails.push({ purpose: 'verify', to: email, redirectTo: body.redirectTo });
        }
        return json({}, 202);
      case 'POST /auth/authenticator/signup':
        if (!server.methods.authenticator) return json({ error: 'method_disabled', message: 'off' }, 403);
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
        server.mails.push({ purpose: 'verify', to: email ?? server.confirmation?.email ?? '', redirectTo: body.redirectTo });
        return json({}, 202);
      case 'POST /auth/password/send-reset':
        if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
        server.mails.push({ purpose: 'reset', to: email, redirectTo: body.redirectTo });
        return json({}, 202);
      case 'POST /auth/email/verify': {
        // The code without an address: the provider's sign-up the confirmation cookie names.
        if (body.email === undefined && body.token === undefined && server.confirmation) {
          if (body.code !== CODE) return json({ error: 'code_invalid', message: 'bad code' }, 400);
          const { email: confirmed, method } = server.confirmation;
          server.confirmation = undefined;
          server.user = { ...userFor(confirmed), amr: [method] };
          issued();
          return json({ user: server.user });
        }
        const target = body.token === VERIFY_TOKEN ? lastMailTo('verify') : body.code === CODE ? email : undefined;
        const account = target && server.accounts.get(target);
        if (!account) {
          return body.token ? json({ error: 'link_invalid', message: 'bad link' }, 400) : json({ error: 'code_invalid', message: 'bad code' }, 400);
        }
        account.verified = true;
        if (account.app) {
          // A sign-up with the app: it is set up now.
          server.challenge = { email: target, next: 'authenticator-setup', method: 'authenticator', factors: [] };
          return json({ error: 'authenticator_setup_required', message: 'set it up', method: 'authenticator', factors: ['authenticator'] }, 401);
        }
        if (account.passkey) {
          // A sign-up with a passkey alone: it is created now.
          server.challenge = { email: target, next: 'passkey-setup', method: 'passkey', factors: [] };
          return json({ error: 'passkey_setup_required', message: 'create it', method: 'passkey', factors: ['passkey'] }, 401);
        }
        return afterPrimary(target, 'password');
      }
      case 'POST /auth/password/reset': {
        if (weakPassword(body.password)) return weakPassword(body.password)!;
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
      case 'POST /auth/providers/google/nonce':
        return json({ nonce: `nonce-${++server.nonces}` });
      case 'POST /auth/providers/google/verify':
        if (server.verifyError) return json({ error: server.verifyError, message: 'rejected in test' }, 401);
        return afterPrimary(ada.email!, 'google');
      case 'POST /auth/providers/google/link': {
        const user = server.user?.email;
        if (!user) return json({ error: 'no_session', message: 'sign in' }, 401);
        if (server.staleSignIn) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        if (server.verifyError) return json({ error: server.verifyError, message: 'rejected in test' }, server.verifyError === 'account_taken' ? 409 : 401);
        server.linked.set(user, (server.linked.get(user) ?? new Set()).add('google'));
        return json({});
      }
      case 'POST /auth/logout':
        server.user = null;
        setExpiryCookie(null);
        return new Response(null, { status: 204 });
      // --- The authenticator app ---
      case 'POST /auth/authenticator/signin': {
        if (!authenticatorOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (!server.methods.authenticator) return json({ error: 'method_disabled', message: 'not on its own' }, 403);
        if (server.locked) return json({ error: 'too_many_attempts', message: 'Too many failed attempts. Try again in 30 seconds.' }, 429);
        if (!server.authenticators.has(email) || !codeOk(email, body)) return json({ error: 'invalid_credentials', message: 'wrong' }, 401);
        return signedIn(email);
      }
      case 'POST /auth/authenticator/verify': {
        if (!authenticatorOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        const challenge = server.challenge;
        if (!challenge || !challenge.factors.includes('authenticator') || !server.authenticators.has(challenge.email)) {
          return json({ error: 'challenge_expired', message: 'sign in again' }, 401);
        }
        if (server.locked) return json({ error: 'too_many_attempts', message: 'Too many failed attempts. Try again in 30 seconds.' }, 429);
        if (!codeOk(challenge.email, body)) return json({ error: 'code_invalid', message: 'wrong' }, 401);
        server.challenge = undefined;
        return signedIn(challenge.email);
      }
      case 'POST /auth/authenticator/setup': {
        if (!authenticatorOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        const who = whoSetsUp();
        if (!who) return json({ error: 'no_session' }, 401);
        // The signed-in user starts a setup only right after signing in.
        if (server.user?.email === who && server.staleSignIn) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        // Replacing an app: the current one has to agree.
        if (server.authenticators.has(who)) {
          if (body.code === undefined && body.recoveryCode === undefined) return json({ error: 'code_required', message: 'the current app has to agree' }, 401);
          if (!codeOk(who, body)) return json({ error: 'code_invalid', message: 'wrong' }, 401);
        }
        server.authenticatorSetup = { email: who };
        return json({ secret: TOTP_SECRET, uri: `otpauth://totp/app.example.com:${encodeURIComponent(who)}?secret=${TOTP_SECRET}&issuer=app.example.com&algorithm=SHA1&digits=6&period=30` });
      }
      case 'POST /auth/authenticator/confirm': {
        if (!authenticatorOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        const who = whoSetsUp();
        if (!who) return json({ error: 'no_session' }, 401);
        if (server.authenticatorSetup?.email !== who) return json({ error: 'setup_expired', message: 'start again' }, 400);
        if (body.code !== CODE) return json({ error: 'code_invalid', message: 'wrong' }, 400);
        server.authenticatorSetup = undefined;
        server.authenticators.add(who);
        server.recoveryCodes.set(who, [...RECOVERY_CODES]);
        if (server.user) return json({ recoveryCodes: [...RECOVERY_CODES] });
        // The setup finished a sign-in.
        server.challenge = undefined;
        server.user = userFor(who);
        issued();
        return json({ user: server.user, recoveryCodes: [...RECOVERY_CODES] });
      }
      case 'POST /auth/authenticator/remove': {
        if (!authenticatorOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (!server.user?.email) return json({ error: 'no_session' }, 401);
        if (server.staleSignIn) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        if (server.policy.google === 'required' || server.policy.password === 'required') return json({ error: 'required_by_policy', message: 'required' }, 403);
        if (!server.authenticators.has(server.user.email)) return json({});
        // A sign-up with the app has no other way in.
        const account = server.accounts.get(server.user.email);
        if (account?.app && !account.password) return json({ error: 'only_method', message: 'the only way in' }, 403);
        if (!codeOk(server.user.email, body)) return json({ error: 'code_invalid', message: 'wrong' }, 401);
        server.authenticators.delete(server.user.email);
        server.recoveryCodes.delete(server.user.email);
        return json({});
      }
      case 'POST /auth/authenticator/recovery-codes': {
        if (!authenticatorOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (!server.user?.email) return json({ error: 'no_session' }, 401);
        if (server.staleSignIn) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        if (!server.authenticators.has(server.user.email)) return json({ error: 'no_authenticator', message: 'none' }, 400);
        if (!codeOk(server.user.email, body)) return json({ error: 'code_invalid', message: 'wrong' }, 401);
        const fresh = RECOVERY_CODES.map((code) => code.split('').reverse().join(''));
        server.recoveryCodes.set(server.user.email, fresh);
        return json({ recoveryCodes: [...fresh] });
      }
      case 'GET /auth/authenticator/status': {
        if (!authenticatorOn()) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (server.statusDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
        if (!server.user?.email) return json({ error: 'no_session' }, 401);
        const enabled = server.authenticators.has(server.user.email);
        return json({ enabled, recoveryCodesLeft: enabled ? (server.recoveryCodes.get(server.user.email)?.length ?? 0) : 0 });
      }
      // --- SMS codes ---
      case 'POST /auth/sms/setup': {
        if (!server.methods.sms) return json({ error: 'method_disabled', message: 'off' }, 403);
        const who = whoSetsUp();
        if (!who) return json({ error: 'no_session' }, 401);
        const phone = normalizePhone(body.phone);
        if (!phone) return json({ error: 'invalid_phone', message: 'not a number' }, 400);
        // A signed-in user's first number starts right after signing in; replacing one starts with `send`.
        if (server.user?.email === who && server.staleSignIn && !server.phones.has(who)) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        // Replacing a number: the current one has to agree.
        if (server.phones.has(who)) {
          if (body.code === undefined) return json({ error: 'code_required', message: 'the current number has to agree' }, 401);
          if (body.code !== CODE) return json({ error: 'code_invalid', message: 'wrong' }, 401);
        } else if (server.smsTooSoon) {
          return json({ error: 'too_soon', message: 'wait' }, 429);
        }
        if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
        server.smsSetup = { email: who, phone };
        server.texts.push({ to: phone, purpose: 'setup' });
        return json({ phone: mask(phone) }, 202);
      }
      case 'POST /auth/sms/confirm': {
        if (!server.methods.sms) return json({ error: 'method_disabled', message: 'off' }, 403);
        const who = whoSetsUp();
        if (!who) return json({ error: 'no_session' }, 401);
        if (server.smsSetup?.email !== who) return json({ error: 'setup_expired', message: 'start again' }, 400);
        if (body.code !== CODE) return json({ error: 'code_invalid', message: 'wrong' }, 401);
        server.phones.set(who, server.smsSetup.phone);
        server.smsSetup = undefined;
        if (server.user) return json({});
        // The setup finished a sign-in.
        server.challenge = undefined;
        server.user = userFor(who);
        issued();
        return json({ user: server.user });
      }
      case 'POST /auth/sms/send': {
        if (!server.methods.sms) return json({ error: 'method_disabled', message: 'off' }, 403);
        const challenge = server.challenge?.factors.includes('sms') ? server.challenge : undefined;
        const who = challenge?.email ?? server.user?.email;
        if (!who) return json({ error: challenge === undefined && server.challenge ? 'challenge_expired' : 'no_session', message: 'nobody' }, 401);
        const phone = server.phones.get(who);
        if (!phone) return challenge ? json({ error: 'challenge_expired', message: 'no phone' }, 401) : json({ error: 'no_phone', message: 'none' }, 400);
        // Signed in, the code approves a change to the number, which starts right after signing in.
        if (!challenge && server.staleSignIn) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        if (server.smsTooSoon) return json({ error: 'too_soon', message: 'wait' }, 429);
        if (server.emailsDown) return json({ error: 'temporarily_unavailable', message: 'down' }, 503);
        server.texts.push({ to: phone, purpose: challenge ? 'signin' : 'approve' });
        return json({ phone: mask(phone) }, 202);
      }
      case 'POST /auth/sms/verify': {
        if (!server.methods.sms) return json({ error: 'method_disabled', message: 'off' }, 403);
        const challenge = server.challenge;
        if (!challenge || !challenge.factors.includes('sms') || !server.phones.has(challenge.email)) {
          return json({ error: 'challenge_expired', message: 'sign in again' }, 401);
        }
        if (server.locked) return json({ error: 'too_many_attempts', message: 'Too many failed attempts. Try again in 30 seconds.' }, 429);
        if (body.code !== CODE) return json({ error: 'code_invalid', message: 'wrong' }, 401);
        server.challenge = undefined;
        return signedIn(challenge.email);
      }
      case 'POST /auth/sms/remove': {
        if (!server.methods.sms) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (!server.user?.email) return json({ error: 'no_session' }, 401);
        if (!server.phones.has(server.user.email)) return json({ error: 'no_phone', message: 'none' }, 400);
        const required = Object.values(server.policy).includes('required');
        if (required && !server.authenticators.has(server.user.email)) return json({ error: 'required_by_policy', message: 'required' }, 403);
        if (body.code !== CODE) return json({ error: 'code_invalid', message: 'wrong' }, 401);
        server.phones.delete(server.user.email);
        return json({});
      }
      case 'GET /auth/sms/status': {
        if (!server.methods.sms) return json({ error: 'method_disabled', message: 'off' }, 403);
        if (!server.user?.email) return json({ error: 'no_session' }, 401);
        const phone = server.phones.get(server.user.email);
        return json({ enabled: !!phone, phone: phone ? mask(phone) : null });
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
      case 'POST /auth/admin/settings/set':
      case 'POST /auth/admin/settings/method': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (!isAdmin()) return json({ error: 'forbidden', message: 'admins only' }, 403);
        // One method: the list as it is, with only that method changed; answered like the others.
        if (url.pathname.endsWith('/method')) {
          if (server.settingsRefused) return json({ error: 'invalid_settings', message: server.settingsRefused }, 400);
          const { method, setting } = body as unknown as { method: string; setting: { allowAsSignInMethod: boolean; secondFactor: SecondFactorPolicy } | null };
          const provider = server.oidc.find((p) => p.id === method);
          if (provider) Object.assign(provider, { on: !!setting, secondFactor: setting?.secondFactor ?? 'none' });
          else if (method === 'google' || method === 'github' || method === 'password' || method === 'email-link') {
            server.methods[method] = !!setting;
            server.policy[method] = setting?.secondFactor ?? 'none';
          } else return json({ error: 'invalid_settings', message: `"${method}" is no sign-in method of this server` }, 400);
        }
        if (url.pathname.endsWith('/set')) {
          const { password, loginUrl } = body as { password?: { minLength?: number; minScore?: number }; loginUrl?: string | null };
          if (password) server.passwordRules = { minLength: password.minLength ?? 8, minScore: password.minScore ?? 2 };
          if (loginUrl !== undefined) server.loginUrl = loginUrl;
        }
        if (url.pathname.endsWith('/set') && (body as { methods?: unknown }).methods !== undefined) {
          const methods = (body as { methods?: Record<string, unknown> }).methods;
          if (!methods || typeof methods !== 'object') return json({ error: 'invalid_settings', message: 'invalid' }, 400);
          if (server.settingsRefused) return json({ error: 'invalid_settings', message: server.settingsRefused }, 400);
          const on = (value: unknown) => value === true || (!!value && typeof value === 'object');
          const policyOf = (value: unknown): SecondFactorPolicy =>
            value && typeof value === 'object' && 'secondFactor' in value ? ((value as { secondFactor: SecondFactorPolicy }).secondFactor ?? 'none') : 'none';
          // The app is listed in `methods` when it signs in on its own.
          const signsIn = (value: unknown) => on(value) && (value as { allowAsSignInMethod?: unknown }).allowAsSignInMethod === true;
          server.methods = { google: on(methods.google), github: on(methods.github), password: on(methods.password), authenticator: signsIn(methods.authenticator), 'email-link': on(methods['email-link']), sms: on(methods.sms) };
          server.policy = { google: policyOf(methods.google), github: policyOf(methods.github), password: policyOf(methods.password), 'email-link': policyOf(methods['email-link']) };
          for (const provider of server.oidc) Object.assign(provider, { on: on(methods[provider.id]), secondFactor: policyOf(methods[provider.id]) });
        }
        return json({
          password: server.passwordRules,
          loginUrl: server.loginUrl,
          methods: {
            google: setting(server.google, server.methods.google, true, server.policy.google),
            github: setting(server.github, server.methods.github, true, server.policy.github),
            password: setting(server.password, server.methods.password, true, server.policy.password),
            authenticator: setting(true, server.methods.authenticator, true, 'none'),
            'email-link': setting(server.emailLink, server.methods['email-link'], true, server.policy['email-link']),
            passkey: setting(true, !!server.passkey, !!server.passkey?.signIn, server.passkey?.secondFactor ?? 'none'),
            sms: setting(true, server.methods.sms, false, 'none'),
            ...Object.fromEntries(server.oidc.map((provider) => [provider.id, setting(true, provider.on !== false, true, provider.secondFactor)])),
          },
        });
      }
      case 'POST /auth/admin/api-keys/list':
      case 'POST /auth/admin/api-keys/revoke': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (!isAdmin()) return json({ error: 'forbidden', message: 'admins only' }, 403);
        if (!email?.includes('@')) return json({ error: 'invalid_email', message: 'invalid' }, 400);
        if (!server.accounts.has(email)) return json({ error: 'user_not_found', message: 'no user' }, 404);
        const userId = userFor(email).id;
        if (url.pathname.endsWith('/list')) {
          return json({ email, userId, apiKeys: server.apiKeys.filter((k) => k.email === email).map(({ key: _, email: __, ...info }) => info) });
        }
        const index = server.apiKeys.findIndex((k) => k.id === (body as { id?: string }).id && k.email === email);
        if (index < 0) return json({ error: 'api_key_not_found', message: 'gone' }, 404);
        server.apiKeys.splice(index, 1);
        return json({ email, userId });
      }
      // The OpenID Connect provider's token exchange for native apps: a nonce, then tokens for a Google ID token.
      case 'POST /auth/oidc/nonce':
      case 'POST /auth/oidc/token': {
        const oauth = (error: string, description: string, status = 400) => json({ error, error_description: description }, status);
        const client = server.clients.find((c) => c.id === body.client_id);
        if (!client) return oauth('invalid_client', 'unknown', 401);
        if (!client.tokenExchange) return oauth('unauthorized_client', 'not allowed');
        if (url.pathname.endsWith('/nonce')) return json({ nonce: 'nonce-token', google_client_id: 'google-client', expires_in: 300 });
        const tokens = (scope: string) => json({ access_token: 'at', token_type: 'Bearer', expires_in: 900, ...(scope.includes('openid') ? { id_token: 'idt' } : {}), ...(scope.includes('offline_access') ? { refresh_token: 'rt2' } : {}), scope });
        if (body.grant_type === 'refresh_token') return body.refresh_token === 'rt1' ? tokens(body.scope ?? 'openid offline_access') : oauth('invalid_grant', 'ended');
        if (body.grant_type !== 'urn:ietf:params:oauth:grant-type:token-exchange') return oauth('unsupported_grant_type', 'no');
        if (body.subject_token === 'needs-second-factor') return json({ error: 'interaction_required', error_description: 'a browser step', next: 'authenticator', factors: ['authenticator'] }, 400);
        if (body.subject_token !== 'google-id-token') return oauth('invalid_grant', 'subject_token: nonce mismatch.');
        return tokens(body.scope ?? '');
      }
      // A device's sign-in: the code binds to whoever looks it up first, who then approves or denies it.
      case 'POST /auth/device/lookup':
      case 'POST /auth/device/approve':
      case 'POST /auth/device/deny': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        const action = url.pathname.split('/').at(-1);
        if (action === 'lookup' && server.deviceLookupBlocked) return json({ error: 'too_many_attempts', message: 'Too many wrong codes. Try again in a few minutes.' }, 429);
        const code = String((body as { code?: unknown }).code ?? '').replace(/[\s-]/g, '').toUpperCase();
        const request = server.devices.find((d) => d.code === code);
        const invalid = () => json({ error: 'device_code_invalid', message: 'unknown' }, 404);
        if (!request || request.decided || (request.boundTo && request.boundTo !== server.user.id)) return invalid();
        if (action === 'lookup') {
          request.boundTo = server.user.id;
          return json({ code: `${code.slice(0, 4)}-${code.slice(4)}`, client: request.client, scope: request.scope, expiresAt: request.expiresAt });
        }
        if (!request.boundTo) return invalid();
        request.decided = action === 'approve' ? 'approved' : 'denied';
        return json({});
      }
      // The OpenID Connect clients: a confidential one's secret shows when it is added or gets a new one.
      case 'POST /auth/admin/clients/list':
      case 'POST /auth/admin/clients/add':
      case 'POST /auth/admin/clients/update':
      case 'POST /auth/admin/clients/remove': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (!isAdmin()) return json({ error: 'forbidden', message: 'admins only' }, 403);
        const action = url.pathname.split('/').at(-1);
        if (action === 'list') return json({ clients: server.clients });
        if (server.staleSignIn) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        const data = body as unknown as { id?: string; name?: string; redirectUris?: string[]; postLogoutRedirectUris?: string[]; public?: boolean; newSecret?: boolean; deviceFlow?: boolean; tokenExchange?: boolean; idTokenAlg?: 'ES256' | 'RS256' };
        if (action === 'add') {
          if (!data.name || !data.redirectUris?.length) return json({ error: 'invalid_client', message: 'name and redirectUris' }, 400);
          const client = { id: `mc_${server.clients.length + 1}`, name: data.name, public: !!data.public, redirectUris: data.redirectUris, postLogoutRedirectUris: data.postLogoutRedirectUris ?? [], deviceFlow: !!data.deviceFlow, tokenExchange: !!data.tokenExchange, idTokenAlg: data.idTokenAlg ?? 'ES256', createdAt: 1, updatedAt: 1 };
          server.clients.push(client);
          return json({ client, ...(client.public ? {} : { clientSecret: 'mcs_secret' }) });
        }
        const client = server.clients.find((c) => c.id === data.id);
        if (!client) return json({ error: 'client_not_found', message: 'gone' }, 404);
        if (action === 'remove') {
          server.clients.splice(server.clients.indexOf(client), 1);
          return json({ client });
        }
        Object.assign(client, { ...(data.name ? { name: data.name } : {}), ...(data.redirectUris ? { redirectUris: data.redirectUris } : {}), ...(data.deviceFlow !== undefined ? { deviceFlow: data.deviceFlow } : {}), ...(data.tokenExchange !== undefined ? { tokenExchange: data.tokenExchange } : {}), ...(data.idTokenAlg !== undefined ? { idTokenAlg: data.idTokenAlg } : {}) });
        return json({ client, ...(data.newSecret && !client.public ? { clientSecret: 'mcs_new' } : {}) });
      }
      // The providers as the admin API answers them: an admin adds, changes and removes Google, GitHub and
      // OpenID Connect providers; a removal or its dry run counts `usersAlone`.
      case 'POST /auth/admin/providers/list':
      case 'POST /auth/admin/providers/add':
      case 'POST /auth/admin/providers/update':
      case 'POST /auth/admin/providers/remove': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (!isAdmin()) return json({ error: 'forbidden', message: 'admins only' }, 403);
        const data = body as unknown as { id?: string; kind?: string; name?: string; clientId?: string; clientSecret?: string | null; issuer?: string; scopes?: string; trustEmail?: boolean; dryRun?: boolean };
        const action = url.pathname.split('/').at(-1);
        const callbackUrl = (id: string) => `${SERVER}/auth/providers/${id}/callback`;
        const builtIn = (kind: 'google' | 'github') => ({ id: kind, kind, name: server.providerNames[kind], clientId: `${kind}-client`, hasClientSecret: true, callbackUrl: callbackUrl(kind), createdAt: 1, updatedAt: 1 });
        const oidcInfo = (p: FakeServer['oidc'][number]) => ({
          id: p.id, kind: 'oidc', name: p.name, clientId: p.clientId ?? `${p.id}-client`, hasClientSecret: true, callbackUrl: callbackUrl(p.id), createdAt: 1, updatedAt: 1,
          issuer: p.issuer ?? `https://${p.id}.example.com`, scopes: p.scopes ?? [], trustEmail: p.trustEmail ?? false,
        });
        if (action === 'list') {
          const providers = [...(['google', 'github'] as const).filter((kind) => server[kind]).map(builtIn), ...server.oidc.map(oidcInfo)];
          return json({ providers, callbackBase: `${SERVER}/auth/providers/` });
        }
        const dryRun = action === 'remove' && data.dryRun === true;
        if (server.staleSignIn && !dryRun) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        const id = action === 'add' ? (data.kind === 'oidc' ? data.id : data.kind) : data.id;
        const oidc = server.oidc.find((p) => p.id === id);
        if (action === 'add' && data.kind === 'oidc') {
          if (!id || !data.issuer?.startsWith('https://')) return json({ error: 'invalid_provider', message: 'The issuer must be an https URL.' }, 400);
          if (oidc) return json({ error: 'provider_exists', message: 'exists' }, 409);
          const added = { id, name: data.name ?? id, secondFactor: 'none' as const, on: false, issuer: data.issuer, clientId: data.clientId, scopes: data.scopes?.split(' ').filter(Boolean) ?? [], trustEmail: !!data.trustEmail };
          server.oidc.push(added);
          return json({ provider: oidcInfo(added) });
        }
        if (oidc) {
          if (action === 'update') {
            Object.assign(oidc, {
              ...(data.name ? { name: data.name } : {}),
              ...(data.clientId ? { clientId: data.clientId } : {}),
              ...(data.scopes !== undefined ? { scopes: data.scopes.split(' ').filter(Boolean) } : {}),
              ...(data.trustEmail !== undefined ? { trustEmail: data.trustEmail } : {}),
            });
            return json({ provider: oidcInfo(oidc) });
          }
          if (!dryRun) server.oidc.splice(server.oidc.indexOf(oidc), 1);
          return json({ provider: oidcInfo(oidc), usersWithoutSignIn: server.usersAlone[oidc.id] ?? 0, ...(dryRun ? { dryRun: true } : {}) });
        }
        const kind = id as 'google' | 'github';
        if (kind !== 'google' && kind !== 'github') return json(action === 'add' ? { error: 'invalid_provider', message: 'kind' } : { error: 'provider_not_found', message: 'none' }, action === 'add' ? 400 : 404);
        if (action === 'add' && server[kind]) return json({ error: 'provider_exists', message: 'exists' }, 409);
        if (action !== 'add' && !server[kind]) return json({ error: 'provider_not_found', message: 'none' }, 404);
        if (dryRun) return json({ provider: builtIn(kind), usersWithoutSignIn: server.usersAlone[kind] ?? 0, dryRun: true });
        if (data.name) server.providerNames[kind] = data.name;
        server[kind] = action !== 'remove';
        // A new provider is off until it is switched on; removed, it is out of the settings too.
        if (action !== 'update') server.methods[kind] = false;
        return json(action === 'remove' ? { provider: builtIn(kind), usersWithoutSignIn: server.usersAlone[kind] ?? 0 } : { provider: builtIn(kind) });
      }
      // Every user in the order they signed up, a page at a time; the cursor is the last one's address.
      case 'POST /auth/admin/users/search': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (!isAdmin()) return json({ error: 'forbidden', message: 'admins only' }, 403);
        const { role, limit = 50, cursor, method } = body as { role?: string; limit?: number; cursor?: string; method?: string };
        if (method !== undefined) return json({ error: 'invalid_search', message: '"method" is not a filter' }, 400);
        const all = [...server.accounts.keys()];
        const from = cursor ? all.indexOf(cursor) + 1 : 0;
        const roles = (address: string) => (server.claims.get(address)?.roles as string[] | undefined) ?? [];
        const page = all.slice(from, from + limit);
        const users = page
          .filter((address) => !role || roles(address).includes(role))
          .map((address) => ({ id: userFor(address).id, email: address, name: server.accounts.get(address)!.name ?? null, emailVerified: server.accounts.get(address)!.verified, claims: server.claims.get(address) ?? {}, methods: ['password'], signedUpAt: 1, pending: false }));
        return json({ users, ...(from + limit < all.length ? { cursor: page.at(-1) } : {}) });
      }
      case 'POST /auth/admin/users/delete': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (!isAdmin()) return json({ error: 'forbidden', message: 'admins only' }, 403);
        if (!email?.includes('@')) return json({ error: 'invalid_email', message: 'invalid' }, 400);
        if (!server.accounts.has(email)) return json({ error: 'user_not_found', message: 'no user' }, 404);
        if (server.user.email === email) return json({ error: 'own_admin_role', message: 'not yourself' }, 403);
        const userId = userFor(email).id;
        server.accounts.delete(email);
        server.claims.delete(email);
        return json({ email, userId });
      }
      case 'POST /auth/admin/sign-in/reset': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (!isAdmin()) return json({ error: 'forbidden', message: 'admins only' }, 403);
        if (!email?.includes('@')) return json({ error: 'invalid_email', message: 'invalid' }, 400);
        const account = server.accounts.get(email);
        if (!account) return json({ error: 'user_not_found', message: 'no user' }, 404);
        // Every way in goes, and the address is unconfirmed until the next sign-up proves it.
        server.accounts.set(email, { password: '', verified: false, ...(account.name ? { name: account.name } : {}) });
        server.authenticators.delete(email);
        server.recoveryCodes.delete(email);
        server.phones.delete(email);
        server.linked.delete(email);
        for (const [id, passkey] of server.passkeys) if (passkey.email === email) server.passkeys.delete(id);
        const userId = userFor(email).id;
        // Their sessions end: the admin's own as well.
        if (server.user.email === email) server.user = null;
        return json({ email, userId });
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
        // Like the real server: the Google account's sub, if the user has one (ada's id is `google:<sub>`).
        const googleSub = server.user.id.startsWith('google:') ? server.user.id.slice('google:'.length) : undefined;
        server.user = null;
        return googleSub ? json({ googleSub }) : new Response(null, { status: 204 });
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
    revoke: vi.fn(),
  };
  (window as { google?: unknown }).google = { accounts: { id } };
  return {
    id,
    /** Simulates Google handing a credential to the callback of the latest initialize(). */
    signIn(credential = 'google-id-token') {
      id.initialize.mock.lastCall![0].callback!({ credential });
    },
  };
}

export function gisScripts(): NodeListOf<HTMLScriptElement> {
  return document.querySelectorAll('script[src="https://accounts.google.com/gsi/client"]');
}

/**
 * A browser with passkeys: `PublicKeyCredential` and `navigator.credentials`, whose dialog answers with the
 * passkey `id` (its credential id at the fake server), or as `outcome` says: the user closed it, or the
 * device holds one of the user's passkeys already. `conditional` says whether autofill offers passkeys.
 */
export function stubWebAuthn(options: { id?: string; outcome?: 'ok' | 'cancel' | 'exists'; conditional?: boolean } = {}) {
  const state = { id: options.id ?? 'cred-1', outcome: options.outcome ?? 'ok', conditional: options.conditional ?? false };
  const answer = (kind: 'create' | 'get') => {
    if (state.outcome === 'cancel') return Promise.reject(new DOMException('closed', 'NotAllowedError'));
    if (state.outcome === 'exists') return Promise.reject(new DOMException('exists', 'InvalidStateError'));
    return Promise.resolve({ id: state.id, toJSON: () => ({ id: state.id, rawId: state.id, type: 'public-key', response: { kind } }) });
  };
  const credentials = {
    create: vi.fn((_options: CredentialCreationOptions) => answer('create')),
    get: vi.fn((request: CredentialRequestOptions) =>
      // Autofill waits for a pick that never comes in a test, until it is aborted.
      request.mediation === 'conditional'
        ? new Promise((_, reject) => request.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))))
        : answer('get'),
    ),
  };
  vi.stubGlobal(
    'PublicKeyCredential',
    class {
      static isConditionalMediationAvailable = async () => state.conditional;
      static parseCreationOptionsFromJSON = (json: unknown) => json;
      static parseRequestOptionsFromJSON = (json: unknown) => json;
      static signalUnknownCredential = vi.fn(async () => {});
    },
  );
  Object.defineProperty(navigator, 'credentials', { value: credentials, configurable: true });
  return { state, credentials };
}

export function resetAll(): void {
  delete (navigator as { credentials?: unknown }).credentials;
  resetMadauthForTests();
  resetGisForTests();
  delete (window as { google?: unknown }).google;
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
