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
  /** Error code that /auth/google/verify answers with, if set. */
  verifyError: string | undefined;
  /** Makes every request fail like an unreachable server. */
  down: boolean;
  /** Every request waits for this before it is answered, if set: a slow server. */
  held: Promise<void> | undefined;
  nonces: number;
  requests: RecordedRequest[];
  /** Claims by e-mail address, as set through the admin API. */
  claims: Map<string, Record<string, unknown>>;
  /** Which sign-in methods are on (the list an admin sets); `totp` is the app on its own, `sms` SMS codes as a second factor. */
  methods: { google: boolean; github: boolean; password: boolean; totp: boolean; 'email-link': boolean; sms: boolean };
  /** Whether Google, GitHub, password and the e-mail link ask for the authenticator app as a second factor. */
  policy: { google: SecondFactorPolicy; github: SecondFactorPolicy; password: SecondFactorPolicy; 'email-link': SecondFactorPolicy };
  /** The addresses whose users have set up the authenticator app, and their recovery codes left. */
  authenticators: Set<string>;
  recoveryCodes: Map<string, string[]>;
  /** A sign-in whose first step is done, waiting for a second factor or a setup (the challenge cookie), with the factors that can finish it. */
  challenge:
    | { email: string; next: 'passkey' | 'totp' | 'totp-setup' | 'sms'; method: 'google' | 'github' | 'password' | 'totp' | 'email-link' | 'passkey'; factors: ('passkey' | 'totp' | 'sms')[] }
    | undefined;
  /** Passkeys, when the server has them on: whether they sign in on their own (and sign people up), and that sign-in's policy. */
  passkey: { signIn: boolean; signUp?: boolean; secondFactor: SecondFactorPolicy } | null;
  /** The passkeys, by credential id: whose, their account id and name. */
  passkeys: Map<string, { email: string; id: string; name: string }>;
  /** Google, GitHub and the e-mail link the users added while signed in, by e-mail address. */
  linked: Map<string, Set<'google' | 'github' | 'email-link'>>;
  /** The user signed in more than ten minutes ago: changing a method answers `reauth_required`. */
  staleSignIn: boolean;
  /** A setup under way (the setup cookie); set to undefined to simulate its expiry. */
  totpSetup: { email: string } | undefined;
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
    methods: { google: true, github: true, password: true, totp: false, 'email-link': false, sms: false },
    policy: { google: 'none', github: 'none', password: 'none', 'email-link': 'none' },
    authenticators: new Set(),
    recoveryCodes: new Map(),
    challenge: undefined,
    totpSetup: undefined,
    phones: new Map(),
    texts: [],
    smsSetup: undefined,
    smsTooSoon: false,
    sessionTtl: 3600,
    passkey: null,
    passkeys: new Map(),
    linked: new Map(),
    staleSignIn: false,
  };
  const mask = (phone: string) => `${phone.slice(0, 3)} ${'•'.repeat(Math.max(0, phone.length - 5))} ${phone.slice(-2)}`;
  const normalizePhone = (value: unknown) => {
    const digits = String(value ?? '').replace(/[\s().-]/g, '');
    return /^\+[1-9]\d{6,14}$/.test(digits) ? digits : undefined;
  };
  const userFor = (email: string): MadauthUser => {
    const account = server.accounts.get(email);
    return email === grace.email ? grace : email === ada.email ? ada : { id: `usr_${email.split('@')[0]}`, email, ...(account?.name ? { name: account.name } : {}) };
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
  const totpOn = () => server.methods.totp || server.policy.google !== 'none' || server.policy.github !== 'none' || server.policy.password !== 'none' || server.policy['email-link'] !== 'none';
  /** What follows a primary method that succeeded: the session, or a code (from the app, or by SMS) or the app's setup. */
  const passkeysOf = (email: string) => [...server.passkeys.values()].filter((p) => p.email === email);
  const afterPrimary = (email: string, method: 'google' | 'github' | 'password' | 'email-link' | 'passkey') => {
    const policy = method === 'passkey' ? (server.passkey?.secondFactor ?? 'none') : server.policy[method];
    const app = server.authenticators.has(email);
    const phone = server.methods.sms && server.phones.has(email);
    const passkey = !!server.passkey && method !== 'passkey' && passkeysOf(email).length > 0;
    const factors: ('passkey' | 'totp' | 'sms')[] = [...(passkey ? (['passkey'] as const) : []), ...(app ? (['totp'] as const) : []), ...(phone ? (['sms'] as const) : [])];
    const next: 'passkey' | 'totp' | 'sms' | 'totp-setup' | undefined =
      policy === 'none' ? undefined : factors.length ? factors[0] : policy === 'required' ? 'totp-setup' : undefined;
    if (!next) return signedIn(email);
    // As the real server: a sign-in that goes on with a second step ends the session there was.
    server.user = null;
    server.challenge = { email, next, method, factors };
    const error = { passkey: 'passkey_required', totp: 'totp_required', sms: 'sms_required', 'totp-setup': 'totp_setup_required' }[next];
    // For the setup, the factors that can be set up: a passkey when they are on, the app, and a phone when SMS codes are on.
    const named = next === 'totp-setup' ? [...(server.passkey && method !== 'passkey' ? ['passkey'] : []), 'totp', ...(server.methods.sms ? ['sms'] : [])] : factors;
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
      body: typeof init.body === 'string' ? JSON.parse(init.body) : undefined,
      credentials: init.credentials,
    });
    if (server.held) await server.held;
    if (server.down) throw new TypeError('Failed to fetch');
    const body = (typeof init.body === 'string' ? JSON.parse(init.body) : {}) as Record<string, string>;
    const email = body.email?.trim().toLowerCase();
    /** The user a setup belongs to: the signed-in one, or the one whose sign-in waits for it. */
    const whoSetsUp = () => server.user?.email ?? (server.challenge?.next === 'totp-setup' ? server.challenge.email : undefined);
    switch (`${method} ${url.pathname}`) {
      case 'GET /auth/config':
        return json({
          google: server.google && server.methods.google ? { clientId: CLIENT_ID, codeFlow: server.codeFlow, secondFactor: server.policy.google } : null,
          github: server.github && server.methods.github ? { secondFactor: server.policy.github } : null,
          password: server.password && server.methods.password ? { ...server.passwordRules, secondFactor: server.policy.password } : null,
          totp: totpOn() ? { signIn: server.methods.totp, signUp: server.methods.totp && server.password } : null,
          email: { verification: server.password },
          emailLink: server.emailLink && server.methods['email-link'] ? { secondFactor: server.policy['email-link'] } : null,
          sms: server.methods.sms,
          passkey: server.passkey ? { signUp: false, ...server.passkey } : null,
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
        if (!server.user && server.challenge?.next === 'totp-setup') {
          // A sign-up with a passkey alone: it signs in as a passkey would, its policy may ask for a second factor.
          const signUp = server.challenge.method === 'passkey';
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
      // --- The user's methods ---
      case 'GET /auth/methods': {
        const user = server.user?.email;
        if (!user) return json({ error: 'no_session', message: 'sign in' }, 401);
        const account = server.accounts.get(user);
        const methods = [
          ...(account?.password ? [{ id: 'acc_password', method: 'password', signIn: true, removable: true, createdAt: 1 }] : []),
          ...[...(server.linked.get(user) ?? [])].map((method) => ({ id: `acc_${method}`, method, signIn: true, removable: true, createdAt: 1, ...(method === 'email-link' ? {} : { email: user }) })),
          ...(server.authenticators.has(user) ? [{ id: 'acc_totp', method: 'totp', signIn: server.methods.totp, removable: false, createdAt: 1 }] : []),
          ...passkeysOf(user).map((p) => ({ id: p.id, method: 'passkey', signIn: !!server.passkey?.signIn, removable: true, createdAt: 1, name: p.name, lastUsedAt: 0 })),
        ];
        return json({ methods });
      }
      case 'POST /auth/methods/remove': {
        const user = server.user?.email;
        if (!user) return json({ error: 'no_session', message: 'sign in' }, 401);
        if (server.staleSignIn) return json({ error: 'reauth_required', message: 'sign in again' }, 401);
        const id = (body as { id?: string }).id;
        const passkey = [...server.passkeys.entries()].find(([, p]) => p.id === id && p.email === user);
        if (passkey) server.passkeys.delete(passkey[0]);
        else if (id === 'acc_password' && server.accounts.get(user)?.password) server.accounts.get(user)!.password = '';
        else if (id?.startsWith('acc_') && server.linked.get(user)?.delete(id.slice(4) as 'google')) {
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
        if (!account || account.app || account.password !== body.password) return json({ error: 'invalid_credentials', message: 'wrong' }, 401);
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
          server.challenge = { email: target, next: 'totp-setup', method: 'totp', factors: [] };
          return json({ error: 'totp_setup_required', message: 'set it up', method: 'totp', factors: ['totp'] }, 401);
        }
        if (account.passkey) {
          // A sign-up with a passkey alone: it is created now.
          server.challenge = { email: target, next: 'totp-setup', method: 'passkey', factors: [] };
          return json({ error: 'totp_setup_required', message: 'create it', method: 'passkey', factors: ['passkey'] }, 401);
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
        if (!challenge || !challenge.factors.includes('totp') || !server.authenticators.has(challenge.email)) {
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
        // Replacing an app: the current one has to agree.
        if (server.authenticators.has(who)) {
          if (body.code === undefined && body.recoveryCode === undefined) return json({ error: 'code_required', message: 'the current app has to agree' }, 401);
          if (!codeOk(who, body)) return json({ error: 'code_invalid', message: 'wrong' }, 401);
        }
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
        // A sign-up with the app has no other way in.
        const account = server.accounts.get(server.user.email);
        if (account?.app && !account.password) return json({ error: 'only_method', message: 'the only way in' }, 403);
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
      // --- SMS codes ---
      case 'POST /auth/sms/setup': {
        if (!server.methods.sms) return json({ error: 'method_disabled', message: 'off' }, 403);
        const who = whoSetsUp();
        if (!who) return json({ error: 'no_session' }, 401);
        const phone = normalizePhone(body.phone);
        if (!phone) return json({ error: 'invalid_phone', message: 'not a number' }, 400);
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
      case 'POST /auth/admin/settings/set': {
        if (!server.user) return json({ error: 'no_session' }, 401);
        if (!isAdmin()) return json({ error: 'forbidden', message: 'admins only' }, 403);
        if (url.pathname.endsWith('/set')) {
          const { password } = body as { password?: { minLength?: number; minScore?: number } };
          if (password) server.passwordRules = { minLength: password.minLength ?? 8, minScore: password.minScore ?? 2 };
        }
        if (url.pathname.endsWith('/set') && (body as { methods?: unknown }).methods !== undefined) {
          const methods = (body as { methods?: Record<string, unknown> }).methods;
          if (!methods || typeof methods !== 'object') return json({ error: 'invalid_settings', message: 'invalid' }, 400);
          const on = (value: unknown) => value === true || (!!value && typeof value === 'object');
          const policyOf = (value: unknown): SecondFactorPolicy =>
            value && typeof value === 'object' && 'secondFactor' in value ? ((value as { secondFactor: SecondFactorPolicy }).secondFactor ?? 'none') : 'none';
          // The app is listed in `methods` when it signs in on its own.
          const signsIn = (value: unknown) => on(value) && (value as { allowAsSignInMethod?: unknown }).allowAsSignInMethod === true;
          server.methods = { google: on(methods.google), github: on(methods.github), password: on(methods.password), totp: signsIn(methods.totp), 'email-link': on(methods['email-link']), sms: on(methods.sms) };
          server.policy = { google: policyOf(methods.google), github: policyOf(methods.github), password: policyOf(methods.password), 'email-link': policyOf(methods['email-link']) };
        }
        return json({
          password: server.passwordRules,
          methods: {
            google: setting(server.google, server.methods.google, true, server.policy.google),
            github: setting(server.github, server.methods.github, true, server.policy.github),
            password: setting(server.password, server.methods.password, true, server.policy.password),
            totp: setting(true, server.methods.totp, true, 'none'),
            'email-link': setting(server.emailLink, server.methods['email-link'], true, server.policy['email-link']),
            passkey: setting(true, !!server.passkey, !!server.passkey?.signIn, server.passkey?.secondFactor ?? 'none'),
            sms: setting(true, server.methods.sms, false, 'none'),
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
