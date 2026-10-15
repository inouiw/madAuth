import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWTPayload } from 'jose';
import { vi } from 'vitest';
import { createApp } from '../app.js';
import type { MadauthConfig } from '../config.js';
import { generateSigningKey } from '../keys.js';
import { METHODS_SETTING, Settings, parseMethodSettings, type MethodId, type MethodSettings, type SecondFactorPolicy } from '../settings.js';
import type { StoreAdapter } from '../store/schema.js';
import { createSqliteAdapter } from '../store/sqlite.js';
import { Users } from '../users.js';
import { EMAIL_TYPES, SMS_TYPES, WEBHOOK_TYPES, generateWebhookSecret, verifyWebhook } from '../webhooks.js';

export const ISSUER = 'https://auth.example.com';
export const APP_ORIGIN = 'https://app.example.com';
export const CLIENT_ID = '123-test.apps.googleusercontent.com';

/** A key pair standing in for Google's signing key. */
const google = await generateKeyPair('RS256');
const googleJwk = { ...(await exportJWK(google.publicKey)), kid: 'google-test', alg: 'RS256' };
export const googleJwks = createLocalJWKSet({ keys: [googleJwk] });

/** Signs a "Google" ID token; override any claim, or sign with another key. */
export async function googleIdToken(
  claims: JWTPayload = {},
  opts: { key?: CryptoKey; kid?: string } = {},
): Promise<string> {
  return new SignJWT({
    iss: 'https://accounts.google.com',
    aud: CLIENT_ID,
    sub: '1001',
    email: 'ada@example.com',
    email_verified: true,
    name: 'Ada Lovelace',
    picture: 'https://example.com/ada.png',
    ...claims,
  })
    .setProtectedHeader({ alg: 'RS256', kid: opts.kid ?? 'google-test' })
    .setIssuedAt()
    .setExpirationTime(typeof claims.exp === 'number' ? claims.exp : '1h')
    .sign(opts.key ?? google.privateKey);
}

export const signingKey = await generateSigningKey();

/** Google sign-in with an in-memory store; no e-mail & password and no webhook unless overridden. */
export function testConfig(overrides: Partial<MadauthConfig> = {}): MadauthConfig {
  return {
    issuer: ISSUER,
    signingKey,
    allowedOrigins: [APP_ORIGIN],
    sessionTtlSeconds: 3600,
    renewalTtlSeconds: 30 * 24 * 3600,
    google: { clientId: CLIENT_ID, clientSecret: 'test-secret' },
    store: createSqliteAdapter(':memory:'),
    jwksResolver: googleJwks,
    ...overrides,
  };
}

export function testApp(overrides: Partial<MadauthConfig> = {}) {
  return createApp(testConfig(overrides));
}

/** Parses the Set-Cookie headers of a response into name → { value, attributes }. */
export function cookies(res: Response): Record<string, { value: string; attrs: Record<string, string | true> }> {
  const result: Record<string, { value: string; attrs: Record<string, string | true> }> = {};
  for (const header of res.headers.getSetCookie()) {
    const [pair, ...attrs] = header.split(';').map((s) => s.trim());
    const eq = pair.indexOf('=');
    result[pair.slice(0, eq)] = {
      value: pair.slice(eq + 1),
      attrs: Object.fromEntries(
        attrs.map((a) => {
          const [k, ...v] = a.split('=');
          return [k.toLowerCase(), v.length ? v.join('=') : true];
        }),
      ),
    };
  }
  return result;
}

/** The Cookie header a browser would send after this response: every cookie it set, e.g. session and renewal. */
export function cookieHeader(res: Response): string {
  return Object.entries(cookies(res))
    .filter(([, cookie]) => cookie.value)
    .map(([name, cookie]) => `${name}=${cookie.value}`)
    .join('; ');
}

type App = ReturnType<typeof testApp>;

/** Gets a nonce from the app as the allowed browser would; returns the nonce and its cookie. */
export async function getNonce(app: App): Promise<{ nonce: string; cookie: string }> {
  const res = await app.request('/auth/google/nonce', { method: 'POST', headers: { Origin: APP_ORIGIN } });
  const { nonce } = (await res.json()) as { nonce: string };
  return { nonce, cookie: `madauth_nonce=${cookies(res).madauth_nonce.value}` };
}

export function verify(app: App, credential: string, cookie?: string): Promise<Response> {
  return Promise.resolve(
    app.request('/auth/google/verify', {
      method: 'POST',
      headers: { Origin: APP_ORIGIN, 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
      body: JSON.stringify({ credential }),
    }),
  );
}

/** Signs in through the FedCM flow and returns the sign-in response, with all its cookies. */
export async function signInResponse(app: App): Promise<Response> {
  const { nonce, cookie } = await getNonce(app);
  return verify(app, await googleIdToken({ nonce }), cookie);
}

/** Signs in through the FedCM flow and returns the session cookie value. */
export async function signIn(app: App): Promise<string> {
  const { nonce, cookie } = await getNonce(app);
  const res = await verify(app, await googleIdToken({ nonce }), cookie);
  return cookies(res).madauth_session.value;
}

/**
 * The token with one character of its payload changed, so its signature no longer matches. Not the signature's
 * last characters: they are mostly padding bits, which decoders ignore, so now and then a "tampered" signature
 * decodes to the same bytes and verifies. The signature covers the encoded payload, so any change there breaks it.
 */
export function tamperedToken(token: string): string {
  const [header, payload, signature] = token.split('.');
  return `${header}.${payload.slice(0, -1)}${payload.endsWith('A') ? 'B' : 'A'}.${signature}`;
}

// --- E-mail & password, webhooks ---

export const WEBHOOK_URL = 'https://hooks.example.com/madauth';
export const WEBHOOK_SECRET = generateWebhookSecret();
/** A receiver that asks for every type. */
export const ALL_EVENTS: ReadonlySet<string> = new Set(WEBHOOK_TYPES);

export interface WebhookCall {
  type: string;
  data: Record<string, any>;
}

/**
 * A webhook receiver for tests: checks each call's signature, records it and answers 2xx. Set `fail` to
 * answer with an error status or to fail like an unreachable or slow receiver; `respond` to answer
 * with a body (e.g. for user.signing_up).
 */
export function recordingWebhook() {
  const calls: WebhookCall[] = [];
  const hook = {
    calls,
    fail: undefined as number | 'network' | 'timeout' | undefined,
    /** Which call types `fail` applies to; all by default. */
    failOnly: undefined as ((type: string) => boolean) | undefined,
    respond: undefined as ((call: WebhookCall) => unknown) | undefined,
    /** The e-mails taken over so far. */
    emails: () => calls.filter((c) => (EMAIL_TYPES as readonly string[]).includes(c.type)),
    lastEmail: () => hook.emails().at(-1),
    /** The SMS taken over so far. */
    sms: () => calls.filter((c) => (SMS_TYPES as readonly string[]).includes(c.type)),
    lastSms: () => hook.sms().at(-1),
    types: () => calls.map((c) => c.type),
    fetch: (async (url: string | URL, init: RequestInit = {}) => {
      const body = String(init.body);
      if (String(url) !== WEBHOOK_URL || !verifyWebhook(WEBHOOK_SECRET, new Headers(init.headers), body)) {
        return new Response(null, { status: 401 });
      }
      const call = JSON.parse(body) as WebhookCall;
      const fail = hook.failOnly && !hook.failOnly(call.type) ? undefined : hook.fail;
      if (fail === 'network') throw new TypeError('fetch failed');
      if (fail === 'timeout') throw new DOMException('The operation was aborted due to timeout', 'TimeoutError');
      if (typeof fail === 'number') return new Response('failed', { status: fail });
      calls.push(call);
      const answer = hook.respond?.(call);
      return new Response(answer === undefined ? null : JSON.stringify(answer), { status: 200 });
    }) as typeof fetch,
  };
  return hook;
}

export type RecordingWebhook = ReturnType<typeof recordingWebhook>;

/** Sets a user's claims straight in the store, as madAuth before 0.6 did from the command line; the user must exist. */
export async function setClaims(store: StoreAdapter, email: string, claims: Record<string, unknown> | null): Promise<void> {
  const users = new Users(store);
  const user = await users.findByEmail(email.toLowerCase());
  if (!user) throw new Error(`No user ${email}`);
  await users.updateUser(user.id, { claims: claims && Object.keys(claims).length ? JSON.stringify(claims) : null });
}

export const REDIRECT_TO = `${APP_ORIGIN}/account`;

/** An app with e-mail & password sign-in (in-memory SQLite), Google, and a recording webhook receiver. */
export function passwordApp(overrides: Partial<MadauthConfig> = {}) {
  const hook = recordingWebhook();
  const store = createSqliteAdapter(':memory:');
  const app = testApp({
    store,
    password: {},
    webhook: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET, events: ALL_EVENTS },
    webhookFetch: hook.fetch,
    ...overrides,
  });
  return { app, hook, store };
}

type PasswordApp = ReturnType<typeof passwordApp>['app'];

export function post(app: PasswordApp, path: string, body: unknown, headers: Record<string, string> = {}): Promise<Response> {
  return Promise.resolve(
    app.request(path, {
      method: 'POST',
      headers: { Origin: APP_ORIGIN, 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
    }),
  );
}

/** The link, its token and the code of a verification, reset or sign-in e-mail. */
export function linkAndCode(call: WebhookCall | undefined): { token: string; code: string; link: string } {
  const link = call?.data.link as string | undefined;
  if (!link || !/#madauth_(verify|reset|signin)=/.test(link)) throw new Error(`No e-mail with a link: ${JSON.stringify(call)}`);
  return { link, token: link.split('=').at(-1)!, code: call!.data.code as string };
}

/** Signs up and confirms the e-mail with the link; returns the session cookie. */
export async function signUpVerified(
  app: PasswordApp,
  hook: RecordingWebhook,
  email = 'grace@example.com',
  password = 'correct horse battery',
): Promise<string> {
  await post(app, '/auth/password/signup', { email, password, name: 'Grace Hopper', redirectTo: REDIRECT_TO });
  const res = await post(app, '/auth/email/verify', { token: linkAndCode(hook.lastEmail()).token });
  return cookies(res).madauth_session.value;
}

// --- GitHub ---

export const GITHUB_CLIENT_ID = 'Iv1.0123456789abcdef';
export const GITHUB_CLIENT_SECRET = 'github-test-secret';

/** An app with GitHub sign-in next to Google, in-memory SQLite; no webhook unless overridden. */
export function githubApp(overrides: Partial<MadauthConfig> = {}) {
  return testApp({ github: { clientId: GITHUB_CLIENT_ID, clientSecret: GITHUB_CLIENT_SECRET }, ...overrides });
}

/** What the GitHub stand-in answers; every field has a default that signs Ada in. */
export interface GitHubStub {
  /** The token the code exchange issues; null makes GitHub answer `{ error }` (HTTP 200) instead. */
  token?: string | null;
  user?: { id?: number; login?: string; name?: string | null; avatar_url?: string; email?: string | null };
  emails?: { email: string; primary: boolean; verified: boolean }[];
  /** The status GitHub answers the grant's revocation with. */
  revokeStatus?: number;
  /** The status api.github.com answers with instead of the account (e.g. 401 for a bad token). */
  apiStatus?: number;
  /** Makes every call to GitHub fail like a network error. */
  fail?: boolean;
}

export const GITHUB_USER = { id: 7001, login: 'ada', name: 'Ada Lovelace', avatar_url: 'https://avatars.githubusercontent.com/u/7001', email: null };
export const GITHUB_EMAILS = [{ email: 'ada@example.com', primary: true, verified: true }];

/**
 * Stands in for github.com and api.github.com by stubbing `fetch` (undo with `vi.unstubAllGlobals()`):
 * records every call and answers as GitHub would. Webhooks are unaffected: they use `webhookFetch`.
 */
export function stubGitHub(stub: GitHubStub = {}) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchMock = vi.fn(async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input);
    calls.push({ url, init });
    if (stub.fail) throw new TypeError('fetch failed');
    if (url === 'https://github.com/login/oauth/access_token') {
      return stub.token === null
        ? Response.json({ error: 'bad_verification_code', error_description: 'The code passed is incorrect or expired.' })
        : Response.json({ access_token: stub.token ?? 'gho_test', scope: 'user:email', token_type: 'bearer' });
    }
    if (stub.apiStatus && url.startsWith('https://api.github.com/user')) return Response.json({ message: 'Bad credentials' }, { status: stub.apiStatus });
    if (url === 'https://api.github.com/user') return Response.json({ ...GITHUB_USER, ...stub.user });
    if (url === 'https://api.github.com/user/emails') return Response.json(stub.emails ?? GITHUB_EMAILS);
    if (url.startsWith('https://api.github.com/applications/') && init.method === 'DELETE') return new Response(null, { status: stub.revokeStatus ?? 204 });
    return new Response('not found', { status: 404 });
  });
  vi.stubGlobal('fetch', fetchMock);
  return {
    calls,
    /** The bodies of the code exchanges so far. */
    exchanges: () => calls.filter((c) => c.url === 'https://github.com/login/oauth/access_token').map((c) => ({ ...c, body: new URLSearchParams(c.init.body as URLSearchParams) })),
    /** The revocations so far. */
    revocations: () => calls.filter((c) => c.init.method === 'DELETE'),
  };
}

/** Starts the GitHub redirect flow as the browser would; returns where GitHub would send the user and the state cookie. */
export async function startGitHub(app: App, returnTo = `${APP_ORIGIN}/page`) {
  const res = await app.request(`/auth/github/start?return_to=${encodeURIComponent(returnTo)}`);
  const location = new URL(res.headers.get('location') ?? 'about:blank');
  return { res, location, state: location.searchParams.get('state') ?? '', cookie: `madauth_oauth=${cookies(res).madauth_oauth?.value}` };
}

/** Comes back from GitHub with a code, as the browser would after the user agreed. */
export function githubCallback(app: App, started: { state: string; cookie: string }, query = `code=c&state=${started.state}`): Promise<Response> {
  return Promise.resolve(app.request(`/auth/github/callback?${query}`, { headers: { Cookie: started.cookie } }));
}

/** Signs in through the GitHub flow (the stand-in must be in place) and returns the callback's redirect, with its cookies. */
export async function signInWithGitHub(app: App, returnTo?: string): Promise<Response> {
  return githubCallback(app, await startGitHub(app, returnTo));
}

/**
 * Links a Google account to a user who has a password, as madAuth before 0.4 did: such records don't say which
 * account is the sign-in method, so both are. A user can't get a second sign-in method any more.
 */
export async function linkGoogleAsBefore(store: StoreAdapter, userId: string, sub: string, email: string): Promise<void> {
  const account = await new Users(store).linkAccount(userId, { key: `google:${sub}`, email, primary: false });
  // Records from then say neither whether they sign in nor whether they are a second factor.
  await store.update('account', { id: account!.id }, { secondFactor: null });
}

/** Methods as tests set them: in full, or in a shorthand (`{}` or `{ secondFactor }`), as madAuth before 0.6 stored them. */
export type TestMethods = Partial<Record<MethodId, { allowAsSignInMethod?: boolean; secondFactor?: SecondFactorPolicy }>>;

/**
 * Stores which methods are on. Without `allowAsSignInMethod` anywhere, the shorthand means what it did before
 * 0.6: a listed method signs in on its own (SMS codes: a second factor), and the authenticator app is a second
 * factor wherever a policy asks for one.
 */
export async function setMethods(store: StoreAdapter, methods: TestMethods): Promise<void> {
  const full = Object.values(methods).some((setting) => setting && 'allowAsSignInMethod' in setting);
  const shorthand = (): MethodSettings => {
    const settings: MethodSettings = Object.fromEntries(
      Object.entries(methods).map(([method, setting]) => [method, { allowAsSignInMethod: method !== 'sms', secondFactor: setting?.secondFactor ?? 'none' }]),
    );
    const asks = Object.values(settings).some((setting) => setting.secondFactor !== 'none');
    if (asks && !settings.authenticator) settings.authenticator = { allowAsSignInMethod: false, secondFactor: 'none' };
    return settings;
  };
  const parsed = full ? parseMethodSettings(methods) : shorthand();
  if (!parsed) throw new Error(`Not a methods setting: ${JSON.stringify(methods)}`);
  await new Settings(store).set(METHODS_SETTING, parsed, null);
}
