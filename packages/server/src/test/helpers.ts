import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWTPayload } from 'jose';
import { createApp } from '../app.js';
import type { MadauthConfig } from '../config.js';
import { generateSigningKey } from '../keys.js';
import { createSqliteAdapter } from '../store/sqlite.js';
import { WEBHOOK_TYPES, generateWebhookSecret, verifyWebhook } from '../webhooks.js';

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

export function testConfig(overrides: Partial<MadauthConfig> = {}): MadauthConfig {
  return {
    issuer: ISSUER,
    signingKey,
    allowedOrigins: [APP_ORIGIN],
    sessionTtlSeconds: 3600,
    google: { clientId: CLIENT_ID, clientSecret: 'test-secret' },
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

/** Signs in through the FedCM flow and returns the session cookie value. */
export async function signIn(app: App): Promise<string> {
  const { nonce, cookie } = await getNonce(app);
  const res = await verify(app, await googleIdToken({ nonce }), cookie);
  return cookies(res).madauth_session.value;
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
 * with a body (e.g. for signup.before).
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
    emails: () => calls.filter((c) => c.type.startsWith('email.') && c.type !== 'email.verified'),
    lastEmail: () => hook.emails().at(-1),
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

export const REDIRECT_TO = `${APP_ORIGIN}/account`;

/** An app with e-mail & password sign-in (in-memory SQLite), Google, and a recording webhook receiver. */
export function passwordApp(overrides: Partial<MadauthConfig> = {}) {
  const hook = recordingWebhook();
  const store = createSqliteAdapter(':memory:');
  const app = testApp({
    password: { minLength: 8, store },
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

/** The link, its token and the code of a verification or reset e-mail. */
export function linkAndCode(call: WebhookCall | undefined): { token: string; code: string; link: string } {
  const link = call?.data.link as string | undefined;
  if (!link || !/#madauth_(verify|reset)=/.test(link)) throw new Error(`No e-mail with a link: ${JSON.stringify(call)}`);
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
  const res = await post(app, '/auth/password/verify-email', { token: linkAndCode(hook.lastEmail()).token });
  return cookies(res).madauth_session.value;
}
