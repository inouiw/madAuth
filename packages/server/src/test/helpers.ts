import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWTPayload } from 'jose';
import { createApp } from '../app.js';
import type { MadauthConfig } from '../config.js';
import { generateSigningKey } from '../keys.js';
import type { Mail, Mailer } from '../mail.js';
import { createSqliteAdapter } from '../store/sqlite.js';

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

// --- E-mail & password ---

/** A mailer that keeps the sent mails, so tests can read the links and codes. */
export function recordingMailer(): Mailer & { sent: Mail[]; last(): Mail | undefined } {
  const sent: Mail[] = [];
  return {
    sent,
    last: () => sent.at(-1),
    async send(mail) {
      sent.push(mail);
    },
  };
}

export const REDIRECT_TO = `${APP_ORIGIN}/account`;

/** An app with e-mail & password sign-in (in-memory SQLite) and Google. */
export function passwordApp(overrides: Partial<MadauthConfig> = {}) {
  const mailer = recordingMailer();
  const store = createSqliteAdapter(':memory:');
  const app = testApp({ password: { minLength: 8, store, mailer }, ...overrides });
  return { app, mailer, store };
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

/** The link token and the code of a verification or reset mail. */
export function linkAndCode(mail: Mail | undefined): { token: string; code: string; link: string } {
  const link = mail?.text.match(/https?:\/\/\S+#madauth_(?:verify|reset)=\S+/)?.[0];
  const code = mail?.text.match(/code: (\d{3}) (\d{3})/);
  if (!link || !code) throw new Error(`No link and code in mail:\n${mail?.text}`);
  return { link, token: link.split('=').at(-1)!, code: code[1] + code[2] };
}

/** Signs up and confirms the e-mail with the link; returns the session cookie. */
export async function signUpVerified(
  app: PasswordApp,
  mailer: ReturnType<typeof recordingMailer>,
  email = 'grace@example.com',
  password = 'correct horse battery',
): Promise<string> {
  await post(app, '/auth/password/signup', { email, password, name: 'Grace Hopper', redirectTo: REDIRECT_TO });
  const res = await post(app, '/auth/password/verify-email', { token: linkAndCode(mailer.last()).token });
  return cookies(res).madauth_session.value;
}
