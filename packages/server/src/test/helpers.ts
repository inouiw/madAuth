import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWTPayload } from 'jose';
import { createApp } from '../app.js';
import type { MadauthConfig } from '../config.js';
import { generateSigningKey } from '../keys.js';

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
