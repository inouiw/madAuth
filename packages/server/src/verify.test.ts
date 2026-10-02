import { SignJWT, createLocalJWKSet, importJWK } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createSessionVerifier } from './verify.js';
import { ISSUER, signIn, signingKey, testApp } from './test/helpers.js';

afterEach(() => vi.useRealTimers());

async function setup() {
  const app = testApp();
  const jwks = createLocalJWKSet(await (await app.request('/.well-known/jwks.json')).json());
  return { app, verifySession: createSessionVerifier({ issuer: ISSUER, jwks }) };
}

const ada = { id: 'google:1001', email: 'ada@example.com', name: 'Ada Lovelace', picture: 'https://example.com/ada.png' };

describe('createSessionVerifier', () => {
  it('V1: accepts a Request with the cookie or a bearer token, a cookie header and a bare token', async () => {
    const { app, verifySession } = await setup();
    const token = await signIn(app);

    expect(await verifySession(new Request('https://api.example.com', { headers: { Cookie: `a=1; madauth_session=${token}` } }))).toEqual(ada);
    expect(await verifySession(new Request('https://api.example.com', { headers: { Authorization: `Bearer ${token}` } }))).toEqual(ada);
    expect(await verifySession(`theme=dark; madauth_session=${token}`)).toEqual(ada);
    expect(await verifySession(token)).toEqual(ada);
  });

  it('V2: returns null for an expired, tampered or foreign token, or no session', async () => {
    const { app, verifySession } = await setup();
    vi.useFakeTimers({ toFake: ['Date'] });
    const token = await signIn(app);
    const wrongIssuer = await new SignJWT({ sub: 'google:1' })
      .setProtectedHeader({ alg: 'ES256', kid: signingKey.kid, typ: 'madauth-session+jwt' })
      .setIssuer('https://evil.example')
      .setExpirationTime('1h')
      .sign(await importJWK(signingKey, 'ES256'));

    expect(await verifySession(token.slice(0, -2) + 'xx')).toBeNull();
    expect(await verifySession(wrongIssuer)).toBeNull();
    expect(await verifySession(new Request('https://api.example.com'))).toBeNull();
    expect(await verifySession('')).toBeNull();
    vi.setSystemTime(Date.now() + 3601 * 1000);
    expect(await verifySession(token)).toBeNull();
  });
});
