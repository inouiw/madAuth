import { generateKeyPair, createLocalJWKSet, jwtVerify } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  APP_ORIGIN,
  CLIENT_ID,
  ISSUER,
  cookies,
  getNonce,
  googleIdToken,
  signIn,
  testApp,
  verify,
} from './test/helpers.js';

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const ada = {
  id: 'google:1001',
  email: 'ada@example.com',
  name: 'Ada Lovelace',
  picture: 'https://example.com/ada.png',
};

describe('Google ID token verification (shared by both flows)', () => {
  it('S1: gives a session for a valid token with the matching nonce', async () => {
    const app = testApp();
    const { nonce, cookie } = await getNonce(app);

    const res = await verify(app, await googleIdToken({ nonce }), cookie);

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: ada });
    expect(cookies(res).madauth_session.value).toBeTruthy();
  });

  it('S2: rejects a token for another client ID', async () => {
    const app = testApp();
    const { nonce, cookie } = await getNonce(app);

    const res = await verify(app, await googleIdToken({ nonce, aud: 'other-client' }), cookie);

    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'verification_failed' });
    expect(cookies(res).madauth_session).toBeUndefined();
  });

  it('S3: rejects a token from another issuer', async () => {
    const app = testApp();
    const { nonce, cookie } = await getNonce(app);

    const res = await verify(app, await googleIdToken({ nonce, iss: 'https://evil.example' }), cookie);

    expect(res.status).toBe(401);
  });

  it('S4: rejects an expired token', async () => {
    const app = testApp();
    const { nonce, cookie } = await getNonce(app);

    const res = await verify(app, await googleIdToken({ nonce, exp: Math.floor(Date.now() / 1000) - 60 }), cookie);

    expect(res.status).toBe(401);
  });

  it('S5: rejects a token signed by an unknown key', async () => {
    const app = testApp();
    const { nonce, cookie } = await getNonce(app);
    const { privateKey } = await generateKeyPair('RS256');

    const res = await verify(app, await googleIdToken({ nonce }, { key: privateKey }), cookie);

    expect(res.status).toBe(401);
  });

  it('S6: rejects an unverified e-mail address', async () => {
    const app = testApp();
    const { nonce, cookie } = await getNonce(app);

    const res = await verify(app, await googleIdToken({ nonce, email_verified: false }), cookie);

    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: 'email_unverified' });
  });
});

describe('FedCM / One Tap flow', () => {
  it('F1: returns a random nonce with a signed, HttpOnly, short-lived cookie', async () => {
    const app = testApp();
    const first = await app.request('/auth/google/nonce', { method: 'POST', headers: { Origin: APP_ORIGIN } });
    const second = await getNonce(app);

    const { nonce } = (await first.json()) as { nonce: string };
    expect(nonce).toMatch(/^[\w-]{43}$/);
    expect(nonce).not.toBe(second.nonce);
    const { attrs } = cookies(first).madauth_nonce;
    expect(attrs).toMatchObject({ httponly: true, secure: true, samesite: 'Strict', 'max-age': '300' });
  });

  it('F2: requires the nonce in the token to match this browser’s nonce cookie', async () => {
    const app = testApp();
    const a = await getNonce(app);
    const b = await getNonce(app);

    expect((await verify(app, await googleIdToken({ nonce: b.nonce }), a.cookie)).status).toBe(401);
    expect((await verify(app, await googleIdToken({ nonce: a.nonce }))).status).toBe(401);
    expect((await verify(app, await googleIdToken({ nonce: a.nonce }), b.cookie)).status).toBe(401);
  });

  it('F3: rejects an expired nonce cookie', async () => {
    const app = testApp();
    vi.useFakeTimers({ toFake: ['Date'] });
    const { nonce, cookie } = await getNonce(app);
    vi.setSystemTime(Date.now() + 6 * 60 * 1000);

    const res = await verify(app, await googleIdToken({ nonce }), cookie);

    expect(res.status).toBe(401);
  });

  it('F3: clears the nonce cookie after a successful sign-in', async () => {
    const app = testApp();
    const { nonce, cookie } = await getNonce(app);

    const res = await verify(app, await googleIdToken({ nonce }), cookie);

    expect(cookies(res).madauth_nonce).toMatchObject({ value: '', attrs: { 'max-age': '0' } });
  });

  it('F4: rejects requests from origins that are not allowed', async () => {
    const app = testApp();

    const res = await app.request('/auth/google/nonce', {
      method: 'POST',
      headers: { Origin: 'https://evil.example' },
    });

    expect(res.status).toBe(403);
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
    const noOrigin = await app.request('/auth/google/nonce', { method: 'POST' });
    expect(noOrigin.status).toBe(403);
  });

  it('F4: grants CORS with credentials to allowed origins only', async () => {
    const app = testApp();
    const preflight = (origin: string) =>
      app.request('/auth/google/verify', {
        method: 'OPTIONS',
        headers: { Origin: origin, 'Access-Control-Request-Method': 'POST' },
      });

    const allowed = await preflight(APP_ORIGIN);
    expect(allowed.headers.get('access-control-allow-origin')).toBe(APP_ORIGIN);
    expect(allowed.headers.get('access-control-allow-credentials')).toBe('true');
    expect((await preflight('https://evil.example')).headers.get('access-control-allow-origin')).toBeNull();
  });
});

describe('code (redirect) flow', () => {
  async function start(app = testApp(), returnTo = `${APP_ORIGIN}/page?x=1#old`) {
    const res = await app.request(`/auth/google/start?return_to=${encodeURIComponent(returnTo)}`);
    const location = new URL(res.headers.get('location') ?? 'about:blank');
    return { app, res, location, cookie: `madauth_oauth=${cookies(res).madauth_oauth?.value}` };
  }

  /** Stubs Google's token endpoint to return `idToken`, and records the request body. */
  function stubTokenEndpoint(idToken: () => Promise<string>) {
    const bodies: URLSearchParams[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init: RequestInit) => {
        expect(url).toBe('https://oauth2.googleapis.com/token');
        bodies.push(new URLSearchParams(init.body as URLSearchParams));
        return Response.json({ id_token: await idToken(), access_token: 'x' });
      }),
    );
    return bodies;
  }

  it('R1: redirects to Google with state, nonce and an S256 PKCE challenge', async () => {
    const { res, location, cookie } = await start();

    expect(res.status).toBe(302);
    expect(location.origin + location.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    const params = Object.fromEntries(location.searchParams);
    expect(params).toMatchObject({
      client_id: CLIENT_ID,
      redirect_uri: `${ISSUER}/auth/google/callback`,
      response_type: 'code',
      scope: 'openid email profile',
      code_challenge_method: 'S256',
    });
    expect(params.state).toBeTruthy();
    expect(params.nonce).toBeTruthy();

    // The challenge is the SHA-256 of the verifier kept in the (signed) cookie.
    const payload = JSON.parse(atob(cookie.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload.verifier));
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    expect(params.code_challenge).toBe(expected);
  });

  it('R2: rejects a return_to outside ALLOWED_ORIGINS', async () => {
    const { res } = await start(testApp(), 'https://evil.example/');
    expect(res.status).toBe(400);
  });

  it('R3: rejects a mismatched state', async () => {
    const { app, cookie } = await start();

    const res = await app.request('/auth/google/callback?code=abc&state=wrong', { headers: { Cookie: cookie } });

    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe(`${APP_ORIGIN}/page?x=1#madauth_error=verification_failed`);
    expect(cookies(res).madauth_session).toBeUndefined();
  });

  it('R4: exchanges the code with the secret and PKCE verifier and sets the session', async () => {
    const { app, location, cookie } = await start();
    const nonce = location.searchParams.get('nonce')!;
    const bodies = stubTokenEndpoint(() => googleIdToken({ nonce }));

    const res = await app.request(`/auth/google/callback?code=the-code&state=${location.searchParams.get('state')}`, {
      headers: { Cookie: cookie },
    });

    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe(`${APP_ORIGIN}/page?x=1`);
    expect(cookies(res).madauth_session.value).toBeTruthy();
    expect(Object.fromEntries(bodies[0])).toMatchObject({
      code: 'the-code',
      client_id: CLIENT_ID,
      client_secret: 'test-secret',
      redirect_uri: `${ISSUER}/auth/google/callback`,
      grant_type: 'authorization_code',
    });
    expect(bodies[0].get('code_verifier')).toMatch(/^[\w-]{43}$/);
  });

  it('R5: checks the exchanged ID token, including the nonce', async () => {
    const { app, location, cookie } = await start();
    stubTokenEndpoint(() => googleIdToken({ nonce: 'another-nonce' }));

    const res = await app.request(`/auth/google/callback?code=c&state=${location.searchParams.get('state')}`, {
      headers: { Cookie: cookie },
    });

    expect(res.headers.get('location')).toBe(`${APP_ORIGIN}/page?x=1#madauth_error=verification_failed`);
    expect(cookies(res).madauth_session).toBeUndefined();
  });

  it('reports a sign-in the user cancelled at Google', async () => {
    const { app, cookie } = await start();

    const res = await app.request('/auth/google/callback?error=access_denied', { headers: { Cookie: cookie } });

    expect(res.headers.get('location')).toBe(`${APP_ORIGIN}/page?x=1#madauth_error=cancelled`);
  });

  it('R6: is disabled without GOOGLE_CLIENT_SECRET', async () => {
    const app = testApp({ google: { clientId: CLIENT_ID } });

    expect((await app.request(`/auth/google/start?return_to=${APP_ORIGIN}/`)).status).toBe(404);
    expect((await app.request('/auth/google/callback')).status).toBe(404);
    expect(await (await app.request('/auth/config')).json()).toEqual({ google: { clientId: CLIENT_ID, codeFlow: false } });
    // The FedCM flow still works.
    expect((await getNonce(app)).nonce).toBeTruthy();
  });
});

describe('session', () => {
  it('X1: is a madAuth ES256 JWT that verifies against the published JWKS', async () => {
    const app = testApp();
    const session = await signIn(app);
    const jwks = createLocalJWKSet(await (await app.request('/.well-known/jwks.json')).json());

    const { payload, protectedHeader } = await jwtVerify(session, jwks, { issuer: ISSUER });

    expect(protectedHeader.alg).toBe('ES256');
    expect(payload).toMatchObject({ sub: 'google:1001', email: 'ada@example.com', amr: ['google'] });
  });

  it('X2: sets an HttpOnly, Secure, SameSite=Lax cookie and honours COOKIE_DOMAIN', async () => {
    const sessionCookieAttrs = async (app: ReturnType<typeof testApp>) => {
      const { nonce, cookie } = await getNonce(app);
      return cookies(await verify(app, await googleIdToken({ nonce }), cookie)).madauth_session.attrs;
    };

    const withoutDomain = await sessionCookieAttrs(testApp());
    expect(withoutDomain).toMatchObject({ httponly: true, secure: true, samesite: 'Lax', path: '/', 'max-age': '3600' });
    expect(withoutDomain.domain).toBeUndefined();

    const attrs = await sessionCookieAttrs(testApp({ cookieDomain: '.example.com' }));
    expect(attrs.domain).toBe('.example.com');
  });

  it('X3: returns the user for a valid session cookie only', async () => {
    const app = testApp();
    const session = await signIn(app);
    const get = (cookie?: string) => app.request('/auth/session', { headers: cookie ? { Cookie: cookie } : {} });
    const tampered = session.slice(0, -2) + (session.endsWith('A') ? 'BB' : 'AA');

    const ok = await get(`madauth_session=${session}`);
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ user: ada });
    expect((await get()).status).toBe(401);
    expect((await get(`madauth_session=${tampered}`)).status).toBe(401);
  });

  it('X3: does not accept other madAuth tokens (e.g. the nonce cookie) as a session', async () => {
    const app = testApp();
    const { cookie } = await getNonce(app);
    const nonceToken = cookie.split('=')[1];

    const res = await app.request('/auth/session', { headers: { Cookie: `madauth_session=${nonceToken}` } });

    expect(res.status).toBe(401);
  });

  it('X3: rejects an expired session', async () => {
    const app = testApp();
    vi.useFakeTimers({ toFake: ['Date'] });
    const session = await signIn(app);
    vi.setSystemTime(Date.now() + 3601 * 1000);

    const res = await app.request('/auth/session', { headers: { Cookie: `madauth_session=${session}` } });

    expect(res.status).toBe(401);
  });

  it('X4: renews the session after half of its lifetime', async () => {
    const app = testApp();
    vi.useFakeTimers({ toFake: ['Date'] });
    const session = await signIn(app);
    const get = () => app.request('/auth/session', { headers: { Cookie: `madauth_session=${session}` } });

    vi.setSystemTime(Date.now() + 1000 * 1000);
    expect(cookies(await get()).madauth_session).toBeUndefined();

    vi.setSystemTime(Date.now() + 1000 * 1000);
    const renewed = cookies(await get()).madauth_session;
    expect(renewed.value).toBeTruthy();
    const exp = (token: string) => JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).exp;
    expect(exp(renewed.value)).toBeGreaterThan(exp(session));
  });

  it('X5: logout clears the session cookie', async () => {
    const app = testApp({ cookieDomain: '.example.com' });

    const res = await app.request('/auth/logout', { method: 'POST', headers: { Origin: APP_ORIGIN } });

    expect(res.status).toBe(204);
    expect(cookies(res).madauth_session).toMatchObject({ value: '', attrs: { 'max-age': '0', domain: '.example.com' } });
  });
});

describe('public endpoints', () => {
  it('C1: /auth/config exposes only public information', async () => {
    const res = await testApp().request('/auth/config');

    expect(await res.json()).toEqual({ google: { clientId: CLIENT_ID, codeFlow: true } });
  });

  it('H5: /health returns 200', async () => {
    const res = await testApp().request('/health');

    expect(res.status).toBe(200);
    expect(await res.text()).toBe('ok');
  });

  it('publishes only the public signing key', async () => {
    const { keys } = (await (await testApp().request('/.well-known/jwks.json')).json()) as { keys: object[] };

    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' });
    expect(keys[0]).not.toHaveProperty('d');
  });
});
