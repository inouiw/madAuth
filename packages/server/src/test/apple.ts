// A stand-in for Apple's sign-in in tests: the token, keys and revoke endpoints under https://appleid.apple.com/auth/,
// as a `fetch` the server is given (MadauthConfig.oidcFetch). It checks the client secret as Apple does: a JWT
// signed with the developer account's key, for the Team ID, the client and Apple. Its tokens are issued for the
// client that exchanged the code, as Apple's are.
import { SignJWT, exportJWK, exportPKCS8, generateKeyPair, jwtVerify, type JWTPayload } from 'jose';
import { APPLE_ISSUER } from '../apple.js';

export const APPLE_CLIENT_ID = 'com.example.app.web';
export const APPLE_TEAM_ID = 'TEAM123456';
export const APPLE_KEY_ID = 'KEY1234567';
export const APPLE_BUNDLE_ID = 'com.example.app';

/** What the next code exchange answers: the ID token's claims (`sub` defaults to a fixed value, `email_verified` to true). */
export interface FakeAppleSignIn {
  idToken: JWTPayload;
  /** Apple's `user` form field, sent at the first authorization only: the name as the user left it on Apple's page. */
  user?: { name?: { firstName?: string; lastName?: string }; email?: string };
  /** Whether the token endpoint answers a refresh token (it does). */
  noRefreshToken?: boolean;
}

export async function fakeApple() {
  // The developer account's key, whose private half the admin pastes; Apple holds the public half.
  const developer = await generateKeyPair('ES256', { extractable: true });
  const privateKeyPem = await exportPKCS8(developer.privateKey);
  // Apple's own signing key.
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'apple-key-1', alg: 'RS256', use: 'sig' };
  const codes = new Map<string, FakeAppleSignIn & { nonce: string; redirectUri?: string; clientId?: string }>();
  const calls: { url: string; body?: string }[] = [];
  const revoked: { clientId: string; token: string; hint: string | null }[] = [];
  let next = 1;
  let revokeStatus = 200;
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

  /** Whether `secret` is a client secret for `clientId` as Apple accepts it. */
  const validSecret = async (secret: string | null, clientId: string | null): Promise<boolean> => {
    if (!secret || !clientId) return false;
    const verified = await jwtVerify(secret, developer.publicKey, { issuer: APPLE_TEAM_ID, audience: APPLE_ISSUER, subject: clientId, algorithms: ['ES256'] }).catch(() => null);
    return !!verified && verified.protectedHeader.kid === APPLE_KEY_ID && typeof verified.payload.exp === 'number';
  };

  const identityToken = async (claims: JWTPayload, aud: string, nonce: string) => {
    const now = Math.floor(Date.now() / 1000);
    // The claims a test gives win, also over the issuer, the audience and the nonce, to make a token that must fail.
    return new SignJWT({ iss: APPLE_ISSUER, aud, nonce, nonce_supported: true, email_verified: true, sub: 'apple-sub-1', ...claims })
      .setProtectedHeader({ alg: 'RS256', kid: 'apple-key-1' })
      .setIssuedAt(now)
      .setExpirationTime(now + 600)
      .sign(privateKey);
  };

  const fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input instanceof Request ? input.url : input);
    calls.push({ url, body: typeof init.body === 'string' ? init.body : undefined });
    if (url === `${APPLE_ISSUER}/auth/keys`) return json({ keys: [jwk] });
    if (url === `${APPLE_ISSUER}/auth/token`) {
      const form = new URLSearchParams(String(init.body));
      const clientId = form.get('client_id');
      if (!(await validSecret(form.get('client_secret'), clientId))) return json({ error: 'invalid_client' }, 401);
      const issued = codes.get(form.get('code') ?? '');
      // A code of the web flow comes back with its redirect URI; a native app's with none, as the app that got it.
      if (!issued || form.get('grant_type') !== 'authorization_code') return json({ error: 'invalid_grant' }, 400);
      if (issued.redirectUri ? form.get('redirect_uri') !== issued.redirectUri || clientId !== APPLE_CLIENT_ID : form.has('redirect_uri') || clientId !== issued.clientId) {
        return json({ error: 'invalid_grant' }, 400);
      }
      if (form.has('code_verifier')) return json({ error: 'invalid_request' }, 400);
      codes.delete(form.get('code')!);
      const idToken = await identityToken(issued.idToken, clientId!, issued.nonce);
      return json({ access_token: `at-${next++}`, token_type: 'Bearer', expires_in: 3600, id_token: idToken, ...(issued.noRefreshToken ? {} : { refresh_token: `rt-${next++}` }) });
    }
    if (url === `${APPLE_ISSUER}/auth/revoke`) {
      const form = new URLSearchParams(String(init.body));
      if (!(await validSecret(form.get('client_secret'), form.get('client_id')))) return new Response(null, { status: 401 });
      revoked.push({ clientId: form.get('client_id')!, token: form.get('token') ?? '', hint: form.get('token_type_hint') });
      return new Response(null, { status: revokeStatus });
    }
    return new Response('not found', { status: 404 });
  }) as typeof globalThis.fetch;

  return {
    fetch,
    calls,
    revoked,
    /** The `.p8` file's text: the provider's client secret. */
    privateKeyPem,
    /** What Apple does when the user signs in at its page: the form it POSTs to the callback (code, state, and `user` the first time). */
    approve(authorizeUrl: string, signIn: FakeAppleSignIn): URLSearchParams {
      const params = new URL(authorizeUrl).searchParams;
      const code = `code-${next++}`;
      codes.set(code, { ...signIn, nonce: params.get('nonce')!, redirectUri: params.get('redirect_uri')! });
      const form = new URLSearchParams({ code, state: params.get('state')! });
      if (signIn.user) form.set('user', JSON.stringify(signIn.user));
      return form;
    },
    /** What Apple does when the user cancels at its page. */
    cancel(authorizeUrl: string): URLSearchParams {
      return new URLSearchParams({ error: 'user_cancelled_authorize', state: new URL(authorizeUrl).searchParams.get('state')! });
    },
    /** An identity token as a native app gets it from Apple's sheet, for its App ID `aud`, with `nonce`. */
    identityToken,
    /** An authorization code as a native app gets it beside the token, exchangeable as `clientId` without a redirect URI. */
    nativeCode(clientId: string, signIn: FakeAppleSignIn, nonce: string): string {
      const code = `native-code-${next++}`;
      codes.set(code, { ...signIn, nonce, clientId });
      return code;
    },
    /** What the revoke endpoint answers from now on. */
    failRevocations(status: number) {
      revokeStatus = status;
    },
  };
}

export type FakeApple = Awaited<ReturnType<typeof fakeApple>>;
