// A stand-in for an OpenID Connect provider in tests: what it publishes (the discovery document and its signing keys)
// and what it answers (the code exchange and userinfo), as a `fetch` the server is given (MadauthConfig.oidcFetch).
import { SignJWT, exportJWK, generateKeyPair, type JWTPayload } from 'jose';

export interface FakeOidcOptions {
  issuer?: string;
  /** The client the provider knows madAuth as. */
  clientId?: string;
  clientSecret?: string;
  /** `token_endpoint_auth_methods_supported`; absent: the document says nothing (the default is basic). */
  authMethods?: string[];
  /** Whether it has a userinfo endpoint. Default: yes. */
  userinfo?: boolean;
}

/** What the next code exchange answers: the ID token's claims (`sub` at least) and what userinfo says. */
export interface FakeSignIn {
  idToken: JWTPayload;
  /** A string is answered as it is, as a signed userinfo answer (`application/jwt`) would be. */
  userinfo?: Record<string, unknown> | string;
  /** The ID token's audience; default: the client. */
  audience?: string | string[];
}

export async function fakeOidcProvider(options: FakeOidcOptions = {}) {
  const issuer = options.issuer ?? 'https://idp.example.com';
  const clientId = options.clientId ?? 'madauth-client';
  const clientSecret = options.clientSecret ?? 'madauth-client-secret';
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'key-1', alg: 'ES256', use: 'sig' };
  const codes = new Map<string, FakeSignIn & { nonce: string; redirectUri: string }>();
  const tokens = new Map<string, Record<string, unknown> | string>();
  const calls: { url: string; body?: string; authorization?: string | null }[] = [];
  let next = 1;

  const discovery = {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    ...(options.userinfo === false ? {} : { userinfo_endpoint: `${issuer}/userinfo` }),
    ...(options.authMethods ? { token_endpoint_auth_methods_supported: options.authMethods } : {}),
  };
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

  /** The client's credentials as the request sent them, by the method the provider supports. */
  const credentialsOf = (headers: Headers, form: URLSearchParams) => {
    const basic = headers.get('authorization')?.match(/^Basic (.+)$/)?.[1];
    if (basic) {
      const [id, secret] = Buffer.from(basic, 'base64').toString().split(':').map(decodeURIComponent);
      return { id, secret, via: 'client_secret_basic' };
    }
    return { id: form.get('client_id'), secret: form.get('client_secret'), via: 'client_secret_post' };
  };

  const fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input instanceof Request ? input.url : input);
    const headers = new Headers(init.headers);
    calls.push({ url, body: typeof init.body === 'string' ? init.body : init.body ? String(init.body) : undefined, authorization: headers.get('authorization') });
    if (url === `${issuer}/.well-known/openid-configuration`) return json(discovery);
    if (url === `${issuer}/jwks`) return json({ keys: [jwk] });
    if (url === `${issuer}/token`) {
      const form = new URLSearchParams(String(init.body));
      const client = credentialsOf(headers, form);
      const allowed = options.authMethods ?? ['client_secret_basic'];
      if (client.id !== clientId || client.secret !== clientSecret || !allowed.includes(client.via)) return json({ error: 'invalid_client' }, 401);
      const issued = codes.get(form.get('code') ?? '');
      if (!issued || form.get('redirect_uri') !== issued.redirectUri || !form.get('code_verifier')) return json({ error: 'invalid_grant' }, 400);
      codes.delete(form.get('code')!);
      const now = Math.floor(Date.now() / 1000);
      const idToken = await new SignJWT({ nonce: issued.nonce, ...issued.idToken })
        .setProtectedHeader({ alg: 'ES256', kid: 'key-1' })
        .setIssuer(issuer)
        .setAudience(issued.audience ?? clientId)
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(privateKey);
      const accessToken = `at-${next++}`;
      tokens.set(accessToken, issued.userinfo ?? {});
      return json({ access_token: accessToken, token_type: 'Bearer', id_token: idToken });
    }
    if (url === `${issuer}/userinfo` && options.userinfo !== false) {
      const answer = tokens.get(headers.get('authorization')?.replace(/^Bearer /, '') ?? '');
      if (typeof answer === 'string') return new Response(answer, { headers: { 'Content-Type': 'application/jwt' } });
      return answer ? json(answer) : json({ error: 'invalid_token' }, 401);
    }
    return new Response('not found', { status: 404 });
  }) as typeof globalThis.fetch;

  return {
    issuer,
    clientId,
    clientSecret,
    fetch,
    calls,
    /**
     * What the provider does when the user signs in at its page: a code for `start`'s authorization request
     * (its `location`), which the callback exchanges. Resolves to the callback's query.
     */
    approve(authorizeUrl: string, signIn: FakeSignIn): string {
      const params = new URL(authorizeUrl).searchParams;
      const code = `code-${next++}`;
      codes.set(code, { ...signIn, nonce: params.get('nonce')!, redirectUri: params.get('redirect_uri')! });
      return `code=${code}&state=${encodeURIComponent(params.get('state')!)}`;
    },
  };
}

export type FakeOidcProvider = Awaited<ReturnType<typeof fakeOidcProvider>>;
