// Stand-ins for Facebook's and X's sign-in in tests: the code exchange and the profile API of each, as a `fetch` the
// server is given (MadauthConfig.oidcFetch). Unknown URLs answer 404.
import { createHash, createHmac } from 'node:crypto';

export const FACEBOOK_APP_ID = '1234567890';
export const FACEBOOK_APP_SECRET = 'facebook-app-secret';
export const X_CLIENT_ID = 'eC1jbGllbnQtaWQ6MTpjaQ';
export const X_CLIENT_SECRET = 'x-client-secret';

/** What the profile API answers for the next code: Facebook's `/me` or X's `/2/users/me` `data`. */
export type FakeProfile = Record<string, unknown>;

export function fakeSocial() {
  const codes = new Map<string, { profile: FakeProfile; redirectUri: string; challenge: string | null }>();
  const tokens = new Map<string, FakeProfile>();
  const calls: { url: string; method: string; body?: string; authorization?: string | null }[] = [];
  let next = 1;
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  const issue = (code: string | null, redirectUri: string | null) => {
    const issued = codes.get(code ?? '');
    if (!issued || issued.redirectUri !== redirectUri) return null;
    codes.delete(code!);
    const token = `token-${next++}`;
    tokens.set(token, issued.profile);
    return { token, issued };
  };

  const fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    const headers = new Headers(init.headers);
    const bearer = headers.get('authorization')?.replace(/^Bearer /, '') ?? '';
    calls.push({ url: url.href, method: init.method ?? 'GET', body: typeof init.body === 'string' ? init.body : undefined, authorization: headers.get('authorization') });
    if (url.origin + url.pathname === 'https://graph.facebook.com/v26.0/oauth/access_token') {
      const q = url.searchParams;
      if (q.get('client_id') !== FACEBOOK_APP_ID || q.get('client_secret') !== FACEBOOK_APP_SECRET) return json({ error: { type: 'OAuthException' } }, 400);
      const done = issue(q.get('code'), q.get('redirect_uri'));
      return done ? json({ access_token: done.token, token_type: 'bearer', expires_in: 5183944 }) : json({ error: { type: 'OAuthException' } }, 400);
    }
    if (url.origin + url.pathname === 'https://graph.facebook.com/v26.0/me') {
      const profile = tokens.get(bearer);
      // An app with "Require App Secret" refuses a call without the proof.
      if (!profile || url.searchParams.get('appsecret_proof') !== createHmac('sha256', FACEBOOK_APP_SECRET).update(bearer).digest('hex')) return json({ error: { type: 'OAuthException' } }, 400);
      return json(profile);
    }
    if (url.href === 'https://api.x.com/2/oauth2/token') {
      const form = new URLSearchParams(String(init.body));
      const basic = headers.get('authorization')?.match(/^Basic (.+)$/)?.[1];
      const [id, secret] = basic ? Buffer.from(basic, 'base64').toString().split(':').map(decodeURIComponent) : [];
      if (id !== X_CLIENT_ID || secret !== X_CLIENT_SECRET) return json({ error: 'unauthorized_client' }, 401);
      const issued = codes.get(form.get('code') ?? '');
      const verifier = form.get('code_verifier');
      const challenge = verifier && createHash('sha256').update(verifier).digest('base64url');
      if (!issued || issued.challenge !== challenge || form.get('grant_type') !== 'authorization_code') return json({ error: 'invalid_request' }, 400);
      const done = issue(form.get('code'), form.get('redirect_uri'));
      return done ? json({ token_type: 'bearer', access_token: done.token, expires_in: 7200, scope: 'tweet.read users.read users.email' }) : json({ error: 'invalid_request' }, 400);
    }
    if (url.origin + url.pathname === 'https://api.x.com/2/users/me') {
      const profile = tokens.get(bearer);
      return profile ? json({ data: profile }) : json({ title: 'Unauthorized', status: 401 }, 401);
    }
    return new Response('not found', { status: 404 });
  }) as typeof globalThis.fetch;

  return {
    fetch,
    calls,
    /** What the provider does when the user approves at its page: a code for `start`'s authorization request. Resolves to the callback's query. */
    approve(authorizeUrl: string, profile: FakeProfile): string {
      const params = new URL(authorizeUrl).searchParams;
      const code = `code-${next++}`;
      codes.set(code, { profile, redirectUri: params.get('redirect_uri')!, challenge: params.get('code_challenge') });
      return `code=${code}&state=${encodeURIComponent(params.get('state')!)}`;
    },
  };
}

export type FakeSocial = ReturnType<typeof fakeSocial>;
