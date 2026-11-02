// A stand-in for Microsoft's sign-in in tests: the token endpoint and the signing keys under
// https://login.microsoftonline.com/<tenant>/, as a `fetch` the server is given (MadauthConfig.oidcFetch). Its ID
// tokens are issued by the account's own tenant (`…/<tid>/v2.0`), as Microsoft's are.
import { SignJWT, exportJWK, generateKeyPair, type JWTPayload } from 'jose';
import { CONSUMER_TENANT } from '../microsoft.js';

export const MICROSOFT_CLIENT_ID = '11111111-2222-3333-4444-555555555555';
export const MICROSOFT_CLIENT_SECRET = 'microsoft~test~secret';
/** A work or school tenant. */
export const CONTOSO_TENANT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

/** What the next code exchange answers: the ID token's claims (`tid` defaults to the personal accounts', `oid` and `sub` to fixed values). */
export interface FakeMicrosoftSignIn {
  idToken: JWTPayload;
  /** The issuer the token names instead of its tenant's. */
  issuer?: string;
}

export async function fakeMicrosoft() {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'ms-key-1', alg: 'RS256', use: 'sig' };
  const codes = new Map<string, FakeMicrosoftSignIn & { nonce: string; redirectUri: string }>();
  const calls: { url: string; body?: string; authorization?: string | null }[] = [];
  let next = 1;
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

  const fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input instanceof Request ? input.url : input);
    const headers = new Headers(init.headers);
    calls.push({ url, body: typeof init.body === 'string' ? init.body : undefined, authorization: headers.get('authorization') });
    const path = url.match(/^https:\/\/login\.microsoftonline\.com\/[^/]+\/(.+)$/)?.[1];
    if (path === 'discovery/v2.0/keys') return json({ keys: [jwk] });
    if (path === 'oauth2/v2.0/token') {
      const form = new URLSearchParams(String(init.body));
      // The secret in the form (client_secret_post), as madAuth sends it to Microsoft.
      if (form.get('client_id') !== MICROSOFT_CLIENT_ID || form.get('client_secret') !== MICROSOFT_CLIENT_SECRET) return json({ error: 'invalid_client' }, 401);
      const issued = codes.get(form.get('code') ?? '');
      if (!issued || form.get('redirect_uri') !== issued.redirectUri || !form.get('code_verifier')) return json({ error: 'invalid_grant' }, 400);
      codes.delete(form.get('code')!);
      const claims = { tid: CONSUMER_TENANT, oid: 'oid-1', sub: 'pairwise-sub-1', ...issued.idToken };
      const now = Math.floor(Date.now() / 1000);
      const idToken = await new SignJWT({ nonce: issued.nonce, ver: '2.0', ...claims })
        .setProtectedHeader({ alg: 'RS256', kid: 'ms-key-1' })
        .setIssuer(issued.issuer ?? `https://login.microsoftonline.com/${String(claims.tid)}/v2.0`)
        .setAudience(MICROSOFT_CLIENT_ID)
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(privateKey);
      return json({ access_token: `at-${next++}`, token_type: 'Bearer', id_token: idToken });
    }
    return new Response('not found', { status: 404 });
  }) as typeof globalThis.fetch;

  return {
    fetch,
    calls,
    /** What Microsoft does when the user signs in at its page: a code for `start`'s authorization request. Resolves to the callback's query. */
    approve(authorizeUrl: string, signIn: FakeMicrosoftSignIn): string {
      const params = new URL(authorizeUrl).searchParams;
      const code = `code-${next++}`;
      codes.set(code, { ...signIn, nonce: params.get('nonce')!, redirectUri: params.get('redirect_uri')! });
      return `code=${code}&state=${encodeURIComponent(params.get('state')!)}`;
    },
  };
}

export type FakeMicrosoft = Awaited<ReturnType<typeof fakeMicrosoft>>;
