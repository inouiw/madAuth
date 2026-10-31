// madAuth as an OpenID Connect provider: discovery, the authorization code flow with PKCE, refresh tokens, the
// user info and the sign-out of a client (RP-initiated logout). Other applications sign their users in with madAuth
// like with Keycloak or Auth0; the sign-in itself happens on the app's login page, with madAuth's dialog. The
// clients are registered through the admin API (app.ts). See "OpenID Connect provider" in docs/server.md.
import { createHash } from 'node:crypto';
import type { Context, Hono } from 'hono';
import type { JWTPayload } from 'jose';
import type { AppContext } from '../app.js';
import { claimsFromJson } from '../claims.js';
import {
  ACCESS_TOKEN_TTL_S,
  ID_TOKEN_TTL_S,
  OIDC_SCOPES,
  clientInfo,
  matchesRedirectUri,
  type Grant,
  type OidcClients,
  type StoredClient,
} from '../oidc-clients.js';
import { SIGNING_ALG } from '../keys.js';
import { parseLoginUrl } from '../settings.js';
import { randomString, readToken, signToken } from '../tokens.js';
import { bearerTokenOf } from '../user.js';
import type { StoredUser } from '../users.js';

/** Where the endpoints are: under `/auth`, which the app's origin passes on to madAuth like the rest. */
export const OIDC_PATH = '/auth/oidc/';

/** `typ` of the access tokens (RFC 9068), so no other token of madAuth's counts as one. */
export const ACCESS_TOKEN_TYP = 'at+jwt';

/** `typ` of the ID tokens: what OpenID Connect clients expect. */
export const ID_TOKEN_TYP = 'JWT';

/**
 * Query parameter of the app's login page: where to go back to once the user signed in, the authorization request
 * that sent them there (`<issuer>/auth/oidc/authorize?…`).
 */
export const LOGIN_RETURN_PARAM = 'madauth_return';

/** The claims of an access token beyond the standard ones. */
interface AccessTokenClaims extends JWTPayload {
  sub: string;
  client_id: string;
  scope: string;
  /** The user's session version, so ending their sessions ends the token's use at the user info. */
  sv: number;
}

/** The request's parameters: the query of a GET, the form of a POST; only those given once, as text. */
async function paramsOf(c: Context): Promise<Record<string, string>> {
  const raw = c.req.method === 'POST' ? await c.req.parseBody({ all: true }).catch(() => ({})) : c.req.queries();
  return Object.fromEntries(
    Object.entries(raw)
      .map(([key, value]) => [key, Array.isArray(value) ? (value.length === 1 ? value[0] : undefined) : value] as const)
      .filter((entry): entry is [string, string] => typeof entry[1] === 'string'),
  );
}

/** A part of an HTTP Basic header, which form-encodes the client ID and secret (RFC 6749, section 2.3.1). */
const formDecoded = (value: string): string | null => new URLSearchParams(`v=${value}`).get('v');

const sha256 = (value: string) => createHash('sha256').update(value).digest();

/** Whether `verifier` is the PKCE code verifier of `challenge` (S256). */
const pkceMatches = (verifier: string, challenge: string): boolean =>
  /^[A-Za-z0-9._~-]{43,128}$/.test(verifier) && sha256(verifier).toString('base64url') === challenge;

/** `at_hash` of an ID token: the left half of the access token's SHA-256. */
const atHash = (accessToken: string): string => sha256(accessToken).subarray(0, 16).toString('base64url');

/** What the scopes give away of the user: the address with `email`, the name with `profile`; the claims always. */
function userClaims(user: StoredUser, scope: string): Record<string, unknown> {
  const scopes = scope.split(' ');
  const claims = claimsFromJson(user.claims);
  return {
    ...(scopes.includes('email') ? { email: user.email, email_verified: user.emailVerified } : {}),
    ...(scopes.includes('profile') && user.name ? { name: user.name } : {}),
    ...(Object.keys(claims).length ? { claims } : {}),
  };
}

export function oidcEndpoints(app: Hono, ctx: AppContext, clients: OidcClients): void {
  const { issuer } = ctx.config;
  const { keys } = ctx;
  const endpoint = (name: string) => `${issuer}${OIDC_PATH}${name}`;

  app.get('/.well-known/openid-configuration', (c) => {
    c.header('Cache-Control', 'public, max-age=3600');
    // Read by browser apps too.
    c.header('Access-Control-Allow-Origin', '*');
    return c.json({
      issuer,
      authorization_endpoint: endpoint('authorize'),
      token_endpoint: endpoint('token'),
      userinfo_endpoint: endpoint('userinfo'),
      end_session_endpoint: endpoint('logout'),
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      scopes_supported: OIDC_SCOPES,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: [SIGNING_ALG],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256'],
      claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'amr', 'at_hash', 'email', 'email_verified', 'name', 'claims'],
      authorization_response_iss_parameter_supported: true,
      claims_parameter_supported: false,
      request_parameter_supported: false,
      request_uri_parameter_supported: false,
    });
  });

  // --- Authorization ---

  /** An authorization request that can't go back to the client: its client or redirect URI is unknown. */
  const badRequest = (c: Context, message: string) => c.text(`This sign-in request is not valid: ${message}`, 400);

  /** The app's login page, which signs the user in and goes back to `returnTo`. */
  const loginPage = async (returnTo: URL): Promise<string> => {
    const login = new URL(parseLoginUrl(await ctx.settings.loginUrl(), ctx.config.allowedOrigins) ?? '/', issuer);
    login.searchParams.set(LOGIN_RETURN_PARAM, returnTo.toString());
    return login.toString();
  };

  const authorize = async (c: Context) => {
    const params = await paramsOf(c);
    const client = params.client_id ? await clients.find(params.client_id) : null;
    if (!client) return badRequest(c, 'client_id is not the ID of a registered application.');
    const redirectUri = params.redirect_uri;
    if (!redirectUri || !matchesRedirectUri(clientInfo(client).redirectUris, redirectUri)) {
      return badRequest(c, 'redirect_uri is not one of the application’s registered redirect URIs.');
    }
    // From here on, the answer goes back to the client (RFC 9207: with the issuer).
    const back = (answer: Record<string, string>) => {
      const url = new URL(redirectUri);
      for (const [key, value] of Object.entries(answer)) url.searchParams.set(key, value);
      if (params.state !== undefined) url.searchParams.set('state', params.state);
      url.searchParams.set('iss', issuer);
      return c.redirect(url.toString(), 302);
    };
    const fail = (error: string, description: string) => back({ error, error_description: description });

    if (params.request !== undefined) return fail('request_not_supported', 'Request objects are not supported.');
    if (params.request_uri !== undefined) return fail('request_uri_not_supported', 'request_uri is not supported.');
    if (params.registration !== undefined) return fail('registration_not_supported', 'registration is not supported.');
    if (params.response_type !== 'code') return fail('unsupported_response_type', 'Only response_type=code is supported.');
    if (params.response_mode !== undefined && params.response_mode !== 'query') return fail('invalid_request', 'Only response_mode=query is supported.');
    const scopes = (params.scope ?? '').split(' ').filter(Boolean);
    if (!scopes.includes('openid')) return fail('invalid_scope', 'scope must include openid.');
    // PKCE for every client, with a secret or without.
    if (params.code_challenge_method !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(params.code_challenge ?? '')) {
      return fail('invalid_request', 'PKCE is required: a code_challenge with code_challenge_method=S256.');
    }
    const prompts = (params.prompt ?? '').split(' ').filter(Boolean);
    if (prompts.includes('none') && prompts.length > 1) return fail('invalid_request', 'prompt=none goes with no other value.');
    const maxAge = params.max_age === undefined ? null : Number(params.max_age);
    if (maxAge !== null && !(Number.isInteger(maxAge) && maxAge >= 0)) return fail('invalid_request', 'max_age must be a number of seconds.');

    const signIn = await ctx.currentSignIn(c);
    const recentEnough = !!signIn && signIn.signedInAt !== null && (maxAge === null || Date.now() - signIn.signedInAt <= maxAge * 1000);
    if (!signIn || !recentEnough || prompts.includes('login')) {
      if (prompts.includes('none')) return fail('login_required', 'The user is not signed in.');
      // A sign-in that has to be new ends the one there is: the login page then shows the dialog, and the user
      // who comes back has just signed in. The way back asks for no new sign-in again.
      if (signIn) ctx.signOut(c);
      const returnTo = new URL(endpoint('authorize'));
      for (const [key, value] of Object.entries(params)) if (key !== 'max_age' && key !== 'prompt') returnTo.searchParams.set(key, value);
      const otherPrompts = prompts.filter((prompt) => prompt !== 'login');
      if (otherPrompts.length) returnTo.searchParams.set('prompt', otherPrompts.join(' '));
      return c.redirect(await loginPage(returnTo), 302);
    }

    // First-party clients, registered by an admin: no consent screen.
    const user = signIn.stored;
    const grant: Grant = {
      clientId: client.id,
      userId: user.id,
      scope: scopes.filter((scope) => (OIDC_SCOPES as readonly string[]).includes(scope)).join(' '),
      authTime: Math.floor(signIn.signedInAt! / 1000),
      amr: signIn.amr.join(' '),
      sessionVersion: user.sessionVersion,
    };
    const code = await clients.issueCode(grant, { redirectUri, nonce: params.nonce ?? null, codeChallenge: params.code_challenge! });
    return back({ code });
  };
  app.get(`${OIDC_PATH}authorize`, authorize);
  app.post(`${OIDC_PATH}authorize`, authorize);

  // --- Tokens ---

  const tokenError = (c: Context, status: 400 | 401, error: string, description: string) => c.json({ error, error_description: description }, status);

  /** The client the request authenticates, by its secret (HTTP Basic or in the form) or, for a public client, its ID alone. */
  const authenticate = async (c: Context, form: Record<string, string>): Promise<StoredClient | Response> => {
    const header = c.req.header('authorization');
    const basic = header?.toLowerCase().startsWith('basic ') ? Buffer.from(header.slice(6).trim(), 'base64').toString('utf8') : null;
    const separator = basic?.indexOf(':') ?? -1;
    const fromHeader = basic !== null && separator > 0 ? { id: formDecoded(basic.slice(0, separator)), secret: formDecoded(basic.slice(separator + 1)) } : null;
    const invalidClient = () => {
      if (header !== undefined) c.header('WWW-Authenticate', 'Basic realm="madauth"');
      return tokenError(c, 401, 'invalid_client', 'The client is unknown, or its secret is wrong.');
    };
    if (basic !== null && !fromHeader) return invalidClient();
    if (fromHeader && (form.client_secret !== undefined || (form.client_id !== undefined && form.client_id !== fromHeader.id))) {
      return tokenError(c, 400, 'invalid_request', 'Authenticate the client one way only.');
    }
    const id = fromHeader?.id ?? form.client_id;
    const secret = fromHeader ? fromHeader.secret : form.client_secret;
    const client = id ? await clients.find(id) : null;
    if (!client) return invalidClient();
    // A client with a secret proves it; a public one has none to send.
    const proven = client.secretHash === null ? secret === undefined : typeof secret === 'string' && clients.checkSecret(client, secret);
    return proven ? client : invalidClient();
  };

  /** The tokens of a grant: an access token, an ID token and the refresh token given. */
  const tokens = async (c: Context, user: StoredUser, grant: Grant, scope: string, refreshToken: string, nonce: string | null) => {
    const extra = userClaims(user, scope);
    const amr = grant.amr.split(' ').filter(Boolean);
    const access: AccessTokenClaims = {
      sub: user.id,
      aud: grant.clientId,
      client_id: grant.clientId,
      scope,
      auth_time: grant.authTime,
      jti: randomString(16),
      sv: user.sessionVersion,
      ...('claims' in extra ? { claims: extra.claims } : {}),
    };
    const accessToken = await signToken(keys, issuer, ACCESS_TOKEN_TYP, access, ACCESS_TOKEN_TTL_S);
    const idToken = await signToken(
      keys,
      issuer,
      ID_TOKEN_TYP,
      { sub: user.id, aud: grant.clientId, auth_time: grant.authTime, amr, ...(nonce !== null ? { nonce } : {}), at_hash: atHash(accessToken), ...extra },
      ID_TOKEN_TTL_S,
    );
    return c.json({ access_token: accessToken, token_type: 'Bearer', expires_in: ACCESS_TOKEN_TTL_S, id_token: idToken, refresh_token: refreshToken, scope });
  };

  /** The user of a grant if their sessions haven't ended since: a password reset or change, or a sign-in reset, ends the grant. */
  const userOf = async (grant: Grant): Promise<StoredUser | null> => {
    const user = await ctx.users.findById(grant.userId);
    return user && user.sessionVersion === grant.sessionVersion ? user : null;
  };

  app.post(`${OIDC_PATH}token`, async (c) => {
    c.header('Cache-Control', 'no-store');
    c.header('Pragma', 'no-cache');
    const form = await paramsOf(c);
    const client = await authenticate(c, form);
    if (client instanceof Response) return client;

    if (form.grant_type === 'authorization_code') {
      const code = form.code ? await clients.useCode(form.code) : null;
      if (!code || code.clientId !== client.id) return tokenError(c, 400, 'invalid_grant', 'The code is unknown, expired or used.');
      if (form.redirect_uri !== code.redirectUri) return tokenError(c, 400, 'invalid_grant', 'redirect_uri is not the one of the authorization request.');
      if (!form.code_verifier || !pkceMatches(form.code_verifier, code.codeChallenge)) return tokenError(c, 400, 'invalid_grant', 'code_verifier does not match the code_challenge.');
      const user = await userOf(code);
      if (!user) return tokenError(c, 400, 'invalid_grant', 'The sign-in has ended.');
      const refreshToken = await clients.startRefreshChain(code);
      return tokens(c, user, code, code.scope, refreshToken, code.nonce);
    }

    if (form.grant_type === 'refresh_token') {
      const used = form.refresh_token ? await clients.useRefreshToken(form.refresh_token, client.id) : ({ error: 'invalid' } as const);
      if ('error' in used) return tokenError(c, 400, 'invalid_grant', 'The refresh token is unknown, expired or was used already.');
      const user = await userOf(used.chain);
      if (!user) {
        await clients.endRefreshChain(used.chain.id);
        return tokenError(c, 400, 'invalid_grant', "The user's sessions ended: they sign in again.");
      }
      // A client may ask for fewer scopes than it was granted, never for more.
      const granted = used.chain.scope.split(' ');
      const asked = form.scope === undefined ? granted : form.scope.split(' ').filter(Boolean);
      if (!asked.every((scope) => granted.includes(scope))) return tokenError(c, 400, 'invalid_scope', 'scope asks for more than was granted.');
      return tokens(c, user, used.chain, asked.join(' '), used.token, null);
    }

    return tokenError(c, 400, 'unsupported_grant_type', 'grant_type must be authorization_code or refresh_token.');
  });

  // --- User info ---

  const userinfo = async (c: Context) => {
    c.header('Cache-Control', 'no-store');
    const form = c.req.method === 'POST' ? await paramsOf(c) : {};
    const token = bearerTokenOf(c.req.header('authorization')) ?? form.access_token;
    const claims = await readToken<AccessTokenClaims>(keys, issuer, ACCESS_TOKEN_TYP, token);
    const user = claims ? await ctx.users.findById(claims.sub) : null;
    if (!claims || !user || user.sessionVersion !== claims.sv) {
      c.header('WWW-Authenticate', 'Bearer error="invalid_token"');
      return tokenError(c, 401, 'invalid_token', 'The access token is invalid or expired, or the user signed out everywhere.');
    }
    return c.json({ sub: user.id, ...userClaims(user, claims.scope) });
  };
  app.get(`${OIDC_PATH}userinfo`, userinfo);
  app.post(`${OIDC_PATH}userinfo`, userinfo);

  // --- Signing out (RP-initiated logout) ---

  const logout = async (c: Context) => {
    const params = await paramsOf(c);
    // Only a client that signed the user in, with its ID token, signs them out: no page of madAuth's asks the user.
    const hint = await readToken<JWTPayload & { sub: string }>(keys, issuer, ID_TOKEN_TYP, params.id_token_hint, { allowExpired: true });
    const clientId = typeof hint?.aud === 'string' ? hint.aud : null;
    if (!hint || !clientId) return c.text('This sign-out request is not valid: id_token_hint must be an ID token madAuth issued.', 400);
    if (params.client_id !== undefined && params.client_id !== clientId) return c.text('This sign-out request is not valid: client_id is not the ID token’s.', 400);
    const client = await clients.find(clientId);
    if (!client) return c.text('This sign-out request is not valid: the application is not registered (any more).', 400);
    const target = params.post_logout_redirect_uri;
    if (target !== undefined && !clientInfo(client).postLogoutRedirectUris.includes(target)) {
      return c.text('This sign-out request is not valid: post_logout_redirect_uri is not one of the application’s registered URIs.', 400);
    }
    // The session ends if it is the user's the ID token names; the client's refresh tokens of them in any case.
    const signIn = await ctx.currentSignIn(c);
    if (signIn?.user.id === hint.sub) ctx.signOut(c);
    await clients.endRefreshChains(hint.sub, client.id);
    const url = new URL(target ?? `${issuer}/`);
    if (target !== undefined && params.state !== undefined) url.searchParams.set('state', params.state);
    return c.redirect(url.toString(), 302);
  };
  app.get(`${OIDC_PATH}logout`, logout);
  app.post(`${OIDC_PATH}logout`, logout);
}
