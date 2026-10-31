// madAuth as an OpenID Connect provider: the applications (clients) admins register, the authorization codes
// and the refresh tokens. The endpoints are in routes/oidc-endpoints.ts; see "OpenID Connect provider" in docs/server.md.
import { createHash, randomBytes } from 'node:crypto';
import { safeEqual } from './password.js';
import type { Row, StoreAdapter } from './store/schema.js';

/** How long an authorization code works: the client exchanges it right after the redirect. */
export const CODE_TTL_MS = 2 * 60 * 1000;

/** How long an access token works (seconds). */
export const ACCESS_TOKEN_TTL_S = 15 * 60;

/** How long an ID token counts (seconds); the client checks it once, right after it got it. */
export const ID_TOKEN_TTL_S = 60 * 60;

/** How long a refresh token works after its last use: every use gives a new one, for another 30 days. */
export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** The scopes madAuth knows; a client asks for `openid` and any of the others, and unknown ones are left out. */
export const OIDC_SCOPES = ['openid', 'profile', 'email'] as const;

/** The most redirect URIs a client can have, of each kind. */
export const MAX_REDIRECT_URIS = 20;

/** The longest name of a client. */
export const MAX_CLIENT_NAME = 64;

const sha256 = (value: string): string => createHash('sha256').update(value).digest('base64url');

/** A client as stored: the SHA-256 of its secret, never the secret itself. */
export interface StoredClient {
  /** The client ID (`mc_…`), which the client sends. */
  id: string;
  name: string;
  /** The SHA-256 of its secret (base64url); null for a public client (a native or browser app), which proves itself with PKCE alone. */
  secretHash: string | null;
  /** Where the client may be sent back to after the sign-in, as JSON. */
  redirectUris: string;
  /** Where the client may be sent back to after it signed the user out, as JSON. */
  postLogoutRedirectUris: string;
  createdAt: number;
  updatedAt: number;
  updatedBy: string | null;
}

/** A client as the admin API answers it: never its secret. */
export interface ClientInfo {
  id: string;
  name: string;
  /** Without a secret: a native or browser app. */
  public: boolean;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  createdAt: number;
  updatedAt: number;
}

const urisOf = (json: string): string[] => {
  const list: unknown = JSON.parse(json);
  return Array.isArray(list) ? list.filter((uri): uri is string => typeof uri === 'string') : [];
};

export const clientInfo = (client: StoredClient): ClientInfo => ({
  id: client.id,
  name: client.name,
  public: client.secretHash === null,
  redirectUris: urisOf(client.redirectUris),
  postLogoutRedirectUris: urisOf(client.postLogoutRedirectUris),
  createdAt: client.createdAt,
  updatedAt: client.updatedAt,
});

/** The hosts that are this computer, whose redirect URIs match with any port (RFC 8252, section 7.3). */
const LOOPBACK_HOSTS = ['127.0.0.1', '[::1]', 'localhost'];
/** Schemes a browser runs instead of opening: never a redirect URI. */
const FORBIDDEN_SCHEMES = ['javascript:', 'data:', 'vbscript:', 'file:', 'blob:', 'about:'];

const isLoopback = (url: URL): boolean => url.protocol === 'http:' && LOOPBACK_HOSTS.includes(url.hostname);

/**
 * Why `value` can't be a redirect URI, or null if it can: an absolute URL without a fragment, either https, http
 * on this computer (`http://127.0.0.1`, `http://[::1]` or `http://localhost`, any port), or an app's own scheme
 * (`vscode://…`, `com.example.app:/callback`).
 */
export function redirectUriProblem(value: unknown): string | null {
  if (typeof value !== 'string' || !URL.canParse(value)) return 'must be an absolute URL';
  const url = new URL(value);
  if (value.includes('#')) return 'must not have a fragment (#)';
  if (FORBIDDEN_SCHEMES.includes(url.protocol)) return `can't use the scheme ${url.protocol}`;
  if (url.protocol === 'http:' && !isLoopback(url)) return 'must use https, except on 127.0.0.1, [::1] or localhost';
  return null;
}

/**
 * Whether a redirect URI a client sent is one of those registered: the same string, or, for one on this computer,
 * the same but for the port (RFC 8252: a native app listens on whichever port is free).
 */
export function matchesRedirectUri(registered: readonly string[], sent: string): boolean {
  if (registered.includes(sent)) return true;
  if (!URL.canParse(sent)) return false;
  const url = new URL(sent);
  if (!isLoopback(url)) return false;
  const withoutPort = (u: URL) => `${u.protocol}//${u.hostname}${u.pathname}${u.search}`;
  return registered.some((uri) => URL.canParse(uri) && isLoopback(new URL(uri)) && withoutPort(new URL(uri)) === withoutPort(url));
}

/** What an admin sets of a client; left out: kept as it is. */
export interface ClientFields {
  name?: string;
  redirectUris?: string[];
  postLogoutRedirectUris?: string[];
}

/** A list of redirect URIs as the admin API takes it, or why it isn't one. */
function parseUris(value: unknown, field: string): string[] | { error: string } {
  if (!Array.isArray(value) || value.length > MAX_REDIRECT_URIS) return { error: `${field} must be a list of at most ${MAX_REDIRECT_URIS} URIs.` };
  for (const uri of value) {
    const problem = redirectUriProblem(uri);
    if (problem) return { error: `${field}: ${JSON.stringify(uri)} ${problem}.` };
  }
  return [...new Set(value as string[])];
}

/**
 * The fields of a client as the admin API takes them, or the error to answer. A new client (`isNew`) needs a name
 * and at least one redirect URI.
 */
export function parseClientFields(data: Record<string, unknown>, isNew: boolean): ClientFields | { error: 'invalid_client'; message: string } {
  const invalid = (message: string) => ({ error: 'invalid_client' as const, message });
  const fields: ClientFields = {};
  if (data.name !== undefined || isNew) {
    if (typeof data.name !== 'string' || !data.name.trim() || data.name.length > MAX_CLIENT_NAME) return invalid(`name must be a text of 1 to ${MAX_CLIENT_NAME} characters.`);
    fields.name = data.name.trim();
  }
  if (data.redirectUris !== undefined || isNew) {
    const uris = parseUris(data.redirectUris, 'redirectUris');
    if ('error' in uris) return invalid(uris.error);
    if (!uris.length) return invalid('redirectUris must list at least one URI.');
    fields.redirectUris = uris;
  }
  if (data.postLogoutRedirectUris !== undefined) {
    const uris = parseUris(data.postLogoutRedirectUris, 'postLogoutRedirectUris');
    if ('error' in uris) return invalid(uris.error);
    fields.postLogoutRedirectUris = uris;
  }
  return fields;
}

/** An authorization code as stored: `id` is the code's SHA-256. */
export interface StoredCode {
  id: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  /** The scopes granted, separated by spaces. */
  scope: string;
  nonce: string | null;
  /** The PKCE challenge (S256). */
  codeChallenge: string;
  /** When the user signed in, in seconds since 1970. */
  authTime: number;
  /** How the user signed in, separated by spaces. */
  amr: string;
  /** The user's session version at the sign-in: a password reset or a sign-in reset ends what came of it. */
  sessionVersion: number;
  expiresAt: number;
}

/** A chain of refresh tokens: `hash` is the SHA-256 of its only token that works, each use replaces it. */
export interface StoredRefreshToken {
  /** The chain's id, the first part of each of its tokens. */
  id: string;
  hash: string;
  clientId: string;
  userId: string;
  scope: string;
  authTime: number;
  amr: string;
  sessionVersion: number;
  createdAt: number;
  /** 30 days after its last use. */
  expiresAt: number;
  lastUsedAt: number;
}

/** What a sign-in grants a client, carried from the code to the refresh tokens. */
export type Grant = Pick<StoredCode, 'clientId' | 'userId' | 'scope' | 'authTime' | 'amr' | 'sessionVersion'>;

/** What using a refresh token came to: the chain with its new token; `reused` when an old token came, which ended the chain. */
export type RefreshResult = { chain: StoredRefreshToken; token: string } | { error: 'invalid' | 'reused' };

const refreshTokenOf = (id: string, secret: string) => `${id}.${secret}`;

/** The grant of a code or a chain, without the rest of the record. */
const grantOf = ({ clientId, userId, scope, authTime, amr, sessionVersion }: Grant): Grant => ({ clientId, userId, scope, authTime, amr, sessionVersion });

export class OidcClients {
  constructor(private readonly store: StoreAdapter) {}

  /** Every client, oldest first. */
  async list(): Promise<StoredClient[]> {
    const clients: StoredClient[] = [];
    for (let after: string | undefined; ; ) {
      const page = (await this.store.scan('oidcClient', { after, limit: 100 })) as unknown as StoredClient[];
      clients.push(...page);
      if (page.length < 100) break;
      after = page.at(-1)!.id;
    }
    return clients.sort((a, b) => a.createdAt - b.createdAt);
  }

  async find(id: string): Promise<StoredClient | null> {
    return (await this.store.findOne('oidcClient', { id })) as StoredClient | null;
  }

  /** Registers a client. Resolves to it and its secret, which only this answer ever shows; null for a public client. */
  async add(fields: Required<Pick<ClientFields, 'name' | 'redirectUris'>> & ClientFields, isPublic: boolean, by: string): Promise<{ client: StoredClient; secret: string | null }> {
    const secret = isPublic ? null : newSecret();
    const now = Date.now();
    const client: StoredClient = {
      id: `mc_${randomBytes(16).toString('base64url')}`,
      name: fields.name,
      secretHash: secret && sha256(secret),
      redirectUris: JSON.stringify(fields.redirectUris),
      postLogoutRedirectUris: JSON.stringify(fields.postLogoutRedirectUris ?? []),
      createdAt: now,
      updatedAt: now,
      updatedBy: by,
    };
    await this.store.create('oidcClient', client as unknown as Row);
    return { client, secret };
  }

  /**
   * Changes a client; `newSecret` replaces a confidential client's secret, so the old one stops working at once.
   * Resolves to the client and the new secret, or null if there is no such client (any more).
   */
  async update(id: string, fields: ClientFields, newSecretWanted: boolean, by: string): Promise<{ client: StoredClient; secret: string | null } | null> {
    const current = await this.find(id);
    if (!current) return null;
    const secret = newSecretWanted && current.secretHash !== null ? newSecret() : null;
    const patch: Partial<StoredClient> = {
      ...(fields.name !== undefined ? { name: fields.name } : {}),
      ...(fields.redirectUris ? { redirectUris: JSON.stringify(fields.redirectUris) } : {}),
      ...(fields.postLogoutRedirectUris ? { postLogoutRedirectUris: JSON.stringify(fields.postLogoutRedirectUris) } : {}),
      ...(secret ? { secretHash: sha256(secret) } : {}),
      updatedAt: Date.now(),
      updatedBy: by,
    };
    if ((await this.store.update('oidcClient', { id }, patch as Row)) !== 1) return null;
    return { client: { ...current, ...patch }, secret };
  }

  /** Removes a client and ends its refresh tokens. Resolves to the client, or null if there is no such client (any more). */
  async remove(id: string): Promise<StoredClient | null> {
    const client = await this.find(id);
    if (!client || (await this.store.delete('oidcClient', { id })) !== 1) return null;
    await this.store.delete('oidcRefreshToken', { clientId: id });
    return client;
  }

  /** Whether `secret` is the client's secret. A public client has none, so nothing matches. */
  checkSecret(client: StoredClient, secret: string): boolean {
    return client.secretHash !== null && safeEqual(sha256(secret), client.secretHash);
  }

  /** Issues an authorization code for a sign-in. Removes the user's codes that are of no use any more first. */
  async issueCode(grant: Grant, request: { redirectUri: string; nonce: string | null; codeChallenge: string }): Promise<string> {
    await this.dropUseless('oidcCode', grant);
    const code = randomBytes(32).toString('base64url');
    const stored: StoredCode = { id: sha256(code), ...grantOf(grant), ...request, expiresAt: Date.now() + CODE_TTL_MS };
    await this.store.create('oidcCode', stored as unknown as Row);
    return code;
  }

  /**
   * Uses up a code of `clientId`: resolves to what it grants, or null if it is unknown, another client's, expired or
   * used already. Each code works once; another client can't use it up.
   */
  async useCode(code: string, clientId: string): Promise<StoredCode | null> {
    const id = sha256(code);
    const stored = (await this.store.findOne('oidcCode', { id })) as StoredCode | null;
    if (!stored || stored.clientId !== clientId || (await this.store.delete('oidcCode', { id })) !== 1) return null;
    return stored.expiresAt > Date.now() ? stored : null;
  }

  /** Starts a chain of refresh tokens for a grant. Removes the user's chains that are of no use any more first. Resolves to its first token. */
  async startRefreshChain(grant: Grant): Promise<string> {
    await this.dropUseless('oidcRefreshToken', grant);
    const secret = randomBytes(32).toString('base64url');
    const now = Date.now();
    const chain: StoredRefreshToken = {
      id: `rt_${randomBytes(16).toString('base64url')}`,
      hash: sha256(secret),
      ...grantOf(grant),
      createdAt: now,
      expiresAt: now + REFRESH_TOKEN_TTL_MS,
      lastUsedAt: now,
    };
    await this.store.create('oidcRefreshToken', chain as unknown as Row);
    return refreshTokenOf(chain.id, secret);
  }

  /**
   * Uses a refresh token of `clientId`: its chain gets a new token, for another 30 days, and the token used stops
   * working. A token that was used before ends its whole chain: whoever holds the newer one (the client, or whoever
   * took it) must sign in again (RFC 9700, section 4.14.2).
   */
  async useRefreshToken(token: string, clientId: string): Promise<RefreshResult> {
    const [id, secret, ...rest] = token.split('.');
    if (!id || !secret || rest.length) return { error: 'invalid' };
    const chain = (await this.store.findOne('oidcRefreshToken', { id })) as StoredRefreshToken | null;
    if (!chain || chain.clientId !== clientId) return { error: 'invalid' };
    if (!safeEqual(sha256(secret), chain.hash)) {
      await this.store.delete('oidcRefreshToken', { id });
      return { error: 'reused' };
    }
    const now = Date.now();
    if (chain.expiresAt <= now) {
      await this.store.delete('oidcRefreshToken', { id });
      return { error: 'invalid' };
    }
    const next = randomBytes(32).toString('base64url');
    const patch = { hash: sha256(next), expiresAt: now + REFRESH_TOKEN_TTL_MS, lastUsedAt: now };
    // Only if no other request used the token meanwhile: two uses of one token, one of them comes too late.
    if ((await this.store.update('oidcRefreshToken', { id, hash: chain.hash }, patch)) !== 1) {
      await this.store.delete('oidcRefreshToken', { id });
      return { error: 'reused' };
    }
    return { chain: { ...chain, ...patch }, token: refreshTokenOf(id, next) };
  }

  /** Ends a chain, e.g. one whose user's sessions ended. */
  async endRefreshChain(id: string): Promise<void> {
    await this.store.delete('oidcRefreshToken', { id });
  }

  /** Ends the refresh tokens a client has of a user, e.g. when the client signs the user out. */
  async endRefreshChains(userId: string, clientId: string): Promise<void> {
    await this.store.delete('oidcRefreshToken', { userId, clientId });
  }

  /**
   * Deletes the records of one model of the grant's user that are of no use any more: expired, or from before their
   * sessions ended (a password reset or change), which the session version of `grant`, the user's of now, tells.
   */
  private async dropUseless(model: 'oidcCode' | 'oidcRefreshToken', { userId, sessionVersion }: Grant): Promise<void> {
    const now = Date.now();
    const records = (await this.store.findMany(model, { userId })) as unknown as { id: string; expiresAt: number; sessionVersion: number }[];
    const useless = records.filter((r) => r.expiresAt <= now || r.sessionVersion !== sessionVersion);
    await Promise.all(useless.map((r) => this.store.delete(model, { id: r.id })));
  }
}

/** A new client secret: recognisable by its start, e.g. by secret scanning. */
const newSecret = (): string => `mcs_${randomBytes(32).toString('base64url')}`;
