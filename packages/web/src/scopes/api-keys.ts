import { ok, type Result } from '../result.js';
import { serverCalls, type Core } from './core.js';

/** What an API key may do: which calls it allows, and the role its user needs for it. */
export interface ApiKeyScope {
  /** e.g. `orders:read`; madAuth's own, for its admin API, start with `madauth:`. */
  name: string;
  description: string;
  /** The role a user needs to give a key this scope, and to keep it working; null: any user. */
  role: string | null;
  /** The calls it allows, e.g. `GET /api/orders`, for people to read. */
  endpoints: string[];
  /** Whether the signed-in user may give a key this scope: they hold its role, by their claims as stored now. */
  allowed: boolean;
}

/** An API key of the signed-in user. Never the key itself: only {@link ApiKeysApi.create} returns that, once. */
export interface ApiKeyInfo {
  /** Its id (`key_…`), which {@link ApiKeysApi.revoke} takes. */
  id: string;
  name: string;
  scopes: string[];
  /** When it was made, when it stops working (null: never) and when it was last used, to the hour (0: never), in milliseconds since 1970. */
  createdAt: number;
  expiresAt: number | null;
  lastUsedAt: number;
}

export interface CreateApiKeyOptions {
  /** What the key is for, e.g. `CI deploy`: 1 to 64 characters. */
  name: string;
  /** Its scopes, at least one: among {@link ApiKeysApi.scopes}, and only those the user may give (`allowed`). */
  scopes: string[];
  /** When it stops working, in milliseconds since 1970. Left out: never, until it is revoked. */
  expiresAt?: number;
}

/**
 * The signed-in user's API keys: a program that calls your app's API, or madAuth's admin API, sends one as
 * `Authorization: Bearer madauth_…` and acts as the user, limited to the key's scopes. Your backend checks a key
 * with `createApiKeyVerifier` from `@madauth/server/verify`. `Madauth.showManageApiKeysDialog()` opens all of
 * this in madAuth's dialog. See docs/api-keys.md.
 */
export interface ApiKeysApi {
  /**
   * Every scope a key can have: madAuth's own and your app's (from the server's API_KEY_SCOPES_URL), with
   * whether the signed-in user may give a key each one.
   */
  scopes(): Promise<Result<{ scopes: ApiKeyScope[] }>>;
  /** The user's keys, oldest first. Fails with `no_session`. */
  list(): Promise<Result<{ apiKeys: ApiKeyInfo[] }>>;
  /**
   * Makes a key and resolves with it: `key` is shown this once (madAuth keeps only its hash), so show it to
   * the user to copy. Only within ten minutes of signing in, else it fails with `reauth_required`. Fails with
   * `invalid_options`, `invalid_scopes` (a scope that doesn't exist), `scope_not_allowed` (one the user may not
   * give), `too_many_api_keys` (20), `temporarily_unavailable` (your app's scopes can't be read right now) or
   * `no_session`.
   */
  create(options: CreateApiKeyOptions): Promise<Result<{ key: string; apiKey: ApiKeyInfo }>>;
  /** Revokes a key: it stops working at once (backends that reuse an answer stop within a minute). Fails with `api_key_not_found` or `no_session`. */
  revoke(id: string): Promise<Result>;
}

export function createApiKeysApi(core: Core): ApiKeysApi {
  const call = serverCalls(core);

  return {
    async scopes() {
      const result = await call<{ scopes: ApiKeyScope[] }>('/auth/api-keys/scopes', { method: 'GET' });
      return result.isSuccess ? ok({ scopes: result.scopes }) : result;
    },
    async list() {
      const result = await call<{ apiKeys: ApiKeyInfo[] }>('/auth/api-keys', { method: 'GET', session: true });
      return result.isSuccess ? ok({ apiKeys: result.apiKeys }) : result;
    },
    async create(options) {
      const result = await call<{ key: string; apiKey: ApiKeyInfo }>('/auth/api-keys/create', { body: { ...options }, session: true });
      return result.isSuccess ? ok({ key: result.key, apiKey: result.apiKey }) : result;
    },
    async revoke(id) {
      const result = await call('/auth/api-keys/revoke', { body: { id }, session: true });
      return result.isSuccess ? ok() : result;
    },
  };
}
