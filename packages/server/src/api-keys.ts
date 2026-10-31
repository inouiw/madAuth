// API keys: a user's keys for programs that call your app's API, or madAuth's admin API, on the user's behalf.
// A key acts as its user, limited to its scopes, and only for the scopes its user may hold at the time of each
// use. madAuth's own scopes are fixed here; the app's are listed at API_KEY_SCOPES_URL. See docs/api-keys.md.
import { createHash, randomBytes } from 'node:crypto';
import { ADMIN_ROLE, parseRoles, rolesOf, type Claims } from './claims.js';
import type { Row, StoreAdapter } from './store/schema.js';
import { API_KEY_PREFIX } from './user.js';

/** How many keys one user can have. */
export const MAX_API_KEYS = 20;

/** The longest name of a key. */
export const MAX_API_KEY_NAME = 64;

/** How often the time of a key's last use is written at most: "last used" is shown as a date. */
const LAST_USED_PRECISION_MS = 60 * 60 * 1000;

/** What a key may do: which calls it allows, and which role its user needs for it. */
export interface Scope {
  /** e.g. `orders:read`; madAuth's own start with `madauth:`. */
  name: string;
  /** What it allows, for people to read when they choose the scopes of a key. */
  description: string;
  /** The role the key's user must hold, when the key is made and at every use; null: any user. */
  role: string | null;
  /** The calls it allows, e.g. `POST /auth/admin/claims/get`, for people to read. */
  endpoints: string[];
}

/** madAuth's own scopes, one per admin task: for the admin API, so only users with the role `admin` hold them. */
export const MADAUTH_SCOPES = [
  { name: 'madauth:claims:read', description: "Read a user's claims and roles", role: ADMIN_ROLE, endpoints: ['POST /auth/admin/claims/get'] },
  { name: 'madauth:claims:write', description: "Change a user's claims and roles", role: ADMIN_ROLE, endpoints: ['POST /auth/admin/claims/set'] },
  { name: 'madauth:settings:read', description: 'Read the sign-in settings', role: ADMIN_ROLE, endpoints: ['POST /auth/admin/settings/get'] },
  { name: 'madauth:settings:write', description: 'Change the sign-in settings', role: ADMIN_ROLE, endpoints: ['POST /auth/admin/settings/set'] },
  { name: 'madauth:sign-in:reset', description: "Reset a user's sign-in, for a user who lost every way in", role: ADMIN_ROLE, endpoints: ['POST /auth/admin/sign-in/reset'] },
  { name: 'madauth:users:read', description: 'Find users by role, address or sign-up date', role: ADMIN_ROLE, endpoints: ['POST /auth/admin/users/search'] },
  { name: 'madauth:providers:read', description: 'List the sign-in providers, without their secrets', role: ADMIN_ROLE, endpoints: ['POST /auth/admin/providers/list'] },
  { name: 'madauth:clients:read', description: 'List the applications that sign in with madAuth (OpenID Connect clients)', role: ADMIN_ROLE, endpoints: ['POST /auth/admin/clients/list'] },
] as const satisfies readonly Scope[];

export type MadauthScope = (typeof MADAUTH_SCOPES)[number]['name'];

/** A key as stored: the SHA-256 of the key, never the key itself. */
export interface StoredApiKey {
  /** Its id (`key_…`), which revoking it takes. */
  id: string;
  userId: string;
  /** The SHA-256 of the key (base64url), by which a request's key is found. */
  hash: string;
  name: string;
  /** Its scopes, separated by spaces. */
  scopes: string;
  createdAt: number;
  /** When it stops working; null: never. */
  expiresAt: number | null;
  /** When it was last used, to the hour; 0: never. */
  lastUsedAt: number;
}

/** A key as its user and the admins see it. */
export interface ApiKeyInfo {
  id: string;
  name: string;
  scopes: string[];
  createdAt: number;
  expiresAt: number | null;
  lastUsedAt: number;
}

export const apiKeyInfo = (key: StoredApiKey): ApiKeyInfo => ({
  id: key.id,
  name: key.name,
  scopes: scopesOf(key),
  createdAt: key.createdAt,
  expiresAt: key.expiresAt,
  lastUsedAt: key.lastUsedAt,
});

const scopesOf = (key: StoredApiKey): string[] => key.scopes.split(' ').filter(Boolean);

const hashOf = (key: string): string => createHash('sha256').update(key).digest('base64url');

/** Whether a user with these claims may hold a scope now. */
export const mayHold = (scope: Scope, claims: Claims): boolean => !scope.role || rolesOf({ claims }).includes(scope.role);

/** The scopes of a key that still count: listed now, and held by its user's claims now. */
export function grantedScopes(key: StoredApiKey, scopes: readonly Scope[], claims: Claims): string[] {
  return scopesOf(key).filter((name) => {
    const scope = scopes.find((s) => s.name === name);
    return !!scope && mayHold(scope, claims);
  });
}

export class ApiKeys {
  constructor(private readonly store: StoreAdapter) {}

  /** Makes a key. Resolves to the key, which only this answer ever shows, and what is stored about it. */
  async create(userId: string, data: { name: string; scopes: string[]; expiresAt: number | null }): Promise<{ key: string; stored: StoredApiKey }> {
    const key = `${API_KEY_PREFIX}${randomBytes(32).toString('base64url')}`;
    const stored: StoredApiKey = {
      id: `key_${randomBytes(16).toString('base64url')}`,
      userId,
      hash: hashOf(key),
      name: data.name,
      scopes: data.scopes.join(' '),
      createdAt: Date.now(),
      expiresAt: data.expiresAt,
      lastUsedAt: 0,
    };
    await this.store.create('apiKey', stored as unknown as Row);
    return { key, stored };
  }

  /** A user's keys, oldest first. */
  async list(userId: string): Promise<StoredApiKey[]> {
    const keys = (await this.store.findMany('apiKey', { userId })) as unknown as StoredApiKey[];
    return keys.sort((a, b) => a.createdAt - b.createdAt);
  }

  /** Deletes a user's key. Resolves to the key, or null if the user has no such key (any more). */
  async revoke(userId: string, id: string): Promise<StoredApiKey | null> {
    const key = (await this.store.findOne('apiKey', { id, userId })) as StoredApiKey | null;
    if (!key) return null;
    return (await this.store.delete('apiKey', { id, userId })) === 1 ? key : null;
  }

  /** The stored key a request's key is, if it works now: it exists and hasn't expired. */
  async find(key: string): Promise<StoredApiKey | null> {
    if (!key.startsWith(API_KEY_PREFIX)) return null;
    const stored = (await this.store.findOne('apiKey', { hash: hashOf(key) })) as StoredApiKey | null;
    return stored && (stored.expiresAt === null || stored.expiresAt > Date.now()) ? stored : null;
  }

  /** Notes that a key was used, at most once an hour. */
  async markUsed(key: StoredApiKey): Promise<void> {
    const now = Date.now();
    if (now - key.lastUsedAt >= LAST_USED_PRECISION_MS) await this.store.update('apiKey', { id: key.id }, { lastUsedAt: now });
  }
}

const SCOPE_NAME = /^[a-z][a-z0-9_-]*(:[a-z0-9_-]+)*$/;
const MAX_SCOPE_NAME = 64;
const MAX_APP_SCOPES = 100;
const MAX_DESCRIPTION = 200;
const MAX_ENDPOINTS = 20;

const isText = (value: unknown, max: number): value is string => typeof value === 'string' && value.trim().length > 0 && value.length <= max;

/**
 * The scopes an app lists at API_KEY_SCOPES_URL, or null if `input` is not such a list:
 * `{ "scopes": [{ "name": "orders:read", "description": "Read your orders", "role": "staff", "endpoints": ["GET /api/orders"] }] }`,
 * `role` and `endpoints` optional. Names are lower-case words separated by `:`, at most 64 characters, unique,
 * and never start with `madauth:`.
 */
export function parseAppScopes(input: unknown): Scope[] | null {
  const list = input && typeof input === 'object' ? (input as { scopes?: unknown }).scopes : undefined;
  if (!Array.isArray(list) || list.length > MAX_APP_SCOPES) return null;
  const scopes: Scope[] = [];
  for (const entry of list as Record<string, unknown>[]) {
    if (!entry || typeof entry !== 'object') return null;
    const { name, description, role = null, endpoints = [] } = entry;
    if (typeof name !== 'string' || name.length > MAX_SCOPE_NAME || !SCOPE_NAME.test(name) || name.startsWith('madauth:')) return null;
    if (scopes.some((scope) => scope.name === name) || !isText(description, MAX_DESCRIPTION)) return null;
    if (role !== null && (typeof role !== 'string' || !parseRoles([role]))) return null;
    if (!Array.isArray(endpoints) || endpoints.length > MAX_ENDPOINTS || !endpoints.every((e) => isText(e, MAX_DESCRIPTION))) return null;
    scopes.push({ name, description: description.trim(), role, endpoints });
  }
  return scopes;
}

/** How long a list read from API_KEY_SCOPES_URL counts before it is read again. */
const SCOPES_TTL_MS = 5 * 60 * 1000;
/** After a failed read, how long madAuth waits before it tries again (and keeps the list it had). */
const SCOPES_RETRY_MS = 60 * 1000;
const SCOPES_TIMEOUT_MS = 5_000;

/**
 * The scopes keys can have: madAuth's own, and the app's from API_KEY_SCOPES_URL, read again every five
 * minutes. When the app's list can't be read, the last one read stays; until one was read, there are only
 * madAuth's (`complete` is false then).
 */
export class ScopeCatalog {
  private app: { scopes: Scope[]; readAt: number } | undefined;
  private failedAt = 0;
  private reading: Promise<void> | undefined;

  constructor(
    private readonly url: string | undefined,
    private readonly fetcher: typeof fetch = fetch,
  ) {}

  async all(): Promise<{ scopes: Scope[]; complete: boolean }> {
    if (this.url && this.stale()) await (this.reading ??= this.read().finally(() => (this.reading = undefined)));
    return { scopes: [...MADAUTH_SCOPES, ...(this.app?.scopes ?? [])], complete: !this.url || !!this.app };
  }

  private stale(): boolean {
    const now = Date.now();
    return (!this.app || now - this.app.readAt >= SCOPES_TTL_MS) && now - this.failedAt >= SCOPES_RETRY_MS;
  }

  private async read(): Promise<void> {
    const scopes = await this.fetchScopes();
    if (typeof scopes === 'string') {
      this.failedAt = Date.now();
      console.error(`[madauth] API_KEY_SCOPES_URL: could not read the app's scopes from ${this.url}: ${scopes}`);
      return;
    }
    this.app = { scopes, readAt: Date.now() };
  }

  /** The app's scopes, or why they couldn't be read. */
  private async fetchScopes(): Promise<Scope[] | string> {
    const init = { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(SCOPES_TIMEOUT_MS) };
    const res = await this.fetcher(this.url!, init).catch((e: Error) => e);
    if (res instanceof Error) return res.message;
    if (!res.ok) return `the answer was ${res.status}`;
    const list = await res.json().catch(() => undefined);
    return parseAppScopes(list) ?? 'the answer is not a list of scopes, see docs/api-keys.md';
  }
}
