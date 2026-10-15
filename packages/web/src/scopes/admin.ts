import type { SecondFactorPolicy } from '../providers/provider.js';
import type { Result } from '../result.js';
import type { ApiKeyInfo } from './api-keys.js';
import type { Core } from './core.js';

/** What admins attach to a user, e.g. `{ roles: ['admin'], plan: 'pro' }`. See "Claims" in docs/server.md. */
export type Claims = Record<string, unknown>;

/** A method of the server, as the settings describe it. */
export interface MethodSetting {
  /** Whether the server has what the method needs (e.g. a Google client). Only a configured method can be on. */
  configured: boolean;
  /** Whether it is on: listed in the settings, and configured. */
  enabled: boolean;
  /** Whether it signs users in on its own; false for one that is off, or only a second factor. */
  allowAsSignInMethod: boolean;
  /** Whether a sign-in with it asks for a second factor; `none` for one that is off or does not sign in. */
  secondFactor: SecondFactorPolicy;
}

/** How an admin switches a method on: both settings, always. */
export interface MethodToSet {
  /**
   * Whether it signs users in on its own. Google, GitHub, password and the e-mail link always do (`true`),
   * SMS codes never (`false`); the authenticator app and passkeys either do, or are only a second factor.
   */
  allowAsSignInMethod: boolean;
  /** Whether a sign-in with it asks for a second factor; `none` for a method that does not sign in. */
  secondFactor: SecondFactorPolicy;
}

/**
 * The rules for new passwords: the fewest characters (1 to 128, default 8), and how hard to guess a password
 * must be as zxcvbn rates it, 0 (anything) to 4 (default 2: no common passwords or simple patterns).
 */
export interface PasswordRules {
  minLength: number;
  minScore: number;
}

/** The ids of the methods in the settings. */
export type MethodId = 'google' | 'github' | 'password' | 'authenticator' | 'email-link' | 'passkey' | 'sms';

export interface Settings {
  methods: Record<MethodId, MethodSetting>;
  password: PasswordRules;
}

/**
 * The list of methods to switch on, each with both of its settings. A method left out is off. A second
 * factor a policy asks for must be on too (`authenticator`, `passkey` or `sms`), e.g.
 * `{ password: { allowAsSignInMethod: true, secondFactor: 'optional' }, authenticator: { allowAsSignInMethod: false, secondFactor: 'none' } }`.
 */
export type MethodsToSet = Partial<Record<MethodId, MethodToSet>>;

/**
 * Managing claims, settings and users' API keys, and resetting a user's sign-in, for users with the role `admin`
 * (`claims.roles`). The first admin is the user who signs in with the address in the server's
 * `INITIAL_ADMIN_EMAIL`.
 */
export interface AdminApi {
  /**
   * The claims of the user with this e-mail address. Fails with `forbidden` for users without the role
   * `admin`, `invalid_email`, or `user_not_found` when nobody with the address has signed in yet.
   */
  getClaims(email: string): Promise<Result<{ userId: string; claims: Claims }>>;
  /**
   * Replaces the claims of the user with this e-mail address; an empty object removes them. The user sees
   * the change the next time their app checks the session (`Madauth.getSession`, or the next page load),
   * and backends when that session token reaches them. Fails with `forbidden`, `invalid_email`,
   * `user_not_found`, `invalid_claims`, or `own_admin_role` when it would take the role `admin` from the admin
   * who calls it: another admin has to.
   */
  setClaims(email: string, claims: Claims): Promise<Result<{ userId: string; claims: Claims }>>;
  /** Which sign-in methods the server is configured for, which are on, and their policies. Fails with `forbidden`. */
  getSettings(): Promise<Result<Settings>>;
  /**
   * Sets which sign-in methods are on and the rules for new passwords, at once and for every instance of
   * the server. Pass either or both. `methods` replaces the old list, so a method left out is switched off;
   * in `password`, what is left out takes its default. Fails with `forbidden`, or `invalid_settings` (e.g.
   * when every method would go off).
   */
  setSettings(settings: { methods?: MethodsToSet; password?: Partial<PasswordRules> }): Promise<Result<Settings>>;
  /**
   * Resets the sign-in of the user with this e-mail address, who lost every way in or a second factor:
   * removes all their sign-in methods and second factors, ends their sessions and marks the address
   * unconfirmed. They sign up again with any method that is on and keep their id, claims and roles. Check
   * who is asking first: whoever proves the inbox next gets the account. An admin who resets themselves is
   * signed out at the next session check. Fails with `forbidden`, `invalid_email` or `user_not_found`.
   */
  resetSignIn(email: string): Promise<Result<{ userId: string }>>;
  /**
   * The API keys of the user with this e-mail address, e.g. to find one that leaked. Only with a session: an
   * API key never manages keys. Fails with `forbidden`, `invalid_email` or `user_not_found`.
   */
  listApiKeys(email: string): Promise<Result<{ userId: string; apiKeys: ApiKeyInfo[] }>>;
  /** Revokes an API key of the user with this e-mail address. Fails with `forbidden`, `invalid_email`, `user_not_found` or `api_key_not_found`. */
  revokeApiKey(email: string, id: string): Promise<Result<{ userId: string }>>;
}

export function createAdminApi(core: Core): AdminApi {
  async function call<T extends object>(path: string, body: Record<string, unknown>, pick: (data: any) => T): Promise<Result<T>> {
    const ready = await core.whenReady();
    if (!ready.isSuccess) return ready;
    const res = await core.request<unknown>(`/auth/admin/${path}`, { method: 'POST', body });
    return res.ok ? { isSuccess: true, ...pick(res.data) } : { isSuccess: false, error: res.error };
  }
  const claims = (data: { userId: string; claims: Claims }) => ({ userId: data.userId, claims: data.claims });
  const settings = (data: Settings) => ({ methods: data.methods, password: data.password });

  return {
    getClaims: (email) => call('claims/get', { email }, claims),
    setClaims: (email, value) => call('claims/set', { email, claims: value }, claims),
    getSettings: () => call('settings/get', {}, settings),
    setSettings: (value) => call('settings/set', { methods: value.methods, password: value.password }, settings),
    resetSignIn: (email) => call('sign-in/reset', { email }, (data: { userId: string }) => ({ userId: data.userId })),
    listApiKeys: (email) => call('api-keys/list', { email }, (data: { userId: string; apiKeys: ApiKeyInfo[] }) => ({ userId: data.userId, apiKeys: data.apiKeys })),
    revokeApiKey: (email, id) => call('api-keys/revoke', { email, id }, (data: { userId: string }) => ({ userId: data.userId })),
  };
}
