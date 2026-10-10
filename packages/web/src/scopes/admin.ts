import type { SecondFactorPolicy } from '../providers/provider.js';
import type { Result } from '../result.js';
import type { Core } from './core.js';

/** What admins attach to a user, e.g. `{ roles: ['admin'], plan: 'pro' }`. See "Claims" in docs/server.md. */
export type Claims = Record<string, unknown>;

/** A sign-in method of the server, as the settings describe it. */
export interface MethodSetting {
  /** Whether the server has what the method needs (e.g. a Google client). Only a configured method can be on. */
  configured: boolean;
  /** Whether users can sign in with it right now. */
  enabled: boolean;
  /** Google and password: whether they ask for the authenticator app as a second factor. */
  secondFactor?: SecondFactorPolicy;
}

export interface Settings {
  methods: { google: MethodSetting; password: MethodSetting; totp: MethodSetting };
}

/** The list of methods to switch on: `true` or `{}` for on, with a policy for Google and password. A method left out is off. */
export interface MethodsToSet {
  google?: boolean | { secondFactor?: SecondFactorPolicy };
  password?: boolean | { secondFactor?: SecondFactorPolicy };
  /** The authenticator app on its own: the e-mail address and a code sign in. */
  totp?: boolean | {};
}

/**
 * Managing claims and settings, for users with the role `admin` (`claims.roles`). The first admin is made
 * on the server: `npx @madauth/server set-roles you@example.com admin`.
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
   * `user_not_found` or `invalid_claims`.
   */
  setClaims(email: string, claims: Claims): Promise<Result<{ userId: string; claims: Claims }>>;
  /** Which sign-in methods the server is configured for, which are on, and their policies. Fails with `forbidden`. */
  getSettings(): Promise<Result<Settings>>;
  /**
   * Sets which sign-in methods are on, at once and for every instance of the server: the given list
   * replaces the old one, so a method left out is switched off. Fails with `forbidden`, or
   * `invalid_settings` (e.g. when every method would go off).
   */
  setSettings(settings: { methods: MethodsToSet }): Promise<Result<Settings>>;
  /**
   * Removes a user's authenticator app and recovery codes: the last resort when both are lost. With a
   * `required` policy the user sets it up again at the next sign-in. Fails with `forbidden`,
   * `invalid_email` or `user_not_found`.
   */
  removeAuthenticator(email: string): Promise<Result<{ userId: string }>>;
}

export function createAdminApi(core: Core): AdminApi {
  async function call<T extends object>(path: string, body: Record<string, unknown>, pick: (data: any) => T): Promise<Result<T>> {
    const ready = await core.whenReady();
    if (!ready.isSuccess) return ready;
    const res = await core.request<unknown>(`/auth/admin/${path}`, { method: 'POST', body });
    return res.ok ? { isSuccess: true, ...pick(res.data) } : { isSuccess: false, error: res.error };
  }
  const claims = (data: { userId: string; claims: Claims }) => ({ userId: data.userId, claims: data.claims });
  const settings = (data: Settings) => ({ methods: data.methods });

  return {
    getClaims: (email) => call('claims/get', { email }, claims),
    setClaims: (email, value) => call('claims/set', { email, claims: value }, claims),
    getSettings: () => call('settings/get', {}, settings),
    setSettings: (value) => call('settings/set', { methods: value.methods }, settings),
    removeAuthenticator: (email) => call('totp/remove', { email }, (data: { userId: string }) => ({ userId: data.userId })),
  };
}
