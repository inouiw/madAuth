import type { Result } from '../result.js';
import type { Core } from './core.js';

/** What admins attach to a user, e.g. `{ roles: ['admin'], plan: 'pro' }`. See "Claims" in docs/server.md. */
export type Claims = Record<string, unknown>;

/** A sign-in method of the server, as the settings describe it. */
export interface MethodSetting {
  /** Whether the server is configured for the method. Only an available method can be switched on. */
  available: boolean;
  /** Whether users can sign in with it right now. */
  enabled: boolean;
}

export interface Settings {
  methods: { google: MethodSetting; password: MethodSetting };
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
  /** Which sign-in methods the server offers and which are switched on. Fails with `forbidden`. */
  getSettings(): Promise<Result<Settings>>;
  /**
   * Switches sign-in methods on or off, at once and for every instance of the server; a method that is
   * not mentioned stays as it is. Fails with `forbidden`, or `invalid_settings` (e.g. when the last method
   * would go off).
   */
  setSettings(settings: { methods: Partial<Record<'google' | 'password', boolean>> }): Promise<Result<Settings>>;
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
  };
}
