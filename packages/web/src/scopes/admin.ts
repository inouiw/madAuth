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
  /** Google, GitHub, password and the e-mail link: whether they ask for the authenticator app as a second factor. */
  secondFactor?: SecondFactorPolicy;
}

/**
 * The rules for new passwords: the fewest characters (1 to 128, default 8), and how hard to guess a password
 * must be as zxcvbn rates it, 0 (anything) to 4 (default 2: no common passwords or simple patterns).
 */
export interface PasswordRules {
  minLength: number;
  minScore: number;
}

export interface Settings {
  methods: { google: MethodSetting; github: MethodSetting; password: MethodSetting; totp: MethodSetting; 'email-link': MethodSetting; sms: MethodSetting };
  password: PasswordRules;
}

/** The list of methods to switch on: `true` or `{}` for on, with a policy for Google, GitHub, password and the e-mail link. A method left out is off. */
export interface MethodsToSet {
  google?: boolean | { secondFactor?: SecondFactorPolicy };
  github?: boolean | { secondFactor?: SecondFactorPolicy };
  password?: boolean | { secondFactor?: SecondFactorPolicy };
  /** The authenticator app on its own: the e-mail address and a code sign in. */
  totp?: boolean | Record<string, never>;
  /** The passwordless e-mail link. */
  'email-link'?: boolean | { secondFactor?: SecondFactorPolicy };
  /** SMS codes as a second factor (next to the authenticator app), for the methods whose policy asks for one. */
  sms?: boolean | Record<string, never>;
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
   * Sets which sign-in methods are on and the rules for new passwords, at once and for every instance of
   * the server. Pass either or both. `methods` replaces the old list, so a method left out is switched off;
   * in `password`, what is left out takes its default. Fails with `forbidden`, or `invalid_settings` (e.g.
   * when every method would go off).
   */
  setSettings(settings: { methods?: MethodsToSet; password?: Partial<PasswordRules> }): Promise<Result<Settings>>;
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
  const settings = (data: Settings) => ({ methods: data.methods, password: data.password });

  return {
    getClaims: (email) => call('claims/get', { email }, claims),
    setClaims: (email, value) => call('claims/set', { email, claims: value }, claims),
    getSettings: () => call('settings/get', {}, settings),
    setSettings: (value) => call('settings/set', { methods: value.methods, password: value.password }, settings),
    removeAuthenticator: (email) => call('totp/remove', { email }, (data: { userId: string }) => ({ userId: data.userId })),
  };
}
