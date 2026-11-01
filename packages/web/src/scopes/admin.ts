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
   * Whether it signs users in on its own. Google, GitHub, the OpenID Connect providers, password and the
   * e-mail link always do (`true`), SMS codes never (`false`); the authenticator app and passkeys either do, or are only a second factor.
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

/** The ids of the methods in the settings: madAuth's own, and those of the OpenID Connect providers an admin added. */
export type MethodId = 'google' | 'github' | 'password' | 'authenticator' | 'email-link' | 'passkey' | 'sms' | (string & {});

export interface Settings {
  methods: Record<MethodId, MethodSetting>;
  password: PasswordRules;
  /**
   * The app's login page, where madAuth sends people when an application that signs in with madAuth as its OpenID
   * Connect provider needs them to sign in: a path on the server's origin (`/login`) or a URL on an allowed origin;
   * `null` is `/`. Absent from servers before 0.7.
   */
  loginUrl?: string | null;
}

/**
 * The list of methods to switch on, each with both of its settings. A method left out is off. A second
 * factor a policy asks for must be on too (`authenticator`, `passkey` or `sms`), e.g.
 * `{ password: { allowAsSignInMethod: true, secondFactor: 'optional' }, authenticator: { allowAsSignInMethod: false, secondFactor: 'none' } }`.
 */
export type MethodsToSet = Partial<Record<MethodId, MethodToSet>>;

/**
 * The kinds of sign-in providers. Google and GitHub exist once each, with the kind as the id; `oidc`, an
 * OpenID Connect provider (e.g. GitLab, Keycloak, Okta), as often as needed, each with an id of its own.
 */
export type ProviderKind = 'google' | 'github' | 'oidc';

/** A sign-in provider as the admin API answers it: never its secret, only whether it has one. */
export interface ProviderInfo {
  id: string;
  kind: ProviderKind;
  /** What the sign-in dialog's button says: "Continue with <name>". */
  name: string;
  clientId: string;
  hasClientSecret: boolean;
  /** What the provider's console must list as the redirect URI (Google, OpenID Connect) or the callback URL (GitHub). */
  callbackUrl: string;
  /** Milliseconds since 1970. */
  createdAt: number;
  updatedAt: number;
  /** OpenID Connect: the issuer, whose discovery document says where the rest is. */
  issuer?: string;
  /** OpenID Connect: the scopes asked for beyond `openid email profile`. */
  scopes?: string[];
  /** OpenID Connect: whether its addresses count as verified without `email_verified`. */
  trustEmail?: boolean;
}

/** What an admin sets of a provider: `clientSecret` in plain text, `null` to remove it (Google only), left out to keep it. */
export interface ProviderChanges {
  name?: string;
  clientId?: string;
  clientSecret?: string | null;
  /** OpenID Connect: the scopes to ask for beyond `openid email profile`, separated by spaces, e.g. `'read_user'`. */
  scopes?: string;
  /**
   * OpenID Connect: whether its addresses count as verified without `email_verified` in its claims (default
   * `false`). Only for a provider whose addresses its operator verifies, e.g. the company's own.
   */
  trustEmail?: boolean;
}

/** A new provider: Google or GitHub by its kind, an OpenID Connect provider with its id, name and issuer. */
export type NewProvider = ({ kind: 'google' | 'github' } | { kind: 'oidc'; id: string; name: string; issuer: string; clientId: string; clientSecret: string }) & ProviderChanges;

/**
 * An application that signs its users in with madAuth as its OpenID Connect provider, as the admin API answers it:
 * never its secret. See "OpenID Connect provider" in docs/server.md.
 */
export interface ClientInfo {
  /** The client ID it sends (`mc_…`). */
  id: string;
  name: string;
  /** Without a secret: a native or browser app, which proves itself with PKCE alone. */
  public: boolean;
  /** Where it may be sent back to after the sign-in. */
  redirectUris: string[];
  /** Where it may be sent back to after it signed the user out. */
  postLogoutRedirectUris: string[];
  /** Whether it may sign in from a device without a browser (the device authorization grant). Absent from servers before 0.7. */
  deviceFlow?: boolean;
  /** Whether it may exchange a Google ID token it obtained itself for tokens (a native app). Absent from servers before 0.7.1. */
  tokenExchange?: boolean;
  /** The algorithm its ID tokens are signed with: `ES256`, or `RS256` for an application that can't verify ES256. Absent from servers before 0.7.2. */
  idTokenAlg?: 'ES256' | 'RS256';
  /** Milliseconds since 1970. */
  createdAt: number;
  updatedAt: number;
}

/**
 * What an admin sets of an application; left out: kept. A redirect URI is https, http on this computer
 * (`http://127.0.0.1`, `http://[::1]` or `http://localhost`, which match at any port) or an app's own scheme
 * (`vscode://…`), without a fragment.
 */
export interface ClientChanges {
  name?: string;
  redirectUris?: string[];
  postLogoutRedirectUris?: string[];
  /** Whether it may use the device authorization grant: a TV or a command-line tool shows a code the user approves (default `false`). */
  deviceFlow?: boolean;
  /** Whether it may exchange a Google ID token for madAuth's tokens, as a native app with its own Google sign-in does (default `false`). See `Madauth.tokens`. */
  tokenExchange?: boolean;
  /**
   * The algorithm of its ID tokens (OpenID Connect's `id_token_signed_response_alg`): `ES256` (default), or `RS256`
   * for an application that can't verify ES256. RS256 needs a key for it in the server's key service (`invalid_client` otherwise).
   */
  idTokenAlg?: 'ES256' | 'RS256';
}

/** A new application: its name and at least one redirect URI; `public: true` for one without a secret (default `false`). */
export type NewClient = { name: string; redirectUris: string[]; public?: boolean } & ClientChanges;

/** What `searchUsers` looks for; every filter given must match. */
export interface UserSearch {
  /** Users whose `claims.roles` hold this role. */
  role?: string;
  /** The user with this address (exact, ignoring case). */
  email?: string;
  /** Users who signed up after this time, in milliseconds since 1970. */
  signedUpAfter?: number;
  /** Users who signed up before this time. */
  signedUpBefore?: number;
  /** `true`: only pending sign-ups, whose address isn't confirmed yet; `false`: only complete ones. Default: both. */
  pending?: boolean;
  /** The most users on a page, 1 to 100. Default: 50. */
  limit?: number;
  /** The `cursor` of the previous page, for the next one. */
  cursor?: string;
}

/** A user as `searchUsers` finds them. */
export interface FoundUser {
  id: string;
  email: string;
  name: string | null;
  emailVerified: boolean;
  claims: Claims;
  /** The user's sign-in methods and second factors, e.g. `['passkey', 'password']`. */
  methods: string[];
  /** When the sign-up was complete (milliseconds since 1970); `null` while it is pending. */
  signedUpAt: number | null;
  pending: boolean;
}

/**
 * Managing claims, settings, users' API keys, sign-in providers and the applications that sign in with madAuth
 * (OpenID Connect clients), and resetting a user's sign-in, for users with the role `admin`
 * (`claims.roles`). The first admin is the user who signs in with the address in the server's
 * `INITIAL_ADMIN_EMAIL`. A change (claims, settings, providers, clients, a sign-in reset) takes a sign-in within the last
 * two minutes, else it fails with `reauth_required`; reading, and revoking a user's API key, take none.
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
  setSettings(settings: { methods?: MethodsToSet; password?: Partial<PasswordRules>; loginUrl?: string | null }): Promise<Result<Settings>>;
  /**
   * Switches one method on with `setting`, or off with `null`, leaving the others as they are: the server changes
   * its entry in the stored list, so what another admin changes meanwhile stays. Checked like `setSettings`.
   * Fails with `forbidden` or `invalid_settings`.
   */
  setMethod(method: MethodId, setting: MethodToSet | null): Promise<Result<Settings>>;
  /**
   * Resets the sign-in of the user with this e-mail address, who lost every way in or a second factor:
   * removes all their sign-in methods and second factors, ends their sessions and marks the address
   * unconfirmed. They sign up again with any method that is on and keep their id, claims and roles. Check
   * who is asking first: whoever proves the inbox next gets the account. An admin who resets themselves is
   * signed out at the next session check. Fails with `forbidden`, `invalid_email` or `user_not_found`.
   */
  resetSignIn(email: string): Promise<Result<{ userId: string }>>;
  /**
   * Deletes the user with this e-mail address for good, as if they never signed up: with all their sign-in methods,
   * claims, API keys and pending links. Their sessions end at the next session check, and the address can sign up
   * again as a new user (a new id). Your app's data under their id is your app's to delete, e.g. on `user.deleted`.
   * Not for a user with the role `admin`: another admin takes it first. Needs a recent sign-in. Fails with
   * `forbidden`, `reauth_required`, `invalid_email`, `user_not_found` or `own_admin_role`.
   */
  deleteUser(email: string): Promise<Result<{ userId: string }>>;
  /**
   * The API keys of the user with this e-mail address, e.g. to find one that leaked. Only with a session: an
   * API key never manages keys. Fails with `forbidden`, `invalid_email` or `user_not_found`.
   */
  listApiKeys(email: string): Promise<Result<{ userId: string; apiKeys: ApiKeyInfo[] }>>;
  /** Revokes an API key of the user with this e-mail address. Fails with `forbidden`, `invalid_email`, `user_not_found` or `api_key_not_found`. */
  revokeApiKey(email: string, id: string): Promise<Result<{ userId: string }>>;
  /**
   * The users that match every filter, a page at a time, in no particular order. With `cursor` there may be more:
   * pass it for the next page, which can hold fewer users than `limit`, or none, and still have a cursor; the
   * search reads at most a thousand users per call. Without filters, every user. What it finds is for showing:
   * it may be outdated by the time it is shown. Fails with `forbidden`, `invalid_email` or `invalid_search`.
   */
  searchUsers(search?: UserSearch): Promise<Result<{ users: FoundUser[]; cursor?: string }>>;
  /**
   * The sign-in providers, without their secrets. `callbackBase` gives a new provider's callback URL before it is
   * added, `<callbackBase><id>/callback`, to register at the provider (absent from servers of the first 0.7
   * betas). Fails with `forbidden`.
   */
  listProviders(): Promise<Result<{ providers: ProviderInfo[]; callbackBase?: string }>>;
  /**
   * Adds a sign-in provider: Google (its client ID; a client secret for the redirect sign-in), GitHub (its client
   * ID and secret), or an OpenID Connect provider (an id of its own, e.g. `gitlab`, which becomes its method's;
   * its name, issuer, client ID and secret). The server reads an OpenID Connect provider's discovery document
   * first, and refuses it with `invalid_provider` when that fails. A provider is off until switched on with
   * `setSettings`. Needs a sign-in within the last two minutes. Fails with `forbidden`, `reauth_required`,
   * `invalid_provider` or `provider_exists`.
   */
  addProvider(provider: NewProvider): Promise<Result<{ provider: ProviderInfo }>>;
  /**
   * Changes a provider; an OpenID Connect provider's issuer can't change (its accounts belong to it). Needs a
   * recent sign-in. Fails with `forbidden`, `reauth_required`, `invalid_provider` or `provider_not_found`.
   */
  updateProvider(id: string, changes: ProviderChanges): Promise<Result<{ provider: ProviderInfo }>>;
  /**
   * Removes a provider; needs a recent sign-in. Its users' accounts stay, so adding it again brings their sign-ins
   * back; `usersWithoutSignIn` says how many users signed in with nothing else. With `dryRun: true` it only
   * counts them, to confirm the removal with, and needs no recent sign-in. Fails with `forbidden`,
   * `reauth_required` or `provider_not_found`.
   */
  removeProvider(id: string, options?: { dryRun?: boolean }): Promise<Result<{ provider: ProviderInfo; usersWithoutSignIn: number }>>;
  /** The applications that sign in with madAuth as their OpenID Connect provider, without their secrets. Fails with `forbidden`. */
  listClients(): Promise<Result<{ clients: ClientInfo[] }>>;
  /**
   * Registers an application. `clientSecret` is its secret, which only this answer ever shows (none for a public
   * one). Needs a sign-in within the last two minutes, and no API key. Fails with `forbidden`, `reauth_required`
   * or `invalid_client`.
   */
  addClient(client: NewClient): Promise<Result<{ client: ClientInfo; clientSecret?: string }>>;
  /**
   * Changes an application; `newSecret: true` gives a confidential one a new secret, and the old one stops working at
   * once. Needs a recent sign-in. Fails with `forbidden`, `reauth_required`, `invalid_client` or `client_not_found`.
   */
  updateClient(id: string, changes: ClientChanges & { newSecret?: boolean }): Promise<Result<{ client: ClientInfo; clientSecret?: string }>>;
  /** Removes an application and ends its refresh tokens. Needs a recent sign-in. Fails with `forbidden`, `reauth_required` or `client_not_found`. */
  removeClient(id: string): Promise<Result<{ client: ClientInfo }>>;
}

export function createAdminApi(core: Core): AdminApi {
  async function call<T extends object>(path: string, body: Record<string, unknown>, pick: (data: any) => T): Promise<Result<T>> {
    const ready = await core.whenReady();
    if (!ready.isSuccess) return ready;
    const res = await core.request<unknown>(`/auth/admin/${path}`, { method: 'POST', body });
    return res.ok ? { isSuccess: true, ...pick(res.data) } : { isSuccess: false, error: res.error };
  }
  const claims = (data: { userId: string; claims: Claims }) => ({ userId: data.userId, claims: data.claims });
  const settings = (data: Settings) => ({ methods: data.methods, password: data.password, ...(data.loginUrl !== undefined ? { loginUrl: data.loginUrl } : {}) });
  const client = (data: { client: ClientInfo; clientSecret?: string }) => ({ client: data.client, ...(data.clientSecret ? { clientSecret: data.clientSecret } : {}) });

  return {
    getClaims: (email) => call('claims/get', { email }, claims),
    setClaims: (email, value) => call('claims/set', { email, claims: value }, claims),
    getSettings: () => call('settings/get', {}, settings),
    setSettings: (value) => call('settings/set', { methods: value.methods, password: value.password, loginUrl: value.loginUrl }, settings),
    setMethod: (method, setting) => call('settings/method', { method, setting }, settings),
    resetSignIn: (email) => call('sign-in/reset', { email }, (data: { userId: string }) => ({ userId: data.userId })),
    deleteUser: (email) => call('users/delete', { email }, (data: { userId: string }) => ({ userId: data.userId })),
    listApiKeys: (email) => call('api-keys/list', { email }, (data: { userId: string; apiKeys: ApiKeyInfo[] }) => ({ userId: data.userId, apiKeys: data.apiKeys })),
    revokeApiKey: (email, id) => call('api-keys/revoke', { email, id }, (data: { userId: string }) => ({ userId: data.userId })),
    searchUsers: (search = {}) =>
      call('users/search', { ...search }, (data: { users: FoundUser[]; cursor?: string }) => ({ users: data.users, ...(data.cursor ? { cursor: data.cursor } : {}) })),
    listProviders: () =>
      call('providers/list', {}, (data: { providers: ProviderInfo[]; callbackBase?: string }) => ({
        providers: data.providers,
        ...(typeof data.callbackBase === 'string' ? { callbackBase: data.callbackBase } : {}),
      })),
    addProvider: (provider) => call('providers/add', { ...provider }, (data: { provider: ProviderInfo }) => ({ provider: data.provider })),
    updateProvider: (id, changes) => call('providers/update', { id, ...changes }, (data: { provider: ProviderInfo }) => ({ provider: data.provider })),
    removeProvider: (id, options = {}) =>
      call('providers/remove', { id, ...(options.dryRun ? { dryRun: true } : {}) }, (data: { provider: ProviderInfo; usersWithoutSignIn: number }) => ({ provider: data.provider, usersWithoutSignIn: data.usersWithoutSignIn })),
    listClients: () => call('clients/list', {}, (data: { clients: ClientInfo[] }) => ({ clients: data.clients })),
    addClient: (value) => call('clients/add', { ...value }, client),
    updateClient: (id, changes) => call('clients/update', { id, ...changes }, client),
    removeClient: (id) => call('clients/remove', { id }, (data: { client: ClientInfo }) => ({ client: data.client })),
  };
}
