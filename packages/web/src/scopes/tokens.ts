import { toErrorCode, type MadauthError, type Result } from '../result.js';
import type { Core } from './core.js';

/** The tokens madAuth's OpenID Connect provider issues a client, see "OpenID Connect provider" in docs/server.md. */
export interface TokenSet {
  /** A JWT (`at+jwt`) for the app's own backend, valid `expiresIn` seconds. */
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  /** With the scope `openid`. */
  idToken?: string;
  /** With the scope `offline_access`: keep it in the Keychain or Keystore, and renew with `refresh`. */
  refreshToken?: string;
  scope: string;
}

/**
 * Tokens instead of cookies, for a native app (Capacitor, say) that signs in with a Google ID token it obtained
 * itself: a WebView gets no cookies from the madAuth server, so the app is a registered application of madAuth's
 * OpenID Connect provider and exchanges the Google token for madAuth's own (RFC 8693). An admin allows it with
 * `tokenExchange: true` on the application. See "Native apps" in docs/server.md.
 */
export interface TokensApi {
  /**
   * The nonce for Google's sign-in (the plugin's `nonce` option) and the server's Google client ID the token must
   * be issued for. A nonce works five minutes. Fails with `unauthorized_client` (the application may not exchange
   * tokens) or `invalid_request` (Google sign-in is off).
   */
  nonce(options: { clientId: string }): Promise<Result<{ nonce: string; googleClientId: string; expiresIn: number }>>;
  /**
   * Signs the user in with the Google ID token (`credential`) and resolves with the application's tokens: an ID
   * token with the scope `openid`, a refresh token with `offline_access` (default scope: `openid email profile
   * offline_access`). The user is created when new. Fails with `invalid_grant` (the token, its nonce or its
   * address; `message` says what), `interaction_required` (the sign-in needs a second factor or a setup, which the
   * app finishes through the authorization endpoint in the system browser), `unauthorized_client` or
   * `temporarily_unavailable`.
   */
  exchange(options: { clientId: string; credential: string; scope?: string; locale?: string }): Promise<Result<TokenSet>>;
  /** New tokens for a refresh token, which stops working: keep the new one. Fails with `invalid_grant` when it ended. */
  refresh(options: { clientId: string; refreshToken: string; scope?: string }): Promise<Result<TokenSet>>;
}

const DEFAULT_SCOPE = 'openid email profile offline_access';

export function createTokensApi(core: Core): TokensApi {
  /** A call to the OpenID Connect provider: form-encoded, without cookies, answered as OAuth answers. */
  async function call<T extends object>(path: string, params: Record<string, string | undefined>): Promise<Result<T>> {
    const ready = await core.whenReady();
    if (!ready.isSuccess) return ready;
    const body = new URLSearchParams(Object.entries(params).filter((entry): entry is [string, string] => entry[1] !== undefined));
    let response: Response;
    try {
      response = await fetch(`${core.serverUrl()}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    } catch (e) {
      return { isSuccess: false, error: { code: 'network', message: `Could not reach the madAuth server: ${(e as Error).message}` } };
    }
    const data = (await response.json().catch(() => undefined)) as (T & { error?: unknown; error_description?: unknown; factors?: unknown }) | undefined;
    if (response.ok && data) return { isSuccess: true, ...(data as T) };
    const message = typeof data?.error_description === 'string' ? data.error_description : `${path} failed with HTTP ${response.status}`;
    const factors = Array.isArray(data?.factors) ? { factors: data.factors as MadauthError['factors'] } : {};
    return { isSuccess: false, error: { code: toErrorCode(data?.error), message, ...factors } };
  }
  const tokenSet = (data: { access_token: string; token_type: 'Bearer'; expires_in: number; id_token?: string; refresh_token?: string; scope: string }): TokenSet => ({
    accessToken: data.access_token,
    tokenType: data.token_type,
    expiresIn: data.expires_in,
    ...(data.id_token ? { idToken: data.id_token } : {}),
    ...(data.refresh_token ? { refreshToken: data.refresh_token } : {}),
    scope: data.scope,
  });
  type Raw = Parameters<typeof tokenSet>[0];

  return {
    async nonce({ clientId }) {
      const result = await call<{ nonce: string; google_client_id: string; expires_in: number }>('/auth/oidc/nonce', { client_id: clientId });
      return result.isSuccess ? { isSuccess: true, nonce: result.nonce, googleClientId: result.google_client_id, expiresIn: result.expires_in } : result;
    },
    async exchange({ clientId, credential, scope = DEFAULT_SCOPE, locale }) {
      const result = await call<Raw>('/auth/oidc/token', {
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        client_id: clientId,
        subject_token: credential,
        subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
        scope,
        locale: locale ?? core.locale(),
      });
      return result.isSuccess ? { isSuccess: true, ...tokenSet(result) } : result;
    },
    async refresh({ clientId, refreshToken, scope }) {
      const result = await call<Raw>('/auth/oidc/token', { grant_type: 'refresh_token', client_id: clientId, refresh_token: refreshToken, scope });
      return result.isSuccess ? { isSuccess: true, ...tokenSet(result) } : result;
    },
  };
}
