import type { HttpResult, RequestInit } from '../http.js';
import type { LoginMethodId } from '../methods.js';
import type { MadauthError, MadauthUser, Result } from '../result.js';

/** Public settings from the server's `GET /auth/config`. */
export interface ServerConfig {
  google: { clientId: string; codeFlow: boolean };
}

/** What the madAuth core gives a provider during setup. */
export interface ProviderContext {
  readonly serverUrl: string;
  readonly config: ServerConfig;
  readonly currentUser: MadauthUser | null;
  request<T>(path: string, init?: RequestInit): Promise<HttpResult<T>>;
  /** A sign-in succeeded (also when it happened outside the dialog, e.g. One Tap). */
  signedIn(user: MadauthUser): void;
  /** A sign-in failed outside the dialog (e.g. after the redirect flow); shown the next time the dialog opens. */
  signInFailed(error: MadauthError): void;
}

/**
 * A sign-in method implementation, e.g. {@link GoogleFedcm} or {@link GoogleRedirect}.
 * Pass providers to `Madauth.initialize`; their members are internal to madAuth.
 */
export interface SignInProvider {
  readonly method: LoginMethodId;
  /** Called by `Madauth.initialize`. A failure makes `initialize` fail. */
  setup(ctx: ProviderContext): Promise<Result>;
  /** Renders the provider's own sign-in UI into the dialog. Returns a cleanup function. */
  renderInDialog?(container: HTMLElement, onResult: (result: Result<{ user: MadauthUser }>) => void): () => void;
  /** Starts a sign-in from the dialog's built-in button (used when there is no `renderInDialog`). */
  start?(): void;
  onSignedOut?(): void;
}
