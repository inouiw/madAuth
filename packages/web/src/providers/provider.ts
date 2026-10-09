import type { HttpResult, RequestInit } from '../http.js';
import type { LoginMethodId } from '../methods.js';
import type { MadauthError, MadauthUser, Result } from '../result.js';

/** Public settings from the server's `GET /auth/config`; a method is null when the server doesn't offer it. */
export interface ServerConfig {
  google: { clientId: string; codeFlow: boolean } | null;
  password: { minLength: number } | null;
}

/** What the madAuth core gives a provider during setup. */
export interface ProviderContext {
  readonly serverUrl: string;
  readonly config: ServerConfig;
  readonly currentUser: MadauthUser | null;
  /** The locale of the texts shown to the user: the configured one, else the page's, else the browser's. */
  readonly locale: string | undefined;
  /** Calls `listener` when the locale changes. Returns a function that unsubscribes. */
  onLocaleChanged(listener: () => void): () => void;
  request<T>(path: string, init?: RequestInit): Promise<HttpResult<T>>;
  /** A sign-in succeeded (also when it happened outside the dialog, e.g. One Tap). */
  signedIn(user: MadauthUser): void;
  /** A sign-in failed outside the dialog (e.g. after the redirect flow); shown the next time the dialog opens. */
  signInFailed(error: MadauthError): void;
}

export interface ButtonOptions {
  theme: 'light' | 'dark';
  onResult(result: Result<{ user: MadauthUser }>): void;
}

/**
 * A sign-in method implementation, e.g. {@link GoogleFedcm} or {@link Password}.
 * Pass providers to `Madauth.initialize`; their members are internal to madAuth.
 */
export interface SignInProvider {
  readonly method: LoginMethodId;
  /**
   * Called by `Madauth.initialize`. A failure makes `initialize` fail — except `flow_not_enabled` (the
   * server doesn't offer the method), which leaves the provider out and lets the others work.
   */
  setup(ctx: ProviderContext): Promise<Result>;
  /** Renders the provider's sign-in button into `container`. Returns a function that removes it. */
  renderButton?(container: HTMLElement, options: ButtonOptions): () => void;
  /** Someone signed in, with this or another method. */
  onSignedIn?(): void;
  onSignedOut?(): void;
}
