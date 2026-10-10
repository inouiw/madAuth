import type { HttpResult, RequestInit } from '../http.js';
import type { LoginMethodId } from '../methods.js';
import type { PendingStep, ServerConfig, SignInProvider } from '../providers/provider.js';
import type { MadauthUser, Result } from '../result.js';

/** What the method scopes (`Madauth.password`, `Madauth.google`, `Madauth.totp`) need from the madAuth core. */
export interface Core {
  /** Whether `initialize` was called. */
  isConfigured(): boolean;
  /** Resolves when `initialize` is done, or with why madAuth is not usable. */
  whenReady(): Promise<Result>;
  provider(method: LoginMethodId): SignInProvider | undefined;
  /** The server's public settings, once `initialize` has fetched them. */
  config(): ServerConfig | undefined;
  /**
   * The user's locale, so the webhook can send the e-mail in it: the one from `initialize` or `setLocale`,
   * else the page's, else the browser's.
   */
  locale(): string | undefined;
  request<T>(path: string, init?: RequestInit): Promise<HttpResult<T>>;
  signedIn(user: MadauthUser): void;
  /** What a sign-in still needs with the authenticator app, if one is under way. */
  pendingStep(): PendingStep | null;
  /** A sign-in's first step is done and the authenticator app is next, or (null) the sign-in is over. */
  setPendingStep(pending: PendingStep | null): void;
}
