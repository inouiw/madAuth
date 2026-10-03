import type { HttpResult, RequestInit } from '../http.js';
import type { LoginMethodId } from '../methods.js';
import type { ServerConfig, SignInProvider } from '../providers/provider.js';
import type { MadauthUser, Result } from '../result.js';

/** What the method scopes (`Madauth.password`, `Madauth.google`) need from the madAuth core. */
export interface Core {
  /** Whether `initialize` was called. */
  isConfigured(): boolean;
  /** Resolves when `initialize` is done, or with why madAuth is not usable. */
  whenReady(): Promise<Result>;
  provider(method: LoginMethodId): SignInProvider | undefined;
  /** The server's public settings, once `initialize` has fetched them. */
  config(): ServerConfig | undefined;
  request<T>(path: string, init?: RequestInit): Promise<HttpResult<T>>;
  signedIn(user: MadauthUser): void;
}
