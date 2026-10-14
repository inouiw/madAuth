import type { HttpResult, RequestInit } from '../http.js';
import type { LoginMethodId } from '../methods.js';
import type { PendingStep, ServerConfig, SignInProvider } from '../providers/provider.js';
import { fail, ok, type MadauthError, type MadauthUser, type Result } from '../result.js';

/** What the method scopes (`Madauth.password`, `Madauth.google`, `Madauth.authenticator`) need from the madAuth core. */
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

/** A request of {@link serverCalls}. */
export interface CallInit {
  method?: 'GET' | 'POST';
  body?: Record<string, unknown>;
  /** For the signed-in user: the server's 401 `no_session` means that nobody is signed in. */
  session?: boolean;
}

/** Whether the server has a scope's method on, and the failure when it hasn't. */
interface Gate {
  isOn(config: ServerConfig | undefined): boolean;
  switchedOff(): { isSuccess: false; error: MadauthError };
}

/** A scope's calls to the server: each waits for initialize, checks `gate`, then sends the request (`POST` unless said). */
export function serverCalls(core: Core, gate?: Gate) {
  return async <T extends object>(path: string, init: CallInit = {}): Promise<Result<T>> => {
    const ready = await core.whenReady();
    if (!ready.isSuccess) return ready;
    if (gate && !gate.isOn(core.config())) return gate.switchedOff();
    const res = await core.request<T>(path, { method: init.method ?? 'POST', body: init.body });
    if (res.ok) return ok(res.data);
    if (init.session && res.status === 401 && res.error.code === 'no_session') return fail('no_session', 'Nobody is signed in.');
    return { isSuccess: false, error: res.error };
  };
}
