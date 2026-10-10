import type { HttpResult, RequestInit } from '../http.js';
import type { LoginMethodId } from '../methods.js';
import type { MadauthError, MadauthUser, Result } from '../result.js';

/**
 * Whether a method asks for the authenticator app as a second factor: never, when the user has set one up
 * (`optional`), or always, so that a user without one sets it up at the next sign-in (`required`).
 */
export type SecondFactorPolicy = 'none' | 'optional' | 'required';

/** Public settings from the server's `GET /auth/config`; a method is null when the server doesn't offer it. */
export interface ServerConfig {
  google: { clientId: string; codeFlow: boolean; secondFactor: SecondFactorPolicy } | null;
  password: { minLength: number; secondFactor: SecondFactorPolicy } | null;
  /**
   * The authenticator app, when it is in use at all: `signIn` says whether it signs in on its own (the e-mail
   * address and a code), `signUp` whether people can sign up with it alone.
   */
  totp: { signIn: boolean; signUp: boolean } | null;
  /** Whether the server confirms addresses by e-mail (sign-ups with a password or the authenticator app). */
  email: { verification: boolean };
}

/** What a sign-in still needs after its first step, and which sign-in it is. */
export interface PendingStep {
  /** `code`: a code from the authenticator app; `setup`: the app has to be set up first. */
  step: 'code' | 'setup';
  method: LoginMethodId;
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
  /**
   * A sign-in failed outside the dialog (e.g. after the redirect flow); shown the next time the dialog opens.
   * A `totp_required` or `totp_setup_required` error is not a failure: the sign-in goes on with the
   * authenticator app, see {@link signInContinues}.
   */
  signInFailed(error: MadauthError): void;
  /** A sign-in outside the dialog needs the authenticator app next: the dialog opens on that step. */
  signInContinues(pending: PendingStep): void;
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
