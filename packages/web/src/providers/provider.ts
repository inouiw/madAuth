import type { HttpResult, RequestInit } from '../http.js';
import type { LoginMethodId } from '../methods.js';
import { SECOND_FACTORS, type MadauthError, type MadauthUser, type Result, type SecondFactor } from '../result.js';

/**
 * Whether a method asks for a second factor: never, when the user has set one up (`optional`), or always, so
 * that a user without one sets it up at the next sign-in (`required`).
 */
export type SecondFactorPolicy = 'none' | 'optional' | 'required';

/** Public settings from the server's `GET /auth/config`; a method is null when the server doesn't offer it. */
export interface ServerConfig {
  google: { clientId: string; codeFlow: boolean; secondFactor: SecondFactorPolicy } | null;
  /** GitHub sign-in (the redirect flow), with its policy for the second factor. */
  github: { secondFactor: SecondFactorPolicy } | null;
  /** `minLength` and `minScore`: the rules for new passwords, see `Madauth.password.policy`. */
  password: { minLength: number; minScore: number; secondFactor: SecondFactorPolicy } | null;
  /**
   * The authenticator app, when it is in use at all: `signIn` says whether it signs in on its own (the e-mail
   * address and a code), `signUp` whether people can sign up with it alone.
   */
  authenticator: { signIn: boolean; signUp: boolean } | null;
  /** Whether the server confirms addresses by e-mail (sign-ups with a password, the authenticator app or a passkey). */
  email: { verification: boolean };
  /** The passwordless e-mail link, with its policy for the authenticator app as a second factor. */
  emailLink: { secondFactor: SecondFactorPolicy } | null;
  /** Whether SMS codes are on as a second factor: a signed-in user can add a phone, and a sign-in can ask for a code sent to it. */
  sms: boolean;
  /**
   * Passkeys, when they are on: a signed-in user can add them, and they are a second factor of the methods
   * that ask for one. `signIn` says whether they sign in on their own, `signUp` whether people can sign up
   * with one alone, `secondFactor` whether such a sign-in then asks for a second factor. Absent from servers
   * before madAuth 0.6.
   */
  passkey?: { signIn: boolean; signUp: boolean; secondFactor: SecondFactorPolicy } | null;
}

/** What a sign-in still needs after its first step, and which sign-in it is. */
export interface PendingStep {
  /**
   * `passkey`: a passkey of the user; `code`: a code from the authenticator app; `sms`: a code sent to the
   * user's phone; `setup`: a second factor has to be set up first.
   */
  step: 'passkey' | 'code' | 'setup' | 'sms';
  method: LoginMethodId;
  /**
   * With `passkey`, `code` and `sms`: the second factors the user can finish with, so a screen can offer the
   * switch. With `setup`: those the user can set up (a server before madAuth 0.6 names none: the app, or a phone).
   */
  factors?: SecondFactor[];
}

const STEPS: Partial<Record<string, PendingStep['step']>> = {
  passkey_required: 'passkey',
  authenticator_required: 'code',
  sms_required: 'sms',
  second_factor_setup_required: 'setup',
  // A sign-up with the app or a passkey alone: the method it signs up with is set up next, as a second factor would be.
  authenticator_setup_required: 'setup',
  passkey_setup_required: 'setup',
};

/** The step that asks for each factor. */
export const FACTOR_STEPS: Record<SecondFactor, Exclude<PendingStep['step'], 'setup'>> = { passkey: 'passkey', authenticator: 'code', sms: 'sms' };

/**
 * The step an error stands for: `passkey_required`, `authenticator_required`, `sms_required`, or a setup
 * (`second_factor_setup_required`, `authenticator_setup_required`, `passkey_setup_required`); undefined for
 * any other.
 */
export function secondStepOf(error: MadauthError): PendingStep['step'] | undefined {
  return STEPS[error.code];
}

/** The pending step a second-step error stands for, with the factors it names; undefined for any other error. */
export function pendingStepOf(error: MadauthError, method: LoginMethodId): PendingStep | undefined {
  const step = secondStepOf(error);
  if (!step) return undefined;
  // The passkey of a sign-up with one is its only factor, also when the answer doesn't name it.
  if (error.code === 'passkey_setup_required') return { step, method, factors: ['passkey'] };
  if (step === 'setup') return error.factors?.length ? { step, method, factors: error.factors } : { step, method };
  const factor = SECOND_FACTORS.find((f) => FACTOR_STEPS[f] === step)!;
  return { step, method, factors: error.factors?.length ? error.factors : [factor] };
}

/** What the madAuth core gives a provider during setup. */
export interface ProviderContext {
  readonly serverUrl: string;
  readonly config: ServerConfig;
  readonly currentUser: MadauthUser | null;
  /** A sign-in waits for its second step (a code, or a setup): no automatic prompt meanwhile. */
  readonly signInPending: boolean;
  /** The locale of the texts shown to the user: the configured one, else the page's, else the browser's. */
  readonly locale: string | undefined;
  /** Calls `listener` when the locale changes. Returns a function that unsubscribes. */
  onLocaleChanged(listener: () => void): () => void;
  request<T>(path: string, init?: RequestInit): Promise<HttpResult<T>>;
  /** A sign-in succeeded (also when it happened outside the dialog, e.g. One Tap). */
  signedIn(user: MadauthUser): void;
  /**
   * A sign-in failed outside the dialog (e.g. after the redirect flow): with `ui: 'dialog'` and nobody signed
   * in, the dialog opens by itself and shows it; otherwise it is shown the next time the dialog opens. A
   * `passkey_required`, `authenticator_required`, `sms_required`, `second_factor_setup_required`,
   * `authenticator_setup_required` or `passkey_setup_required` error is not a failure: the sign-in goes on with
   * its next step, see {@link signInContinues}.
   */
  signInFailed(error: MadauthError): void;
  /** A sign-in outside the dialog needs its second step next: the dialog opens on that step. */
  signInContinues(pending: PendingStep): void;
}

export interface ButtonOptions {
  theme: 'light' | 'dark';
  /** `link`: the button adds the provider to the signed-in user's methods instead of signing in. */
  purpose?: 'signin' | 'link';
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
  /** The signed-in user deleted their account (called after {@link onSignedOut}). */
  onAccountDeleted?(account: DeletedAccount): void;
}

/** What the server reports about an account it deleted. */
export interface DeletedAccount {
  /** The `sub` of the Google account that was linked to the user, if any. */
  googleSub?: string;
}
