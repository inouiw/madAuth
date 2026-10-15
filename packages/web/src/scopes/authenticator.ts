import { Authenticator } from '../providers/authenticator.js';
import type { PendingStep } from '../providers/provider.js';
import { qrSvg } from '../qr.js';
import { fail, ok, type MadauthUser, type Result } from '../result.js';
import { serverCalls, type Core } from './core.js';
import { currentPage, emailConfirmation, signedIn, type SendEmailOptions } from './email.js';

/** A code from the authenticator app, or one of the recovery codes. */
export type CodeOptions = { code: string } | { recoveryCode: string };

export type SignInWithAuthenticatorOptions = { email: string } & CodeOptions;

export interface AuthenticatorSignUpOptions {
  email: string;
  /** Shown to the user and in `MadauthUser.name`. */
  name?: string;
  /** The page the link in the e-mail opens. Default: the current page. Its origin must be in ALLOWED_ORIGINS. */
  redirectTo?: string;
}

/** A new key for the authenticator app, from {@link AuthenticatorApi.startSetup}. */
export interface AuthenticatorSetup {
  /** The key in base32, to type into the app when the QR code can't be scanned. */
  secret: string;
  /** The `otpauth://totp/...` URI the QR code contains. */
  uri: string;
  /**
   * The QR code of `uri` as an SVG (`<svg …>…</svg>`): the dark modules in `currentColor`, no background.
   * Put it in the page with `innerHTML`, dark on a light background, and size it with CSS.
   */
  qrSvg: string;
}

/** What `startSetup` and the dialog tell the user the app will do, from the server's policy. */
export interface AuthenticatorPolicy {
  /** The app signs in on its own: the e-mail address and a code. */
  signIn: boolean;
  /** People can sign up with the app alone. */
  signUp: boolean;
  /** The methods that ask for a second factor once one is set up (`optional`) or always (`required`). */
  secondFactorFor: ('google' | 'github' | 'password' | 'email-link' | 'passkey')[];
}

/**
 * The authenticator app (TOTP) for custom login screens. The methods work whenever the server has the app
 * switched on (a policy asks for it, or it signs in on its own); otherwise they fail with `flow_not_enabled`.
 * Signing in or up with the app alone ({@link signIn}, {@link signUp}) also needs `new Authenticator()` in
 * `Madauth.initialize`.
 */
export interface AuthenticatorApi {
  /**
   * Signs in with the e-mail address and a code from the app (or a recovery code), when the server lets
   * the app sign in on its own. Fails with `invalid_credentials` (an unknown address, one without an app,
   * or a wrong code: all the same), `too_many_attempts` or `method_disabled`.
   */
  signIn(options: SignInWithAuthenticatorOptions): Promise<Result<{ user: MadauthUser }>>;
  /**
   * Finishes a sign-in that `password.signIn`, `verifyEmail`, `confirmReset`, Google or GitHub ended with
   * `authenticator_required`: the code from the app, or a recovery code. Fails with `code_invalid`,
   * `too_many_attempts` or `challenge_expired` (more than ten minutes passed: sign in again).
   */
  verify(options: CodeOptions): Promise<Result<{ user: MadauthUser }>>;
  /**
   * Starts setting the app up, for the signed-in user or for a sign-in that ended with
   * `second_factor_setup_required` or `authenticator_setup_required`: a new key to scan or type into the app.
   * Confirm it within ten minutes with {@link confirmSetup}. A user who has an app already gives a current code
   * from it (or a recovery code) in `options`, since the new app replaces it; without one it fails with
   * `code_required`, with a wrong one with `code_invalid`. Fails with `no_session`.
   */
  startSetup(options?: CodeOptions): Promise<Result<AuthenticatorSetup>>;
  /**
   * Proves the setup with the first code the app shows and turns the app on; a new app replaces an earlier
   * one. Resolves with the recovery codes, to show once, and with the user when this finished a sign-in.
   * Fails with `code_invalid`, `setup_expired` (start again) or `no_session`.
   */
  confirmSetup(options: { code: string }): Promise<Result<{ recoveryCodes: string[]; user?: MadauthUser }>>;
  /**
   * Turns the signed-in user's app off, with a current code from it or a recovery code. Fails with
   * `code_invalid`, `required_by_policy` (a method requires the app, so nobody can remove it), `only_method`
   * (the app is the user's only way to sign in; they can delete the account instead) or `no_session`.
   */
  remove(options: CodeOptions): Promise<Result>;
  /** New recovery codes for the signed-in user, with a current code; the old ones stop working. Fails with `code_invalid`, `no_authenticator` or `no_session`. */
  newRecoveryCodes(options: CodeOptions): Promise<Result<{ recoveryCodes: string[] }>>;
  /** Whether the signed-in user has an app, and how many recovery codes are left. Fails with `no_session`. */
  status(): Promise<Result<{ enabled: boolean; recoveryCodesLeft: number }>>;
  /**
   * Creates an account that signs in with the app alone (no password) and sends an e-mail with a link
   * and a code to confirm the address; confirming leads to the setup (`authenticator_setup_required`). Succeeds
   * even if the address is registered, so nobody can probe for accounts. Fails with `invalid_email`,
   * `signup_rejected`, `temporarily_unavailable` or `method_disabled`.
   */
  signUp(options: AuthenticatorSignUpOptions): Promise<Result>;
  /** Sends the confirmation e-mail again. Fails with `temporarily_unavailable`. */
  sendVerificationEmail(options: SendEmailOptions): Promise<Result>;
  /**
   * Confirms the address with the code from the e-mail. For a sign-up with the app it fails with
   * `authenticator_setup_required`: call {@link startSetup} and {@link confirmSetup} next.
   */
  verifyEmail(options: { email: string; code: string }): Promise<Result<{ user: MadauthUser }>>;
  /**
   * What a sign-in under way still needs: `code` (call {@link verify}) or `setup` (the setup pair), and which
   * method's sign-in it is. Set when a sign-in ends with `authenticator_required`,
   * `second_factor_setup_required` or `authenticator_setup_required`, also by the redirect flow or an e-mail
   * link; null otherwise.
   */
  readonly pendingStep: PendingStep | null;
  /** What the app does on this server, for the texts of your setup screen; null until initialized. */
  readonly policy: AuthenticatorPolicy | null;
}

const notRegistered = () => fail('flow_not_enabled', 'Pass new Authenticator() to Madauth.initialize to sign in or up with the authenticator app alone.');
const switchedOff = () =>
  fail('flow_not_enabled', 'The madAuth server has the authenticator app switched off: no sign-in method is set to ask for it, and it does not sign in on its own.');

export function createAuthenticatorApi(core: Core): AuthenticatorApi {
  /** The app as a method of its own is what the provider adds; the second step and the account calls need none. */
  const registered = () => core.provider('authenticator') instanceof Authenticator;

  const call = serverCalls(core, { isOn: (config) => !!config?.authenticator, switchedOff });

  const post = <T extends object>(path: string, body: Record<string, unknown>) => call<T>(path, { body });
  const confirmation = emailConfirmation(core, 'authenticator', post);

  return {
    async signIn(options) {
      if (!registered()) return notRegistered();
      return signedIn(core, 'authenticator', await post('/auth/authenticator/signin', { ...options }));
    },

    async verify(options) {
      const result = await post<{ user: MadauthUser }>('/auth/authenticator/verify', { ...options });
      if (!result.isSuccess) return result;
      core.signedIn(result.user);
      return { isSuccess: true, user: result.user };
    },

    async startSetup(options) {
      const result = await call<{ secret: string; uri: string }>('/auth/authenticator/setup', { body: { ...options }, session: true });
      return result.isSuccess ? ok({ secret: result.secret, uri: result.uri, qrSvg: qrSvg(result.uri) }) : result;
    },

    async confirmSetup({ code }) {
      const result = await call<{ recoveryCodes: string[]; user?: MadauthUser }>('/auth/authenticator/confirm', { body: { code }, session: true });
      if (!result.isSuccess) return result;
      if (result.user) core.signedIn(result.user);
      return ok(result.user ? { recoveryCodes: result.recoveryCodes, user: result.user } : { recoveryCodes: result.recoveryCodes });
    },

    async remove(options) {
      const result = await call('/auth/authenticator/remove', { body: { ...options }, session: true });
      return result.isSuccess ? ok() : result;
    },

    async newRecoveryCodes(options) {
      const result = await call<{ recoveryCodes: string[] }>('/auth/authenticator/recovery-codes', { body: { ...options }, session: true });
      return result.isSuccess ? ok({ recoveryCodes: result.recoveryCodes }) : result;
    },

    async status() {
      const result = await call<{ enabled: boolean; recoveryCodesLeft: number }>('/auth/authenticator/status', { method: 'GET', session: true });
      return result.isSuccess ? ok({ enabled: result.enabled, recoveryCodesLeft: result.recoveryCodesLeft }) : result;
    },

    async signUp({ email, name, redirectTo }) {
      if (!registered()) return notRegistered();
      const result = await post('/auth/authenticator/signup', { email, name, redirectTo: redirectTo ?? currentPage(), locale: core.locale() });
      return result.isSuccess ? ok() : result;
    },

    sendVerificationEmail: confirmation.sendVerificationEmail,
    verifyEmail: confirmation.verifyEmail,

    get pendingStep() {
      return core.pendingStep();
    },

    get policy() {
      const config = core.config();
      if (!config?.authenticator) return null;
      const secondFactorFor: AuthenticatorPolicy['secondFactorFor'] = [];
      if (config.google && config.google.secondFactor !== 'none') secondFactorFor.push('google');
      if (config.github && config.github.secondFactor !== 'none') secondFactorFor.push('github');
      if (config.password && config.password.secondFactor !== 'none') secondFactorFor.push('password');
      if (config.emailLink && config.emailLink.secondFactor !== 'none') secondFactorFor.push('email-link');
      if (config.passkey?.signIn && config.passkey.secondFactor !== 'none') secondFactorFor.push('passkey');
      return { signIn: config.authenticator.signIn, signUp: config.authenticator.signUp, secondFactorFor };
    },
  };
}
