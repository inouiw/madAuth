import type { PendingStep } from '../providers/provider.js';
import { Totp } from '../providers/totp.js';
import { qrSvg } from '../qr.js';
import { fail, ok, type MadauthUser, type Result } from '../result.js';
import type { Core } from './core.js';
import { currentPage, emailConfirmation, signedIn, type SendEmailOptions } from './email.js';

/** A code from the authenticator app, or one of the recovery codes. */
export type CodeOptions = { code: string } | { recoveryCode: string };

export type SignInWithTotpOptions = { email: string } & CodeOptions;

export interface TotpSignUpOptions {
  email: string;
  /** Shown to the user and in `MadauthUser.name`. */
  name?: string;
  /** The page the link in the e-mail opens. Default: the current page. Its origin must be in ALLOWED_ORIGINS. */
  redirectTo?: string;
}

/** A new key for the authenticator app, from {@link TotpApi.startSetup}. */
export interface TotpSetup {
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
export interface TotpPolicy {
  /** The app signs in on its own: the e-mail address and a code. */
  signIn: boolean;
  /** People can sign up with the app alone. */
  signUp: boolean;
  /** The methods that ask for a code from the app once it is set up (`optional`) or always (`required`). */
  secondFactorFor: ('google' | 'password')[];
}

/**
 * The authenticator app (TOTP) for custom login screens. Needs `new Totp()` in `Madauth.initialize`; without
 * it, or when the server has the app switched off, every method fails with `flow_not_enabled`.
 */
export interface TotpApi {
  /**
   * Signs in with the e-mail address and a code from the app (or a recovery code), when the server lets
   * the app sign in on its own. Fails with `invalid_credentials` (an unknown address, one without an app,
   * or a wrong code: all the same), `too_many_attempts` or `method_disabled`.
   */
  signIn(options: SignInWithTotpOptions): Promise<Result<{ user: MadauthUser }>>;
  /**
   * Finishes a sign-in that `password.signIn`, `verifyEmail`, `confirmReset` or Google ended with
   * `totp_required`: the code from the app, or a recovery code. Fails with `code_invalid`,
   * `too_many_attempts` or `challenge_expired` (more than ten minutes passed: sign in again).
   */
  verify(options: CodeOptions): Promise<Result<{ user: MadauthUser }>>;
  /**
   * Starts setting the app up, for the signed-in user or for a sign-in that ended with
   * `totp_setup_required`: a new key to scan or type into the app. Confirm it within ten minutes with
   * {@link confirmSetup}. Fails with `no_session`.
   */
  startSetup(): Promise<Result<TotpSetup>>;
  /**
   * Proves the setup with the first code the app shows and turns the app on; a new app replaces an earlier
   * one. Resolves with the recovery codes, to show once, and with the user when this finished a sign-in.
   * Fails with `code_invalid`, `setup_expired` (start again) or `no_session`.
   */
  confirmSetup(options: { code: string }): Promise<Result<{ recoveryCodes: string[]; user?: MadauthUser }>>;
  /**
   * Turns the signed-in user's app off, with a current code from it or a recovery code. Fails with
   * `code_invalid`, `required_by_policy` (a method requires the app, so nobody can remove it) or `no_session`.
   */
  remove(options: CodeOptions): Promise<Result>;
  /** New recovery codes for the signed-in user, with a current code; the old ones stop working. Fails with `code_invalid`, `no_authenticator` or `no_session`. */
  newRecoveryCodes(options: CodeOptions): Promise<Result<{ recoveryCodes: string[] }>>;
  /** Whether the signed-in user has an app, and how many recovery codes are left. Fails with `no_session`. */
  status(): Promise<Result<{ enabled: boolean; recoveryCodesLeft: number }>>;
  /**
   * Creates an account that signs in with the app alone (no password) and sends an e-mail with a link
   * and a code to confirm the address; confirming leads to the setup (`totp_setup_required`). Succeeds
   * even if the address is registered, so nobody can probe for accounts. Fails with `invalid_email`,
   * `signup_rejected`, `temporarily_unavailable` or `method_disabled`.
   */
  signUp(options: TotpSignUpOptions): Promise<Result>;
  /** Sends the confirmation e-mail again. Fails with `temporarily_unavailable`. */
  sendVerificationEmail(options: SendEmailOptions): Promise<Result>;
  /**
   * Confirms the address with the code from the e-mail. For a sign-up with the app it fails with
   * `totp_setup_required`: call {@link startSetup} and {@link confirmSetup} next.
   */
  verifyEmail(options: { email: string; code: string }): Promise<Result<{ user: MadauthUser }>>;
  /**
   * What a sign-in under way still needs: `code` (call {@link verify}) or `setup` (the setup pair), and
   * which method's sign-in it is. Set when a sign-in ends with `totp_required` or `totp_setup_required`,
   * also by the redirect flow or an e-mail link; null otherwise.
   */
  readonly pendingStep: PendingStep | null;
  /** What the app does on this server, for the texts of your setup screen; null until initialized. */
  readonly policy: TotpPolicy | null;
}

const notRegistered = () => fail('flow_not_enabled', 'Pass new Totp() to Madauth.initialize to use Madauth.totp.');

export function createTotpApi(core: Core): TotpApi {
  const registered = () => core.provider('totp') instanceof Totp;

  /**
   * Waits for initialize, checks that the Totp provider is registered, then calls the server. With
   * `session`, a 401 means that nobody is signed in.
   */
  async function call<T extends object>(
    path: string,
    init: { method?: 'GET' | 'POST'; body?: Record<string, unknown>; session?: boolean } = {},
  ): Promise<Result<T>> {
    const ready = await core.whenReady();
    if (!ready.isSuccess) return ready;
    if (!registered()) return notRegistered();
    const res = await core.request<T>(path, { method: init.method ?? 'POST', body: init.body });
    if (res.ok) return ok(res.data);
    if (init.session && res.status === 401 && res.error.code === 'no_session') return fail('no_session', 'Nobody is signed in.');
    return { isSuccess: false, error: res.error };
  }

  const post = <T extends object>(path: string, body: Record<string, unknown>) => call<T>(path, { body });
  const confirmation = emailConfirmation(core, 'totp', post);

  return {
    async signIn(options) {
      const result = signedIn(core, 'totp', await post('/auth/totp/signin', { ...options }));
      if (result.isSuccess) core.setPendingStep(null);
      return result;
    },

    async verify(options) {
      const result = await post<{ user: MadauthUser }>('/auth/totp/verify', { ...options });
      if (!result.isSuccess) return result;
      core.setPendingStep(null);
      core.signedIn(result.user);
      return { isSuccess: true, user: result.user };
    },

    async startSetup() {
      const result = await call<{ secret: string; uri: string }>('/auth/totp/setup', { body: {}, session: true });
      return result.isSuccess ? ok({ secret: result.secret, uri: result.uri, qrSvg: qrSvg(result.uri) }) : result;
    },

    async confirmSetup({ code }) {
      const result = await call<{ recoveryCodes: string[]; user?: MadauthUser }>('/auth/totp/confirm', { body: { code }, session: true });
      if (!result.isSuccess) return result;
      if (result.user) {
        core.setPendingStep(null);
        core.signedIn(result.user);
      }
      return ok(result.user ? { recoveryCodes: result.recoveryCodes, user: result.user } : { recoveryCodes: result.recoveryCodes });
    },

    async remove(options) {
      const result = await call('/auth/totp/remove', { body: { ...options }, session: true });
      return result.isSuccess ? ok() : result;
    },

    async newRecoveryCodes(options) {
      const result = await call<{ recoveryCodes: string[] }>('/auth/totp/recovery-codes', { body: { ...options }, session: true });
      return result.isSuccess ? ok({ recoveryCodes: result.recoveryCodes }) : result;
    },

    async status() {
      const result = await call<{ enabled: boolean; recoveryCodesLeft: number }>('/auth/totp/status', { method: 'GET', session: true });
      return result.isSuccess ? ok({ enabled: result.enabled, recoveryCodesLeft: result.recoveryCodesLeft }) : result;
    },

    async signUp({ email, name, redirectTo }) {
      const result = await post('/auth/totp/signup', { email, name, redirectTo: redirectTo ?? currentPage(), locale: core.locale() });
      return result.isSuccess ? ok() : result;
    },

    sendVerificationEmail: confirmation.sendVerificationEmail,
    verifyEmail: confirmation.verifyEmail,

    get pendingStep() {
      return registered() ? core.pendingStep() : null;
    },

    get policy() {
      const config = registered() ? core.config() : undefined;
      if (!config?.totp) return null;
      const secondFactorFor: ('google' | 'password')[] = [];
      if (config.google && config.google.secondFactor !== 'none') secondFactorFor.push('google');
      if (config.password && config.password.secondFactor !== 'none') secondFactorFor.push('password');
      return { signIn: config.totp.signIn, signUp: config.totp.signUp, secondFactorFor };
    },
  };
}
