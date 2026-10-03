import { Password, clearResetToken, pendingResetToken } from '../providers/password.js';
import { fail, ok, type MadauthUser, type Result } from '../result.js';
import type { Core } from './core.js';

export interface SignInWithPasswordOptions {
  email: string;
  password: string;
}

export interface SignUpOptions {
  email: string;
  password: string;
  /** Shown to the user and in `MadauthUser.name`. */
  name?: string;
  /** The page the link in the e-mail opens. Default: the current page. Its origin must be in ALLOWED_ORIGINS. */
  redirectTo?: string;
}

export interface SendEmailOptions {
  email: string;
  /** The page the link in the e-mail opens. Default: the current page. Its origin must be in ALLOWED_ORIGINS. */
  redirectTo?: string;
}

export type ConfirmResetOptions =
  /** With the link the page was opened from, or an explicit `token` from such a link. */
  | { newPassword: string; token?: string }
  /** With the 6-digit code from the e-mail. */
  | { newPassword: string; email: string; code: string };

/** E-mail & password sign-in for custom login screens. Needs `new Password()` in `Madauth.initialize`. */
export interface PasswordApi {
  /** Signs in. Fails with `invalid_credentials`, `email_unverified` or `too_many_attempts`. */
  signIn(options: SignInWithPasswordOptions): Promise<Result<{ user: MadauthUser }>>;
  /**
   * Creates an account and sends an e-mail with a link and a code to confirm the address. Succeeds even if
   * the address is already registered (its owner gets an e-mail instead), so nobody can probe for accounts.
   * Fails with `invalid_email`, `weak_password`, `signup_rejected` (the operator's sign-up check refused; the
   * message says why) or `temporarily_unavailable` (the e-mail could not be sent).
   */
  signUp(options: SignUpOptions): Promise<Result>;
  /** Sends the confirmation e-mail again. Fails with `temporarily_unavailable` if it could not be sent. */
  sendVerificationEmail(options: SendEmailOptions): Promise<Result>;
  /**
   * Confirms the address with the code from the e-mail and signs in. Fails with `code_invalid`.
   * Links are handled by `Madauth.initialize` when the page opens.
   */
  verifyEmail(options: { email: string; code: string }): Promise<Result<{ user: MadauthUser }>>;
  /**
   * Sends an e-mail with a link and a code to choose a new password. Succeeds for unknown addresses too.
   * Fails with `temporarily_unavailable` if it could not be sent.
   */
  sendResetEmail(options: SendEmailOptions): Promise<Result>;
  /** True when the page was opened from a reset link; then ask for a new password and call {@link confirmReset}. */
  readonly pendingReset: boolean;
  /**
   * Sets a new password and signs in. Uses the reset link the page was opened from unless `token`, or
   * `email` and `code`, are given. Fails with `link_invalid`, `code_invalid` or `weak_password`.
   */
  confirmReset(options: ConfirmResetOptions): Promise<Result<{ user: MadauthUser }>>;
  /** The server's password rules, for hints in your form; null until initialized. */
  readonly policy: { minLength: number } | null;
}

const currentPage = () => location.href.split('#')[0];
/** The user's language, so the webhook can send the e-mail in it. */
const locale = () => (typeof navigator !== 'undefined' ? navigator.language : undefined);

const notRegistered = () => fail('flow_not_enabled', 'Pass new Password() to Madauth.initialize to use Madauth.password.');

export function createPasswordApi(core: Core): PasswordApi {
  const provider = (): Password | undefined => {
    const p = core.provider('password');
    return p instanceof Password ? p : undefined;
  };

  /** Waits for initialize, checks that the Password provider is registered, then calls the server. */
  async function call<T extends object>(path: string, body: Record<string, unknown>): Promise<Result<T>> {
    const ready = await core.whenReady();
    if (!ready.isSuccess) return ready;
    if (!provider()) return notRegistered();
    const res = await core.request<T>(path, { method: 'POST', body });
    return res.ok ? ok(res.data) : { isSuccess: false, error: res.error };
  }

  function signedIn(result: Result<{ user: MadauthUser }>): Result<{ user: MadauthUser }> {
    if (result.isSuccess) {
      core.signedIn(result.user);
      return { isSuccess: true, user: result.user };
    }
    return result;
  }

  return {
    async signIn({ email, password }) {
      return signedIn(await call('/auth/password/signin', { email, password }));
    },

    async signUp({ email, password, name, redirectTo }) {
      const result = await call('/auth/password/signup', {
        email,
        password,
        name,
        redirectTo: redirectTo ?? currentPage(),
        locale: locale(),
      });
      return result.isSuccess ? ok() : result;
    },

    async sendVerificationEmail({ email, redirectTo }) {
      const result = await call('/auth/password/send-verification', { email, redirectTo: redirectTo ?? currentPage(), locale: locale() });
      return result.isSuccess ? ok() : result;
    },

    async verifyEmail({ email, code }) {
      return signedIn(await call('/auth/password/verify-email', { email, code }));
    },

    async sendResetEmail({ email, redirectTo }) {
      const result = await call('/auth/password/send-reset', { email, redirectTo: redirectTo ?? currentPage(), locale: locale() });
      return result.isSuccess ? ok() : result;
    },

    get pendingReset() {
      const p = provider();
      return !!p && pendingResetToken(p) !== undefined;
    },

    async confirmReset(options) {
      const ready = await core.whenReady();
      if (!ready.isSuccess) return ready;
      const p = provider();
      if (!p) return notRegistered();
      let body: Record<string, unknown>;
      if ('code' in options) {
        body = { password: options.newPassword, email: options.email, code: options.code };
      } else {
        const token = options.token ?? pendingResetToken(p);
        if (!token) return fail('link_invalid', 'No reset link: pass token, or email and code, to confirmReset.');
        body = { password: options.newPassword, token };
      }
      const result = signedIn(await call('/auth/password/reset', body));
      // A used or expired link stays useless, so forget it either way; a weak password can be retried.
      if (result.isSuccess || result.error.code === 'link_invalid') clearResetToken(p);
      return result;
    },

    get policy() {
      return provider() ? (core.config()?.password ?? null) : null;
    },
  };
}
