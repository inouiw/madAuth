// Confirming an e-mail address, shared by the methods that sign people up with one (password and the
// authenticator app): the routes are the same, only the scope that offers them differs.
import type { LoginMethodId } from '../methods.js';
import { ok, type MadauthUser, type Result } from '../result.js';
import type { Core } from './core.js';

export interface SendEmailOptions {
  email: string;
  /** The page the link in the e-mail opens. Default: the current page. Its origin must be in ALLOWED_ORIGINS. */
  redirectTo?: string;
}

export const currentPage = (): string => location.href.split('#')[0];

/**
 * Marks a sign-in that goes on with the authenticator app, and returns the result as it is: a `totp_required`
 * or `totp_setup_required` failure tells the caller what comes next.
 */
export function noteNextStep<T extends object>(core: Core, method: LoginMethodId, result: Result<T>): Result<T> {
  if (!result.isSuccess && (result.error.code === 'totp_required' || result.error.code === 'totp_setup_required')) {
    core.setPendingStep({ step: result.error.code === 'totp_required' ? 'code' : 'setup', method });
  }
  return result;
}

/** Notes a sign-in that succeeded, or one that goes on with the app. */
export function signedIn(core: Core, method: LoginMethodId, result: Result<{ user: MadauthUser }>): Result<{ user: MadauthUser }> {
  if (result.isSuccess) {
    core.signedIn(result.user);
    return { isSuccess: true, user: result.user };
  }
  return noteNextStep(core, method, result);
}

/** The e-mail confirmation calls of a method's scope; `call` is the scope's own request helper. */
export function emailConfirmation(
  core: Core,
  method: LoginMethodId,
  call: <T extends object>(path: string, body: Record<string, unknown>) => Promise<Result<T>>,
) {
  return {
    async sendVerificationEmail({ email, redirectTo }: SendEmailOptions): Promise<Result> {
      const result = await call('/auth/email/send-verification', { email, redirectTo: redirectTo ?? currentPage(), locale: core.locale() });
      return result.isSuccess ? ok() : result;
    },
    async verifyEmail({ email, code }: { email: string; code: string }): Promise<Result<{ user: MadauthUser }>> {
      return signedIn(core, method, await call('/auth/email/verify', { email, code }));
    },
  };
}
