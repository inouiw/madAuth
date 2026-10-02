import { REDIRECT_ERROR_PARAM } from '../constants.js';
import { fail, ok, toErrorCode, type Result } from '../result.js';
import type { ProviderContext, SignInProvider } from './provider.js';

const errorMessages: Record<string, string> = {
  cancelled: 'The Google sign-in was cancelled.',
  verification_failed: 'The Google sign-in could not be verified. Please try again.',
  email_unverified: 'Your Google account’s e-mail address is not verified.',
};

/**
 * Google sign-in with the server-side authorization-code flow (like Cognito): the browser is redirected
 * to Google and back, and the madAuth server exchanges the code. Needs GOOGLE_CLIENT_SECRET on the server.
 */
export class GoogleRedirect implements SignInProvider {
  readonly method = 'google' as const;
  #ctx?: ProviderContext;

  async setup(ctx: ProviderContext): Promise<Result> {
    this.#ctx = ctx;
    if (!ctx.config.google.codeFlow) {
      return fail(
        'flow_not_enabled',
        'GoogleRedirect needs GOOGLE_CLIENT_SECRET on the madAuth server. Set it there, or use GoogleFedcm.',
      );
    }
    // Coming back from a failed redirect sign-in: report it and tidy up the URL.
    const params = new URLSearchParams(location.hash.slice(1));
    const error = params.get(REDIRECT_ERROR_PARAM);
    if (error) {
      params.delete(REDIRECT_ERROR_PARAM);
      const hash = params.toString();
      history.replaceState(history.state, '', `${location.pathname}${location.search}${hash ? `#${hash}` : ''}`);
      ctx.signInFailed({ code: toErrorCode(error), message: errorMessages[error] ?? `Google sign-in failed (${error}).` });
    }
    return ok();
  }

  start(): void {
    const returnTo = location.href.split('#')[0];
    location.assign(`${this.#ctx!.serverUrl}/auth/google/start?return_to=${encodeURIComponent(returnTo)}`);
  }
}
