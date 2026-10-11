import { fail, ok, type Result } from '../result.js';
import type { ProviderContext, SignInProvider } from './provider.js';

/**
 * The authenticator app (TOTP) as a sign-in method of its own: the e-mail address and a code. Enables
 * `Madauth.totp.signIn` and `signUp` and, in the dialog, the "Authenticator app" entry when the server lets
 * the app sign in on its own, and "Create account" with it when the server lets people sign up with it.
 *
 * Not needed for the app as a second factor: the code step after a password or Google sign-in, the setup
 * (`Madauth.setUpAuthenticator()`) and the account methods of `Madauth.totp` work whenever the server has
 * the app switched on, with or without this provider, so an admin's policy applies to every app.
 */
export class Totp implements SignInProvider {
  readonly method = 'totp' as const;

  async setup(ctx: ProviderContext): Promise<Result> {
    if (!ctx.config.totp) {
      return fail('flow_not_enabled', 'The madAuth server has the authenticator app switched off: no sign-in method is set to ask for it, and it does not sign in on its own.');
    }
    return ok();
  }
}
