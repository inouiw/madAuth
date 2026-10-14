import { fail, ok, type Result } from '../result.js';
import type { ProviderContext, SignInProvider } from './provider.js';

/**
 * The authenticator app (TOTP) as a sign-in method of its own: the e-mail address and a code. Enables
 * `Madauth.authenticator.signIn` and `signUp` and, in the dialog, the "Authenticator app" entry when the server lets
 * the app sign in on its own, and "Create account" with it when the server lets people sign up with it.
 *
 * Not needed for the app as a second factor: the code step after a password, Google, GitHub or e-mail link sign-in, the setup
 * (`Madauth.setUpAuthenticator()`) and the account methods of `Madauth.authenticator` work whenever the server has
 * the app switched on, with or without this provider, so an admin's policy applies to every app.
 */
export class Authenticator implements SignInProvider {
  readonly method = 'authenticator' as const;

  async setup(ctx: ProviderContext): Promise<Result> {
    if (!ctx.config.authenticator?.signIn) {
      return fail(
        'flow_not_enabled',
        'The madAuth server does not let the authenticator app sign in on its own (an admin lists it with set-methods). As a second factor it works without this provider.',
      );
    }
    return ok();
  }
}
