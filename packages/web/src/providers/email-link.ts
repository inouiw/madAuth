import { fail, ok, type Result } from '../result.js';
import type { ProviderContext, SignInProvider } from './provider.js';

/**
 * Passwordless sign-in with an e-mail link: the address, then the link or the code from the e-mail. Enables
 * `Madauth.emailLink` and the "E-mail link" entry in the sign-in dialog. The links in the e-mails are
 * handled by `Madauth.initialize`, like the confirmation links.
 */
export class EmailLink implements SignInProvider {
  readonly method = 'email-link' as const;

  async setup(ctx: ProviderContext): Promise<Result> {
    if (!ctx.config.emailLink) {
      return fail(
        'flow_not_enabled',
        'The madAuth server does not offer the e-mail link: its webhook must send email.send_signin_link, and an admin lists the method with set-methods.',
      );
    }
    return ok();
  }
}
