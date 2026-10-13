import { fail, ok, type Result } from '../result.js';
import { webauthnSupported } from '../webauthn.js';
import type { ProviderContext, SignInProvider } from './provider.js';

/**
 * Passkeys as a sign-in method of their own: the browser's passkey dialog signs in, without the address.
 * Enables `Madauth.passkey.signIn` and, in the dialog, the "Passkey" entry and passkeys in the e-mail
 * field's autofill, when the server lets passkeys sign in on their own and the browser has them.
 *
 * Not needed for passkeys as a second factor, nor to add one: `Madauth.passkey.verify`, `add` and
 * `Madauth.setUpPasskey()` work whenever the server has passkeys on.
 */
export class Passkey implements SignInProvider {
  readonly method = 'passkey' as const;

  async setup(ctx: ProviderContext): Promise<Result> {
    if (!ctx.config.passkey?.signIn) {
      return fail('flow_not_enabled', 'The madAuth server does not let passkeys sign in on their own (an admin allows them with set-methods passkey).');
    }
    if (!webauthnSupported()) return fail('flow_not_enabled', 'This browser does not support passkeys.');
    return ok();
  }
}
