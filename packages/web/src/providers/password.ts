import { RESET_LINK_PARAM } from '../constants.js';
import { fail, ok, type Result } from '../result.js';
import type { ProviderContext, SignInProvider } from './provider.js';

/** Reset tokens from e-mail links, kept out of the class so they don't show up on its instances. */
const resetTokens = new WeakMap<Password, string>();

/**
 * E-mail & password sign-in. Enables `Madauth.password` and the form in the sign-in dialog. A reset link
 * in madAuth's e-mails makes `Madauth.password.pendingReset` true when the page opens; the confirmation
 * links are handled by `Madauth.initialize` for every method that confirms an address.
 */
export class Password implements SignInProvider {
  readonly method = 'password' as const;

  async setup(ctx: ProviderContext): Promise<Result> {
    resetTokens.delete(this);
    if (!ctx.config.password) {
      return fail('flow_not_enabled', 'The madAuth server has no webhook that sends the e-mails, so e-mail & password sign-in is off.');
    }
    const params = new URLSearchParams(location.hash.slice(1));
    const resetToken = params.get(RESET_LINK_PARAM);
    if (!resetToken) return ok();

    // The token is a secret: take it out of the address bar (and so the history) right away.
    params.delete(RESET_LINK_PARAM);
    const hash = params.toString();
    history.replaceState(history.state, '', `${location.pathname}${location.search}${hash ? `#${hash}` : ''}`);
    resetTokens.set(this, resetToken);
    return ok();
  }
}

/** The reset token from the e-mail link the page was opened with, if any. */
export function pendingResetToken(provider: Password): string | undefined {
  return resetTokens.get(provider);
}

export function clearResetToken(provider: Password): void {
  resetTokens.delete(provider);
}
