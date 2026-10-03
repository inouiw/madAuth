import { RESET_LINK_PARAM, VERIFY_LINK_PARAM } from '../constants.js';
import { fail, ok, type MadauthUser, type Result } from '../result.js';
import type { ProviderContext, SignInProvider } from './provider.js';

/** Reset tokens from e-mail links, kept out of the class so they don't show up on its instances. */
const resetTokens = new WeakMap<Password, string>();

/**
 * E-mail & password sign-in. Enables `Madauth.password` and the form in the sign-in dialog, and handles
 * the links in madAuth's e-mails when the page opens: a verification link signs the user in, a reset link
 * makes `Madauth.password.pendingReset` true.
 */
export class Password implements SignInProvider {
  readonly method = 'password' as const;

  async setup(ctx: ProviderContext): Promise<Result> {
    resetTokens.delete(this);
    if (!ctx.config.password) {
      return fail('flow_not_enabled', 'The madAuth server has no DATABASE_URL, so e-mail & password sign-in is off.');
    }
    const params = new URLSearchParams(location.hash.slice(1));
    const verifyToken = params.get(VERIFY_LINK_PARAM);
    const resetToken = params.get(RESET_LINK_PARAM);
    if (!verifyToken && !resetToken) return ok();

    // The tokens are secrets: take them out of the address bar (and so the history) right away.
    params.delete(VERIFY_LINK_PARAM);
    params.delete(RESET_LINK_PARAM);
    const hash = params.toString();
    history.replaceState(history.state, '', `${location.pathname}${location.search}${hash ? `#${hash}` : ''}`);

    if (resetToken) resetTokens.set(this, resetToken);
    if (verifyToken) {
      const res = await ctx.request<{ user: MadauthUser }>('/auth/password/verify-email', {
        method: 'POST',
        body: { token: verifyToken },
      });
      if (res.ok) ctx.signedIn(res.data.user);
      else ctx.signInFailed(res.error);
    }
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
