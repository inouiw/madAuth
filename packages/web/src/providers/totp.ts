import { REDIRECT_NEXT_PARAM } from '../constants.js';
import { fail, ok, type Result } from '../result.js';
import type { ProviderContext, SignInProvider } from './provider.js';

/**
 * The authenticator app (TOTP). Enables `Madauth.totp`, `Madauth.setUpAuthenticator()` and, in the dialog,
 * the code step after a password or Google sign-in whose policy asks for the app, the "Authenticator app"
 * entry when the server lets the app sign in on its own, and "Create account" with it when the server
 * lets people sign up with it. A user sets the app up while signed in, or when a policy requires it.
 */
export class Totp implements SignInProvider {
  readonly method = 'totp' as const;

  async setup(ctx: ProviderContext): Promise<Result> {
    if (!ctx.config.totp) {
      return fail('flow_not_enabled', 'The madAuth server has the authenticator app switched off: no sign-in method is set to ask for it, and it does not sign in on its own.');
    }
    // Back from the redirect flow with the first step done: the code or the setup is next.
    const params = new URLSearchParams(location.hash.slice(1));
    const next = params.get(REDIRECT_NEXT_PARAM);
    if (next === 'totp' || next === 'totp-setup') {
      params.delete(REDIRECT_NEXT_PARAM);
      const hash = params.toString();
      history.replaceState(history.state, '', `${location.pathname}${location.search}${hash ? `#${hash}` : ''}`);
      ctx.signInContinues({ step: next === 'totp' ? 'code' : 'setup', method: 'google' });
    }
    return ok();
  }
}
