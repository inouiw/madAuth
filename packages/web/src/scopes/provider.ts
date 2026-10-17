import { fail, ok, type Result } from '../result.js';
import { createButtonApi, type ButtonApi, type ButtonRenderOptions } from './button.js';
import type { Core } from './core.js';

/**
 * A sign-in provider the server offers, for custom login screens: Google, GitHub or an OpenID Connect provider
 * an admin added, by its id (`Madauth.provider('gitlab')`). madAuth registers the providers the server offers
 * by itself, except Google's One Tap (`new GoogleFedcm()`).
 */
export interface ProviderApi extends ButtonApi {
  /**
   * Renders the provider's "Continue with <name>" button into `container` (Google's own with `GoogleFedcm`).
   * Can be called before `initialize` has finished.
   */
  renderButton(container: HTMLElement, options?: ButtonRenderOptions): ReturnType<ButtonApi['renderButton']>;
  /**
   * Starts the provider's sign-in without a button of madAuth's: the browser goes to the provider and comes
   * back to this page, whose `Madauth.initialize` reports the result. With `purpose: 'link'`, it adds the
   * provider to the signed-in user's methods instead (within ten minutes of signing in). Fails with
   * `flow_not_enabled` when the server doesn't offer the provider, or when it signs in without a redirect here
   * (Google with `GoogleFedcm`: render its button).
   */
  signIn(options?: { purpose?: 'signin' | 'link' }): Promise<Result>;
}

export function createProviderApi(core: Core, id: string): ProviderApi {
  const hint = `The madAuth server offers no sign-in provider "${id}": an admin adds it (Madauth.admin.addProvider) and switches it on (Madauth.admin.setSettings).`;
  return {
    ...createButtonApi(core, id, hint),
    async signIn(options = {}) {
      const ready = await core.whenReady();
      if (!ready.isSuccess) return ready;
      const provider = core.provider(id);
      if (!provider?.redirect) {
        return fail('flow_not_enabled', provider ? `"${id}" signs in with its own button here (GoogleFedcm): use renderButton.` : hint);
      }
      provider.redirect(options.purpose === 'link');
      return ok();
    },
  };
}
