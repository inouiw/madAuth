import type { LoginMethodId } from '../methods.js';
import { fail, ok, type MadauthUser, type Result } from '../result.js';
import { isDark } from '../theme.js';
import type { Core } from './core.js';

export interface ButtonRenderOptions {
  /** `auto` (default) follows the `color-scheme` of the container. */
  theme?: 'auto' | 'light' | 'dark';
  /**
   * Called with the outcome of a sign-in through this button. `Madauth.onAuthStateChanged` listeners are
   * notified as well. With a redirect provider (`GoogleRedirect`, `GitHub`) the page navigates away instead.
   */
  onResult?(result: Result<{ user: MadauthUser }>): void;
}

/** The scope of a method whose provider renders a branded button: `Madauth.google`, `Madauth.github`. */
export interface ButtonApi {
  /**
   * Renders the provider's sign-in button into `container`. Can be called before `initialize` has
   * finished. Fails with `flow_not_enabled` when no provider with a button is registered for the method.
   */
  renderButton(container: HTMLElement, options?: ButtonRenderOptions): Result<{ remove(): void }>;
}

/** `hint` says which provider to pass to `Madauth.initialize` when none is registered for `method`. */
export function createButtonApi(core: Core, method: LoginMethodId, hint: string): ButtonApi {
  return {
    renderButton(container, options = {}) {
      if (!core.isConfigured()) return fail('not_initialized', 'Call Madauth.initialize({ providers: [...] }) first.');
      const provider = core.provider(method);
      if (!provider?.renderButton) return fail('flow_not_enabled', hint);
      let removed = false;
      let unmount: (() => void) | undefined;
      void core.whenReady().then((ready) => {
        if (removed) return;
        if (!ready.isSuccess) {
          options.onResult?.(ready);
          return;
        }
        const theme = options.theme === 'light' || options.theme === 'dark' ? options.theme : isDark(container) ? 'dark' : 'light';
        unmount = provider.renderButton!(container, { theme, onResult: (result) => options.onResult?.(result) });
      });
      return ok({
        remove() {
          removed = true;
          unmount?.();
        },
      });
    },
  };
}
