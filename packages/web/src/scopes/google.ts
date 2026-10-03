import { fail, ok, type MadauthUser, type Result } from '../result.js';
import { isDark } from '../theme.js';
import type { Core } from './core.js';

export interface GoogleButtonOptions {
  /** `auto` (default) follows the `color-scheme` of the container. */
  theme?: 'auto' | 'light' | 'dark';
  /**
   * Called with the outcome of a sign-in through this button. `Madauth.onAuthStateChanged` listeners are
   * notified as well. With `GoogleRedirect` the page navigates to Google instead.
   */
  onResult?(result: Result<{ user: MadauthUser }>): void;
}

/** Google sign-in for custom login screens. Needs `GoogleFedcm` or `GoogleRedirect` in `Madauth.initialize`. */
export interface GoogleApi {
  /**
   * Renders Google's sign-in button into `container`: the FedCM button with `GoogleFedcm`, or a button that
   * starts the redirect with `GoogleRedirect`. Can be called before `initialize` has finished.
   */
  renderButton(container: HTMLElement, options?: GoogleButtonOptions): Result<{ remove(): void }>;
}

export function createGoogleApi(core: Core): GoogleApi {
  return {
    renderButton(container, options = {}) {
      if (!core.isConfigured()) return fail('not_initialized', 'Call Madauth.initialize({ providers: [...] }) first.');
      const provider = core.provider('google');
      if (!provider?.renderButton) {
        return fail('flow_not_enabled', 'Pass new GoogleFedcm() or new GoogleRedirect() to Madauth.initialize to use Madauth.google.');
      }
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
