import { fail, ok, type Result } from '../result.js';
import type { ButtonOptions, ProviderContext, SignInProvider } from './provider.js';
import { renderRedirectButton, startRedirect } from './redirect.js';

/** The Apple logo, as Apple's Sign in with Apple guidelines show it: black on white in the light theme, white on black in the dark one. */
const APPLE_LOGO = `<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="M12.152 6.896c-.948 0-2.415-1.078-3.96-1.04-2.04.027-3.91 1.183-4.961 3.014-2.117 3.675-.546 9.103 1.519 12.09 1.013 1.454 2.208 3.09 3.792 3.039 1.52-.065 2.09-.987 3.935-.987 1.831 0 2.35.987 3.96.948 1.637-.026 2.676-1.48 3.676-2.948 1.156-1.688 1.636-3.325 1.662-3.415-.039-.013-3.182-1.221-3.22-4.857-.026-3.04 2.48-4.494 2.597-4.559-1.429-2.09-3.623-2.324-4.39-2.376-2-.156-3.675 1.09-4.61 1.09zM15.53 3.83c.843-1.012 1.4-2.427 1.245-3.83-1.207.052-2.662.805-3.532 1.818-.78.896-1.454 2.338-1.273 3.714 1.338.104 2.715-.688 3.559-1.701"/></svg>`;

/** Apple's button colours: white on black in the light theme, black on white in the dark one, as its guidelines have them. */
const buttonColors = {
  light: { background: '#000000', color: '#ffffff', border: '#000000' },
  dark: { background: '#ffffff', color: '#000000', border: '#ffffff' },
};

/**
 * Sign in with Apple: the redirect to Apple and back, as with GitHub. madAuth adds it when the server offers it, so
 * the app passes none; `Madauth.provider('apple')` renders its button in a custom login screen, and `Madauth.apple`
 * signs in with an identity token a native app got from Apple itself.
 */
export class Apple implements SignInProvider {
  readonly method = 'apple';
  #ctx?: ProviderContext;

  async setup(ctx: ProviderContext): Promise<Result> {
    this.#ctx = ctx;
    if (!ctx.config.providers?.some((p) => p.id === 'apple' && p.kind === 'apple')) {
      return fail('flow_not_enabled', 'The madAuth server does not offer Sign in with Apple: an admin adds an Apple provider (Madauth.admin.addProvider) and switches it on.');
    }
    return ok();
  }

  /** Renders a "Continue with Apple" button that starts the redirect. The result arrives after the return. */
  renderButton(container: HTMLElement, options: ButtonOptions): () => void {
    return renderRedirectButton(container, options, {
      ctx: this.#ctx!,
      method: this.method,
      style: { logo: APPLE_LOGO, colors: buttonColors, font: "600 14px/20px -apple-system, BlinkMacSystemFont, system-ui, 'Segoe UI', Roboto, sans-serif" },
    });
  }

  redirect(link: boolean): void {
    startRedirect(this.#ctx!, this.method, link);
  }
}
