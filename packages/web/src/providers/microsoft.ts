import { fail, ok, type Result } from '../result.js';
import type { ButtonOptions, ProviderContext, SignInProvider } from './provider.js';
import { renderRedirectButton, startRedirect } from './redirect.js';

/** Microsoft's logo, the four squares in its own colours, as its sign-in branding guidelines show it on both themes. */
const MICROSOFT_LOGO = `<svg viewBox="0 0 21 21" width="18" height="18" aria-hidden="true"><rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg>`;

/** Microsoft's sign-in button colours: dark grey on white with a grey border in the light theme, white on #2f2f2f in the dark one. */
const buttonColors = {
  light: { background: '#ffffff', color: '#5e5e5e', border: '#8c8c8c' },
  dark: { background: '#2f2f2f', color: '#ffffff', border: '#2f2f2f' },
};

/**
 * Microsoft sign-in, for personal Microsoft accounts and work or school accounts (Microsoft Entra ID): the
 * redirect to Microsoft and back, as with GitHub. madAuth adds it when the server offers it, so the app passes
 * none; `Madauth.provider('microsoft')` renders its button in a custom login screen.
 */
export class Microsoft implements SignInProvider {
  readonly method = 'microsoft';
  #ctx?: ProviderContext;

  async setup(ctx: ProviderContext): Promise<Result> {
    this.#ctx = ctx;
    if (!ctx.config.providers?.some((p) => p.id === 'microsoft' && p.kind === 'microsoft')) {
      return fail('flow_not_enabled', 'The madAuth server does not offer Microsoft sign-in: an admin adds a Microsoft provider (Madauth.admin.addProvider) and switches it on.');
    }
    return ok();
  }

  /** Renders a "Continue with Microsoft" button that starts the redirect. The result arrives after the return. */
  renderButton(container: HTMLElement, options: ButtonOptions): () => void {
    return renderRedirectButton(container, options, {
      ctx: this.#ctx!,
      method: this.method,
      style: { logo: MICROSOFT_LOGO, colors: buttonColors, font: "600 14px/20px 'Segoe UI', system-ui, -apple-system, Roboto, sans-serif" },
    });
  }

  redirect(link: boolean): void {
    startRedirect(this.#ctx!, this.method, link);
  }
}
