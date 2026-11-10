import { fail, ok, type Result } from '../result.js';
import { BRANDS } from './brands.js';
import type { ButtonOptions, ProviderContext, SignInProvider } from './provider.js';
import { renderRedirectButton, startRedirect } from './redirect.js';

/** A neutral sign-in mark (an arrow into a door), in the button's text colour: no provider's logo is loaded from anywhere. */
export const SIGN_IN_MARK = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m10 17 5-5-5-5"/><path d="M15 12H3"/><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/></svg>`;

/** The colours of the dialog's own buttons. */
const buttonColors = {
  light: { background: '#ffffff', color: '#17181a', border: '#d0d2d6' },
  dark: { background: '#232428', color: '#f1f2f3', border: '#3d4045' },
};

/**
 * Sign-in with an OpenID Connect provider an admin added (`Madauth.admin.addProvider` with the kind `oidc`), or
 * with Facebook or X (the kinds `facebook` and `x`): the redirect to the provider and back, as with GitHub. madAuth
 * adds one for every such provider the server offers, so the app passes none; `Madauth.provider(id)` renders its
 * button in a custom login screen. A preset's provider (GitLab, LinkedIn, Slack), Facebook and X show their logo.
 */
export class OpenIdConnect implements SignInProvider {
  #ctx?: ProviderContext;
  #brand?: string;

  /** `method` is the provider's id; `kind` the provider's kind, `facebook` and `x` have their kind as their id. */
  constructor(
    readonly method: string,
    private readonly kind: 'oidc' | 'facebook' | 'x' = 'oidc',
  ) {}

  async setup(ctx: ProviderContext): Promise<Result> {
    this.#ctx = ctx;
    const offered = ctx.config.providers?.find((p) => p.id === this.method && p.kind === this.kind);
    if (!offered) return fail('flow_not_enabled', `The madAuth server offers no ${this.kind === 'oidc' ? 'OpenID Connect provider' : 'provider'} "${this.method}".`);
    this.#brand = offered.preset ?? (this.kind === 'oidc' ? undefined : this.kind);
    return ok();
  }

  /** Renders a "Continue with <name>" button that starts the redirect. The result arrives after the return. */
  renderButton(container: HTMLElement, options: ButtonOptions): () => void {
    return renderRedirectButton(container, options, {
      ctx: this.#ctx!,
      method: this.method,
      style: (this.#brand && BRANDS[this.#brand]) || { logo: SIGN_IN_MARK, colors: buttonColors, font: "500 14px/20px system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif" },
    });
  }

  redirect(link: boolean): void {
    startRedirect(this.#ctx!, this.method, link);
  }
}
