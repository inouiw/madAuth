import { fail, ok, type Result } from '../result.js';
import type { ButtonOptions, ProviderContext, SignInProvider } from './provider.js';
import { renderRedirectButton, startRedirect } from './redirect.js';

const GOOGLE_LOGO = `<svg viewBox="0 0 48 48" width="18" height="18" aria-hidden="true">
<path fill="#ea4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
<path fill="#4285f4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
<path fill="#fbbc05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
<path fill="#34a853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
</svg>`.replace(/>\s+</g, '><');

/** Colors of Google's own "Continue with Google" button, per its branding guidelines. */
const buttonColors = {
  light: { background: '#ffffff', color: '#1f1f1f', border: '#747775' },
  dark: { background: '#131314', color: '#e3e3e3', border: '#8e918f' },
};

/**
 * Google sign-in with the server-side authorization-code flow (like Cognito): the browser is redirected
 * to Google and back, and the madAuth server exchanges the code. Needs a Google provider with a client secret on the server.
 * A failed sign-in, or one that goes on with a second step, is reported by `Madauth.initialize` on the return.
 */
export class GoogleRedirect implements SignInProvider {
  readonly method = 'google' as const;
  #ctx?: ProviderContext;

  async setup(ctx: ProviderContext): Promise<Result> {
    this.#ctx = ctx;
    if (!ctx.config.google?.codeFlow) {
      return fail(
        'flow_not_enabled',
        'GoogleRedirect needs a Google provider with a client secret on the madAuth server, switched on: an admin adds it (Madauth.admin.addProvider). Or use GoogleFedcm.',
      );
    }
    return ok();
  }

  /** Renders a "Continue with Google" button that starts the redirect. The result arrives after the return. */
  renderButton(container: HTMLElement, options: ButtonOptions): () => void {
    return renderRedirectButton(container, options, {
      ctx: this.#ctx!,
      method: 'google',
      style: { logo: GOOGLE_LOGO, colors: buttonColors, font: "500 14px/20px Roboto, 'Google Sans', Arial, sans-serif" },
    });
  }

  redirect(link: boolean): void {
    startRedirect(this.#ctx!, 'google', link);
  }
}
