import { fail, ok, type Result } from '../result.js';
import type { ButtonOptions, ProviderContext, SignInProvider } from './provider.js';
import { renderRedirectButton } from './redirect.js';

/** GitHub's mark (the octicon `mark-github`), in the button's text colour: black or white, as GitHub's brand guidelines allow. */
const GITHUB_MARK = `<svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"/></svg>`;

/** Black on white in the light theme, white on GitHub's dark grey in the dark theme. */
const buttonColors = {
  light: { background: '#ffffff', color: '#24292f', border: '#d0d7de' },
  dark: { background: '#24292f', color: '#ffffff', border: '#444c56' },
};

/**
 * GitHub sign-in: the server-side authorization-code flow, the only one GitHub has. The browser is
 * redirected to GitHub and back, and the madAuth server exchanges the code. Needs GITHUB_CLIENT_ID and
 * GITHUB_CLIENT_SECRET on the server. Enables `Madauth.github` and the "Continue with GitHub" button in
 * the sign-in dialog. A failed sign-in, or one that goes on with a second step, is reported by
 * `Madauth.initialize` on the return.
 */
export class GitHub implements SignInProvider {
  readonly method = 'github' as const;
  #ctx?: ProviderContext;

  async setup(ctx: ProviderContext): Promise<Result> {
    this.#ctx = ctx;
    if (!ctx.config.github) {
      return fail(
        'flow_not_enabled',
        'The madAuth server does not offer GitHub sign-in: set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET there, and an admin lists the method in the settings (Madauth.admin.setSettings).',
      );
    }
    return ok();
  }

  /** Renders a "Continue with GitHub" button that starts the redirect. The result arrives after the return. */
  renderButton(container: HTMLElement, options: ButtonOptions): () => void {
    return renderRedirectButton(container, options, {
      ctx: this.#ctx!,
      method: 'github',
      style: { logo: GITHUB_MARK, colors: buttonColors, font: "500 14px/20px -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif" },
    });
  }
}
