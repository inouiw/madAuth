// What the providers with a redirect sign-in share (`GoogleRedirect`, `GitHub`): the "Continue with …"
// button that starts it, and the start itself. The server does the rest and sends the user back.
import type { LoginMethodId } from '../methods.js';
import { stringsFor } from '../strings.js';
import type { ButtonOptions, ProviderContext } from './provider.js';

/** How a provider's button looks: its mark, its colours in both themes, and the font of the label. */
export interface RedirectButtonStyle {
  /** The provider's mark, as inline SVG. */
  logo: string;
  colors: Record<'light' | 'dark', { background: string; color: string; border: string }>;
  /** The CSS `font` shorthand of the label. */
  font: string;
}

/**
 * Renders the button that starts a redirect sign-in into `container`. The label is the method's, in the
 * current language, and follows `Madauth.setLocale` while the button is shown. Returns a function that
 * removes the button.
 */
export function renderRedirectButton(
  container: HTMLElement,
  options: ButtonOptions,
  provider: { ctx: ProviderContext; method: LoginMethodId; style: RedirectButtonStyle },
): () => void {
  const { ctx, method, style } = provider;
  const colors = style.colors[options.theme];
  const button = document.createElement('button');
  button.type = 'button';
  button.innerHTML = `${style.logo}<span></span>`;
  const label = button.querySelector('span')!;
  const setLabel = () => {
    const s = stringsFor(ctx.locale);
    label.textContent = options.purpose === 'link' ? s.methodsView.connect(s.methodNames[method]) : s.methods[method].label;
  };
  setLabel();
  const stopFollowingLocale = ctx.onLocaleChanged(setLabel);
  Object.assign(button.style, {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '10px',
    width: '100%',
    height: '40px',
    padding: '0 12px',
    border: `1px solid ${colors.border}`,
    borderRadius: '4px',
    background: colors.background,
    color: colors.color,
    font: style.font,
    cursor: 'pointer',
  });
  button.addEventListener('click', () => startRedirect(ctx, method, options.purpose === 'link'));
  container.replaceChildren(button);
  return () => {
    stopFollowingLocale();
    container.replaceChildren();
  };
}

/**
 * Sends the browser to the server's start route of the method, with the locale for the sign-up check (like the
 * other sign-up requests); the user comes back to this page, without its hash. With `link`, the flow adds the
 * provider to the signed-in user's methods instead of signing in.
 */
export function startRedirect(ctx: ProviderContext, method: LoginMethodId, link = false): void {
  const returnTo = location.href.split('#')[0];
  const locale = ctx.locale ? `&locale=${encodeURIComponent(ctx.locale)}` : '';
  location.assign(`${ctx.serverUrl}/auth/providers/${method}/start?return_to=${encodeURIComponent(returnTo)}${locale}${link ? '&link=1' : ''}`);
}
