import { LitElement, css, html, type TemplateResult } from 'lit';
import { providerFor, readyForDialog, takePendingError } from './madauth.js';
import { loginMethods, type LoginMethod, type LoginMethodId } from './methods.js';
import type { MadauthError, MadauthErrorCode, MadauthUser, Result } from './result.js';

export interface SignedInDetail {
  method: LoginMethodId;
  user: MadauthUser;
}

export type ErrorDetail = { method?: LoginMethodId } & MadauthError;

/** What the dialog tells the user; the technical details are in the `madauth-error` event and the console. */
const errorTexts: Partial<Record<MadauthErrorCode, string>> = {
  network: 'Could not reach the sign-in service. Please check your connection and try again.',
  verification_failed: 'The sign-in could not be verified. Please try again.',
  email_unverified: 'The e-mail address of this account is not verified.',
  cancelled: 'The sign-in was cancelled.',
  not_initialized: 'Sign-in is not set up on this page.',
};
const defaultErrorText = 'Sign-in is not available right now.';

const closeIcon = html`
  <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
    <path d="M18 6 6 18" />
    <path d="m6 6 12 12" />
  </svg>
`;

const chevronIcon = html`
  <svg class="icon chevron" viewBox="0 0 24 24" aria-hidden="true">
    <path d="m9 18 6-6-6-6" />
  </svg>
`;

const infoIcon = html`
  <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
    <circle cx="12" cy="12" r="10" />
    <path d="M12 16v-4" />
    <path d="M12 8h.01" />
  </svg>
`;

const googleLogo = html`
  <svg class="logo" viewBox="0 0 48 48" aria-hidden="true">
    <path
      fill="#ea4335"
      d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
    />
    <path
      fill="#4285f4"
      d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
    />
    <path
      fill="#fbbc05"
      d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
    />
    <path
      fill="#34a853"
      d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
    />
  </svg>
`;

/** Icons of the methods listed under "Other ways to sign in". */
const rowIcons: Partial<Record<LoginMethodId, TemplateResult>> = {
  totp: html`
    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
      />
      <path d="m9 12 2 2 4-4" />
    </svg>
  `,
  email: html`
    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
      <rect x="2" y="4" width="20" height="16" rx="2" />
      <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
    </svg>
  `,
  sms: html`
    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
    </svg>
  `,
};

/**
 * Modal sign-in dialog listing all madAuth login methods. Usually opened with `Madauth.signIn()`, which
 * creates it when the page has none; add it to your HTML yourself only to customize it.
 *
 * @fires madauth-signed-in - A user signed in. `detail` is a {@link SignedInDetail}.
 * @fires madauth-cancel - The dialog was closed without signing in.
 * @fires madauth-error - A sign-in failed, or madAuth is not initialized. `detail` is an {@link ErrorDetail}.
 *
 * @cssprop --madauth-primary - Fill color of the primary "Sign in" button.
 * @cssprop --madauth-radius - Corner radius of the dialog, buttons and fields.
 * @cssprop --madauth-font - Font family.
 *
 * @csspart dialog - The `<dialog>` element.
 * @csspart method - Each sign-in method button.
 * @csspart error - The error message.
 */
export class MadauthLogin extends LitElement {
  static override properties = {
    heading: { type: String },
    notice: { state: true },
    error: { state: true },
    usable: { state: true },
  };

  /** Title shown at the top of the dialog. */
  heading = 'Sign in';

  /** Message shown below the heading, e.g. after picking a method that is not available yet. */
  private notice = '';

  /** Error shown below the heading. */
  private error: MadauthError | null = null;

  /** Whether madAuth is initialized, so providers can render their sign-in UI. */
  private usable = false;

  /** Removes the UI a provider rendered into the dialog. */
  private unmountProvider?: () => void;

  /** Opens the dialog as a modal. */
  async open(): Promise<void> {
    await this.updateComplete;
    this.dialog.showModal();
    const ready = await readyForDialog();
    if (!this.dialog.open) return;
    this.usable = ready.isSuccess;
    const error = ready.isSuccess ? takePendingError() : ready.error;
    if (error) this.showError(error);
    await this.updateComplete;
    this.mountProviders();
  }

  /** Closes the dialog without firing `madauth-cancel`. */
  close(): void {
    this.dialog.close('done');
  }

  private get dialog(): HTMLDialogElement {
    return this.renderRoot.querySelector('dialog')!;
  }

  private onDialogClose(): void {
    this.unmountProvider?.();
    this.unmountProvider = undefined;
    if (this.dialog.returnValue !== 'done') {
      this.dispatchEvent(new CustomEvent('madauth-cancel', { bubbles: true, composed: true }));
    }
    this.dialog.returnValue = '';
    this.notice = '';
    this.error = null;
  }

  /** Lets providers with their own UI (e.g. Google's FedCM button) render into the dialog. */
  private mountProviders(): void {
    const slot = this.renderRoot.querySelector<HTMLElement>('.google-slot');
    const provider = providerFor('google');
    if (!slot || !provider?.renderInDialog || this.unmountProvider) return;
    this.unmountProvider = provider.renderInDialog(slot, (result) => this.onProviderResult('google', result));
  }

  private onProviderResult(method: LoginMethodId, result: Result<{ user: MadauthUser }>): void {
    if (!result.isSuccess) {
      this.showError(result.error, method);
      return;
    }
    const detail: SignedInDetail = { method, user: result.user };
    this.dispatchEvent(new CustomEvent('madauth-signed-in', { detail, bubbles: true, composed: true }));
    this.close();
  }

  private showError(error: MadauthError, method?: LoginMethodId): void {
    this.notice = '';
    this.error = error;
    const detail: ErrorDetail = { method, ...error };
    this.dispatchEvent(new CustomEvent('madauth-error', { detail, bubbles: true, composed: true }));
  }

  private onBackdropClick(e: MouseEvent): void {
    // Clicks on the backdrop target the <dialog> itself; clicks inside hit its children.
    if (e.target === this.dialog) this.dialog.close();
  }

  private onMethodChosen(m: LoginMethod): void {
    const provider = providerFor(m.id);
    if (!provider) {
      this.error = null;
      this.notice = `“${m.label}” is coming soon.`;
    } else if (this.usable) {
      provider.start?.();
    }
  }

  override render() {
    const google = loginMethods.find((m) => m.id === 'google');
    const password = loginMethods.find((m) => m.id === 'password');
    const others = loginMethods.filter((m) => m !== google && m !== password);
    return html`
      <dialog part="dialog" @close=${this.onDialogClose} @click=${this.onBackdropClick}>
        <div class="panel">
          <header>
            <h2>${this.heading}</h2>
            <button class="close" type="button" aria-label="Close" @click=${() => this.dialog.close()}>
              ${closeIcon}
            </button>
          </header>
          ${this.notice
            ? html`<p class="notice" role="status">${infoIcon}<span>${this.notice}</span></p>`
            : null}
          ${this.error
            ? html`<p class="notice error" part="error" role="alert" data-code=${this.error.code}>
                ${infoIcon}<span>${errorTexts[this.error.code] ?? defaultErrorText}</span>
              </p>`
            : null}
          ${google ? this.renderGoogle(google) : null}
          ${google && password ? html`<div class="divider">or</div>` : null}
          ${password ? this.renderPassword(password) : null}
          ${others.length
            ? html`
                <section class="others">
                  <h3>Other ways to sign in</h3>
                  <ul>
                    ${others.map((m) => html`<li>${this.renderRow(m)}</li>`)}
                  </ul>
                </section>
              `
            : null}
        </div>
      </dialog>
    `;
  }

  private renderGoogle(m: LoginMethod) {
    if (this.usable && providerFor('google')?.renderInDialog) {
      // Google renders its own (FedCM) button here; see GoogleFedcm.
      return html`<div class="google-slot" title=${m.description}></div>`;
    }
    return html`
      <button
        part="method"
        class="google"
        type="button"
        title=${m.description}
        data-method=${m.id}
        @click=${() => this.onMethodChosen(m)}
      >
        ${googleLogo}
        <span class="label">${m.label}</span>
      </button>
    `;
  }

  private renderPassword(m: LoginMethod) {
    const onSubmit = (e: Event) => {
      e.preventDefault();
      this.onMethodChosen(m);
    };
    return html`
      <form @submit=${onSubmit}>
        <div class="field">
          <label for="username">Username</label>
          <input id="username" name="username" type="text" autocomplete="username" />
        </div>
        <div class="field">
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" />
        </div>
        <button part="method" class="submit" type="submit" data-method=${m.id}>
          <span class="label">Sign in</span>
        </button>
      </form>
    `;
  }

  private renderRow(m: LoginMethod) {
    return html`
      <button
        part="method"
        class="row"
        type="button"
        title=${m.description}
        data-method=${m.id}
        @click=${() => this.onMethodChosen(m)}
      >
        ${rowIcons[m.id]}
        <span class="label">${m.label}</span>
        ${chevronIcon}
      </button>
    `;
  }

  static override styles = css`
    :host {
      /* Follows the user's preference; a page can force a theme by setting color-scheme on the element. */
      color-scheme: light dark;
      --_primary: var(--madauth-primary, light-dark(#17181a, #f1f2f3));
      --_on-primary: light-dark(#fff, #17181a);
      --_radius: var(--madauth-radius, 14px);
      --_control-radius: max(0px, calc(var(--_radius) - 6px));
      --_group-radius: max(0px, calc(var(--_radius) - 4px));
      --_control-height: 44px;
      --_surface: light-dark(#fff, #1b1c1f);
      --_text: light-dark(#17181a, #f1f2f3);
      --_muted: light-dark(#5c6066, #a6a9af);
      --_subtle: light-dark(#8f9298, #70747b);
      --_line: light-dark(#dedfe2, #2e3034);
      --_dialog-border: light-dark(rgb(23 24 26 / 0.08), #2e3034);
      --_button-bg: light-dark(#fff, #232428);
      --_button-border: light-dark(#d0d2d6, #3d4045);
      --_field-bg: light-dark(#fff, #141517);
      --_hover: light-dark(#f3f4f5, #26272b);
      --_shadow:
        0 24px 64px -12px light-dark(rgb(16 18 22 / 0.32), rgb(0 0 0 / 0.7)),
        0 2px 6px light-dark(rgb(16 18 22 / 0.08), rgb(0 0 0 / 0.4));
      /* Public Sans when the page has loaded it (see docs/styling.md), the system font otherwise. */
      font-family: var(--madauth-font, 'Public Sans Variable', 'Public Sans', system-ui, sans-serif);
    }

    @supports (color: oklch(from red l c h)) {
      :host {
        /* Whatever the primary color is: near-black text on a light one, white on a dark one. */
        --_on-primary: oklch(from var(--_primary) clamp(0.2, (0.6 - l) * 1000, 1) 0 0);
      }
    }

    dialog {
      width: min(400px, calc(100vw - 32px));
      box-sizing: border-box;
      padding: 0;
      border: 1px solid var(--_dialog-border);
      border-radius: var(--_radius);
      box-shadow: var(--_shadow);
      color: var(--_text);
      background: var(--_surface);
      font: inherit;
    }

    dialog::backdrop {
      background: light-dark(rgb(16 18 22 / 0.4), rgb(0 0 0 / 0.6));
    }

    .panel {
      display: grid;
      gap: 20px;
      padding: 32px;
      font-size: 0.9375rem;
      letter-spacing: 0.02em;
    }

    button,
    input {
      font: inherit;
      letter-spacing: inherit;
      color: inherit;
    }

    button {
      cursor: pointer;
    }

    button:focus-visible {
      outline: 2px solid var(--_text);
      outline-offset: 2px;
    }

    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      height: 28px;
    }

    h2 {
      margin: 0;
      font-size: 1.375rem;
      font-weight: 600;
      line-height: 28px;
      letter-spacing: normal;
    }

    .icon {
      flex-shrink: 0;
      width: 18px;
      height: 18px;
      fill: none;
      stroke: currentColor;
      stroke-width: 1.75;
      stroke-linecap: round;
      stroke-linejoin: round;
    }

    .logo {
      flex-shrink: 0;
      width: 18px;
      height: 18px;
    }

    .close {
      flex-shrink: 0;
      display: grid;
      place-items: center;
      width: 44px;
      height: 44px;
      margin-right: -12px;
      padding: 0;
      border: none;
      border-radius: var(--_control-radius);
      color: var(--_muted);
      background: none;
    }

    .close:hover {
      color: var(--_text);
      background: var(--_hover);
    }

    .close .icon {
      stroke-width: 2;
    }

    .google {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      height: var(--_control-height);
      padding: 0 16px;
      font-weight: 500;
      border: 1px solid var(--_button-border);
      border-radius: var(--_control-radius);
      background: var(--_button-bg);
    }

    .notice {
      display: flex;
      gap: 8px;
      margin: 0;
      padding: 10px 12px;
      font-size: 0.8125rem;
      line-height: 18px;
      border-radius: var(--_control-radius);
      background: var(--_hover);
    }

    .notice .icon {
      color: var(--_muted);
    }

    .error,
    .error .icon {
      color: light-dark(#b42318, #fda29b);
    }

    .error {
      background: light-dark(#fef3f2, rgb(240 68 56 / 0.12));
    }

    .google-slot {
      /* Google's button is an iframe with a light page. If the iframe's color-scheme differed, the
         browser would paint it with an opaque background (a white box in dark mode). */
      color-scheme: light;
      display: flex;
      justify-content: center;
      min-height: var(--_control-height);
    }

    .google:hover {
      border-color: var(--_subtle);
      background: var(--_hover);
    }

    .divider {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 0.8125rem;
      line-height: 18px;
      color: var(--_muted);
    }

    .divider::before,
    .divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--_line);
    }

    form {
      display: grid;
      gap: 16px;
    }

    .field {
      display: grid;
      gap: 6px;
    }

    label {
      font-size: 0.8125rem;
      font-weight: 500;
      line-height: 18px;
    }

    input {
      width: 100%;
      height: var(--_control-height);
      box-sizing: border-box;
      padding: 0 12px;
      border: 1px solid var(--_subtle);
      border-radius: var(--_control-radius);
      background: var(--_field-bg);
    }

    input:focus-visible {
      outline: 2px solid var(--_text);
      outline-offset: -1px;
    }

    .submit {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      height: var(--_control-height);
      margin-top: 4px;
      padding: 0 16px;
      font-weight: 600;
      border: none;
      border-radius: var(--_control-radius);
      color: var(--_on-primary);
      background: var(--_primary);
    }

    .submit:hover {
      background: color-mix(in srgb, var(--_primary) 86%, var(--_surface));
    }

    .others {
      display: grid;
      gap: 10px;
      margin-top: 4px;
    }

    h3 {
      margin: 0;
      font-size: 0.8125rem;
      font-weight: 400;
      line-height: 18px;
      color: var(--_muted);
    }

    ul {
      list-style: none;
      margin: 0;
      padding: 0;
      border: 1px solid var(--_line);
      border-radius: var(--_group-radius);
    }

    li + li {
      border-top: 1px solid var(--_line);
    }

    .row {
      width: 100%;
      display: flex;
      align-items: center;
      gap: 12px;
      height: calc(var(--_control-height) + 4px);
      padding: 0 12px 0 14px;
      text-align: left;
      font-weight: 500;
      border: none;
      border-radius: 0;
      background: none;
    }

    li:first-child .row {
      border-top-left-radius: calc(var(--_group-radius) - 1px);
      border-top-right-radius: calc(var(--_group-radius) - 1px);
    }

    li:last-child .row {
      border-bottom-left-radius: calc(var(--_group-radius) - 1px);
      border-bottom-right-radius: calc(var(--_group-radius) - 1px);
    }

    .row .label {
      flex: 1;
    }

    .row .icon {
      color: var(--_muted);
    }

    .row .chevron {
      width: 16px;
      height: 16px;
      stroke-width: 2;
      color: var(--_subtle);
    }

    .row:hover {
      background: var(--_hover);
    }

    .row:hover .icon {
      color: var(--_text);
    }

    @media (max-width: 480px) {
      :host {
        --_control-height: 48px;
      }
      .panel {
        padding: 24px;
        /* 16px text keeps iOS from zooming into a focused field. */
        font-size: 1rem;
      }
      label,
      h3 {
        font-size: 0.875rem;
      }
    }
  `;
}

declare global {
  interface HTMLElementTagNameMap {
    'madauth-login': MadauthLogin;
  }
  interface HTMLElementEventMap {
    'madauth-signed-in': CustomEvent<SignedInDetail>;
    'madauth-cancel': CustomEvent<void>;
    'madauth-error': CustomEvent<ErrorDetail>;
  }
}
