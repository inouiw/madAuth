import { LitElement, css, html, type TemplateResult } from 'lit';
import {
  Madauth,
  currentLocale,
  onLocaleChanged,
  providerFor,
  readyForDialog,
  takePendingError,
  takePendingStep,
  type SignInOptions,
} from './madauth.js';
import { loginMethods, type LoginMethod, type LoginMethodId } from './methods.js';
import type { PendingStep } from './providers/provider.js';
import { qrModules, qrViewBox, type QrModules } from './qr.js';
import type { MadauthError, MadauthErrorCode, MadauthUser, Result } from './result.js';
import { languageOf, stringsFor, type Strings } from './strings.js';

export interface SignedInDetail {
  method: LoginMethodId;
  user: MadauthUser;
}

export type ErrorDetail = { method?: LoginMethodId } & MadauthError;

/** The authenticator app was set up and the recovery codes shown. */
export interface AuthenticatorEnabledDetail {
  recoveryCodes: string[];
}

/** The screens of the dialog. */
type View = 'signin' | 'signup' | 'check-inbox' | 'forgot' | 'reset' | 'totp' | 'totp-code' | 'totp-setup' | 'totp-codes';

/** The step a sign-in goes on with, from the error that says so. */
function nextStep(error: MadauthError): PendingStep['step'] | undefined {
  return error.code === 'totp_required' ? 'code' : error.code === 'totp_setup_required' ? 'setup' : undefined;
}

/** The key in groups of four, as authenticator apps show it. */
const groupSecret = (secret: string) => secret.replace(/(.{4})(?=.)/g, '$1 ');

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
 * It is built only on the public `Madauth` API, so a custom login screen can do everything it does.
 *
 * @fires madauth-signed-in - A user signed in. `detail` is a {@link SignedInDetail}.
 * @fires madauth-cancel - The dialog was closed without signing in (or before the authenticator app was set up).
 * @fires madauth-error - A sign-in failed, or madAuth is not initialized. `detail` is an {@link ErrorDetail}.
 * @fires madauth-authenticator-enabled - The signed-in user set up the authenticator app and saw the recovery codes. `detail` is an {@link AuthenticatorEnabledDetail}.
 *
 * @cssprop --madauth-primary - Fill color of the primary buttons.
 * @cssprop --madauth-radius - Corner radius of the dialog, buttons and fields.
 * @cssprop --madauth-font - Font family.
 *
 * @csspart dialog - The `<dialog>` element.
 * @csspart method - Each sign-in method button.
 * @csspart error - The error message.
 * @csspart form - Each form (sign-in, create account, code, new password, the authenticator app's).
 * @csspart input - Each text field.
 * @csspart link - The text buttons, e.g. "Forgot password?".
 * @csspart qr - The QR code of the authenticator app's key (an inline SVG, dark on a white background).
 * @csspart codes - The list of recovery codes.
 */
export class MadauthLogin extends LitElement {
  static override properties = {
    heading: { type: String },
    notice: { state: true },
    error: { state: true },
    usable: { state: true },
    view: { state: true },
    busy: { state: true },
    email: { state: true },
    setup: { state: true },
    recoveryCodes: { state: true },
    useRecovery: { state: true },
  };

  /** Title shown at the top of the dialog. Default: "Sign in" in the dialog's language. */
  heading = '';

  /** Message shown below the heading, e.g. after picking a method that is not available yet. */
  private notice?: (strings: Strings) => string;

  /** Error shown below the heading. */
  private error: (MadauthError & { method?: LoginMethodId }) | null = null;

  /** Whether madAuth is initialized, so providers can render their sign-in UI. */
  private usable = false;

  private view: View = 'signin';

  /** A request is running; the buttons are disabled meanwhile. */
  private busy = false;

  /** The e-mail address last entered, kept across the views. */
  private email = '';

  /** What the e-mail in the check-inbox view is for. */
  private inboxPurpose: 'verify' | 'reset' = 'verify';

  /** The reset code entered in the check-inbox view, used with the new password. */
  private resetCode?: string;

  /** Length of the password last sent for a new account or a reset, to explain a `weak_password` error. */
  private passwordLength = 0;

  /** The method whose sign-in is under way: for the second step, and for a sign-up with the authenticator app. */
  private primary: LoginMethodId = 'password';

  /** The authenticator app's setup in progress: the key to show as QR code and as text. */
  private setup?: { secret: string; qr: QrModules };

  /** Whether the setup is a step of a sign-in (the policy requires the app), as opposed to the signed-in user's choice. */
  private setupForSignIn = false;

  /** The recovery codes to show once the app is set up, and the user when the setup finished a sign-in. */
  private recoveryCodes?: string[];
  private setupUser?: MadauthUser;

  /** A recovery code instead of a code from the app. */
  private useRecovery = false;

  private stopFollowingLocale?: () => void;

  /** Google's button, rendered into the slot of the sign-in view. */
  private googleButton?: { slot: Element; remove(): void };

  override connectedCallback(): void {
    super.connectedCallback();
    // Madauth.setLocale shows an open dialog in the new language.
    this.stopFollowingLocale = onLocaleChanged(() => this.requestUpdate());
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.stopFollowingLocale?.();
  }

  /**
   * Opens the dialog as a modal. Opens on the "new password" form when the page came from a reset link.
   * `email` fills the e-mail field.
   */
  async open(options: SignInOptions = {}): Promise<void> {
    const email = typeof options.email === 'string' ? options.email.trim() : '';
    if (email) this.email = email;
    const ready = await this.show();
    if (!ready) return;
    if (ready.isSuccess && Madauth.password.pendingReset) this.view = 'reset';
    // A sign-in that started outside the dialog (the redirect flow, an e-mail link) goes on with the app.
    const pending = ready.isSuccess ? takePendingStep() : undefined;
    if (pending) this.continueWith(pending);
    const error = ready.isSuccess ? takePendingError() : ready.error;
    if (error) this.showError(error);
    // Reopened with nothing changed there is no re-render, so render Google's button here.
    await this.updateComplete;
    this.syncGoogleButton();
    if (email) this.prefill(email);
  }

  /**
   * Opens the dialog on the "Set up authenticator app" screen for the signed-in user. Usually called
   * through `Madauth.setUpAuthenticator()`, which resolves once the recovery codes were shown.
   */
  async openAuthenticatorSetup(): Promise<void> {
    this.setupForSignIn = false;
    this.view = 'totp-setup';
    const ready = await this.show();
    if (!ready) return;
    if (!ready.isSuccess) {
      this.showError(ready.error, 'totp');
      return;
    }
    await this.startSetup();
  }

  /** Shows the dialog and waits for madAuth; undefined if the dialog was closed meanwhile. */
  private async show(): Promise<Result | undefined> {
    await this.updateComplete;
    this.dialog.showModal();
    const ready = await readyForDialog();
    if (!this.dialog.open) return undefined;
    this.usable = ready.isSuccess;
    // What the views show depends on the providers and the server's settings, which a new initialize may have changed.
    this.requestUpdate();
    return ready;
  }

  /** Goes on with the authenticator app where a sign-in left off. */
  private continueWith(pending: PendingStep): void {
    this.primary = pending.method;
    this.useRecovery = false;
    if (pending.step === 'code') {
      this.view = 'totp-code';
      return;
    }
    this.setupForSignIn = true;
    this.view = 'totp-setup';
    void this.startSetup();
  }

  /** Shows `email` in the e-mail field, also if the field was edited since, and moves on to the password. */
  private prefill(email: string): void {
    const field = this.renderRoot.querySelector<HTMLInputElement>('input[name="email"]');
    if (field) field.value = email;
    if (this.passwordAvailable) this.renderRoot.querySelector<HTMLInputElement>('form.signin input[name="password"]')?.focus();
  }

  /** Closes the dialog without firing `madauth-cancel`. */
  close(): void {
    this.dialog.close('done');
  }

  private get dialog(): HTMLDialogElement {
    return this.renderRoot.querySelector('dialog')!;
  }

  /** The texts in the dialog's language, looked up once per update. */
  private strings: Strings = stringsFor(currentLocale());

  override willUpdate(): void {
    this.strings = stringsFor(currentLocale());
  }

  override updated(): void {
    this.syncGoogleButton();
  }

  /** Renders Google's button while the sign-in view is shown, and removes it otherwise. */
  private syncGoogleButton(): void {
    const slot = this.dialog.open ? this.renderRoot.querySelector('.google-slot') : null;
    if (this.googleButton && this.googleButton.slot !== slot) {
      this.googleButton.remove();
      this.googleButton = undefined;
    }
    if (slot instanceof HTMLElement && !this.googleButton) {
      const rendered = Madauth.google.renderButton(slot, { onResult: (result) => this.finish('google', result) });
      if (rendered.isSuccess) this.googleButton = { slot, remove: rendered.remove };
    }
  }

  private onDialogClose(): void {
    this.googleButton?.remove();
    this.googleButton = undefined;
    // Closing the recovery codes counts as having seen them: the app is set up either way.
    if (this.view === 'totp-codes') this.completeSetup();
    if (this.dialog.returnValue !== 'done') {
      this.dispatchEvent(new CustomEvent('madauth-cancel', { bubbles: true, composed: true }));
    }
    this.dialog.returnValue = '';
    this.notice = undefined;
    this.error = null;
    this.view = 'signin';
    this.busy = false;
    this.resetCode = undefined;
    this.primary = 'password';
    this.setup = undefined;
    this.setupForSignIn = false;
    this.recoveryCodes = undefined;
    this.setupUser = undefined;
    this.useRecovery = false;
  }

  /**
   * Ends a sign-in attempt: closes on success, goes on with the authenticator app when the method's
   * policy asks for it, and shows the error otherwise.
   */
  private finish(method: LoginMethodId, result: Result<{ user: MadauthUser }>): void {
    if (!result.isSuccess) {
      const step = nextStep(result.error);
      if (step) {
        this.continueWith({ step, method });
        this.notice = undefined;
        this.error = null;
        return;
      }
      this.showError(result.error, method);
      return;
    }
    const detail: SignedInDetail = { method, user: result.user };
    this.dispatchEvent(new CustomEvent('madauth-signed-in', { detail, bubbles: true, composed: true }));
    this.close();
  }

  /** The recovery codes were seen: the setup is done, and a sign-in that waited for it is finished. */
  private completeSetup(): void {
    const recoveryCodes = this.recoveryCodes;
    if (!recoveryCodes) return;
    this.recoveryCodes = undefined;
    if (this.setupUser) {
      const detail: SignedInDetail = { method: this.primary, user: this.setupUser };
      this.dispatchEvent(new CustomEvent('madauth-signed-in', { detail, bubbles: true, composed: true }));
    } else {
      const detail: AuthenticatorEnabledDetail = { recoveryCodes };
      this.dispatchEvent(new CustomEvent('madauth-authenticator-enabled', { detail, bubbles: true, composed: true }));
    }
    this.dialog.returnValue = 'done';
    if (this.dialog.open) this.dialog.close('done');
  }

  private showError(error: MadauthError, method?: LoginMethodId): void {
    this.notice = undefined;
    this.error = { ...error, method };
    const detail: ErrorDetail = { ...error, method };
    this.dispatchEvent(new CustomEvent('madauth-error', { detail, bubbles: true, composed: true }));
  }

  private onBackdropClick(e: MouseEvent): void {
    // Clicks on the backdrop target the <dialog> itself; clicks inside hit its children.
    if (e.target === this.dialog) this.dialog.close();
  }

  private onMethodChosen(m: LoginMethod): void {
    if (!providerFor(m.id)) {
      this.error = null;
      this.notice = (strings) => strings.comingSoon(strings.methods[m.id].label);
      return;
    }
    if (m.id === 'totp' && this.totpAvailable) {
      this.useRecovery = false;
      this.goTo('totp');
    }
  }

  private get passwordAvailable(): boolean {
    return this.usable && !!providerFor('password');
  }

  /** Whether the authenticator app signs in on its own here (the e-mail address and a code). */
  private get totpAvailable(): boolean {
    return this.usable && !!providerFor('totp') && !!Madauth.totp.policy?.signIn;
  }

  /** Switches the view, keeping the e-mail address typed so far. */
  private goTo(view: View): void {
    const typed = this.renderRoot.querySelector<HTMLInputElement>('input[name="email"]')?.value;
    if (typed !== undefined) this.email = typed.trim();
    this.notice = undefined;
    this.error = null;
    this.view = view;
  }

  /** Runs one request at a time, with the buttons disabled. */
  private async run<T>(task: () => Promise<T>): Promise<T | undefined> {
    if (this.busy) return undefined;
    this.busy = true;
    this.notice = undefined;
    this.error = null;
    try {
      return await task();
    } finally {
      this.busy = false;
    }
  }

  private fields(e: Event): Record<string, string> {
    e.preventDefault();
    const data = new FormData(e.target as HTMLFormElement);
    return Object.fromEntries([...data.entries()].map(([k, v]) => [k, String(v)]));
  }

  private async onSignIn(e: Event, m: LoginMethod): Promise<void> {
    const { email = '', password = '' } = this.fields(e);
    if (!this.passwordAvailable) {
      this.onMethodChosen(m);
      return;
    }
    this.email = email.trim();
    const result = await this.run(() => Madauth.password.signIn({ email, password }));
    if (result) this.finish('password', result);
  }

  private async onSignUp(e: Event): Promise<void> {
    const { email = '', password = '', name = '' } = this.fields(e);
    this.email = email.trim();
    this.passwordLength = [...password].length;
    const withApp = this.primary === 'totp';
    const result = await this.run(() =>
      withApp
        ? Madauth.totp.signUp({ email, name: name.trim() || undefined })
        : Madauth.password.signUp({ email, password, name: name.trim() || undefined }),
    );
    if (!result) return;
    if (!result.isSuccess) {
      this.showError(result.error, this.primary);
      return;
    }
    this.inboxPurpose = 'verify';
    this.view = 'check-inbox';
  }

  /** The scope that confirms the address of the sign-up under way: the password's, or the authenticator app's. */
  private get signUpScope() {
    return this.primary === 'totp' ? Madauth.totp : Madauth.password;
  }

  private async onForgot(e: Event): Promise<void> {
    const { email = '' } = this.fields(e);
    this.email = email.trim();
    const result = await this.run(() => Madauth.password.sendResetEmail({ email }));
    if (!result) return;
    if (!result.isSuccess) {
      this.showError(result.error, 'password');
      return;
    }
    this.inboxPurpose = 'reset';
    this.view = 'check-inbox';
  }

  private async onCode(e: Event): Promise<void> {
    const code = (this.fields(e).code ?? '').replace(/\s/g, '');
    if (this.inboxPurpose === 'reset') {
      // The code is checked together with the new password.
      this.resetCode = code;
      this.goTo('reset');
      return;
    }
    const result = await this.run(() => this.signUpScope.verifyEmail({ email: this.email, code }));
    if (result) this.finish(this.primary, result);
  }

  private async onReset(e: Event): Promise<void> {
    const { password = '' } = this.fields(e);
    this.passwordLength = [...password].length;
    const code = this.resetCode;
    const result = await this.run(() =>
      Madauth.password.confirmReset(code ? { newPassword: password, email: this.email, code } : { newPassword: password }),
    );
    if (!result) return;
    if (!result.isSuccess && result.error.code === 'code_invalid') {
      // Back to the code field, so it can be corrected.
      this.resetCode = undefined;
      this.view = 'check-inbox';
    }
    this.finish('password', result);
  }

  private async resend(purpose: 'verify' | 'reset'): Promise<void> {
    const email = this.email;
    const result = await this.run(() =>
      purpose === 'verify' ? this.signUpScope.sendVerificationEmail({ email }) : Madauth.password.sendResetEmail({ email }),
    );
    if (!result) return;
    if (!result.isSuccess) {
      this.showError(result.error, purpose === 'verify' ? this.primary : 'password');
      return;
    }
    this.inboxPurpose = purpose;
    this.view = 'check-inbox';
    this.notice = (strings) => strings.emailSentAgain;
  }

  private get viewTitle(): string {
    const s = this.strings;
    switch (this.view) {
      case 'signup':
        return s.createAccount;
      case 'check-inbox':
        return s.checkInbox;
      case 'forgot':
        return s.resetPassword;
      case 'reset':
        return s.chooseNewPassword;
      case 'totp':
        return s.methods.totp.label;
      case 'totp-code':
        return s.totpCode.heading;
      case 'totp-setup':
        return s.totpSetup.heading;
      case 'totp-codes':
        return s.totpCodes.heading;
      default:
        return this.heading || s.signIn;
    }
  }

  /** What the dialog tells the user; the technical details are in the `madauth-error` event and the console. */
  private errorText(error: MadauthError & { method?: LoginMethodId }): string {
    const s = this.strings;
    // Written by the operator's sign-up check, which gets the user's locale.
    if (error.code === 'signup_rejected') return error.message;
    if (error.code === 'weak_password') {
      const minLength = Madauth.password.policy?.minLength;
      return s.weakPassword(error.message, minLength && this.passwordLength < minLength ? minLength : undefined);
    }
    if (error.code === 'too_many_attempts') return s.tooManyAttempts(error.message);
    if (error.code === 'temporarily_unavailable') return this.view === 'signup' ? s.signUpUnavailable : s.emailsUnavailable;
    if (error.code === 'email_unverified' && error.method === 'password') return s.confirmEmailFirst;
    if (error.code === 'invalid_credentials' && error.method === 'totp') return s.totpInvalid;
    if (error.code === 'other_method' && error.methods?.length) {
      const names: Partial<Record<string, string>> = s.methodNames;
      return s.otherMethod(error.methods.map((method) => names[method] ?? method).join(s.and));
    }
    const texts: Partial<Record<MadauthErrorCode, string>> = s.errors;
    return texts[error.code] ?? s.errorFallback;
  }

  override render() {
    const s = this.strings;
    return html`
      <dialog part="dialog" lang=${languageOf(currentLocale())} @close=${this.onDialogClose} @click=${this.onBackdropClick}>
        <div class="panel">
          <header>
            <h2>${this.viewTitle}</h2>
            <button class="close" type="button" aria-label=${s.close} @click=${() => this.dialog.close()}>
              ${closeIcon}
            </button>
          </header>
          ${this.notice
            ? html`<p class="notice" role="status">${infoIcon}<span>${this.notice(s)}</span></p>`
            : null}
          ${this.error ? this.renderError(this.error) : null}
          ${this.renderView()}
        </div>
      </dialog>
    `;
  }

  private renderError(error: MadauthError & { method?: LoginMethodId }) {
    const resend = error.code === 'email_unverified' && error.method === 'password' && this.view === 'signin';
    const restart = error.code === 'setup_expired' && this.view === 'totp-setup';
    return html`
      <div class="notice error" part="error" role="alert" data-code=${error.code}>
        ${infoIcon}
        <span>
          ${this.errorText(error)}
          ${resend
            ? html`<button class="link" part="link" type="button" data-action="resend-verification" ?disabled=${this.busy}
                @click=${() => this.resend('verify')}>${this.strings.sendEmailAgain}</button>`
            : null}
          ${restart
            ? html`<button class="link" part="link" type="button" data-action="restart-setup" ?disabled=${this.busy}
                @click=${() => this.startSetup()}>${this.strings.totpSetup.startAgain}</button>`
            : null}
        </span>
      </div>
    `;
  }

  private renderView() {
    switch (this.view) {
      case 'signup':
        return this.renderSignUp();
      case 'check-inbox':
        return this.renderCheckInbox();
      case 'forgot':
        return this.renderForgot();
      case 'reset':
        return this.renderReset();
      case 'totp':
        return this.renderTotp();
      case 'totp-code':
        return this.renderTotpCode();
      case 'totp-setup':
        return this.renderTotpSetup();
      case 'totp-codes':
        return this.renderTotpCodes();
      default:
        return this.renderSignInView();
    }
  }

  private renderSignInView() {
    const google = loginMethods.find((m) => m.id === 'google');
    const password = loginMethods.find((m) => m.id === 'password');
    // The authenticator app is listed when it signs in on its own; with its provider but without that, not at all.
    const others = loginMethods.filter((m) => m !== google && m !== password && (m.id !== 'totp' || !providerFor('totp') || this.totpAvailable));
    const s = this.strings;
    return html`
      ${google ? this.renderGoogle(google) : null}
      ${google && password ? html`<div class="divider">${s.or}</div>` : null}
      ${password ? this.renderPassword(password) : null}
      ${others.length
        ? html`
            <section class="others">
              <h3>${s.otherWays}</h3>
              <ul>
                ${others.map((m) => html`<li>${this.renderRow(m)}</li>`)}
              </ul>
            </section>
          `
        : null}
    `;
  }

  private renderGoogle(m: LoginMethod) {
    const { label, description } = this.strings.methods[m.id];
    if (this.usable && providerFor('google')) {
      // Google's button is rendered here through Madauth.google.renderButton.
      return html`<div class="google-slot" title=${description}></div>`;
    }
    return html`
      <button
        part="method"
        class="google"
        type="button"
        title=${description}
        data-method=${m.id}
        @click=${() => this.onMethodChosen(m)}
      >
        ${googleLogo}
        <span class="label">${label}</span>
      </button>
    `;
  }

  private renderPassword(m: LoginMethod) {
    const s = this.strings;
    return html`
      <form part="form" class="signin" @submit=${(e: Event) => this.onSignIn(e, m)}>
        ${this.emailField('email')}
        <div class="field">
          <label for="password">${s.password}</label>
          <input part="input" id="password" name="password" type="password" autocomplete="current-password" />
        </div>
        <button part="method" class="submit" type="submit" data-method=${m.id} ?disabled=${this.busy}>
          <span class="label">${s.signIn}</span>
        </button>
      </form>
      ${this.passwordAvailable
        ? html`
            <p class="links">
              <button class="link" part="link" type="button" data-action="forgot" @click=${() => this.goTo('forgot')}>
                ${s.forgotPassword}
              </button>
              <button class="link" part="link" type="button" data-action="signup" @click=${() => this.startSignUp('password')}>
                ${s.createAccount}
              </button>
            </p>
          `
        : null}
    `;
  }

  /** To the "Create account" form, with a password or with the authenticator app alone. */
  private startSignUp(method: 'password' | 'totp'): void {
    this.primary = method;
    this.goTo('signup');
  }

  private renderSignUp() {
    const s = this.strings;
    const withApp = this.primary === 'totp';
    const minLength = Madauth.password.policy?.minLength;
    return html`
      ${withApp ? html`<p class="hint">${s.totpSignUpHint}</p>` : null}
      <form part="form" class="signup" @submit=${this.onSignUp}>
        <div class="field">
          <label for="name">${s.name} <span class="optional">${s.optional}</span></label>
          <input part="input" id="name" name="name" type="text" autocomplete="name" />
        </div>
        ${this.emailField('email')}
        ${withApp
          ? null
          : html`
              <div class="field">
                <label for="new-password">${s.password}</label>
                <input part="input" id="new-password" name="password" type="password" autocomplete="new-password" />
                ${minLength ? html`<p class="hint">${s.minLength(minLength)}</p>` : null}
              </div>
            `}
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.createAccount}</span>
        </button>
      </form>
      ${this.backLink(s.haveAccount)}
    `;
  }

  // --- The authenticator app ---

  /** The field for the code from the app, or for a recovery code. */
  private codeField() {
    const s = this.strings;
    return this.useRecovery
      ? html`
          <div class="field">
            <label for="recovery-code">${s.recoveryCode}</label>
            <input part="input" id="recovery-code" name="recoveryCode" type="text" autocomplete="off" spellcheck="false" />
          </div>
        `
      : html`
          <div class="field">
            <label for="code">${s.appCode}</label>
            <input part="input" id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="7" />
            <p class="hint">${s.totpHint}</p>
          </div>
        `;
  }

  /** What was typed into {@link codeField}, as the scope takes it. */
  private codeOptions(fields: Record<string, string>): { code: string } | { recoveryCode: string } {
    return this.useRecovery ? { recoveryCode: (fields.recoveryCode ?? '').trim() } : { code: (fields.code ?? '').replace(/\s/g, '') };
  }

  private toggleRecoveryLink() {
    const s = this.strings;
    return html`
      <button class="link" part="link" type="button" data-action="toggle-recovery" @click=${() => (this.useRecovery = !this.useRecovery)}>
        ${this.useRecovery ? s.useApp : s.useRecoveryCode}
      </button>
    `;
  }

  /** Signing in with the app alone: the e-mail address and a code. */
  private renderTotp() {
    const s = this.strings;
    return html`
      <form part="form" class="totp" @submit=${this.onTotpSignIn}>
        ${this.emailField('email')}
        ${this.codeField()}
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.signIn}</span>
        </button>
      </form>
      <p class="links">
        ${this.toggleRecoveryLink()}
        ${Madauth.totp.policy?.signUp
          ? html`<button class="link" part="link" type="button" data-action="signup" @click=${() => this.startSignUp('totp')}>${s.createAccount}</button>`
          : null}
        <button class="link" part="link" type="button" data-action="back" @click=${() => this.goTo('signin')}>${s.backToSignIn}</button>
      </p>
    `;
  }

  private async onTotpSignIn(e: Event): Promise<void> {
    const fields = this.fields(e);
    this.email = (fields.email ?? '').trim();
    const result = await this.run(() => Madauth.totp.signIn({ email: this.email, ...this.codeOptions(fields) }));
    if (result) this.finish('totp', result);
  }

  /** The second step after a password or Google sign-in. */
  private renderTotpCode() {
    const s = this.strings;
    return html`
      <p class="lead">${s.totpCode.lead}</p>
      <form part="form" class="totp-code" @submit=${this.onTotpVerify}>
        ${this.codeField()}
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.continue}</span>
        </button>
      </form>
      <p class="links">
        ${this.toggleRecoveryLink()}
        <button class="link" part="link" type="button" data-action="back" @click=${() => this.goTo('signin')}>${s.backToSignIn}</button>
      </p>
    `;
  }

  private async onTotpVerify(e: Event): Promise<void> {
    const fields = this.fields(e);
    const result = await this.run(() => Madauth.totp.verify(this.codeOptions(fields)));
    if (!result) return;
    if (!result.isSuccess && result.error.code === 'challenge_expired') {
      // The sign-in starts over.
      this.goTo('signin');
      this.showError(result.error, this.primary);
      return;
    }
    this.finish(this.primary, result);
  }

  /** Setting the app up: the QR code (and the key as text), and the first code from the app. */
  private renderTotpSetup() {
    const s = this.strings;
    const setup = this.setup;
    const policy = Madauth.totp.policy;
    const asks = (policy?.secondFactorFor ?? []).map((method) => s.methods[method].label).join(s.and);
    return html`
      <p class="lead">${this.setupForSignIn ? s.totpSetup.requiredLead : s.totpSetup.lead}</p>
      ${!this.setupForSignIn && asks ? html`<p class="hint">${s.totpSetup.effects.secondFactor(asks)}</p>` : null}
      ${!this.setupForSignIn && policy?.signIn ? html`<p class="hint">${s.totpSetup.effects.standalone}</p>` : null}
      ${setup
        ? html`
            <svg part="qr" class="qr" viewBox=${qrViewBox(setup.qr.size)} role="img" aria-label=${s.totpSetup.qrLabel} shape-rendering="crispEdges">
              <path d=${setup.qr.d} fill="currentColor" />
            </svg>
            <p class="hint">${s.totpSetup.cantScan} <code class="secret">${groupSecret(setup.secret)}</code></p>
            <form part="form" class="totp-setup" @submit=${this.onConfirmSetup}>
              <div class="field">
                <label for="code">${s.appCode}</label>
                <input part="input" id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="7" />
              </div>
              <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
                <span class="label">${s.totpSetup.turnOn}</span>
              </button>
            </form>
          `
        : this.busy
          ? html`<p class="hint" role="status">${s.loading}</p>`
          : null}
      <p class="links">
        <button class="link" part="link" type="button" data-action="cancel" @click=${() => this.dialog.close()}>${s.cancel}</button>
      </p>
    `;
  }

  /** Asks the server for a new key and shows it: the first step of the setup, also after "Start again". */
  private async startSetup(): Promise<void> {
    this.setup = undefined;
    const result = await this.run(() => Madauth.totp.startSetup());
    if (!result) return;
    if (!result.isSuccess) {
      this.showError(result.error, 'totp');
      return;
    }
    this.setup = { secret: result.secret, qr: qrModules(result.uri) };
    await this.updateComplete;
    this.renderRoot.querySelector<HTMLInputElement>('form.totp-setup input[name="code"]')?.focus();
  }

  private async onConfirmSetup(e: Event): Promise<void> {
    const code = (this.fields(e).code ?? '').replace(/\s/g, '');
    const result = await this.run(() => Madauth.totp.confirmSetup({ code }));
    if (!result) return;
    if (!result.isSuccess) {
      // The key on the screen is of no use any more; "Start again" gets a new one.
      if (result.error.code === 'setup_expired') this.setup = undefined;
      this.showError(result.error, 'totp');
      return;
    }
    this.recoveryCodes = result.recoveryCodes;
    this.setupUser = result.user;
    this.setup = undefined;
    this.goTo('totp-codes');
  }

  /** The recovery codes, shown once. */
  private renderTotpCodes() {
    const s = this.strings;
    return html`
      <p class="lead">${s.totpCodes.lead}</p>
      <ol part="codes" class="codes">
        ${(this.recoveryCodes ?? []).map((code) => html`<li><code>${code}</code></li>`)}
      </ol>
      <button part="method" class="submit" type="button" data-action="saved" @click=${() => this.completeSetup()}>
        <span class="label">${s.totpCodes.saved}</span>
      </button>
    `;
  }

  private renderForgot() {
    const s = this.strings;
    return html`
      <p class="lead">${s.forgotLead}</p>
      ${providerFor('google') ? html`<p class="hint">${s.forgotGoogleHint}</p>` : null}
      <form part="form" class="forgot" @submit=${this.onForgot}>
        ${this.emailField('email')}
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.sendEmail}</span>
        </button>
      </form>
      ${this.backLink()}
    `;
  }

  private renderCheckInbox() {
    const s = this.strings;
    return html`
      <p class="lead">${s.inboxLead.before}<strong>${this.email}</strong>${s.inboxLead.after}</p>
      <form part="form" class="code" @submit=${this.onCode}>
        <div class="field">
          <label for="code">${s.code}</label>
          <input part="input" id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="7" />
        </div>
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.continue}</span>
        </button>
      </form>
      <p class="links">
        <button class="link" part="link" type="button" data-action="resend" ?disabled=${this.busy}
          @click=${() => this.resend(this.inboxPurpose)}>${s.sendEmailAgain}</button>
        <button class="link" part="link" type="button" data-action="back" @click=${() => this.goTo('signin')}>${s.backToSignIn}</button>
      </p>
    `;
  }

  private renderReset() {
    const s = this.strings;
    const minLength = Madauth.password.policy?.minLength;
    return html`
      <form part="form" class="reset" @submit=${this.onReset}>
        ${this.email
          ? html`<input type="email" name="username" autocomplete="username" .value=${this.email} hidden />`
          : null}
        <div class="field">
          <label for="new-password">${s.newPassword}</label>
          <input part="input" id="new-password" name="password" type="password" autocomplete="new-password" />
          ${minLength ? html`<p class="hint">${s.minLength(minLength)}</p>` : null}
        </div>
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.setPassword}</span>
        </button>
      </form>
      ${this.backLink()}
    `;
  }

  private emailField(id: string) {
    return html`
      <div class="field">
        <label for=${id}>${this.strings.email}</label>
        <input part="input" id=${id} name="email" type="email" autocomplete="email" .value=${this.email} />
      </div>
    `;
  }

  private backLink(label = this.strings.backToSignIn) {
    return html`
      <p class="links">
        <button class="link" part="link" type="button" data-action="back" @click=${() => this.goTo('signin')}>${label}</button>
      </p>
    `;
  }

  private renderRow(m: LoginMethod) {
    const { label, description } = this.strings.methods[m.id];
    return html`
      <button
        part="method"
        class="row"
        type="button"
        title=${description}
        data-method=${m.id}
        @click=${() => this.onMethodChosen(m)}
      >
        ${rowIcons[m.id]}
        <span class="label">${label}</span>
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

    .submit:disabled,
    .link:disabled {
      opacity: 0.6;
      cursor: default;
    }

    .lead {
      margin: 0;
      line-height: 1.5;
    }

    .hint {
      margin: 0;
      font-size: 0.8125rem;
      line-height: 18px;
      color: var(--_muted);
    }

    .optional {
      font-weight: 400;
      color: var(--_muted);
    }

    .links {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 8px 16px;
      margin: -4px 0 0;
    }

    .link {
      padding: 0;
      border: none;
      background: none;
      font-size: 0.8125rem;
      line-height: 18px;
      text-decoration: underline;
      text-underline-offset: 2px;
      color: var(--_muted);
    }

    .link:hover:not(:disabled) {
      color: var(--_text);
    }

    .error .link {
      display: block;
      margin-top: 4px;
      color: inherit;
    }

    .qr {
      display: block;
      width: 176px;
      height: 176px;
      margin: 0 auto;
      padding: 8px;
      box-sizing: content-box;
      border-radius: var(--_control-radius);
      /* Dark on light in both themes: not every authenticator app reads an inverted code. */
      color: #000;
      background: #fff;
    }

    .secret,
    .codes {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      letter-spacing: 0.06em;
    }

    .secret {
      user-select: all;
      color: var(--_text);
    }

    .codes {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px 16px;
      margin: 0;
      padding: 12px 16px;
      list-style: none;
      line-height: 24px;
      border: 1px solid var(--_line);
      border-radius: var(--_group-radius);
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
    'madauth-authenticator-enabled': CustomEvent<AuthenticatorEnabledDetail>;
  }
}
