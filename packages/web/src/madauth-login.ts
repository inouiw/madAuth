import { LitElement, css, html, nothing, type PropertyValues, type TemplateResult } from 'lit';
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
import type { ButtonApi } from './scopes/button.js';
import type { SignInMethodInfo } from './scopes/methods.js';
import type { PasskeyInfo } from './scopes/passkey.js';
import { secondStepOf, type PendingStep } from './providers/provider.js';
import type { CodeOptions } from './scopes/totp.js';
import { qrModules, qrViewBox, type QrModules } from './qr.js';
import type { MadauthError, MadauthErrorCode, MadauthUser, Result, SecondFactor } from './result.js';
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

/** `madauth-authenticator-failed`: the setup opened by `Madauth.setUpAuthenticator()` can't go on. */
export interface AuthenticatorFailedDetail {
  error: MadauthError;
}

/** `madauth-sms-enabled`: the signed-in user added (or replaced) their phone number for SMS codes. `phone` is masked. */
export interface SmsEnabledDetail {
  phone: string;
}

/** `madauth-sms-failed`: the setup opened by `Madauth.setUpSms()` can't go on. */
export interface SmsFailedDetail {
  error: MadauthError;
}

/** `madauth-passkey-added`: the signed-in user added a passkey. */
export interface PasskeyAddedDetail {
  passkey: PasskeyInfo;
}

/** The screens of the dialog. */
type View =
  | 'signin'
  | 'signup'
  | 'check-inbox'
  | 'forgot'
  | 'reset'
  | 'totp'
  | 'totp-code'
  | 'totp-setup'
  | 'totp-codes'
  | 'email-link'
  | 'sms-code'
  | 'sms-setup'
  | 'sms-setup-code'
  | 'passkey'
  | 'passkey-setup'
  | 'methods'
  | 'add-password';

/** The views that change the signed-in user's methods: after signing in again, the dialog goes back to them. */
type ChangeView = 'passkey-setup' | 'methods' | 'add-password';
const changeViews: readonly View[] = ['passkey-setup', 'methods', 'add-password'];

/** How long the passkeys' autofill waits with one ceremony before it starts over: the server's lasts five minutes. */
const CONDITIONAL_RENEW_MS = 4 * 60 * 1000;

/** The step a sign-in goes on with, from the error that says so. */
const nextStep = secondStepOf;

/** The key in groups of four, as authenticator apps show it. */
const groupSecret = (secret: string) => secret.replace(/(.{4})(?=.)/g, '$1 ');

const closeIcon = html`
  <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
    <path d="M18 6 6 18" />
    <path d="m6 6 12 12" />
  </svg>
`;

/** The eye button in a password field shows one of the two, by its aria-pressed. */
const eyeIcons = html`
  <svg class="icon eye" viewBox="0 0 24 24" aria-hidden="true">
    <path d="M2.06 12.35a1 1 0 0 1 0-.7 10.75 10.75 0 0 1 19.88 0 1 1 0 0 1 0 .7 10.75 10.75 0 0 1-19.88 0" />
    <circle cx="12" cy="12" r="3" />
  </svg>
  <svg class="icon eye-off" viewBox="0 0 24 24" aria-hidden="true">
    <path d="M10.73 5.08a10.74 10.74 0 0 1 11.2 6.57 1 1 0 0 1 0 .7 10.75 10.75 0 0 1-1.44 2.49" />
    <path d="M14.08 14.16a3 3 0 0 1-4.24-4.24" />
    <path d="M17.48 17.5a10.75 10.75 0 0 1-15.42-5.15 1 1 0 0 1 0-.7 10.75 10.75 0 0 1 4.45-5.14" />
    <path d="m2 2 20 20" />
  </svg>
`;

/** Shows or hides the password of an eye button's field (the button's previous sibling). */
function setPasswordShown(button: Element, shown: boolean): void {
  (button.previousElementSibling as HTMLInputElement).type = shown ? 'text' : 'password';
  button.setAttribute('aria-pressed', String(shown));
}

/** Hides every shown password under `root`. */
function hidePasswords(root: ParentNode): void {
  for (const button of root.querySelectorAll('.reveal[aria-pressed="true"]')) setPasswordShown(button, false);
}

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

/** The scopes that render a provider's button (Google, GitHub), by method: the dialog stays on the public API. */
const buttonScopes: Partial<Record<LoginMethodId, () => ButtonApi>> = { google: () => Madauth.google, github: () => Madauth.github };

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
  'email-link': html`
    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
      <rect x="2" y="4" width="20" height="16" rx="2" />
      <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
    </svg>
  `,
  password: html`
    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  `,
  passkey: html`
    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z" />
      <circle cx="16.5" cy="7.5" r=".5" fill="currentColor" />
    </svg>
  `,
};

/**
 * Modal sign-in dialog listing the login methods that are on: those whose provider was passed to
 * `Madauth.initialize` and not left out because the server doesn't offer them. Usually opened with
 * `Madauth.signIn()`, which creates it when the page has none; add it to your HTML yourself only to customize it.
 *
 * It is built only on the public `Madauth` API, so a custom login screen can do everything it does.
 *
 * @fires madauth-signed-in - A user signed in. `detail` is a {@link SignedInDetail}.
 * @fires madauth-cancel - The dialog was closed without signing in (or before the authenticator app was set up).
 * @fires madauth-error - A sign-in failed, or madAuth is not initialized. `detail` is an {@link ErrorDetail}.
 * @fires madauth-authenticator-enabled - The signed-in user set up the authenticator app and saw the recovery codes. `detail` is an {@link AuthenticatorEnabledDetail}.
 * @fires madauth-sms-enabled - The signed-in user added a phone number for SMS codes. `detail` is an {@link SmsEnabledDetail}.
 * @fires madauth-passkey-added - The signed-in user added a passkey. `detail` is a {@link PasskeyAddedDetail}.
 *
 * @cssprop --madauth-primary - Fill color of the primary buttons.
 * @cssprop --madauth-radius - Corner radius of the dialog, buttons and fields.
 * @cssprop --madauth-font - Font family.
 *
 * @csspart dialog - The `<dialog>` element.
 * @csspart method - Each sign-in method button.
 * @csspart error - The error message.
 * @csspart form - Each form (sign-in, create account, code, new password, the e-mail link's, the authenticator app's, the SMS code's).
 * @csspart input - Each text field.
 * @csspart link - The text buttons, e.g. "Forgot password?".
 * @csspart qr - The QR code of the authenticator app's key (an inline SVG, dark on a white background).
 * @csspart codes - The list of recovery codes.
 */
export class MadauthLogin extends LitElement {
  static override properties = {
    heading: { type: String },
    codeAutocomplete: { type: String, attribute: 'code-autocomplete' },
    notice: { state: true },
    error: { state: true },
    usable: { state: true },
    view: { state: true },
    busy: { state: true },
    email: { state: true },
    setup: { state: true },
    recoveryCodes: { state: true },
    useRecovery: { state: true },
    setupNeedsCode: { state: true },
    smsPhone: { state: true },
    factors: { state: true },
    passwordScore: { state: true },
    methodList: { state: true },
  };

  /** Title shown at the top of the dialog. Default: "Sign in" in the dialog's language. */
  heading = '';

  /**
   * `autocomplete` of the fields for the code from the authenticator app: `off` (the default) or `one-time-code`.
   * `one-time-code` lets password managers offer a stored code, but the iCloud Passwords extension for Chrome then
   * opens its panel on the field even with nothing stored; see docs/custom-ui.md.
   */
  codeAutocomplete: 'off' | 'one-time-code' = 'off';

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

  /** What the e-mail in the check-inbox view is for: confirming the address, a password reset, or a sign-in link. */
  private inboxPurpose: 'verify' | 'reset' | 'signin' = 'verify';

  /** The reset code entered in the check-inbox view, used with the new password. */
  private resetCode?: string;

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

  /** How hard the new password being typed is to guess, 0 to 4, for the strength meter; null while there is none. */
  private passwordScore: number | null = null;
  /** The meter rates the password a moment after typing stops, and only the latest rating counts. */
  private rateTimer?: ReturnType<typeof setTimeout>;
  private rateRun = 0;
  /** The setup replaces an app the user has: a code from the current one comes first. */
  private setupNeedsCode = false;

  /** The second factors the sign-in under way can finish with, so the code views offer the switch. */
  private factors?: SecondFactor[];
  /** The phone number (masked) a code was sent to. */
  private smsPhone?: string;
  /** The number typed into the phone setup, for the code to the current number and for "send again". */
  private pendingPhone?: string;
  /** What the code in the sms-code view is for: the second step, or approving a new number. */
  private smsCodePurpose: 'signin' | 'replace' = 'signin';
  /** In the setup step of a sign-in: the second factors the user can set up. */
  private setupFactors?: SecondFactor[];
  /** The signed-in user's methods, in the methods view; undefined while they load. */
  private methodList?: SignInMethodInfo[];
  /** The view that changes the user's methods and asked them to sign in again: the dialog goes back to it after. */
  private reauthThen?: ChangeView;
  /** The passkey's setup or the app's was started from the methods view: it goes back there after. */
  private fromMethods = false;
  /** Passkeys offered in the e-mail field's autofill, while the sign-in view is shown: how to stop it, and when it has stopped. */
  private conditional?: { abort: AbortController; done: Promise<void> };

  private stopFollowingLocale?: () => void;

  /** The providers' buttons (Google, GitHub), rendered into the slots of the sign-in view, by slot. */
  private buttons = new Map<HTMLElement, { method: LoginMethodId; remove(): void }>();

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
    if (ready.isSuccess && Madauth.password.pendingReset) this.view = 'reset';
    // A sign-in that started outside the dialog (the redirect flow, an e-mail link) goes on with the app.
    const pending = ready.isSuccess ? takePendingStep() : undefined;
    if (pending) this.continueWith(pending);
    const error = ready.isSuccess ? takePendingError() : ready.error;
    if (error) this.showError(error);
    // Reopened with nothing changed there is no re-render, so render the providers' buttons here.
    await this.updateComplete;
    this.syncButtons();
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
    if (!ready.isSuccess) {
      this.showError(ready.error, 'totp');
      return;
    }
    await this.startSetup();
  }

  /**
   * Waits for madAuth, then shows the dialog: it opens with the methods the server offers already in place
   * instead of filling in while it is open.
   */
  private async show(): Promise<Result> {
    const ready = await readyForDialog();
    this.usable = ready.isSuccess;
    // What the views show depends on the providers and the server's settings, which a new initialize may have changed.
    this.requestUpdate();
    await this.updateComplete;
    if (!this.dialog.open) this.dialog.showModal();
    // The dialog was closed during the render above: the passkeys' autofill starts now that it is open.
    if (this.view === 'signin' && this.usable) this.startConditional();
    return ready;
  }

  /** Goes on with the second step where a sign-in left off. */
  private continueWith(pending: PendingStep): void {
    void this.stopConditional();
    this.primary = pending.method;
    this.useRecovery = false;
    this.setupNeedsCode = false;
    if (pending.step === 'setup') {
      this.factors = undefined;
      this.setupForSignIn = true;
      // A server before madAuth 0.6 names none: the app, or a phone (never for a sign-up with the app).
      const named = pending.factors?.length ? pending.factors : undefined;
      this.setupFactors = (named ?? ['totp', ...(this.primary !== 'totp' && Madauth.sms.available ? (['sms'] as const) : [])]).filter(
        (factor) => factor !== 'passkey' || Madauth.passkey.available,
      );
      // Only passkeys can be set up, and this browser has none: nothing the dialog can do.
      if (!this.setupFactors.length) {
        this.showError({ code: 'passkey_unsupported', message: 'This browser does not support passkeys.' }, this.primary);
        return;
      }
      this.startFactorSetup(this.setupFactors[0]);
      return;
    }
    this.factors = pending.factors;
    if (pending.step === 'code') {
      this.view = 'totp-code';
      return;
    }
    if (pending.step === 'passkey') {
      this.view = 'passkey';
      return;
    }
    void this.startSmsStep();
  }

  /** The setup of a second factor in a sign-in: the app, a phone, or a passkey. */
  private startFactorSetup(factor: SecondFactor): void {
    this.notice = undefined;
    this.error = null;
    if (factor === 'passkey') {
      this.view = 'passkey-setup';
      return;
    }
    if (factor === 'sms') {
      this.view = 'sms-setup';
      return;
    }
    this.view = 'totp-setup';
    void this.startSetup();
  }

  /**
   * Opens the dialog on the "Create a passkey" screen for the signed-in user. Usually called through
   * `Madauth.setUpPasskey()`, which resolves once the passkey is added.
   */
  async openPasskeySetup(): Promise<void> {
    this.setupForSignIn = false;
    this.fromMethods = false;
    this.view = 'passkey-setup';
    const ready = await this.show();
    if (!ready.isSuccess) this.showError(ready.error);
  }

  /**
   * Opens the dialog on the signed-in user's sign-in methods. Usually called through
   * `Madauth.manageSignInMethods()`, which resolves when the dialog is closed.
   */
  async openMethods(): Promise<void> {
    this.setupForSignIn = false;
    this.view = 'methods';
    const ready = await this.show();
    if (!ready.isSuccess) {
      this.showError(ready.error);
      return;
    }
    await this.loadMethods();
  }

  /**
   * Opens the dialog on the "Add your phone number" screen for the signed-in user. Usually called through
   * `Madauth.setUpSms()`, which resolves once the number is confirmed.
   */
  async openSmsSetup(): Promise<void> {
    this.setupForSignIn = false;
    this.view = 'sms-setup';
    const ready = await this.show();
    if (!ready.isSuccess) this.showError(ready.error);
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

  override updated(changed: PropertyValues): void {
    this.syncButtons();
    // The user's passkeys in the e-mail field's autofill, while the sign-in view is shown.
    if (this.view === 'signin' && this.dialog.open && this.usable) this.startConditional();
    else void this.stopConditional();
    // The button that led here is gone with the old view, which would leave the focus on the page behind the
    // dialog. A view that focuses a field of its own (e.g. the password after signIn({ email })) does so later.
    if (changed.has('view') && changed.get('view') !== undefined && this.dialog.open) this.focusView();
  }

  /** Focuses the view's first field, or its heading when it has none, so keyboard and screen reader users are on it. */
  private focusView(): void {
    const field = this.renderRoot.querySelector<HTMLElement>('form input:not([hidden])');
    (field ?? this.renderRoot.querySelector<HTMLElement>('h2'))?.focus();
  }

  /** Renders the providers' buttons into their slots while the sign-in view is shown, and removes them otherwise. */
  private syncButtons(): void {
    const slots = this.dialog.open ? [...this.renderRoot.querySelectorAll<HTMLElement>('.button-slot')] : [];
    for (const [slot, button] of this.buttons) {
      if (!slots.includes(slot)) {
        button.remove();
        this.buttons.delete(slot);
      }
    }
    for (const slot of slots) {
      if (this.buttons.has(slot)) continue;
      const method = slot.dataset.button as LoginMethodId;
      const link = slot.dataset.purpose === 'link';
      const onResult = link ? (result: Result<{ user: MadauthUser }>) => this.onLinked(result) : (result: Result<{ user: MadauthUser }>) => this.finish(method, result);
      const rendered = buttonScopes[method]?.().renderButton(slot, { purpose: link ? 'link' : 'signin', onResult });
      if (rendered?.isSuccess) this.buttons.set(slot, { method, remove: rendered.remove });
    }
  }

  private onDialogClose(): void {
    void this.stopConditional();
    // The sign-in view's fields stay for the next opening: a shown password must not.
    hidePasswords(this.renderRoot);
    for (const button of this.buttons.values()) button.remove();
    this.buttons.clear();
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
    this.inboxPurpose = 'verify';
    this.primary = 'password';
    this.setup = undefined;
    this.setupForSignIn = false;
    this.recoveryCodes = undefined;
    this.setupUser = undefined;
    this.useRecovery = false;
    this.setupNeedsCode = false;
    this.factors = undefined;
    this.smsPhone = undefined;
    this.pendingPhone = undefined;
    this.smsCodePurpose = 'signin';
    this.setupFactors = undefined;
    this.methodList = undefined;
    this.reauthThen = undefined;
    this.fromMethods = false;
    this.clearStrength();
  }

  /**
   * Ends a sign-in attempt: closes on success, goes on with the second step when the method's policy asks
   * for it, and shows the error otherwise.
   */
  private finish(method: LoginMethodId, result: Result<{ user: MadauthUser }>): void {
    if (!result.isSuccess) {
      const step = nextStep(result.error);
      if (step) {
        this.notice = undefined;
        this.error = null;
        this.continueWith({ step, method, factors: result.error.factors });
        return;
      }
      this.showError(result.error, method);
      return;
    }
    const detail: SignedInDetail = { method, user: result.user };
    this.dispatchEvent(new CustomEvent('madauth-signed-in', { detail, bubbles: true, composed: true }));
    // Signed in again to change a method: back to where that was.
    const then = this.reauthThen;
    if (then) {
      this.reauthThen = undefined;
      this.goTo(then);
      if (then === 'methods') void this.loadMethods();
      return;
    }
    this.close();
  }

  /** The recovery codes were seen: the setup is done, and a sign-in that waited for it is finished. */
  private completeSetup(): void {
    const recoveryCodes = this.recoveryCodes;
    if (!recoveryCodes) return;
    this.recoveryCodes = undefined;
    if (this.fromMethods && this.dialog.open) {
      // Set up from the list of methods: back to it.
      this.fromMethods = false;
      const detail: AuthenticatorEnabledDetail = { recoveryCodes };
      this.dispatchEvent(new CustomEvent('madauth-authenticator-enabled', { detail, bubbles: true, composed: true }));
      this.goTo('methods');
      this.notice = (strings) => strings.methodsView.added;
      void this.loadMethods();
      return;
    }
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

  private onMethodChosen(m: LoginMethod): void {
    if (m.id === 'totp' && this.totpAvailable) {
      this.useRecovery = false;
      this.goTo('totp');
    }
    if (m.id === 'email-link' && this.emailLinkAvailable) this.goTo('email-link');
    if (m.id === 'passkey' && this.passkeyAvailable) void this.onPasskeySignIn();
  }

  /** Whether passkeys sign in on their own here: the Passkey provider, the server, and the browser. */
  private get passkeyAvailable(): boolean {
    return this.usable && Madauth.passkey.signInAvailable;
  }

  private get passwordAvailable(): boolean {
    return this.usable && !!providerFor('password');
  }

  /** Whether the authenticator app signs in on its own here (the e-mail address and a code). */
  private get totpAvailable(): boolean {
    return this.usable && !!providerFor('totp') && !!Madauth.totp.policy?.signIn;
  }

  /** Whether the e-mail link is offered here: its provider is registered and the server has it on. */
  private get emailLinkAvailable(): boolean {
    return this.usable && !!providerFor('email-link') && !!Madauth.emailLink.policy;
  }

  /** Switches the view, keeping the e-mail address typed so far. */
  private goTo(view: View): void {
    const typed = this.renderRoot.querySelector<HTMLInputElement>('input[name="email"]')?.value;
    if (typed !== undefined) this.email = typed.trim();
    this.notice = undefined;
    this.error = null;
    this.view = view;
    this.clearStrength();
  }

  /** Rates the new password as it is typed, with the name and e-mail address on the form as the user's own words. */
  private onNewPassword(e: Event): void {
    const input = e.target as HTMLInputElement;
    const field = (name: string) => (input.form?.elements.namedItem(name) as HTMLInputElement | null)?.value.trim() ?? '';
    const password = input.value;
    const userInputs = [field('name'), field('email') || this.email].filter(Boolean);
    clearTimeout(this.rateTimer);
    const run = ++this.rateRun;
    if (!password) {
      this.passwordScore = null;
      return;
    }
    this.rateTimer = setTimeout(async () => {
      const rate = await Madauth.password.loadRating().catch(() => undefined);
      if (rate && run === this.rateRun) this.passwordScore = rate(password, userInputs);
    }, 150);
  }

  private clearStrength(): void {
    clearTimeout(this.rateTimer);
    this.rateRun++;
    this.passwordScore = null;
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
    // Sent as a password field, so password managers offer to save it.
    hidePasswords(e.target as HTMLFormElement);
    const data = new FormData(e.target as HTMLFormElement);
    return Object.fromEntries([...data.entries()].map(([k, v]) => [k, String(v)]));
  }

  private async onSignIn(e: Event): Promise<void> {
    const { email = '', password = '' } = this.fields(e);
    this.email = email.trim();
    const result = await this.run(() => Madauth.password.signIn({ email, password }));
    if (result) this.finish('password', result);
  }

  private async onSignUp(e: Event): Promise<void> {
    const { email = '', password = '', name = '' } = this.fields(e);
    this.email = email.trim();
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
    if (this.inboxPurpose === 'signin') {
      const result = await this.run(() => Madauth.emailLink.verify({ email: this.email, code }));
      if (result) this.finish('email-link', result);
      return;
    }
    const result = await this.run(() => this.signUpScope.verifyEmail({ email: this.email, code }));
    if (result) this.finish(this.primary, result);
  }

  private async onReset(e: Event): Promise<void> {
    const { password = '' } = this.fields(e);
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

  private async resend(purpose: 'verify' | 'reset' | 'signin'): Promise<void> {
    const email = this.email;
    const result = await this.run(() =>
      purpose === 'verify'
        ? this.signUpScope.sendVerificationEmail({ email })
        : purpose === 'reset'
          ? Madauth.password.sendResetEmail({ email })
          : Madauth.emailLink.send({ email }),
    );
    if (!result) return;
    if (!result.isSuccess) {
      this.showError(result.error, purpose === 'verify' ? this.primary : purpose === 'reset' ? 'password' : 'email-link');
      return;
    }
    this.inboxPurpose = purpose;
    this.view = 'check-inbox';
    this.notice = (strings) => strings.emailSentAgain;
  }

  private get viewTitle(): string {
    const s = this.strings;
    switch (this.view) {
      case 'passkey':
        return s.passkeyStep.heading;
      case 'passkey-setup':
        return s.passkeySetup.heading;
      case 'methods':
        return s.methodsView.heading;
      case 'add-password':
        return s.addPassword.heading;
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
      case 'email-link':
        return s.emailLink.heading;
      case 'sms-code':
        return s.smsCode.heading;
      case 'sms-setup':
      case 'sms-setup-code':
        return s.smsSetup.heading;
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
      return s.weakPassword(error.message, { minLength: error.minLength, minScore: error.minScore });
    }
    if (error.code === 'too_many_attempts') return s.tooManyAttempts(error.message);
    if (error.code === 'temporarily_unavailable') {
      return this.view === 'signup' ? s.signUpUnavailable : this.view.startsWith('sms') ? s.smsUnavailable : s.emailsUnavailable;
    }
    if (error.code === 'email_unverified' && error.method === 'password') return s.confirmEmailFirst;
    if (error.code === 'invalid_credentials' && error.method === 'totp') return s.totpInvalid;
    if (error.code === 'other_method' && error.methods?.length) {
      const names: Partial<Record<string, string>> = s.methodNames;
      // The provider that was refused, when a provider's sign-in got the error.
      const instead = error.method === 'google' || error.method === 'github' ? s.methodNames[error.method] : undefined;
      return s.otherMethod(error.methods.map((method) => names[method] ?? method).join(s.orList), instead);
    }
    const texts: Partial<Record<MadauthErrorCode, string>> = s.errors;
    return texts[error.code] ?? s.errorFallback;
  }

  override render() {
    const s = this.strings;
    return html`
      <dialog part="dialog" lang=${languageOf(currentLocale())} @close=${this.onDialogClose}>
        <div class="panel">
          <header>
            <h2 tabindex="-1">${this.viewTitle}</h2>
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
    const restartSms = error.code === 'setup_expired' && this.view === 'sms-setup-code';
    const reauth = error.code === 'reauth_required' && changeViews.includes(this.view);
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
          ${restartSms
            ? html`<button class="link" part="link" type="button" data-action="restart-sms-setup" ?disabled=${this.busy}
                @click=${() => this.startSmsSetup({ phone: this.pendingPhone ?? '' })}>${this.strings.totpSetup.startAgain}</button>`
            : null}
          ${reauth
            ? html`<button class="link" part="link" type="button" data-action="sign-in-again" @click=${() => this.signInAgain()}>${this.strings.signInAgain}</button>`
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
      case 'email-link':
        return this.renderEmailLink();
      case 'sms-code':
        return this.renderSmsCode();
      case 'sms-setup':
        return this.renderSmsSetup();
      case 'sms-setup-code':
        return this.renderSmsSetupCode();
      case 'passkey':
        return this.renderPasskeyStep();
      case 'passkey-setup':
        return this.renderPasskeySetup();
      case 'methods':
        return this.renderMethods();
      case 'add-password':
        return this.renderAddPassword();
      default:
        return this.renderSignInView();
    }
  }

  /**
   * Once madAuth is ready, only the methods whose provider was passed to Madauth.initialize (and not left out
   * because the server doesn't offer them) are listed, all at once. The authenticator app is listed only when
   * it signs in on its own here.
   */
  private get offered(): LoginMethod[] {
    return this.usable
      ? loginMethods.filter(
          (m) =>
            providerFor(m.id) &&
            (m.id !== 'totp' || this.totpAvailable) &&
            (m.id !== 'email-link' || this.emailLinkAvailable) &&
            (m.id !== 'passkey' || this.passkeyAvailable),
        )
      : [];
  }

  private renderSignInView() {
    const offered = this.offered;
    // The providers with a button of their own (Google, GitHub) come first, in the order of loginMethods.
    const branded = offered.filter((m) => !!providerFor(m.id)?.renderButton);
    const password = offered.find((m) => m.id === 'password');
    const others = offered.filter((m) => !branded.includes(m) && m !== password);
    const s = this.strings;
    return html`
      ${branded.length ? html`<div class="buttons">${branded.map((m) => this.renderButtonSlot(m))}</div>` : null}
      ${branded.length && password ? html`<div class="divider">${s.or}</div>` : null}
      ${password ? this.renderPassword(password) : null}
      ${others.length
        ? html`
            <section class="others">
              ${branded.length || password ? html`<h3>${s.otherWays}</h3>` : null}
              <ul>
                ${others.map((m) => html`<li>${this.renderRow(m)}</li>`)}
              </ul>
            </section>
          `
        : null}
    `;
  }

  private renderButtonSlot(m: LoginMethod) {
    // The provider's button is rendered here through its scope (Madauth.google, Madauth.github), see syncButtons.
    return html`<div class="button-slot ${m.id}-slot" data-button=${m.id} title=${this.strings.methods[m.id].description}></div>`;
  }

  private renderPassword(m: LoginMethod) {
    const s = this.strings;
    return html`
      <form part="form" class="signin" @submit=${(e: Event) => this.onSignIn(e)}>
        ${this.emailField({ withPassword: true })}
        ${this.passwordField('password', s.password)}
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
              ${this.questionLink(s.noAccount, 'signup', () => this.startSignUp('password'))}
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
    // A provider (Google, GitHub) signs up a new user as well, so its button is offered here too: this form
    // makes an account with a password (or the app) only.
    const branded = this.offered.filter((m) => !!providerFor(m.id)?.renderButton);
    return html`
      ${branded.length ? html`<div class="buttons">${branded.map((m) => this.renderButtonSlot(m))}</div><div class="divider">${s.or}</div>` : null}
      ${withApp ? html`<p class="hint">${s.totpSignUpHint}</p>` : null}
      <form part="form" class="signup" @submit=${this.onSignUp}>
        ${this.emailField({ withPassword: !withApp })}
        ${withApp ? null : this.passwordField('new-password', s.password)}
        <div class="field">
          <label for="name">${s.name} <span class="optional">${s.optional}</span></label>
          <input part="input" id="name" name="name" type="text" autocomplete="name" />
        </div>
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.createAccount}</span>
        </button>
      </form>
      <p class="links">${this.questionLink(s.haveAccount, 'back', () => this.goTo('signin'))}</p>
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
            ${this.appCodeInput()}
            <p class="hint">${s.totpHint}</p>
          </div>
        `;
  }

  /** The input for the code from the app, in {@link codeField} and in the setup; {@link codeAutocomplete} applies. */
  private appCodeInput() {
    return html`<input part="input" id="code" name="code" type="text" inputmode="numeric" autocomplete=${this.codeAutocomplete || 'off'} maxlength="7" />`;
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
        ${this.emailField()}
        ${this.codeField()}
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.signIn}</span>
        </button>
      </form>
      <p class="links">
        ${this.toggleRecoveryLink()}
        ${Madauth.totp.policy?.signUp
          ? this.questionLink(s.noAccount, 'signup', () => this.startSignUp('totp'))
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

  /** The second step after a password, Google, GitHub or e-mail link sign-in. */
  private renderTotpCode() {
    const s = this.strings;
    return html`
      <p class="lead">${this.setupNeedsCode ? s.totpCode.replaceLead : s.totpCode.lead}</p>
      <form part="form" class="totp-code" @submit=${this.onTotpVerify}>
        ${this.codeField()}
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.continue}</span>
        </button>
      </form>
      <p class="links">
        ${this.toggleRecoveryLink()}
        ${!this.setupNeedsCode && this.factors?.includes('passkey')
          ? html`<button class="link" part="link" type="button" data-action="use-passkey" @click=${() => this.goTo('passkey')}>${s.usePasskey}</button>`
          : null}
        ${!this.setupNeedsCode && this.factors?.includes('sms')
          ? html`<button class="link" part="link" type="button" data-action="use-sms" @click=${() => this.startSmsStep()}>${s.useSms}</button>`
          : null}
        ${this.setupNeedsCode
          ? html`<button class="link" part="link" type="button" data-action="cancel" @click=${() => this.dialog.close()}>${s.cancel}</button>`
          : html`<button class="link" part="link" type="button" data-action="back" @click=${() => this.goTo('signin')}>${s.backToSignIn}</button>`}
      </p>
    `;
  }

  private async onTotpVerify(e: Event): Promise<void> {
    const fields = this.fields(e);
    // Replacing an app: the code is for the current one, and the setup starts once it agrees.
    if (this.setupNeedsCode) return this.startSetup(this.codeOptions(fields));
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
      ${setup
        ? html`
            <svg part="qr" class="qr" viewBox=${qrViewBox(setup.qr.size)} role="img" aria-label=${s.totpSetup.qrLabel} shape-rendering="crispEdges">
              <path d=${setup.qr.d} fill="currentColor" />
            </svg>
            <p class="hint">${s.totpSetup.cantScan} <code class="secret">${groupSecret(setup.secret)}</code></p>
            <form part="form" class="totp-setup" @submit=${this.onConfirmSetup}>
              <div class="field">
                <label for="code">${s.appCode}</label>
                ${this.appCodeInput()}
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
        ${this.setupAlternatives('totp')}
        <button class="link" part="link" type="button" data-action="cancel" @click=${() => this.dialog.close()}>${s.cancel}</button>
      </p>
    `;
  }

  /** In the setup step of a sign-in: links to set up the other factors the user can choose from instead of `current`. */
  private setupAlternatives(current: SecondFactor) {
    if (!this.setupForSignIn) return null;
    const s = this.strings;
    const links = { passkey: ['use-passkey-setup', s.passkeySetup.useInstead], totp: ['use-app-setup', s.smsSetup.useAppInstead], sms: ['use-phone', s.smsSetup.usePhone] } as const;
    return (this.setupFactors ?? []).filter((factor) => factor !== current).map((factor) => {
      const [action, text] = links[factor];
      return html`<button class="link" part="link" type="button" data-action=${action} @click=${() => this.startFactorSetup(factor)}>${text}</button>`;
    });
  }

  /**
   * Asks the server for a new key and shows it: the first step of the setup, also after "Start again". A
   * user who has an app already is sent to the code step first, which calls this again with the code.
   */
  private async startSetup(current?: CodeOptions): Promise<void> {
    this.setup = undefined;
    const result = await this.run(() => Madauth.totp.startSetup(current));
    if (!result) return;
    if (!result.isSuccess) {
      if (result.error.code === 'code_required') {
        this.setupNeedsCode = true;
        this.useRecovery = false;
        this.view = 'totp-code';
        return;
      }
      this.showError(result.error, 'totp');
      // Nothing the user can do here: the caller of setUpAuthenticator() learns it as well.
      if (!this.setupForSignIn && (result.error.code === 'no_session' || result.error.code === 'method_disabled')) {
        const detail: AuthenticatorFailedDetail = { error: result.error };
        this.dispatchEvent(new CustomEvent('madauth-authenticator-failed', { detail, bubbles: true, composed: true }));
      }
      return;
    }
    this.setupNeedsCode = false;
    this.notice = undefined;
    this.error = null;
    this.view = 'totp-setup';
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

  // --- SMS codes ---

  /** The second step with a code by SMS: the view, and the SMS itself. */
  private async startSmsStep(): Promise<void> {
    this.smsCodePurpose = 'signin';
    this.smsPhone = undefined;
    this.notice = undefined;
    this.error = null;
    this.view = 'sms-code';
    await this.sendSms();
  }

  /** Asks the server to send the code to the user's number, and shows where it went. */
  private async sendSms(again = false): Promise<void> {
    const result = await this.run(() => Madauth.sms.send());
    if (!result) return;
    if (!result.isSuccess) {
      // The sign-in starts over.
      if (result.error.code === 'challenge_expired') this.goTo('signin');
      this.showError(result.error, this.primary);
      return;
    }
    this.smsPhone = result.phone;
    if (again) this.notice = (strings) => strings.smsCode.sentAgain;
  }

  /** The second step after a sign-in, or the current number agreeing to be replaced. */
  private renderSmsCode() {
    const s = this.strings;
    const replacing = this.smsCodePurpose === 'replace';
    const phone = this.smsPhone;
    return html`
      <p class="lead">${phone ? (replacing ? s.smsCode.replaceLead(phone) : s.smsCode.lead(phone)) : s.smsCode.sending}</p>
      <form part="form" class="sms-code" @submit=${this.onSmsVerify}>
        <div class="field">
          <label for="code">${s.code}</label>
          <input part="input" id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="7" />
        </div>
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.continue}</span>
        </button>
      </form>
      <p class="links">
        <button class="link" part="link" type="button" data-action="resend-sms" ?disabled=${this.busy} @click=${() => this.sendSms(true)}>
          ${s.smsCode.sendAgain}
        </button>
        ${!replacing && this.factors?.includes('passkey')
          ? html`<button class="link" part="link" type="button" data-action="use-passkey" @click=${() => this.goTo('passkey')}>${s.usePasskey}</button>`
          : null}
        ${!replacing && this.factors?.includes('totp')
          ? html`<button class="link" part="link" type="button" data-action="use-app" @click=${() => this.switchToApp()}>${s.useApp}</button>`
          : null}
        ${replacing
          ? html`<button class="link" part="link" type="button" data-action="cancel" @click=${() => this.dialog.close()}>${s.cancel}</button>`
          : html`<button class="link" part="link" type="button" data-action="back" @click=${() => this.goTo('signin')}>${s.backToSignIn}</button>`}
      </p>
    `;
  }

  /** From the SMS step to the app's code: the user has both. */
  private switchToApp(): void {
    this.useRecovery = false;
    this.setupNeedsCode = false;
    this.goTo('totp-code');
  }

  private async onSmsVerify(e: Event): Promise<void> {
    const code = (this.fields(e).code ?? '').replace(/\s/g, '');
    // Replacing the number: the code is for the current one, and the new one's setup starts once it agrees.
    if (this.smsCodePurpose === 'replace') return this.startSmsSetup({ phone: this.pendingPhone ?? '', code });
    const result = await this.run(() => Madauth.sms.verify({ code }));
    if (!result) return;
    if (!result.isSuccess && result.error.code === 'challenge_expired') {
      // The sign-in starts over.
      this.goTo('signin');
      this.showError(result.error, this.primary);
      return;
    }
    this.finish(this.primary, result);
  }

  /** Adding a phone number: the number, then (next view) the code sent to it. */
  private renderSmsSetup() {
    const s = this.strings;
    const asks = (Madauth.totp.policy?.secondFactorFor ?? []).map((method) => s.methods[method].label).join(s.and);
    return html`
      <p class="lead">${this.setupForSignIn ? s.smsSetup.requiredLead : s.smsSetup.lead}</p>
      ${!this.setupForSignIn && asks ? html`<p class="hint">${s.smsSetup.effect(asks)}</p>` : null}
      <form part="form" class="sms-setup" @submit=${this.onSmsSetup}>
        <div class="field">
          <label for="phone">${s.smsSetup.phone}</label>
          <input part="input" id="phone" name="phone" type="tel" inputmode="tel" autocomplete="tel" .value=${this.pendingPhone ?? ''} />
          <p class="hint">${s.smsSetup.phoneHint}</p>
        </div>
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.smsSetup.sendCode}</span>
        </button>
      </form>
      <p class="links">
        ${this.setupAlternatives('sms')}
        <button class="link" part="link" type="button" data-action="cancel" @click=${() => this.dialog.close()}>${s.cancel}</button>
      </p>
    `;
  }

  private async onSmsSetup(e: Event): Promise<void> {
    const { phone = '' } = this.fields(e);
    this.pendingPhone = phone.trim();
    await this.startSmsSetup({ phone: this.pendingPhone });
  }

  /**
   * Asks the server to send the code to the new number, also for "send again" and after the current
   * number agreed (`code`). A user who has a number already is sent to the code view first, which calls
   * this again with the code.
   */
  private async startSmsSetup(options: { phone: string; code?: string }): Promise<void> {
    const result = await this.run(() => Madauth.sms.setUp(options));
    if (!result) return;
    if (!result.isSuccess) {
      if (result.error.code === 'code_required') {
        this.smsCodePurpose = 'replace';
        this.smsPhone = undefined;
        this.notice = undefined;
        this.error = null;
        this.view = 'sms-code';
        await this.sendSms();
        return;
      }
      this.showError(result.error);
      // Nothing the user can do here: the caller of setUpSms() learns it as well.
      if (!this.setupForSignIn && (result.error.code === 'no_session' || result.error.code === 'method_disabled' || result.error.code === 'flow_not_enabled')) {
        const detail: SmsFailedDetail = { error: result.error };
        this.dispatchEvent(new CustomEvent('madauth-sms-failed', { detail, bubbles: true, composed: true }));
      }
      return;
    }
    this.smsCodePurpose = 'signin';
    this.smsPhone = result.phone;
    this.notice = undefined;
    this.error = null;
    this.view = 'sms-setup-code';
    await this.updateComplete;
    this.renderRoot.querySelector<HTMLInputElement>('form.sms-setup-code input[name="code"]')?.focus();
  }

  /** The code that confirms the new number. */
  private renderSmsSetupCode() {
    const s = this.strings;
    return html`
      <p class="lead">${s.smsSetup.codeLead(this.smsPhone ?? '')}</p>
      <form part="form" class="sms-setup-code" @submit=${this.onSmsConfirm}>
        <div class="field">
          <label for="code">${s.code}</label>
          <input part="input" id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="7" />
        </div>
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.smsSetup.confirm}</span>
        </button>
      </form>
      <p class="links">
        <button class="link" part="link" type="button" data-action="resend-sms" ?disabled=${this.busy}
          @click=${() => this.startSmsSetup({ phone: this.pendingPhone ?? '' })}>${s.smsCode.sendAgain}</button>
        <button class="link" part="link" type="button" data-action="cancel" @click=${() => this.dialog.close()}>${s.cancel}</button>
      </p>
    `;
  }

  private async onSmsConfirm(e: Event): Promise<void> {
    const code = (this.fields(e).code ?? '').replace(/\s/g, '');
    const result = await this.run(() => Madauth.sms.confirmSetup({ code }));
    if (!result) return;
    if (!result.isSuccess) {
      this.showError(result.error);
      return;
    }
    // The setup finished a sign-in: the user is in.
    if (result.user) {
      this.finish(this.primary, { isSuccess: true, user: result.user });
      return;
    }
    const detail: SmsEnabledDetail = { phone: this.smsPhone ?? '' };
    this.dispatchEvent(new CustomEvent('madauth-sms-enabled', { detail, bubbles: true, composed: true }));
    this.dialog.returnValue = 'done';
    if (this.dialog.open) this.dialog.close('done');
  }

  // --- Passkeys ---

  /** Signs in with a passkey alone: the browser's passkey dialog. */
  private async onPasskeySignIn(): Promise<void> {
    // The browser takes one passkey request at a time: the autofill's has to be over first.
    await this.stopConditional();
    const result = await this.run(() => Madauth.passkey.signIn());
    if (!result) return;
    // Closing the browser's dialog is no error worth showing.
    if (!result.isSuccess && result.error.code === 'cancelled') return;
    this.finish('passkey', result);
  }

  /**
   * Offers the user's passkeys in the e-mail field's autofill while the sign-in view is shown: the browser
   * waits for a pick, which signs in. Stopped when the view goes or another sign-in starts, and started over
   * before the server's ceremony expires, since the browser may wait longer.
   */
  private startConditional(): void {
    if (this.conditional || !this.passkeyAvailable) return;
    const abort = new AbortController();
    const renew = setTimeout(() => {
      if (this.conditional?.abort !== abort) return;
      void this.stopConditional().then(() => {
        if (this.view === 'signin' && this.dialog.open) this.startConditional();
      });
    }, CONDITIONAL_RENEW_MS);
    const done = this.waitForPick(abort).finally(() => clearTimeout(renew));
    this.conditional = { abort, done };
  }

  private async waitForPick(abort: AbortController): Promise<void> {
    if (!(await Madauth.passkey.conditionalAvailable()) || abort.signal.aborted) return;
    const result = await Madauth.passkey.signIn({ conditional: true, signal: abort.signal });
    if (abort.signal.aborted || this.conditional?.abort !== abort) return;
    this.conditional = undefined;
    if (!result.isSuccess && result.error.code === 'cancelled') return;
    this.finish('passkey', result);
  }

  /** Ends the autofill's wait; resolves once the browser has let go of it, so another passkey request can start. */
  private stopConditional(): Promise<void> {
    const conditional = this.conditional;
    this.conditional = undefined;
    conditional?.abort.abort();
    return conditional?.done ?? Promise.resolve();
  }

  /** The second step with a passkey. */
  private renderPasskeyStep() {
    const s = this.strings;
    return html`
      <p class="lead">${s.passkeyStep.lead}</p>
      <button part="method" class="submit" type="button" data-action="verify-passkey" ?disabled=${this.busy} @click=${() => this.onPasskeyVerify()}>
        <span class="label">${s.passkeyStep.button}</span>
      </button>
      <p class="links">
        ${this.factors?.includes('totp')
          ? html`<button class="link" part="link" type="button" data-action="use-app" @click=${() => this.switchToApp()}>${s.useApp}</button>`
          : null}
        ${this.factors?.includes('sms')
          ? html`<button class="link" part="link" type="button" data-action="use-sms" @click=${() => this.startSmsStep()}>${s.useSms}</button>`
          : null}
        <button class="link" part="link" type="button" data-action="back" @click=${() => this.goTo('signin')}>${s.backToSignIn}</button>
      </p>
    `;
  }

  private async onPasskeyVerify(): Promise<void> {
    const result = await this.run(() => Madauth.passkey.verify());
    if (!result) return;
    if (!result.isSuccess && result.error.code === 'challenge_expired') {
      // The sign-in starts over.
      this.goTo('signin');
      this.showError(result.error, this.primary);
      return;
    }
    this.finish(this.primary, result);
  }

  /** Creating a passkey: for the signed-in user, or as the setup step of a sign-in. */
  private renderPasskeySetup() {
    const s = this.strings;
    const asks = (Madauth.totp.policy?.secondFactorFor ?? []).filter((m) => m !== 'passkey').map((method) => s.methods[method].label).join(s.and);
    return html`
      <p class="lead">${this.setupForSignIn ? s.passkeySetup.requiredLead : s.passkeySetup.lead}</p>
      ${!this.setupForSignIn && Madauth.passkey.policy?.signIn ? html`<p class="hint">${s.passkeySetup.signsIn}</p>` : null}
      ${!this.setupForSignIn && asks ? html`<p class="hint">${s.passkeySetup.effect(asks)}</p>` : null}
      <form part="form" class="passkey-setup" @submit=${this.onPasskeyCreate}>
        <div class="field">
          <label for="passkey-name">${s.passkeySetup.name} <span class="optional">${s.optional}</span></label>
          <input part="input" id="passkey-name" name="name" type="text" autocomplete="off" maxlength="64" />
          <p class="hint">${s.passkeySetup.nameHint}</p>
        </div>
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.passkeySetup.create}</span>
        </button>
      </form>
      <p class="links">
        ${this.setupAlternatives('passkey')}
        ${this.fromMethods
          ? html`<button class="link" part="link" type="button" data-action="back-to-methods" @click=${() => this.backToMethods()}>${s.cancel}</button>`
          : html`<button class="link" part="link" type="button" data-action="cancel" @click=${() => this.dialog.close()}>${s.cancel}</button>`}
      </p>
    `;
  }

  private async onPasskeyCreate(e: Event): Promise<void> {
    const name = (this.fields(e).name ?? '').trim();
    const result = await this.run(() => Madauth.passkey.add(name ? { name } : {}));
    if (!result) return;
    if (!result.isSuccess) {
      if (result.error.code !== 'cancelled') this.showError(result.error, 'passkey');
      return;
    }
    // The setup finished a sign-in: the user is in.
    if (result.user) {
      this.finish(this.primary, { isSuccess: true, user: result.user });
      return;
    }
    const detail: PasskeyAddedDetail = { passkey: result.passkey };
    this.dispatchEvent(new CustomEvent('madauth-passkey-added', { detail, bubbles: true, composed: true }));
    if (this.fromMethods) {
      this.backToMethods();
      this.notice = (strings) => strings.methodsView.added;
      return;
    }
    this.dialog.returnValue = 'done';
    if (this.dialog.open) this.dialog.close('done');
  }

  // --- The signed-in user's methods ---

  /** Changing a method needs a recent sign-in: to the sign-in view, and back to this view after. */
  private signInAgain(): void {
    this.reauthThen = changeViews.includes(this.view) ? (this.view as ChangeView) : undefined;
    this.goTo('signin');
  }

  private backToMethods(): void {
    this.fromMethods = false;
    this.goTo('methods');
    void this.loadMethods();
  }

  /** Loads the user's methods into the list. */
  private async loadMethods(): Promise<void> {
    const result = await Madauth.methods.list();
    if (!result.isSuccess) {
      this.showError(result.error);
      return;
    }
    this.methodList = result.methods;
  }

  /** A date as the user's language writes it, e.g. "3 Oct 2026". */
  private date(ms: number): string {
    return new Date(ms).toLocaleDateString(currentLocale(), { day: 'numeric', month: 'short', year: 'numeric' });
  }

  private renderMethods() {
    const s = this.strings;
    const v = s.methodsView;
    const list = this.methodList;
    const has = (method: LoginMethodId) => !!list?.some((m) => m.method === method);
    // The last method that signs the user in can't go (the server refuses it): no button for it.
    const signsIn = list?.filter((m) => m.signIn) ?? [];
    const lastWayIn = (m: SignInMethodInfo) => m.signIn && signsIn.length === 1;
    const config = (method: 'google' | 'github') => providerFor(method)?.renderButton && !has(method);
    return html`
      <p class="lead">${v.lead}</p>
      ${list
        ? html`
            <ul class="method-list">
              ${list.map((m) => {
                const label = m.method === 'passkey' && m.name ? m.name : v.labels[m.method];
                const details = [
                  m.method === 'passkey' ? v.labels.passkey : m.email,
                  m.method === 'passkey' ? (m.lastUsedAt ? v.lastUsed(this.date(m.lastUsedAt)) : v.neverUsed) : undefined,
                  m.signIn ? undefined : v.secondFactorOnly,
                ].filter(Boolean);
                return html`
                  <li class="method" data-method=${m.method}>
                    ${rowIcons[m.method] ?? null}
                    <span class="method-text">
                      <span class="label">${label}</span>
                      ${details.length ? html`<span class="hint">${details.join(' · ')}</span>` : null}
                    </span>
                    ${m.removable && !lastWayIn(m)
                      ? html`<button class="link" part="link" type="button" data-action="remove" aria-label=${v.removeLabel(label)} ?disabled=${this.busy}
                          @click=${() => this.onRemove(m)}>${v.remove}</button>`
                      : null}
                  </li>
                `;
              })}
            </ul>
          `
        : html`<p class="hint" role="status">${v.loading}</p>`}
      ${list
        ? html`
            <section class="others">
              <h3>${v.add}</h3>
              <ul>
                ${Madauth.passkey.available
                  ? html`<li>${this.addRow('passkey', v.addPasskey, () => {
                      this.fromMethods = true;
                      this.goTo('passkey-setup');
                    })}</li>`
                  : null}
                ${providerFor('password') && Madauth.password.policy && !has('password')
                  ? html`<li>${this.addRow('password', v.addPassword, () => this.goTo('add-password'))}</li>`
                  : null}
                ${providerFor('email-link') && Madauth.emailLink.policy && !has('email-link')
                  ? html`<li>${this.addRow('email-link', v.addEmailLink, () => this.onAddEmailLink())}</li>`
                  : null}
                ${Madauth.totp.policy && !has('totp')
                  ? html`<li>${this.addRow('totp', v.addApp, () => {
                      this.fromMethods = true;
                      this.setupForSignIn = false;
                      this.goTo('totp-setup');
                      void this.startSetup();
                    })}</li>`
                  : null}
              </ul>
              ${config('google') || config('github')
                ? html`<div class="buttons">
                    ${(['google', 'github'] as const)
                      .filter((m) => config(m))
                      .map((m) => html`<div class="button-slot ${m}-slot" data-button=${m} data-purpose="link" title=${v.connect(s.methodNames[m])}></div>`)}
                  </div>`
                : null}
            </section>
          `
        : null}
      <p class="links">
        <button class="link" part="link" type="button" data-action="done" @click=${() => this.dialog.close()}>${v.done}</button>
      </p>
    `;
  }

  /** A row of the "Add a sign-in method" list. */
  private addRow(method: LoginMethodId, label: string, onClick: () => void) {
    return html`
      <button part="method" class="row" type="button" data-add=${method} ?disabled=${this.busy} @click=${onClick}>
        ${rowIcons[method] ?? null}
        <span class="label">${label}</span>
        ${chevronIcon}
      </button>
    `;
  }

  private async onRemove(m: SignInMethodInfo): Promise<void> {
    const result = await this.run(() => Madauth.methods.remove(m.id));
    if (!result) return;
    if (!result.isSuccess) {
      this.showError(result.error, m.method);
      return;
    }
    await this.loadMethods();
    this.notice = (strings) => strings.methodsView.removed;
  }

  private async onAddEmailLink(): Promise<void> {
    const result = await this.run(() => Madauth.emailLink.add());
    if (!result) return;
    if (!result.isSuccess) {
      this.showError(result.error, 'email-link');
      return;
    }
    await this.loadMethods();
    this.notice = (strings) => strings.methodsView.added;
  }

  /** A provider's button that links (Google, GitHub) reported back. */
  private async onLinked(result: Result<{ user: MadauthUser }>): Promise<void> {
    if (!result.isSuccess) {
      this.showError(result.error);
      return;
    }
    this.notice = undefined;
    this.error = null;
    await this.loadMethods();
    this.notice = (strings) => strings.methodsView.added;
  }

  /** A password for the signed-in user. */
  private renderAddPassword() {
    const s = this.strings;
    return html`
      <p class="lead">${s.addPassword.lead}</p>
      <form part="form" class="add-password" @submit=${this.onAddPassword}>
        <input type="email" name="username" autocomplete="username" .value=${Madauth.currentUser?.email ?? ''} hidden />
        ${this.passwordField('new-password', s.password)}
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.setPassword}</span>
        </button>
      </form>
      <p class="links">
        <button class="link" part="link" type="button" data-action="back-to-methods" @click=${() => this.backToMethods()}>${s.cancel}</button>
      </p>
    `;
  }

  private async onAddPassword(e: Event): Promise<void> {
    const { password = '' } = this.fields(e);
    const result = await this.run(() => Madauth.password.add({ password }));
    if (!result) return;
    if (!result.isSuccess) {
      this.showError(result.error, 'password');
      return;
    }
    this.backToMethods();
    this.notice = (strings) => strings.methodsView.added;
  }

  // --- The e-mail link ---

  /** Asking for the sign-in e-mail: the address, and a button that sends the link and the code. */
  private renderEmailLink() {
    const s = this.strings;
    return html`
      <p class="lead">${s.emailLink.lead}</p>
      <p class="hint">${s.emailLink.codeHint}</p>
      <form part="form" class="email-link" @submit=${this.onEmailLink}>
        ${this.emailField()}
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.emailLink.send}</span>
        </button>
      </form>
      ${this.backLink()}
    `;
  }

  private async onEmailLink(e: Event): Promise<void> {
    const { email = '' } = this.fields(e);
    this.email = email.trim();
    const result = await this.run(() => Madauth.emailLink.send({ email }));
    if (!result) return;
    if (!result.isSuccess) {
      this.showError(result.error, 'email-link');
      return;
    }
    this.inboxPurpose = 'signin';
    this.view = 'check-inbox';
  }

  private renderForgot() {
    const s = this.strings;
    // Users of a provider (Google, GitHub) have no password to reset: name the ones offered here.
    const providerNames = (['google', 'github'] as const).filter((id) => providerFor(id)).map((id) => s.methodNames[id]);
    return html`
      <p class="lead">${s.forgotLead}</p>
      ${providerNames.length ? html`<p class="hint">${s.forgotProviderHint(providerNames.join(s.orList))}</p>` : null}
      <form part="form" class="forgot" @submit=${this.onForgot}>
        ${this.emailField()}
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.sendEmail}</span>
        </button>
      </form>
      ${this.backLink()}
    `;
  }

  private renderCheckInbox() {
    const s = this.strings;
    const lead = this.inboxPurpose === 'signin' ? s.signInInboxLead : s.inboxLead;
    return html`
      <p class="lead">${lead.before}<strong>${this.email}</strong>${lead.after}</p>
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
    return html`
      <form part="form" class="reset" @submit=${this.onReset}>
        ${this.email
          ? html`<input type="email" name="username" autocomplete="username" .value=${this.email} hidden />`
          : null}
        ${this.passwordField('new-password', s.newPassword)}
        <button part="method" class="submit" type="submit" ?disabled=${this.busy}>
          <span class="label">${s.setPassword}</span>
        </button>
      </form>
      ${this.backLink()}
    `;
  }

  /** The strength meter under a new password: four bars and a word, and whether the server's rules accept it. */
  private renderStrength() {
    const score = this.passwordScore;
    if (score === null) return null;
    const s = this.strings.strength;
    const enough = score >= (Madauth.password.policy?.minScore ?? 0);
    const text = enough ? s.levels[score] : `${s.levels[score]}: ${s.tooEasy}`;
    return html`
      <div class="strength" part="strength" data-score=${score} ?data-too-easy=${!enough}>
        <div class="bars" role="meter" aria-label=${s.label} aria-valuemin="0" aria-valuemax="4" aria-valuenow=${score} aria-valuetext=${text}>
          ${[1, 2, 3, 4].map((bar) => html`<span class=${bar <= Math.max(score, 1) ? 'on' : ''}></span>`)}
        </div>
        <span class="level" id="new-password-strength" aria-hidden="true">${text}</span>
      </div>
    `;
  }

  private emailField({ withPassword = false } = {}) {
    // Next to a password, `username`: password managers save and fill the address together with it. Without
    // one, `email`: on a `username` field the iCloud Passwords extension for Chrome opens its panel, with
    // nothing to fill there.
    // `webauthn`: the browser offers the user's passkeys in the field's autofill as well (see startConditional).
    const passkeys = this.view === 'signin' && this.passkeyAvailable ? ' webauthn' : '';
    return html`
      <div class="field">
        <label for="email">${this.strings.email}</label>
        <input part="input" id="email" name="email" type="email" autocomplete=${`${withPassword ? 'username' : 'email'}${passkeys}`} .value=${this.email} />
      </div>
    `;
  }

  /**
   * A password field with an eye button that shows what was typed. A new password (`new-password`) gets the
   * policy's minimum length and the strength meter under it, both read out with the field.
   */
  private passwordField(id: 'password' | 'new-password', label: string) {
    const isNew = id === 'new-password';
    const minLength = isNew ? Madauth.password.policy?.minLength : undefined;
    const describedBy = [minLength ? 'new-password-hint' : '', isNew && this.passwordScore !== null ? 'new-password-strength' : '']
      .filter(Boolean)
      .join(' ');
    return html`
      <div class="field">
        <label for=${id}>${label}</label>
        <div class="password">
          <input part="input" id=${id} name="password" type="password" autocomplete=${isNew ? 'new-password' : 'current-password'}
            aria-describedby=${describedBy || nothing} @input=${isNew ? this.onNewPassword : undefined} />
          <button class="reveal" type="button" aria-label=${this.strings.showPassword} aria-pressed="false" aria-controls=${id}
            @click=${this.togglePassword}>${eyeIcons}</button>
        </div>
        ${minLength ? html`<p class="hint" id="new-password-hint">${this.strings.minLength(minLength)}</p>` : null}
        ${isNew ? this.renderStrength() : null}
      </div>
    `;
  }

  /** The eye button: shows or hides the password in the field before it. */
  private togglePassword(e: Event): void {
    const button = e.currentTarget as HTMLButtonElement;
    setPasswordShown(button, button.getAttribute('aria-pressed') !== 'true');
  }

  /** A link that asks a question and names the action, e.g. "No account? Create one": only the action is underlined. */
  private questionLink(text: { question: string; action: string }, action: string, onClick: () => void) {
    return html`<button class="link question" part="link" type="button" data-action=${action} @click=${onClick}>${text.question} <span>${text.action}</span></button>`;
  }

  private backLink() {
    return html`
      <p class="links">
        <button class="link" part="link" type="button" data-action="back" @click=${() => this.goTo('signin')}>${this.strings.backToSignIn}</button>
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
      position: relative;
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
      /* Room for the close button, which sits in the panel's top right corner. */
      padding-right: 32px;
    }

    /* Focused only to move the focus into a new view (see focusView), so it shows no ring. */
    h2:focus {
      outline: none;
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

    /* Centered on the heading's line, with the icon at the panel's right padding. */
    .close {
      position: absolute;
      top: 24px;
      right: 20px;
      display: grid;
      place-items: center;
      width: 44px;
      height: 44px;
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

    .buttons {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .button-slot {
      display: flex;
      justify-content: center;
      min-height: var(--_control-height);
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

    /* A password field and its eye button, which sits inside the field on the right. */
    .password {
      position: relative;
    }

    .password input {
      padding-right: var(--_control-height);
    }

    .reveal {
      position: absolute;
      top: 0;
      right: 0;
      display: grid;
      place-items: center;
      width: var(--_control-height);
      height: var(--_control-height);
      padding: 0;
      border: none;
      border-radius: var(--_control-radius);
      color: var(--_muted);
      background: none;
    }

    .reveal:hover {
      color: var(--_text);
    }

    .reveal:focus-visible {
      outline-offset: -4px;
    }

    .reveal[aria-pressed='true'] .eye,
    .reveal:not([aria-pressed='true']) .eye-off {
      display: none;
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

    .strength {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 0.8125rem;
      line-height: 18px;
      color: var(--_muted);
    }

    .strength .bars {
      display: flex;
      flex: 0 0 96px;
      gap: 4px;
    }

    .strength .bars span {
      flex: 1;
      height: 4px;
      border-radius: 2px;
      background: var(--_line);
    }

    .strength .bars span.on {
      background: var(--_primary);
    }

    .strength[data-too-easy] .level {
      color: light-dark(#b42318, #fda29b);
    }

    .strength[data-too-easy] .bars span.on {
      background: light-dark(#b42318, #fda29b);
    }

    .optional {
      font-weight: 400;
      color: var(--_muted);
    }

    .links {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      /* 12px between wrapped rows: the links' tap targets reach 6px beyond their text (see .link). */
      gap: 12px 16px;
      margin: -4px 0 0;
    }

    /* The padding makes a 30px tap target; the negative margin keeps the layout as without it. */
    .link {
      margin: -6px 0;
      padding: 6px 0;
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

    /* "No account? Create one": only the action is underlined. */
    .link.question {
      text-decoration: none;
    }

    .link.question span {
      text-decoration: underline;
    }

    .error .link {
      display: block;
      margin: -2px 0 -6px;
      color: inherit;
    }

    .method-list {
      margin: 0 0 16px;
    }
    .method {
      display: flex;
      align-items: center;
      gap: 12px;
      min-height: calc(var(--_control-height) + 4px);
      padding: 6px 12px 6px 14px;
    }
    .method .icon {
      flex: none;
      color: var(--_muted);
    }
    .method-text {
      display: flex;
      flex: 1;
      flex-direction: column;
      min-width: 0;
    }
    .method-text .hint {
      margin: 0;
    }
    .method .link {
      margin: 0;
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
      .close {
        top: 16px;
        right: 12px;
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
    'madauth-authenticator-failed': CustomEvent<AuthenticatorFailedDetail>;
    'madauth-sms-enabled': CustomEvent<SmsEnabledDetail>;
    'madauth-sms-failed': CustomEvent<SmsFailedDetail>;
    'madauth-passkey-added': CustomEvent<PasskeyAddedDetail>;
  }
}
