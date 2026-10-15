import {
  EXPIRY_COOKIE,
  REDIRECT_ERROR_PARAM,
  REDIRECT_FACTORS_PARAM,
  REDIRECT_LINKED_PARAM,
  REDIRECT_METHOD_PARAM,
  REDIRECT_NEXT_PARAM,
  SIGNIN_LINK_PARAM,
  VERIFY_LINK_PARAM,
} from './constants.js';
import { takeHashParam } from './hash.js';
import { request, type HttpResult, type RequestInit } from './http.js';
import { isLoginMethodId, type LoginMethodId } from './methods.js';
import { FACTOR_STEPS, pendingStepOf, type DeletedAccount, type PendingStep, type ProviderContext, type ServerConfig, type SignInProvider } from './providers/provider.js';
import { fail, isSecondFactor, ok, toErrorCode, type MadauthError, type MadauthUser, type Result } from './result.js';
import type { Core } from './scopes/core.js';
import { createAdminApi } from './scopes/admin.js';
import { createEmailLinkApi } from './scopes/email-link.js';
import { createGitHubApi } from './scopes/github.js';
import { createGoogleApi } from './scopes/google.js';
import { createMethodsApi } from './scopes/methods.js';
import { createPasskeyApi, type PasskeyInfo } from './scopes/passkey.js';
import { createPasswordApi } from './scopes/password.js';
import { createSmsApi } from './scopes/sms.js';
import { createTotpApi } from './scopes/totp.js';
import { stringsFor, type Strings } from './strings.js';

export interface MadauthOptions {
  /** Base URL of the madAuth server. Default: the page's own origin (e.g. behind a reverse proxy). */
  serverUrl?: string;
  /** The sign-in methods to offer, e.g. `[new GoogleFedcm(), new Password(), new Totp()]`. */
  providers: SignInProvider[];
  /**
   * `'dialog'` (default): madAuth's sign-in dialog, opened with `Madauth.signIn()`; it also opens by itself
   * when the page was opened from a password reset link, when a sign-in goes on with a second step, or with
   * the error of a sign-in that failed outside it (a redirect, a link, One Tap) while nobody is signed in.
   * `'custom'`: your own login screen, built with `Madauth.password`, `Madauth.google`, `Madauth.github`, `Madauth.totp`,
   * `Madauth.emailLink`, `Madauth.passkey`, `Madauth.sms` and `Madauth.methods`; the dialog never opens.
   */
  ui?: 'dialog' | 'custom';
  /**
   * Language of the dialog and of the e-mails, as a BCP 47 tag such as `de` or `de-CH`. The dialog has
   * English and German texts; every other language shows English. Default: the page's `<html lang>`, then
   * the browser's language. Change it later with `Madauth.setLocale`.
   */
  locale?: string;
}

export interface SignInOptions {
  /** Fills the dialog's e-mail field, e.g. with the address from a link to your page. */
  email?: string;
}

/** A current code from the authenticator app, or a recovery code: needed once the app is set up. */
export type DeleteAccountOptions = { code: string } | { recoveryCode: string };

export type AuthStateListener = (user: MadauthUser | null) => void;

/**
 * What `initialize` resolves to: a {@link Result}, plus `leftOut`, the methods whose providers were left out
 * because the server doesn't offer them (see {@link Madauth.initialize}). It is there on a failure as well,
 * e.g. when a redirect sign-in failed although madAuth is ready; empty when nothing was left out. `linked`
 * is set when the page came back from a redirect that added Google or GitHub to the signed-in user's methods
 * (a button with `purpose: 'link'`); one that failed is the failure, e.g. `account_taken`.
 */
export type InitializeResult = Result & { leftOut: LoginMethodId[]; linked?: 'google' | 'github' };

interface State {
  serverUrl: string;
  providers: Map<LoginMethodId, SignInProvider>;
  ui: 'dialog' | 'custom';
  /** The server's public settings, once fetched. */
  config?: ServerConfig;
  /** Settles when `initialize` is done; a failure here means madAuth is not usable. */
  ready: Promise<Result>;
}

let state: State | undefined;
let generation = 0;
let user: MadauthUser | null = null;
let userKnown = false;
const listeners = new Set<AuthStateListener>();
/** A sign-in error that happened outside the dialog (e.g. the redirect flow), shown when it next opens. */
let pendingError: MadauthError | undefined;
/** A sign-in whose first step is done and that goes on with a second step. */
let pendingStep: PendingStep | undefined;
/** The locale from `initialize` or `setLocale`; without one the page's or the browser's language counts. */
let configuredLocale: string | undefined;
const localeListeners = new Set<() => void>();
/** Watches `<html lang>` once something follows the locale. */
let langObserver: MutationObserver | undefined;

function sameUser(a: MadauthUser | null, b: MadauthUser | null): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** How long before its expiry the session no longer counts as usable for a request, and is renewed first. */
const RENEW_BEFORE_MS = 60_000;

let renewing: Promise<boolean> | undefined;

/** When the session expires (milliseconds since 1970), or undefined if the server's cookie is not there. */
function sessionExpiry(): number | undefined {
  const match = document.cookie.match(new RegExp(`(?:^|;\\s*)${EXPIRY_COOKIE}=(\\d+)`));
  return match ? Number(match[1]) * 1000 : undefined;
}

/** Asks the server for the session, which renews it if needed. One request serves all callers that wait. */
function renew(): Promise<boolean> {
  renewing ??= Madauth.getSession()
    .then((result) => result.isSuccess)
    .finally(() => (renewing = undefined));
  return renewing;
}

function setUser(next: MadauthUser | null, notifyAlways = false): void {
  const changed = notifyAlways || !userKnown || !sameUser(user, next);
  const signedIn = next !== null && !sameUser(user, next);
  user = next;
  userKnown = true;
  if (signedIn) for (const provider of state?.providers.values() ?? []) provider.onSignedIn?.();
  if (!changed) return;
  for (const listener of [...listeners]) {
    try {
      listener(user);
    } catch (e) {
      console.error('[madauth] onAuthStateChanged listener failed', e);
    }
  }
}

function changeLocale(locale: string | undefined): void {
  configuredLocale = locale;
  for (const listener of [...localeListeners]) listener();
}

function logError<T extends object>(result: Result<T>): Result<T> {
  if (!result.isSuccess) console.error('[madauth]', result.error.code, result.error.message);
  return result;
}

/** The step a `passkey_required`, `totp_required`, `sms_required`, `totp_setup_required` or `passkey_setup_required` error stands for, with the method whose sign-in it is. */
function nextStepOf(error: MadauthError): PendingStep | undefined {
  return pendingStepOf(error, isLoginMethodId(error.method) ? error.method : 'password');
}

/** A sign-in outside the dialog goes on with its second step: the dialog opens on that step. */
function continueSignIn(pending: PendingStep): void {
  stepPending(pending);
  openDialogSoon();
}

/** Whether the dialog is about to open by itself, so a page load with a reason or two opens it once. */
let dialogQueued = false;

/** Opens madAuth's dialog by itself (with `ui: 'dialog'`) once madAuth is ready. */
function openDialogSoon(): void {
  if (state?.ui !== 'dialog' || dialogQueued) return;
  dialogQueued = true;
  void whenReady().then(() => {
    dialogQueued = false;
    void Madauth.signIn();
  });
}

/**
 * A sign-in goes on with the authenticator app. The server ended the session there was at this browser,
 * so whoever was signed in is signed out until the step is done (then the new session arrives).
 */
function stepPending(pending: PendingStep | null): void {
  pendingStep = pending ?? undefined;
  if (pending && user) setUser(null);
}

function validate(
  options: MadauthOptions | undefined,
): Result<{ serverUrl: string; providers: Map<LoginMethodId, SignInProvider>; ui: 'dialog' | 'custom'; locale?: string }> {
  if (!options || !Array.isArray(options.providers)) {
    return fail('invalid_options', 'Madauth.initialize needs { providers: [...] }, e.g. [new GoogleFedcm()].');
  }
  const ui = options.ui ?? 'dialog';
  if (ui !== 'dialog' && ui !== 'custom') {
    return fail('invalid_options', `ui must be 'dialog' or 'custom' but is "${String(options.ui)}".`);
  }
  if (options.locale !== undefined && typeof options.locale !== 'string') {
    return fail('invalid_options', `locale must be a language tag such as 'de' or 'de-CH' but is "${String(options.locale)}".`);
  }
  let serverUrl = location.origin;
  if (options.serverUrl !== undefined) {
    let url: URL;
    try {
      url = new URL(options.serverUrl);
    } catch {
      return fail('invalid_options', `serverUrl must be an absolute http(s) URL but is "${options.serverUrl}".`);
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return fail('invalid_options', `serverUrl must be an absolute http(s) URL but is "${options.serverUrl}".`);
    }
    serverUrl = `${url.origin}${url.pathname}`.replace(/\/+$/, '');
  }
  const providers = new Map<LoginMethodId, SignInProvider>();
  for (const provider of options.providers) {
    if (!provider || typeof provider.setup !== 'function') {
      return fail('invalid_options', 'providers must contain sign-in providers such as new GoogleFedcm().');
    }
    if (providers.has(provider.method)) {
      return fail('invalid_options', `Only one provider per sign-in method is allowed, but "${provider.method}" is registered twice.`);
    }
    providers.set(provider.method, provider);
  }
  return ok({ serverUrl, providers, ui, locale: options.locale });
}

/**
 * Opened from the link in a confirmation e-mail: confirms the address and signs the user in, or goes on
 * with the next step: a second factor, or setting up the app or the passkey the user signs up with. The
 * same for a sign-up with a password, one with the app and one with a passkey.
 */
async function handleVerifyLink(ctx: ProviderContext): Promise<void> {
  // The token is a secret: it leaves the address bar (and so the history) right away.
  const token = takeHashParam(VERIFY_LINK_PARAM);
  if (!token) return;
  const res = await ctx.request<{ user: MadauthUser }>('/auth/email/verify', { method: 'POST', body: { token } });
  if (res.ok) ctx.signedIn(res.data.user);
  else ctx.signInFailed(res.error);
}

/**
 * Opened from the link in a sign-in e-mail (the e-mail link method): signs the user in, or goes on with the
 * authenticator app. The token is a secret, so it leaves the address bar whether or not the method is in use.
 */
async function handleSignInLink(ctx: ProviderContext, providers: Map<LoginMethodId, SignInProvider>): Promise<void> {
  const token = takeHashParam(SIGNIN_LINK_PARAM);
  if (!token) return;
  if (!providers.has('email-link')) {
    console.warn('[madauth]', 'The page was opened from a sign-in link, but no EmailLink provider is passed to Madauth.initialize.');
    return;
  }
  const res = await ctx.request<{ user: MadauthUser }>('/auth/email-link/verify', { method: 'POST', body: { token } });
  if (res.ok) ctx.signedIn(res.data.user);
  else ctx.signInFailed(res.error);
}

/**
 * Back from a redirect sign-in (Google's code flow, GitHub): with its error, or with the first step done and
 * a second factor or its setup next. The server names the method next to either; a server before 0.5 names
 * none, and only Google had a redirect flow then. Or back from a redirect that added the provider to the
 * signed-in user's methods: resolves to which. The URL is tidied up either way.
 */
function handleRedirectReturn(ctx: ProviderContext): 'google' | 'github' | undefined {
  const linked = takeHashParam(REDIRECT_LINKED_PARAM);
  const error = takeHashParam(REDIRECT_ERROR_PARAM);
  const next = takeHashParam(REDIRECT_NEXT_PARAM);
  const named = (takeHashParam(REDIRECT_FACTORS_PARAM) ?? '').split(',').filter(isSecondFactor);
  // Only the redirect providers come back this way: anything else in the hash counts as Google's.
  const via = takeHashParam(REDIRECT_METHOD_PARAM);
  if (linked === 'google' || linked === 'github') return linked;
  const method: LoginMethodId = via === 'github' ? 'github' : 'google';
  if (error) {
    const code = toErrorCode(error);
    const s = stringsFor(ctx.locale);
    const name = s.methodNames[method];
    const message = Object.hasOwn(s.redirectErrors, code) ? s.redirectErrors[code as keyof Strings['redirectErrors']](name) : s.redirectFailed(name, error);
    ctx.signInFailed({ code, message });
    return undefined;
  }
  if (isSecondFactor(next)) ctx.signInContinues({ step: FACTOR_STEPS[next], method, factors: named.length ? named : [next] });
  else if (next === 'totp-setup') ctx.signInContinues(named.length ? { step: 'setup', method, factors: named } : { step: 'setup', method });
  else if (next === 'passkey-setup') ctx.signInContinues({ step: 'setup', method, factors: ['passkey'] });
  return undefined;
}

async function initialize(target: State, run: number): Promise<{ ready: Result; result: InitializeResult }> {
  const { serverUrl, providers } = target;
  const call = <T>(path: string, init?: RequestInit): Promise<HttpResult<T>> => request<T>(serverUrl, path, init);

  const failed = (error: { isSuccess: false; error: MadauthError }, leftOut: LoginMethodId[] = []) => ({
    ready: error,
    result: { ...error, leftOut },
  });

  const [config, session] = await Promise.all([
    call<ServerConfig>('/auth/config'),
    call<{ user: MadauthUser }>('/auth/session'),
  ]);
  if (!config.ok) return failed({ isSuccess: false, error: config.error });
  if (!session.ok && session.status !== 401) return failed({ isSuccess: false, error: session.error });
  // A later initialize replaced this one: leave the user and the providers to it.
  if (run !== generation) return failed(fail('cancelled', 'Replaced by a later Madauth.initialize call.'));
  target.config = config.data;
  setUser(session.ok ? session.data.user : null, true);

  let signInError: MadauthError | undefined;
  const ctx: ProviderContext = {
    serverUrl,
    config: config.data,
    get currentUser() {
      return user;
    },
    get signInPending() {
      return pendingStep !== undefined;
    },
    get locale() {
      return currentLocale();
    },
    onLocaleChanged,
    request: call,
    signedIn: (signedIn) => {
      pendingError = undefined;
      pendingStep = undefined;
      setUser(signedIn);
    },
    signInFailed: (error) => {
      const next = nextStepOf(error);
      if (next) {
        continueSignIn(next);
        return;
      }
      signInError ??= error;
      pendingError = error;
      console.error('[madauth]', error.code, error.message);
      // The user left the dialog or the page to sign in (a redirect, a link, One Tap): the dialog shows why
      // it failed. Not over a session, e.g. a confirmation link clicked again after it signed the user in.
      if (!user) openDialogSoon();
    },
    signInContinues: continueSignIn,
  };
  await handleVerifyLink(ctx);
  await handleSignInLink(ctx, providers);
  const linked = handleRedirectReturn(ctx);
  // A provider for a method the server doesn't offer (e.g. GoogleRedirect without a Google client on
  // the server) is left out, so the page works with the other methods: the server's configuration
  // decides what is on, and a development server often has less than production. Other failures
  // (e.g. Google's script not loading) fail initialize.
  const notEnabled: string[] = [];
  const leftOut: LoginMethodId[] = [];
  for (const provider of providers.values()) {
    const result = await provider.setup(ctx);
    if (result.isSuccess) continue;
    if (result.error.code !== 'flow_not_enabled') return failed(result);
    providers.delete(provider.method);
    leftOut.push(provider.method);
    notEnabled.push(result.error.message);
    console.warn('[madauth]', result.error.code, `${result.error.message} Sign-in with "${provider.method}" is left out.`);
  }
  if (providers.size === 0 && notEnabled.length > 0) {
    return failed(fail('flow_not_enabled', `No sign-in method is enabled on the madAuth server. ${notEnabled.join(' ')}`), leftOut);
  }
  // Opened from a password reset link: show the dialog's "new password" form once madAuth is ready.
  if (Madauth.password.pendingReset) openDialogSoon();
  // A failed redirect sign-in is reported by initialize, but madAuth itself is ready.
  const extra = linked ? { linked } : {};
  return { ready: ok(), result: signInError ? { isSuccess: false, error: signInError, leftOut, ...extra } : { isSuccess: true, leftOut, ...extra } };
}

async function whenReady(): Promise<Result> {
  if (!state) return fail('not_initialized', 'Call Madauth.initialize({ providers: [...] }) first.');
  return state.ready;
}

const core: Core = {
  isConfigured: () => !!state,
  whenReady,
  provider: (method) => state?.providers.get(method),
  config: () => state?.config,
  locale: currentLocale,
  request: (path, init) => request(state!.serverUrl, path, init),
  signedIn: (signedIn) => {
    pendingError = undefined;
    pendingStep = undefined;
    setUser(signedIn);
  },
  pendingStep: () => pendingStep ?? null,
  setPendingStep: stepPending,
};

/** The page's `<madauth-login>`, created when it has none. */
function dialogElement() {
  let dialog = document.querySelector('madauth-login');
  if (!dialog) {
    dialog = document.createElement('madauth-login');
    document.body.append(dialog);
  }
  return dialog;
}

/** Fails unless madAuth is ready and shows its own dialog; `instead` names the calls for `ui: 'custom'`. */
async function dialogReady(call: string, instead = ''): Promise<Result> {
  const ready = await whenReady();
  if (!ready.isSuccess) return ready;
  if (state!.ui === 'custom') {
    return fail('invalid_options', `Madauth.${call}() opens madAuth's dialog, but initialize was called with ui: 'custom'.${instead && ` Use ${instead} instead.`}`);
  }
  return ok();
}

/** The dialog's events that end a flow, each with the result it resolves to. */
type FlowEvents<T> = { [K in keyof HTMLElementEventMap]?: (event: HTMLElementEventMap[K]) => T };

/**
 * Opens the dialog with `open` and resolves with the result of the first of `events` it fires, or with
 * `closed` when it is closed (`madauth-cancel`).
 */
function dialogFlow<T>(open: (element: HTMLElementTagNameMap['madauth-login']) => Promise<void>, events: FlowEvents<T>, closed: T): Promise<T> {
  const element = dialogElement();
  return new Promise((resolve) => {
    const all: [string, (event: never) => T][] = [...Object.entries(events), ['madauth-cancel', () => closed]];
    const listeners = all.map(([name, toResult]) => [name, (event: Event) => finish(toResult(event as never))] as const);
    const finish = (result: T) => {
      for (const [name, listener] of listeners) element.removeEventListener(name, listener);
      resolve(result);
    };
    for (const [name, listener] of listeners) element.addEventListener(name, listener);
    void open(element);
  });
}

/**
 * The madAuth client. Call {@link Madauth.initialize} once (no need to await it); every other method
 * waits for it. Methods resolve to a {@link Result} and never throw for expected failures.
 */
export const Madauth = {
  /**
   * Configures madAuth: checks the server, sets up the providers (e.g. shows Google One Tap) and loads
   * the current session. Failures are returned and also logged to the console. A provider whose method
   * the server doesn't offer (e.g. `GoogleRedirect` without a client secret on the server) is left out
   * with a warning and named in the result's `leftOut`; the other methods work. Calling it again replaces
   * the configuration.
   */
  initialize(options: MadauthOptions): Promise<InitializeResult> {
    const run = ++generation;
    pendingError = undefined;
    pendingStep = undefined;
    const valid = validate(options);
    changeLocale(valid.isSuccess ? valid.locale : undefined);
    if (!valid.isSuccess) {
      state = { serverUrl: '', providers: new Map(), ui: 'dialog', ready: Promise.resolve(valid) };
      logError(valid);
      return Promise.resolve({ ...valid, leftOut: [] });
    }
    const next: State = { serverUrl: valid.serverUrl, providers: valid.providers, ui: valid.ui, ready: Promise.resolve(ok()) };
    state = next;
    const done = initialize(next, run);
    next.ready = done.then((d) => d.ready);
    return done.then((d) => {
      logError(d.result);
      return d.result;
    });
  },

  /**
   * Opens the sign-in dialog (creating a `<madauth-login>` if the page has none) and resolves with the
   * signed-in user, or fails with `cancelled` when the dialog is closed. With `GoogleRedirect` the page
   * navigates to Google; the user then arrives through {@link Madauth.onAuthStateChanged}.
   * `email` fills the e-mail field, so the user only has to type the password.
   */
  async signIn(options: SignInOptions = {}): Promise<Result<{ user: MadauthUser }>> {
    const ready = await dialogReady('signIn');
    if (!ready.isSuccess) return ready;
    return dialogFlow<Result<{ user: MadauthUser }>>(
      (element) => element.open(options),
      { 'madauth-signed-in': (e) => ({ isSuccess: true, user: e.detail.user }) },
      fail('cancelled', 'The sign-in dialog was closed.'),
    );
  },

  /**
   * Opens the dialog on the "Set up authenticator app" screen for the signed-in user: a QR code to scan
   * with the app, a field for the first code it shows, and the recovery codes to save. Resolves with the
   * recovery codes once the user has seen them. A user who has an app already is asked for a code from it
   * first: a new app replaces it. Fails with `cancelled` when the dialog is closed before, `no_session` when
   * nobody is signed in, and `flow_not_enabled` when the server has the app switched off (no `new Totp()`
   * is needed). With `ui: 'custom'` use `Madauth.totp.startSetup()` and `confirmSetup()`.
   */
  async setUpAuthenticator(): Promise<Result<{ recoveryCodes: string[] }>> {
    const ready = await dialogReady('setUpAuthenticator', 'Madauth.totp.startSetup() and confirmSetup()');
    if (!ready.isSuccess) return ready;
    if (!state!.config?.totp) {
      return fail('flow_not_enabled', 'The madAuth server has the authenticator app switched off: no sign-in method is set to ask for it, and it does not sign in on its own.');
    }
    if (!user) return fail('no_session', 'Nobody is signed in.');
    return dialogFlow<Result<{ recoveryCodes: string[] }>>(
      (element) => element.openAuthenticatorSetup(),
      {
        'madauth-authenticator-enabled': (e) => ({ isSuccess: true, recoveryCodes: e.detail.recoveryCodes }),
        // The setup can't go on (e.g. the session ended meanwhile): the dialog shows why, and the caller learns it too.
        'madauth-authenticator-failed': (e) => ({ isSuccess: false, error: e.detail.error }),
      },
      fail('cancelled', 'The dialog was closed.'),
    );
  },

  /**
   * Opens the dialog on the "Add your phone number" screen for the signed-in user: a field for the number,
   * then one for the code sent to it. Resolves with the number as it is shown (masked) once it is confirmed.
   * A user who has a number already is asked for a code sent to it first: the new number replaces it. Fails
   * with `cancelled` when the dialog is closed before, `no_session` when nobody is signed in, and
   * `flow_not_enabled` when the server has SMS codes switched off. With `ui: 'custom'` use
   * `Madauth.sms.setUp()` and `confirmSetup()`.
   */
  async setUpSms(): Promise<Result<{ phone: string }>> {
    const ready = await dialogReady('setUpSms', 'Madauth.sms.setUp() and confirmSetup()');
    if (!ready.isSuccess) return ready;
    if (!state!.config?.sms) return fail('flow_not_enabled', 'The madAuth server has SMS codes switched off.');
    if (!user) return fail('no_session', 'Nobody is signed in.');
    return dialogFlow<Result<{ phone: string }>>(
      (element) => element.openSmsSetup(),
      {
        'madauth-sms-enabled': (e) => ({ isSuccess: true, phone: e.detail.phone }),
        'madauth-sms-failed': (e) => ({ isSuccess: false, error: e.detail.error }),
      },
      fail('cancelled', 'The dialog was closed.'),
    );
  },

  /**
   * Opens the dialog on the "Create a passkey" screen for the signed-in user; the browser's passkey dialog
   * follows. Resolves with the new passkey. Within ten minutes of signing in only: later the dialog asks the
   * user to sign in again first, and goes on with the passkey after. Fails with `cancelled` when the dialog
   * is closed before, `no_session` when nobody is signed in, and `flow_not_enabled` when the server has
   * passkeys switched off or the browser has none. With `ui: 'custom'` use `Madauth.passkey.add()`.
   */
  async setUpPasskey(): Promise<Result<{ passkey: PasskeyInfo }>> {
    const ready = await dialogReady('setUpPasskey', 'Madauth.passkey.add()');
    if (!ready.isSuccess) return ready;
    if (!Madauth.passkey.available) return fail('flow_not_enabled', 'The madAuth server has passkeys switched off, or this browser has none.');
    if (!user) return fail('no_session', 'Nobody is signed in.');
    return dialogFlow<Result<{ passkey: PasskeyInfo }>>(
      (element) => element.openPasskeySetup(),
      { 'madauth-passkey-added': (e) => ({ isSuccess: true, passkey: e.detail.passkey }) },
      fail('cancelled', 'The dialog was closed.'),
    );
  },

  /**
   * Opens the dialog on the signed-in user's sign-in methods: which they have, with buttons to add another
   * (a passkey, a password, Google, GitHub, the e-mail link, the authenticator app, as the server offers them)
   * and to remove one. Resolves when the dialog is closed. Changing a method takes a sign-in within the last
   * ten minutes: the dialog asks the user to sign in again when needed. Fails with `no_session` when nobody is
   * signed in. With `ui: 'custom'` use `Madauth.methods` and the methods' own calls.
   */
  async manageSignInMethods(): Promise<Result> {
    const ready = await dialogReady('manageSignInMethods', 'Madauth.methods');
    if (!ready.isSuccess) return ready;
    if (!user) return fail('no_session', 'Nobody is signed in.');
    return dialogFlow<Result>((element) => element.openMethods(), {}, ok());
  },

  /**
   * Changes the language of the dialog and of the e-mails, e.g. when the user switches the language of
   * your app. An open dialog shows the new language at once. See {@link MadauthOptions.locale}.
   */
  setLocale(locale: string): void {
    if (typeof locale !== 'string') {
      console.error('[madauth]', 'invalid_options', `locale must be a language tag such as 'de' or 'de-CH' but is "${String(locale)}".`);
      return;
    }
    changeLocale(locale);
  },

  /** Ends the session on the server and notifies {@link Madauth.onAuthStateChanged} listeners. */
  async signOut(): Promise<Result> {
    const ready = await whenReady();
    if (!ready.isSuccess) return ready;
    const res = await request(state!.serverUrl, '/auth/logout', { method: 'POST' });
    if (!res.ok) return { isSuccess: false, error: res.error };
    for (const provider of state!.providers.values()) provider.onSignedOut?.();
    pendingStep = undefined;
    setUser(null);
    return ok();
  },

  /**
   * Deletes the signed-in user's account on the madAuth server and signs them out: the user with all their
   * sign-in methods, whichever way they signed in. Delete the user's data in your own backend first, while
   * they are still signed in. Once the user has an authenticator app, a current code from it (or a recovery
   * code) is needed: without one it fails with `code_required`, with a wrong one with `code_invalid`.
   * Fails with `no_session` when nobody is signed in, and with `own_admin_role` for a user with the role
   * `admin`: another admin takes it from them first. With `GoogleFedcm`, the app's access to the user's
   * Google account is revoked as well, so Google no longer lists it among their connected apps.
   */
  async deleteAccount(options?: DeleteAccountOptions): Promise<Result> {
    const ready = await whenReady();
    if (!ready.isSuccess) return ready;
    const res = await request<DeletedAccount | undefined>(state!.serverUrl, '/auth/account/delete', { method: 'POST', body: options ? { ...options } : undefined });
    if (!res.ok && !(res.status === 401 && res.error.code === 'no_session')) return { isSuccess: false, error: res.error };
    for (const provider of state!.providers.values()) {
      provider.onSignedOut?.();
      // A 204 has no body: the user had no Google account.
      if (res.ok) provider.onAccountDeleted?.(res.data ?? {});
    }
    setUser(null);
    return res.ok ? ok() : fail('no_session', 'Nobody is signed in.');
  },

  /** Asks the server for the current session. Fails with `no_session` when nobody is signed in. */
  async getSession(): Promise<Result<{ user: MadauthUser }>> {
    const ready = await whenReady();
    if (!ready.isSuccess) return ready;
    const res = await request<{ user: MadauthUser }>(state!.serverUrl, '/auth/session');
    if (res.ok) {
      setUser(res.data.user);
      return { isSuccess: true, user: res.data.user };
    }
    if (res.status === 401) {
      setUser(null);
      return fail('no_session', 'Nobody is signed in.');
    }
    return { isSuccess: false, error: res.error };
  },

  /**
   * Resolves when the session cookie can be relied on for a request to your own backend, and to whether
   * somebody is signed in. It resolves at once while the session is valid and when nobody is signed in;
   * a session that has expired (e.g. the page was opened after hours) is renewed first.
   *
   * ```ts
   * await Madauth.sessionReady();
   * const response = await fetch('/api/orders'); // the backend finds a valid session cookie
   * ```
   */
  async sessionReady(): Promise<boolean> {
    if (!state?.serverUrl) return false;
    const expiry = sessionExpiry();
    if (expiry !== undefined) return expiry - Date.now() > RENEW_BEFORE_MS ? true : renew();
    // No cookie from the server. On the server's own origin that means nobody is signed in. A server on
    // another origin may have set a cookie this page can't see, so it is asked.
    if (new URL(state.serverUrl).origin === location.origin) return user !== null;
    await whenReady();
    return user !== null;
  },

  /** The last known signed-in user, or null. */
  get currentUser(): MadauthUser | null {
    return user;
  },

  /** E-mail & password sign-in for custom login screens. Needs `new Password()`. */
  password: createPasswordApi(core),

  /** Google sign-in for custom login screens. Needs `new GoogleFedcm()` or `new GoogleRedirect()`. */
  google: createGoogleApi(core),

  /** GitHub sign-in for custom login screens. Needs `new GitHub()`. */
  github: createGitHubApi(core),

  /** The authenticator app for custom login screens: sign-in, the second step, the setup. Needs `new Totp()`. */
  totp: createTotpApi(core),

  /** The passwordless e-mail link for custom login screens. Needs `new EmailLink()`. */
  emailLink: createEmailLinkApi(core),

  /** SMS codes as a second factor: the second step, and adding or removing the phone. Needs no provider. */
  sms: createSmsApi(core),

  /** Passkeys: signing in with one (needs `new Passkey()`), the second step, adding and renaming them. */
  passkey: createPasskeyApi(core),

  /** The signed-in user's sign-in methods: listing and removing them. */
  methods: createMethodsApi(core),

  /** Reading and setting claims and settings, for users with the role `admin`. */
  admin: createAdminApi(core),

  /**
   * Calls `listener` with the current user once it is known, and again on every sign-in and sign-out.
   * Returns a function that unsubscribes. Can be called before `initialize`.
   */
  onAuthStateChanged(listener: AuthStateListener): () => void {
    listeners.add(listener);
    if (userKnown) {
      queueMicrotask(() => {
        if (listeners.has(listener)) listener(user);
      });
    }
    return () => {
      listeners.delete(listener);
    };
  },
};

// --- Internal, for <madauth-login> ---

/** The provider registered for a sign-in method, if any. */
export function providerFor(method: LoginMethodId): SignInProvider | undefined {
  return state?.providers.get(method);
}

/** Resolves when madAuth is usable (or why not). */
export function readyForDialog(): Promise<Result> {
  return whenReady();
}

/** The locale of the dialog's texts and of the e-mails: the configured one, else the page's, else the browser's. */
export function currentLocale(): string | undefined {
  return configuredLocale || document.documentElement.lang || navigator.language || undefined;
}

/** Calls `listener` when the configured locale changes. Returns a function that unsubscribes. */
export function onLocaleChanged(listener: () => void): () => void {
  localeListeners.add(listener);
  // Without a configured locale the page's <html lang> counts, so a page that changes it is followed too.
  if (!langObserver && typeof MutationObserver !== 'undefined') {
    langObserver = new MutationObserver(() => {
      if (!configuredLocale) for (const l of [...localeListeners]) l();
    });
    langObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
  }
  return () => {
    localeListeners.delete(listener);
  };
}

/** Returns and clears an error from a sign-in that happened outside the dialog. */
export function takePendingError(): MadauthError | undefined {
  const error = pendingError;
  pendingError = undefined;
  return error;
}

/** The step a sign-in that started outside the dialog goes on with, if any; the dialog takes it over. */
export function takePendingStep(): PendingStep | undefined {
  const pending = pendingStep;
  pendingStep = undefined;
  return pending;
}

/** Test hook: forgets all configuration, the user and the listeners. */
export function resetMadauthForTests(): void {
  state = undefined;
  generation++;
  renewing = undefined;
  user = null;
  userKnown = false;
  pendingError = undefined;
  pendingStep = undefined;
  dialogQueued = false;
  configuredLocale = undefined;
  listeners.clear();
  localeListeners.clear();
  langObserver?.disconnect();
  langObserver = undefined;
}
