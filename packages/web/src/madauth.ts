import { EXPIRY_COOKIE, VERIFY_LINK_PARAM } from './constants.js';
import { request, type HttpResult, type RequestInit } from './http.js';
import type { AuthenticatorEnabledDetail } from './madauth-login.js';
import type { LoginMethodId } from './methods.js';
import type { PendingStep, ProviderContext, ServerConfig, SignInProvider } from './providers/provider.js';
import { fail, ok, type MadauthError, type MadauthUser, type Result } from './result.js';
import type { Core } from './scopes/core.js';
import { createAdminApi } from './scopes/admin.js';
import { createGoogleApi } from './scopes/google.js';
import { createPasswordApi } from './scopes/password.js';
import { createTotpApi } from './scopes/totp.js';

export interface MadauthOptions {
  /** Base URL of the madAuth server. Default: the page's own origin (e.g. behind a reverse proxy). */
  serverUrl?: string;
  /** The sign-in methods to offer, e.g. `[new GoogleFedcm(), new Password(), new Totp()]`. */
  providers: SignInProvider[];
  /**
   * `'dialog'` (default): madAuth's sign-in dialog, opened with `Madauth.signIn()`; it also opens by itself
   * when the page was opened from a password reset link, or when a sign-in goes on with the authenticator app.
   * `'custom'`: your own login screen, built with `Madauth.password`, `Madauth.google` and `Madauth.totp`;
   * the dialog never opens.
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
 * e.g. when a redirect sign-in failed although madAuth is ready; empty when nothing was left out.
 */
export type InitializeResult = Result & { leftOut: LoginMethodId[] };

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
/** A sign-in whose first step is done and that goes on with the authenticator app. */
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

/** The step a `totp_required` or `totp_setup_required` error stands for, with the method whose sign-in it is. */
function nextStepOf(error: MadauthError): PendingStep | undefined {
  if (error.code !== 'totp_required' && error.code !== 'totp_setup_required') return undefined;
  const method = (['google', 'password', 'totp'] as const).find((m) => m === error.method) ?? 'password';
  return { step: error.code === 'totp_required' ? 'code' : 'setup', method };
}

/** A sign-in outside the dialog goes on with the authenticator app: the dialog opens on that step. */
function continueSignIn(pending: PendingStep): void {
  pendingStep = pending;
  if (state?.ui === 'dialog') queueMicrotask(() => void Madauth.signIn());
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
 * with the authenticator app. The same for a sign-up with a password and one with the app.
 */
async function handleVerifyLink(ctx: ProviderContext): Promise<void> {
  const params = new URLSearchParams(location.hash.slice(1));
  const token = params.get(VERIFY_LINK_PARAM);
  if (!token) return;
  // The token is a secret: take it out of the address bar (and so the history) right away.
  params.delete(VERIFY_LINK_PARAM);
  const hash = params.toString();
  history.replaceState(history.state, '', `${location.pathname}${location.search}${hash ? `#${hash}` : ''}`);
  const res = await ctx.request<{ user: MadauthUser }>('/auth/email/verify', { method: 'POST', body: { token } });
  if (res.ok) ctx.signedIn(res.data.user);
  else ctx.signInFailed(res.error);
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
    },
    signInContinues: continueSignIn,
  };
  await handleVerifyLink(ctx);
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
  if (target.ui === 'dialog' && Madauth.password.pendingReset) queueMicrotask(() => void Madauth.signIn());
  // A failed redirect sign-in is reported by initialize, but madAuth itself is ready.
  return { ready: ok(), result: signInError ? { isSuccess: false, error: signInError, leftOut } : { isSuccess: true, leftOut } };
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
  setPendingStep: (pending) => {
    pendingStep = pending ?? undefined;
  },
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
    const ready = await whenReady();
    if (!ready.isSuccess) return ready;
    if (state!.ui === 'custom') {
      return fail('invalid_options', "Madauth.signIn() opens madAuth's dialog, but initialize was called with ui: 'custom'.");
    }
    const element = dialogElement();
    return new Promise((resolve) => {
      const finish = (result: Result<{ user: MadauthUser }>) => {
        element.removeEventListener('madauth-signed-in', onSignedIn);
        element.removeEventListener('madauth-cancel', onCancel);
        resolve(result);
      };
      const onSignedIn = (e: CustomEvent<{ user: MadauthUser }>) => finish({ isSuccess: true, user: e.detail.user });
      const onCancel = () => finish(fail('cancelled', 'The sign-in dialog was closed.'));
      element.addEventListener('madauth-signed-in', onSignedIn);
      element.addEventListener('madauth-cancel', onCancel);
      void element.open(options);
    });
  },

  /**
   * Opens the dialog on the "Set up authenticator app" screen for the signed-in user: a QR code to scan
   * with the app, a field for the first code it shows, and the recovery codes to save. Resolves with the
   * recovery codes once the user has seen them. Fails with `cancelled` when the dialog is closed before,
   * `no_session` when nobody is signed in, and `flow_not_enabled` without `new Totp()` or with the app
   * switched off on the server. With `ui: 'custom'` use `Madauth.totp.startSetup()` and `confirmSetup()`.
   */
  async setUpAuthenticator(): Promise<Result<{ recoveryCodes: string[] }>> {
    const ready = await whenReady();
    if (!ready.isSuccess) return ready;
    if (state!.ui === 'custom') {
      return fail(
        'invalid_options',
        "Madauth.setUpAuthenticator() opens madAuth's dialog, but initialize was called with ui: 'custom'. Use Madauth.totp.startSetup() and confirmSetup() instead.",
      );
    }
    if (!state!.providers.has('totp')) {
      return fail('flow_not_enabled', 'Pass new Totp() to Madauth.initialize to use Madauth.setUpAuthenticator (and the server must have the app switched on).');
    }
    if (!user) return fail('no_session', 'Nobody is signed in.');
    const element = dialogElement();
    return new Promise((resolve) => {
      const finish = (result: Result<{ recoveryCodes: string[] }>) => {
        element.removeEventListener('madauth-authenticator-enabled', onEnabled);
        element.removeEventListener('madauth-cancel', onCancel);
        resolve(result);
      };
      const onEnabled = (e: CustomEvent<AuthenticatorEnabledDetail>) => finish({ isSuccess: true, recoveryCodes: e.detail.recoveryCodes });
      const onCancel = () => finish(fail('cancelled', 'The dialog was closed.'));
      element.addEventListener('madauth-authenticator-enabled', onEnabled);
      element.addEventListener('madauth-cancel', onCancel);
      void element.openAuthenticatorSetup();
    });
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
   * Fails with `no_session` when nobody is signed in.
   */
  async deleteAccount(options?: DeleteAccountOptions): Promise<Result> {
    const ready = await whenReady();
    if (!ready.isSuccess) return ready;
    const res = await request(state!.serverUrl, '/auth/account/delete', { method: 'POST', body: options ? { ...options } : undefined });
    if (!res.ok && !(res.status === 401 && res.error.code === 'no_session')) return { isSuccess: false, error: res.error };
    for (const provider of state!.providers.values()) provider.onSignedOut?.();
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

  /** The authenticator app for custom login screens: sign-in, the second step, the setup. Needs `new Totp()`. */
  totp: createTotpApi(core),

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
  configuredLocale = undefined;
  listeners.clear();
  localeListeners.clear();
  langObserver?.disconnect();
  langObserver = undefined;
}
