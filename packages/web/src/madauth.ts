import { EXPIRY_COOKIE } from './constants.js';
import { request, type HttpResult, type RequestInit } from './http.js';
import type { LoginMethodId } from './methods.js';
import type { ProviderContext, ServerConfig, SignInProvider } from './providers/provider.js';
import { fail, ok, type MadauthError, type MadauthUser, type Result } from './result.js';
import type { Core } from './scopes/core.js';
import { createAdminApi } from './scopes/admin.js';
import { createGoogleApi } from './scopes/google.js';
import { createPasswordApi } from './scopes/password.js';

export interface MadauthOptions {
  /** Base URL of the madAuth server. Default: the page's own origin (e.g. behind a reverse proxy). */
  serverUrl?: string;
  /** The sign-in methods to offer, e.g. `[new GoogleFedcm(), new Password()]`. */
  providers: SignInProvider[];
  /**
   * `'dialog'` (default): madAuth's sign-in dialog, opened with `Madauth.signIn()`; it also opens by itself
   * when the page was opened from a password reset link.
   * `'custom'`: your own login screen, built with `Madauth.password` and `Madauth.google`; the dialog never opens.
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

export type AuthStateListener = (user: MadauthUser | null) => void;

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

function logError(result: Result): Result {
  if (!result.isSuccess) console.error('[madauth]', result.error.code, result.error.message);
  return result;
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

async function initialize(target: State, run: number): Promise<{ ready: Result; result: Result }> {
  const { serverUrl, providers } = target;
  const call = <T>(path: string, init?: RequestInit): Promise<HttpResult<T>> => request<T>(serverUrl, path, init);

  const failed = (result: Result) => ({ ready: result, result });

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
      setUser(signedIn);
    },
    signInFailed: (error) => {
      signInError ??= error;
      pendingError = error;
      console.error('[madauth]', error.code, error.message);
    },
  };
  // A provider for a method the server doesn't offer (e.g. GoogleRedirect without a Google client on
  // the server) is left out, so the page works with the other methods: the server's configuration
  // decides what is on, and a development server often has less than production. Other failures
  // (e.g. Google's script not loading) fail initialize.
  const notEnabled: string[] = [];
  for (const provider of providers.values()) {
    const result = await provider.setup(ctx);
    if (result.isSuccess) continue;
    if (result.error.code !== 'flow_not_enabled') return failed(result);
    providers.delete(provider.method);
    notEnabled.push(result.error.message);
    console.warn('[madauth]', result.error.code, `${result.error.message} Sign-in with "${provider.method}" is left out.`);
  }
  if (providers.size === 0 && notEnabled.length > 0) {
    return failed(fail('flow_not_enabled', `No sign-in method is enabled on the madAuth server. ${notEnabled.join(' ')}`));
  }
  // Opened from a password reset link: show the dialog's "new password" form once madAuth is ready.
  if (target.ui === 'dialog' && Madauth.password.pendingReset) queueMicrotask(() => void Madauth.signIn());
  // A failed redirect sign-in is reported by initialize, but madAuth itself is ready.
  return { ready: ok(), result: signInError ? { isSuccess: false, error: signInError } : ok() };
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
    setUser(signedIn);
  },
};

/**
 * The madAuth client. Call {@link Madauth.initialize} once (no need to await it); every other method
 * waits for it. Methods resolve to a {@link Result} and never throw for expected failures.
 */
export const Madauth = {
  /**
   * Configures madAuth: checks the server, sets up the providers (e.g. shows Google One Tap) and loads
   * the current session. Failures are returned and also logged to the console. Calling it again replaces
   * the configuration.
   */
  initialize(options: MadauthOptions): Promise<Result> {
    const run = ++generation;
    pendingError = undefined;
    const valid = validate(options);
    changeLocale(valid.isSuccess ? valid.locale : undefined);
    if (!valid.isSuccess) {
      state = { serverUrl: '', providers: new Map(), ui: 'dialog', ready: Promise.resolve(valid) };
      return Promise.resolve(logError(valid));
    }
    const next: State = { serverUrl: valid.serverUrl, providers: valid.providers, ui: valid.ui, ready: Promise.resolve(ok()) };
    state = next;
    const done = initialize(next, run);
    next.ready = done.then((d) => d.ready);
    return done.then((d) => logError(d.result));
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
    let dialog = document.querySelector('madauth-login');
    if (!dialog) {
      dialog = document.createElement('madauth-login');
      document.body.append(dialog);
    }
    const element = dialog;
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
    setUser(null);
    return ok();
  },

  /**
   * Deletes the signed-in user's account on the madAuth server and signs them out: the e-mail & password
   * account of their address goes, whichever way they signed in. Delete the user's data in your own
   * backend first, while they are still signed in. Fails with `no_session` when nobody is signed in.
   */
  async deleteAccount(): Promise<Result> {
    const ready = await whenReady();
    if (!ready.isSuccess) return ready;
    const res = await request(state!.serverUrl, '/auth/account/delete', { method: 'POST' });
    if (!res.ok && res.status !== 401) return { isSuccess: false, error: res.error };
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

/** Test hook: forgets all configuration, the user and the listeners. */
export function resetMadauthForTests(): void {
  state = undefined;
  generation++;
  renewing = undefined;
  user = null;
  userKnown = false;
  pendingError = undefined;
  configuredLocale = undefined;
  listeners.clear();
  localeListeners.clear();
  langObserver?.disconnect();
  langObserver = undefined;
}
