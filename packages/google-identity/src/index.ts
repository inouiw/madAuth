// @madauth/google-identity: a Google ID token in the browser, and nothing else. The browser's FedCM API where it
// exists, Google One Tap and Google's button otherwise, through Google Identity Services (GIS). No backend: what
// to do with the token is the app's business (the madAuth client verifies it at the madAuth server, for example).
import { loadGis, loadedGis, type GoogleAccountsId, type GsiButtonConfiguration, type PromptMomentNotification } from './gis.js';

export {
  GIS_SRC,
  loadGis,
  resetGisForTests,
  type CredentialResponse,
  type GoogleAccountsId,
  type GsiButtonConfiguration,
  type IdConfiguration,
  type PromptMomentNotification,
} from './gis.js';

/** A Google ID token (a JWT) for the client ID, with the nonce in it. */
export interface GoogleCredential {
  idToken: string;
  /** Whether the browser signed the user in without asking (a returning user with one account). */
  isAutoSelected: boolean;
}

/**
 * Why there is no token:
 * - `cancelled`: `cancel()` was called, the `signal` aborted, or the user closed the browser's dialog;
 * - `skipped`: the prompt was not shown, or closed without a choice: Chrome's cooldown after dismissals, no Google
 *   session in the browser, a user who opted out of One Tap, …; `detail` has Google's reason when it names one;
 * - `configuration_error`: the client ID is missing or the page's origin is not among its authorized origins;
 * - `load_failed`: Google's script could not be loaded (offline, a blocker);
 * - `error`: anything else, named in `detail`.
 */
export type NoCredentialReason = 'cancelled' | 'skipped' | 'configuration_error' | 'load_failed' | 'error';

export interface NoCredential {
  reason: NoCredentialReason;
  detail?: string;
}

export type CredentialResult = ({ isSuccess: true } & GoogleCredential) | ({ isSuccess: false } & NoCredential);

export interface SignInOptions {
  /** The OAuth client ID of type "Web application" the token is issued for. */
  clientId: string;
  /** Goes into the token's `nonce` claim unchanged; a new one for each sign-in, from the server that verifies the token. */
  nonce: string;
  /**
   * Sign a returning user with one account in without asking (`mediation: 'optional'` / `auto_select`). Default
   * `false`: the user always picks. A call after `disableAutoSelect()` always asks.
   */
  autoSelect?: boolean;
  /** How Google words the prompt: signing in (default), signing up, or using the account with this site. */
  context?: 'signin' | 'signup' | 'use';
  /** Aborting it ends the sign-in with `cancelled`. */
  signal?: AbortSignal;
  /**
   * Use the browser's own FedCM API (`navigator.credentials.get`) where the browser has it, default `true`. With
   * `false`, One Tap goes through Google's script in every browser.
   */
  fedcm?: boolean;
  /** Whether a tap outside One Tap closes it (Google's script only; the browser's dialog has its own rules). Default `true`. */
  cancelOnTapOutside?: boolean;
}

export interface ButtonOptions {
  clientId: string;
  nonce: string;
  context?: 'signin' | 'signup' | 'use';
  /**
   * Called with Google's token each time the user signs in through the button. A nonce is for one sign-in: render
   * the button again with a new one when the token was refused.
   */
  onCredential(credential: GoogleCredential): void;
  /** How the button looks; Google's defaults otherwise (`type: 'standard'`). */
  button?: GsiButtonConfiguration;
  /**
   * `popup` (default) hands the token to `onCredential`. `redirect` makes Google's page POST it to `loginUri`
   * (the current page without one) as `credential`, and `onCredential` is not called.
   */
  uxMode?: 'popup' | 'redirect';
  loginUri?: string;
}

/** The button is there, with `remove()`; or Google's script could not be loaded (`load_failed`) or threw (`error`). */
export type RenderedButton = { isSuccess: true; remove(): void } | ({ isSuccess: false } & NoCredential);

/** Whether the browser has the FedCM API that Google's sign-in uses. */
export function isFedcmSupported(): boolean {
  return typeof window !== 'undefined' && 'IdentityCredential' in window && !!navigator.credentials?.get;
}

const fail = (reason: NoCredentialReason, detail?: string): { isSuccess: false } & NoCredential =>
  detail === undefined ? { isSuccess: false, reason } : { isSuccess: false, reason, detail };

/** The sign-ins through the browser's FedCM API that are under way, so that `cancel()` can end them. */
const fedcmInFlight = new Set<AbortController>();

/** What Google's script throws, as a result: its calls are not expected to throw, but a result-only contract has no other place for it. */
function attempt(run: () => void): ({ isSuccess: false } & NoCredential) | undefined {
  try {
    run();
    return undefined;
  } catch (e) {
    return fail('error', e instanceof Error ? `${e.name}: ${e.message}` : String(e));
  }
}

/** Google's script, or why not. */
async function gis(): Promise<{ isSuccess: true; gis: GoogleAccountsId } | ({ isSuccess: false } & NoCredential)> {
  return loadGis().then(
    (loaded) => ({ isSuccess: true as const, gis: loaded }),
    (e: Error) => ({
      isSuccess: false as const,
      reason: 'load_failed' as const,
      detail: e.message,
    }),
  );
}

/**
 * Signs in with Google: the browser's "Continue as …" dialog (FedCM) where the browser has it, One Tap through
 * Google's script otherwise. Resolves once with the ID token, or with why there is none; it never rejects.
 * Google's script holds one configuration at a time: a sign-in or a button started later takes over its callback.
 */
export async function signIn(options: SignInOptions): Promise<CredentialResult> {
  if (options.signal?.aborted) return fail('cancelled');
  if ((options.fedcm ?? true) && isFedcmSupported()) return fedcmSignIn(options);
  return promptSignIn(options);
}

async function fedcmSignIn({ clientId, nonce, autoSelect, context, signal }: SignInOptions): Promise<CredentialResult> {
  const controller = new AbortController();
  signal?.addEventListener('abort', () => controller.abort(), {
    once: true,
    signal: controller.signal,
  });
  fedcmInFlight.add(controller);
  // See https://developers.google.com/privacy-sandbox/cookies/fedcm and Google's gsi/client, which sends the same.
  const request = {
    identity: {
      context: context ?? 'signin',
      providers: [
        {
          configURL: 'https://accounts.google.com/gsi/fedcm.json',
          clientId,
          nonce,
          fields: ['name', 'email', 'picture'],
          // Google builds the continuation popup's URL from these. Without them the popup fails with
          // "Required parameter is missing: response_type".
          params: {
            response_type: 'id_token',
            scope: 'email profile openid',
            ss_domain: location.origin,
            nonce,
          },
        },
      ],
    },
    mediation: autoSelect ? 'optional' : 'required',
    signal: controller.signal,
  } as CredentialRequestOptions;
  const result = await navigator.credentials.get(request).then(
    (credential): CredentialResult => {
      const identity = credential as (Credential & { token?: string; isAutoSelected?: boolean }) | null;
      if (!identity?.token) return fail('skipped', 'the browser answered without a token');
      const idToken = idTokenOf(identity.token);
      return idToken
        ? { isSuccess: true, idToken, isAutoSelected: identity.isAutoSelected ?? false }
        : fail('error', 'the browser answered with a token that holds no id_token');
    },
    (e: unknown) => fedcmFailure(e, controller.signal.aborted),
  );
  fedcmInFlight.delete(controller);
  // The listener on the caller's signal goes with the controller.
  controller.abort();
  return result;
}

/**
 * The ID token in the token the browser's FedCM API answers with. With the `params` this package sends (as Google's
 * own script does), Google's token is JSON with the ID token in `id_token`, e.g.
 * `{"iss":"https://accounts.google.com","id_token":"eyJ…","authuser":"0","prompt":"none"}`. A JWT never starts with
 * `{` (it is base64url), so any other token is taken as the ID token itself. Undefined for JSON without an ID token.
 */
function idTokenOf(token: string): string | undefined {
  const trimmed = token.trim();
  if (!trimmed.startsWith('{')) return token;
  const idToken = parseJson(trimmed)?.id_token;
  return typeof idToken === 'string' && idToken ? idToken : undefined;
}

/** `JSON.parse` for an object, or undefined: the browser's answer is not ours to trust to be well-formed. */
function parseJson(text: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function fedcmFailure(e: unknown, aborted: boolean): CredentialResult {
  const { name = '', message = '' } = (e ?? {}) as {
    name?: string;
    message?: string;
  };
  // Ours, or the browser's own (a competing credentials.get on the page, a navigation).
  if (aborted || name === 'AbortError') return fail('cancelled');
  // Chrome reports the dialog the user closed as a network error.
  if (name === 'NetworkError' && message.includes('Error retrieving a token')) return fail('cancelled');
  // The dialog was not shown: the cooldown, no signed-in Google account, FedCM switched off in the browser, …
  if (name === 'NetworkError' || name === 'NotAllowedError') return fail('skipped', `${name}: ${message}`);
  return fail('error', `${name}: ${message}`);
}

const CONFIGURATION_ERRORS = ['missing_client_id', 'unregistered_origin', 'invalid_client'];

/** One Tap through Google's script, in browsers without FedCM (and with `fedcm: false`). */
async function promptSignIn({
  clientId,
  nonce,
  autoSelect,
  context,
  signal,
  cancelOnTapOutside,
}: SignInOptions): Promise<CredentialResult> {
  const loaded = await gis();
  if (!loaded.isSuccess) return loaded;
  if (signal?.aborted) return fail('cancelled');
  return new Promise<CredentialResult>((resolve) => {
    // Ends the sign-in once, and with it the listener on the caller's signal: a later abort must not cancel a later sign-in.
    const done = new AbortController();
    const finish = (result: CredentialResult): void => {
      if (done.signal.aborted) return;
      done.abort();
      resolve(result);
    };
    signal?.addEventListener(
      'abort',
      () => {
        loaded.gis.cancel();
        finish(fail('cancelled'));
      },
      { once: true, signal: done.signal },
    );
    const threw = attempt(() => {
      loaded.gis.initialize({
        client_id: clientId,
        nonce,
        callback: ({ credential, select_by }) =>
          finish({
            isSuccess: true,
            idToken: credential,
            isAutoSelected: select_by === 'auto',
          }),
        auto_select: !!autoSelect,
        cancel_on_tap_outside: cancelOnTapOutside ?? true,
        context: context ?? 'signin',
        itp_support: true,
        use_fedcm_for_prompt: true,
        use_fedcm_for_button: true,
      });
      loaded.gis.prompt((notification: PromptMomentNotification) => {
        if (notification.isSkippedMoment()) return finish(fail('skipped'));
        if (notification.isDismissedMoment()) {
          const reason = notification.getDismissedReason();
          if (reason === 'cancel_called') return finish(fail('cancelled'));
          // `credential_returned` is answered by the callback.
          if (reason !== 'credential_returned') return finish(fail('skipped', reason));
          return;
        }
        // Without FedCM, Google's script says why One Tap was not shown, a configuration error among the reasons.
        // With FedCM, Google calls these methods unsupported, and a notification may not have them at all.
        if (notification.isDisplayMoment?.() && notification.isNotDisplayed?.()) {
          const reason = notification.getNotDisplayedReason?.() ?? '';
          finish(fail(CONFIGURATION_ERRORS.includes(reason) ? 'configuration_error' : 'skipped', reason));
        }
      });
    });
    if (threw) finish(threw);
  });
}

/**
 * Renders Google's button into `container` and hands each token to `onCredential`. Google's script draws the
 * button in an iframe with a light page: it goes into a wrapper with `color-scheme: light`, or a dark page would
 * paint it on an opaque white box. Resolves once the button is there, or with why it isn't; it never rejects.
 */
export async function renderButton(container: HTMLElement, options: ButtonOptions): Promise<RenderedButton> {
  const loaded = await gis();
  if (!loaded.isSuccess) return loaded;
  const wrapper = document.createElement('div');
  wrapper.style.colorScheme = 'light';
  const threw = attempt(() => {
    loaded.gis.initialize({
      client_id: options.clientId,
      nonce: options.nonce,
      callback: ({ credential, select_by }) =>
        options.onCredential({
          idToken: credential,
          isAutoSelected: select_by === 'auto',
        }),
      context: options.context ?? 'signin',
      itp_support: true,
      use_fedcm_for_button: true,
      ...(options.uxMode ? { ux_mode: options.uxMode } : {}),
      ...(options.loginUri ? { login_uri: options.loginUri } : {}),
    });
    container.replaceChildren(wrapper);
    loaded.gis.renderButton(wrapper, { type: 'standard', ...options.button });
  });
  if (threw) {
    container.replaceChildren();
    return threw;
  }
  return {
    isSuccess: true,
    remove() {
      if (wrapper.parentNode === container) container.replaceChildren();
    },
  };
}

/** Ends the sign-in under way: the browser's dialog, or One Tap. Its `signIn` resolves with `cancelled`. */
export function cancel(): void {
  for (const controller of fedcmInFlight) controller.abort();
  loadedGis()?.cancel();
}

/**
 * After a sign-out: the next sign-in asks the user again instead of picking the account that signed in last
 * (the browser's `preventSilentAccess`, and Google's `disableAutoSelect` when its script has loaded: a page
 * that never loaded it has nothing to disable there, and doesn't load it for this).
 */
export function disableAutoSelect(): void {
  void navigator.credentials?.preventSilentAccess?.().catch(() => {});
  loadedGis()?.disableAutoSelect();
}

/**
 * Revokes the grant the user gave the app at Google, so the app leaves their connected apps and the button no
 * longer says "Continue as …". `hint` is the user's Google e-mail address or account id (the token's `sub`).
 */
export async function revoke(hint: string): Promise<{ isSuccess: true } | { isSuccess: false; error: string }> {
  const loaded = await gis();
  if (!loaded.isSuccess) return { isSuccess: false, error: loaded.detail ?? loaded.reason };
  return new Promise((resolve) => {
    loaded.gis.revoke(hint, (response) =>
      resolve(response.successful ? { isSuccess: true } : { isSuccess: false, error: response.error ?? 'revoke failed' }),
    );
  });
}
