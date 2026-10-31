// Google Identity Services (GIS), the script at accounts.google.com/gsi/client: the parts of `google.accounts.id`
// this package uses, typed, and loading the script once.

/** Google's button, see https://developers.google.com/identity/gsi/web/reference/js-reference#GsiButtonConfiguration. */
export interface GsiButtonConfiguration {
  type?: 'standard' | 'icon';
  theme?: 'outline' | 'filled_blue' | 'filled_black';
  size?: 'large' | 'medium' | 'small';
  text?: 'signin_with' | 'signup_with' | 'continue_with' | 'signin';
  shape?: 'rectangular' | 'pill' | 'circle' | 'square';
  logo_alignment?: 'left' | 'center';
  /** 200 to 400, in pixels. */
  width?: number | string;
  /** A BCP 47 tag; Google's default is the browser's language. */
  locale?: string;
  click_listener?: () => void;
}

/** Google's answer: the ID token, and how the user picked the account (`auto` for a silent sign-in). */
export interface CredentialResponse {
  credential: string;
  select_by?: string;
}

/** What `google.accounts.id.initialize` takes, see https://developers.google.com/identity/gsi/web/reference/js-reference#IdConfiguration. */
export interface IdConfiguration {
  client_id: string;
  nonce?: string;
  callback?: (response: CredentialResponse) => void;
  auto_select?: boolean;
  cancel_on_tap_outside?: boolean;
  context?: 'signin' | 'signup' | 'use';
  itp_support?: boolean;
  login_uri?: string;
  ux_mode?: 'popup' | 'redirect';
  use_fedcm_for_prompt?: boolean;
  use_fedcm_for_button?: boolean;
}

/**
 * What One Tap reports while it is shown, see
 * https://developers.google.com/identity/gsi/web/reference/js-reference#PromptMomentNotification. With FedCM,
 * Google only reports the skipped and dismissed moments.
 */
export interface PromptMomentNotification {
  isDisplayMoment(): boolean;
  isNotDisplayed(): boolean;
  getNotDisplayedReason(): string;
  isSkippedMoment(): boolean;
  isDismissedMoment(): boolean;
  getDismissedReason(): 'credential_returned' | 'cancel_called' | 'flow_restarted' | string;
}

/** `google.accounts.id`. */
export interface GoogleAccountsId {
  initialize(config: IdConfiguration): void;
  prompt(listener?: (notification: PromptMomentNotification) => void): void;
  renderButton(parent: HTMLElement, options: GsiButtonConfiguration): void;
  disableAutoSelect(): void;
  cancel(): void;
  /** Revokes the grant the user gave the app; `hint` is their Google e-mail address or account id (`sub`). */
  revoke(hint: string, callback?: (response: { successful: boolean; error?: string }) => void): void;
}

export const GIS_SRC = 'https://accounts.google.com/gsi/client';

let loading: Promise<GoogleAccountsId> | undefined;
let loaded: GoogleAccountsId | undefined;

const gisOnPage = (): GoogleAccountsId | undefined =>
  (window as { google?: { accounts?: { id?: GoogleAccountsId } } }).google?.accounts?.id;

/** Loads Google Identity Services once (a page that has the script already needs no second one). A failed load can be retried. */
export function loadGis(): Promise<GoogleAccountsId> {
  if (!loading) {
    const onPage = gisOnPage();
    if (onPage) {
      loaded = onPage;
      loading = Promise.resolve(onPage);
      return loading;
    }
    const script = document.createElement('script');
    script.src = GIS_SRC;
    script.async = true;
    loading = new Promise<GoogleAccountsId>((resolve, reject) => {
      script.addEventListener('load', () => {
        const id = gisOnPage();
        if (id) {
          loaded = id;
          resolve(id);
        } else reject(new Error(`${GIS_SRC} loaded but google.accounts.id is missing`));
      });
      script.addEventListener('error', () => reject(new Error(`could not load ${GIS_SRC}`)));
    });
    loading.catch(() => {
      loading = undefined;
      script.remove();
    });
    document.head.append(script);
  }
  return loading;
}

/** Google Identity Services, if it has loaded. */
export function loadedGis(): GoogleAccountsId | undefined {
  return loaded;
}

/** Test hook: forgets the loaded script. */
export function resetGisForTests(): void {
  loading = undefined;
  loaded = undefined;
  document.querySelectorAll(`script[src="${GIS_SRC}"]`).forEach((s) => s.remove());
}
