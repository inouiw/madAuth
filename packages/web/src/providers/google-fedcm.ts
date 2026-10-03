import { loadGis, type GoogleAccountsId } from '../gis.js';
import { fail, ok, type MadauthUser, type Result } from '../result.js';
import type { ButtonOptions, ProviderContext, SignInProvider } from './provider.js';

export interface GoogleFedcmOptions {
  /** Show Google One Tap on page load when nobody is signed in. Default `true`. */
  autoPrompt?: boolean;
}

interface ButtonMount extends ButtonOptions {
  container: HTMLElement;
}

/**
 * Google sign-in in the browser with FedCM / One Tap: the browser shows "Continue as …" and the madAuth
 * server verifies Google's ID token. One Tap is prompted on page load; if Chrome holds it back (after the
 * user dismissed it a few times), the Google button in the sign-in dialog still works.
 */
export class GoogleFedcm implements SignInProvider {
  readonly method = 'google' as const;
  readonly #autoPrompt: boolean;
  #ctx?: ProviderContext;
  #gis?: GoogleAccountsId;
  /** The rendered button, if any; only the latest one gets results. */
  #button?: ButtonMount;

  constructor(options: GoogleFedcmOptions = {}) {
    this.#autoPrompt = options.autoPrompt ?? true;
  }

  async setup(ctx: ProviderContext): Promise<Result> {
    this.#ctx = ctx;
    this.#button = undefined;
    if (!ctx.config.google) {
      return fail('flow_not_enabled', 'The madAuth server has no GOOGLE_CLIENT_ID, so Google sign-in is off.');
    }
    try {
      this.#gis = await loadGis();
    } catch (e) {
      return fail('gis_load_failed', `Google sign-in could not be loaded: ${(e as Error).message}`);
    }
    if (this.#autoPrompt && !ctx.currentUser) void this.#prompt();
    return ok();
  }

  renderButton(container: HTMLElement, options: ButtonOptions): () => void {
    const mount = { container, ...options };
    this.#button = mount;
    // One Tap and the button share the server's nonce cookie, so only the button may be active now.
    this.#gis?.cancel();
    void this.#renderButton(mount);
    return () => {
      if (this.#button === mount) this.#button = undefined;
      container.replaceChildren();
    };
  }

  onSignedIn(): void {
    // E.g. signed in with a password while One Tap was still showing.
    if (!this.#button) this.#gis?.cancel();
  }

  onSignedOut(): void {
    this.#gis?.disableAutoSelect();
  }

  /** Gets a fresh nonce from the server and (re)initializes GIS with it. */
  async #prepare(): Promise<Result> {
    const ctx = this.#ctx!;
    const res = await ctx.request<{ nonce: string }>('/auth/google/nonce', { method: 'POST' });
    if (!res.ok) return { isSuccess: false, error: res.error };
    this.#gis!.initialize({
      client_id: ctx.config.google!.clientId,
      nonce: res.data.nonce,
      callback: ({ credential }) => void this.#onCredential(credential),
      use_fedcm_for_button: true,
      itp_support: true,
      context: 'signin',
    });
    return ok();
  }

  async #prompt(): Promise<void> {
    const prepared = await this.#prepare();
    if (!prepared.isSuccess) {
      console.error('[madauth]', prepared.error.code, prepared.error.message);
      return;
    }
    if (!this.#button && !this.#ctx!.currentUser) this.#gis!.prompt();
  }

  async #renderButton(mount: ButtonMount): Promise<void> {
    const prepared = await this.#prepare();
    if (this.#button !== mount) return;
    if (!prepared.isSuccess) {
      mount.onResult(prepared);
      return;
    }
    // Google's button is an iframe with a light page. If the iframe's color-scheme differed from its
    // parent's, the browser would paint it on an opaque background (a white box on a dark page).
    const wrapper = document.createElement('div');
    wrapper.style.colorScheme = 'light';
    mount.container.replaceChildren(wrapper);
    this.#gis!.renderButton(wrapper, {
      type: 'standard',
      theme: mount.theme === 'dark' ? 'filled_black' : 'outline',
      size: 'large',
      text: 'continue_with',
      shape: 'rectangular',
      logo_alignment: 'center',
      // GIS buttons are 200–400px wide.
      width: Math.min(400, Math.max(200, mount.container.clientWidth || 336)),
    });
  }

  async #onCredential(credential: string): Promise<void> {
    const ctx = this.#ctx!;
    const res = await ctx.request<{ user: MadauthUser }>('/auth/google/verify', {
      method: 'POST',
      body: { credential },
    });
    const result: Result<{ user: MadauthUser }> = res.ok
      ? { isSuccess: true, user: res.data.user }
      : { isSuccess: false, error: res.error };
    if (result.isSuccess) ctx.signedIn(result.user);

    const mount = this.#button;
    if (mount) {
      mount.onResult(result);
      // A nonce is used up by an attempt; give the button a fresh one for a retry.
      if (!result.isSuccess) void this.#renderButton(mount);
    } else if (!result.isSuccess) {
      ctx.signInFailed(result.error);
    }
  }
}
