import { loadGis, type GoogleAccountsId } from '../gis.js';
import { fail, ok, type MadauthUser, type Result } from '../result.js';
import type { ButtonOptions, DeletedAccount, ProviderContext, SignInProvider } from './provider.js';

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
      return fail('flow_not_enabled', 'The madAuth server has no Google provider that is on, so Google sign-in is off: an admin adds it (Madauth.admin.addProvider).');
    }
    try {
      this.#gis = await loadGis();
    } catch (e) {
      return fail('gis_load_failed', `Google sign-in could not be loaded: ${(e as Error).message}`);
    }
    // Not while a sign-in waits for the authenticator app: One Tap on top of the code step would start another.
    if (this.#autoPrompt && !ctx.currentUser && !ctx.signInPending) void this.#prompt();
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

  onAccountDeleted({ googleSub }: DeletedAccount): void {
    // Removes the app from the user's connected apps at Google, and the button no longer says "Continue as …".
    // By the account id, not the address: Google's address may have changed since the user signed up, and a
    // user without a Google account is never sent to Google.
    if (googleSub) this.#gis?.revoke(googleSub);
  }

  /** Gets a fresh nonce from the server and (re)initializes GIS with it. */
  async #prepare(): Promise<Result> {
    const ctx = this.#ctx!;
    const res = await ctx.request<{ nonce: string }>('/auth/providers/google/nonce', { method: 'POST' });
    if (!res.ok) return { isSuccess: false, error: res.error };
    this.#gis!.initialize({
      client_id: ctx.config.google!.clientId,
      nonce: res.data.nonce,
      callback: ({ credential }) => void this.#onCredential(credential),
      use_fedcm_for_button: true,
      itp_support: true,
      // Linking uses the account with this site rather than signing in to it.
      context: this.#button?.purpose === 'link' ? 'use' : 'signin',
    });
    return ok();
  }

  async #prompt(): Promise<void> {
    const prepared = await this.#prepare();
    if (!prepared.isSuccess) {
      console.error('[madauth]', prepared.error.code, prepared.error.message);
      return;
    }
    if (!this.#button && !this.#ctx!.currentUser && !this.#ctx!.signInPending) this.#gis!.prompt();
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
    // A button that links adds the Google account to the signed-in user instead of signing in.
    if (this.#button?.purpose === 'link') return this.#onLink(this.#button, credential);
    const res = await ctx.request<{ user: MadauthUser }>('/auth/providers/google/verify', {
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

  async #onLink(mount: ButtonMount, credential: string): Promise<void> {
    const ctx = this.#ctx!;
    const res = await ctx.request('/auth/providers/google/link', { method: 'POST', body: { credential } });
    const user = ctx.currentUser;
    if (res.ok && user) mount.onResult({ isSuccess: true, user });
    else mount.onResult({ isSuccess: false, error: res.ok ? { code: 'no_session', message: 'Nobody is signed in.' } : res.error });
    // A nonce is used up by an attempt; give the button a fresh one for another.
    if (this.#button === mount) void this.#renderButton(mount);
  }
}
