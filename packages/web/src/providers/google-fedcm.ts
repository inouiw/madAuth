import { cancel, disableAutoSelect, isFedcmSupported, loadGis, renderButton, revoke, signIn, type CredentialResult } from '@madauth/google-identity';
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
 * user dismissed it a few times), the Google button in the sign-in dialog still works. Getting the token is
 * `@madauth/google-identity`'s job; this provider adds the server: the nonce, verifying the token, linking.
 */
export class GoogleFedcm implements SignInProvider {
  readonly method = 'google' as const;
  readonly #autoPrompt: boolean;
  #ctx?: ProviderContext;
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
    // The button needs Google's script, so it is loaded now, and a page that can't load it hears so: unless the
    // browser's own dialog signs in without it, where One Tap still works and only the button reports the failure.
    const loaded = await loadGis().then(
      () => ok(),
      (e: Error) => fail('gis_load_failed', `Google sign-in could not be loaded: ${e.message}`),
    );
    if (!loaded.isSuccess) {
      if (!isFedcmSupported()) return loaded;
      console.warn('[madauth]', loaded.error.code, `${loaded.error.message}; One Tap goes through the browser, Google's button will not render.`);
    }
    // Not while a sign-in waits for the authenticator app: One Tap on top of the code step would start another.
    if (this.#autoPrompt && !ctx.currentUser && !ctx.signInPending) void this.#prompt();
    return ok();
  }

  renderButton(container: HTMLElement, options: ButtonOptions): () => void {
    const mount = { container, ...options };
    this.#button = mount;
    // One Tap and the button share the server's nonce cookie, so only the button may be active now.
    cancel();
    void this.#renderButton(mount);
    return () => {
      if (this.#button === mount) this.#button = undefined;
      container.replaceChildren();
    };
  }

  onSignedIn(): void {
    // E.g. signed in with a password while One Tap was still showing.
    if (!this.#button) cancel();
  }

  onSignedOut(): void {
    disableAutoSelect();
  }

  onAccountDeleted({ googleSub }: DeletedAccount): void {
    // Removes the app from the user's connected apps at Google, and the button no longer says "Continue as …".
    // By the account id, not the address: Google's address may have changed since the user signed up, and a
    // user without a Google account is never sent to Google.
    if (googleSub) void revoke(googleSub);
  }

  /** A fresh nonce from the server: each sign-in needs its own. */
  async #nonce(): Promise<Result<{ nonce: string }>> {
    const res = await this.#ctx!.request<{ nonce: string }>('/auth/providers/google/nonce', { method: 'POST' });
    return res.ok ? ok({ nonce: res.data.nonce }) : { isSuccess: false, error: res.error };
  }

  /** One Tap, or the browser's own dialog: nothing to show when the user closes it or the browser holds it back. */
  async #prompt(): Promise<void> {
    const ctx = this.#ctx!;
    const prepared = await this.#nonce();
    if (!prepared.isSuccess) {
      console.error('[madauth]', prepared.error.code, prepared.error.message);
      return;
    }
    if (this.#button || ctx.currentUser || ctx.signInPending) return;
    const result = await signIn({ clientId: ctx.config.google!.clientId, nonce: prepared.nonce, context: 'signin' });
    if (result.isSuccess) return this.#onCredential(result.idToken);
    if (result.reason === 'configuration_error' || result.reason === 'error') {
      console.error('[madauth] Google One Tap:', result.reason, result.detail ?? '');
    }
  }

  async #renderButton(mount: ButtonMount): Promise<void> {
    const ctx = this.#ctx!;
    const prepared = await this.#nonce();
    if (this.#button !== mount) return;
    if (!prepared.isSuccess) {
      mount.onResult(prepared);
      return;
    }
    const rendered = await renderButton(mount.container, {
      clientId: ctx.config.google!.clientId,
      nonce: prepared.nonce,
      // Linking uses the account with this site rather than signing in to it.
      context: mount.purpose === 'link' ? 'use' : 'signin',
      onCredential: ({ idToken }) => void this.#onCredential(idToken),
      button: {
        theme: mount.theme === 'dark' ? 'filled_black' : 'outline',
        size: 'large',
        text: 'continue_with',
        shape: 'rectangular',
        logo_alignment: 'center',
        // GIS buttons are 200–400px wide.
        width: Math.min(400, Math.max(200, mount.container.clientWidth || 336)),
      },
    });
    if (!rendered.isSuccess) mount.onResult(this.#noCredential(rendered));
  }

  #noCredential(result: Extract<CredentialResult, { isSuccess: false }>): Result<never> {
    return fail('gis_load_failed', `Google sign-in could not be loaded: ${result.detail ?? result.reason}`);
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
