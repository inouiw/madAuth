import { fail, ok, type MadauthUser, type Result } from '../result.js';
import { createButtonApi, type ButtonApi, type ButtonRenderOptions } from './button.js';
import { serverCalls, type Core } from './core.js';
import { currentPage, noteNextStep, signedIn } from './email.js';

/**
 * A sign-in provider the server offers, for custom login screens: Google, GitHub, Microsoft or an OpenID Connect
 * provider an admin added, by its id (`Madauth.provider('microsoft')`, `Madauth.provider('gitlab')`). madAuth registers the providers the server offers
 * by itself, except Google's One Tap (`new GoogleFedcm()`).
 */
export interface ProviderApi extends ButtonApi {
  /**
   * Renders the provider's "Continue with <name>" button into `container` (Google's own with `GoogleFedcm`).
   * Can be called before `initialize` has finished.
   */
  renderButton(container: HTMLElement, options?: ButtonRenderOptions): ReturnType<ButtonApi['renderButton']>;
  /**
   * Starts the provider's sign-in without a button of madAuth's: the browser goes to the provider and comes
   * back to this page, whose `Madauth.initialize` reports the result. With `purpose: 'link'`, it adds the
   * provider to the signed-in user's methods instead (within two minutes of signing in). Fails with
   * `flow_not_enabled` when the server doesn't offer the provider, or when it signs in without a redirect here
   * (Google with `GoogleFedcm`: render its button).
   */
  signIn(options?: { purpose?: 'signin' | 'link' }): Promise<Result>;
  /**
   * Finishes a sign-up through a provider that doesn't vouch for the address: the sign-in came back with the
   * pending step `email` (`Madauth.authenticator.pendingStep`), and the confirmation e-mail went to the address.
   * Pass the code from it; the browser's cookie says whose sign-up it is (the link in the e-mail works on its
   * own). After {@link submitAddress}, pass the address the user typed with the code. Resolves with the user, or
   * the second step the provider's policy asks for. Fails with `code_invalid`, `codes_locked` or `method_disabled`.
   */
  verifyEmail(options: { code: string; email?: string }): Promise<Result<{ user: MadauthUser }>>;
  /** Sends that confirmation e-mail again (one per minute); the link in it opens `redirectTo`, the current page by default. After {@link submitAddress}, pass the address. */
  sendVerificationEmail(options?: { email?: string; redirectTo?: string }): Promise<Result>;
  /**
   * With the pending step `email-address` (the provider told no address): the address to offer, as the provider
   * hinted at it (its `preferred_username`), or null. Fails with `challenge_expired` once the sign-in is more
   * than ten minutes old: start it again.
   */
  addressSuggestion(): Promise<Result<{ suggestion: string | null }>>;
  /**
   * With the pending step `email-address`: the address the user typed. The confirmation e-mail goes to it, and
   * {@link verifyEmail} with the code and the address finishes the sign-up. The answer is the same for every
   * address: the owner of one that already signs in gets an e-mail saying so instead. Fails with `invalid_email`,
   * `signup_rejected`, `challenge_expired` or `method_disabled`.
   */
  submitAddress(options: { email: string; redirectTo?: string }): Promise<Result<{ user?: MadauthUser }>>;
}

export function createProviderApi(core: Core, id: string): ProviderApi {
  const call = serverCalls(core);
  const hint = `The madAuth server offers no sign-in provider "${id}": an admin adds it (Madauth.admin.addProvider) and switches it on (Madauth.admin.setSettings).`;
  return {
    ...createButtonApi(core, id, hint),
    async signIn(options = {}) {
      const ready = await core.whenReady();
      if (!ready.isSuccess) return ready;
      const provider = core.provider(id);
      if (!provider?.redirect) {
        return fail('flow_not_enabled', provider ? `"${id}" signs in with its own button here (GoogleFedcm): use renderButton.` : hint);
      }
      provider.redirect(options.purpose === 'link');
      return ok();
    },
    async verifyEmail({ code, email }) {
      return signedIn(core, id, await call<{ user: MadauthUser }>('/auth/email/verify', { body: { code, ...(email ? { email } : {}) } }));
    },
    async sendVerificationEmail(options = {}) {
      const body = { ...(options.email ? { email: options.email } : {}), redirectTo: options.redirectTo ?? currentPage(), locale: core.locale() };
      const result = await call('/auth/email/send-verification', { body });
      return result.isSuccess ? ok() : result;
    },
    async addressSuggestion() {
      const result = await call<{ suggestion?: string | null }>(`/auth/providers/${id}/address`, { method: 'GET' });
      return result.isSuccess ? ok({ suggestion: result.suggestion ?? null }) : result;
    },
    async submitAddress({ email, redirectTo }) {
      const result = await call<{ user?: MadauthUser }>(`/auth/providers/${id}/address`, { body: { email, redirectTo: redirectTo ?? currentPage(), locale: core.locale() } });
      if (!result.isSuccess) return noteNextStep(core, id, result);
      // A returning account signs in at once (rare: its sign-up was confirmed meanwhile in another tab).
      return result.user ? signedIn(core, id, ok({ user: result.user })) : ok({});
    },
  };
}
