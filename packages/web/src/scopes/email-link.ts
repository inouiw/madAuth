import { EmailLink } from '../providers/email-link.js';
import type { SecondFactorPolicy } from '../providers/provider.js';
import { fail, ok, type MadauthUser, type Result } from '../result.js';
import type { Core } from './core.js';
import { currentPage, signedIn, type SendEmailOptions } from './email.js';

/** Passwordless sign-in with an e-mail link, for custom login screens. Needs `new EmailLink()` in `Madauth.initialize`. */
export interface EmailLinkApi {
  /**
   * Sends an e-mail with a link that signs in and a 6-digit code. Succeeds for every address, so nobody can
   * probe for accounts: an unknown address is signed up on first use (the operator's sign-up check permitting),
   * and the owner of an address that signs in another way (e.g. with a password) gets an e-mail that says so
   * instead. Fails with `invalid_email`, `signup_rejected` (the message says why), `method_disabled` or
   * `temporarily_unavailable` (the e-mail could not be sent).
   */
  send(options: SendEmailOptions): Promise<Result>;
  /**
   * Signs in with the code from the e-mail. Fails with `code_invalid` or `codes_locked`; with `totp_required`
   * or `totp_setup_required` the code was right and the sign-in goes on with the authenticator app:
   * `Madauth.totp.verify`, or the setup (`Madauth.totp.startSetup` and `confirmSetup`). The link in the e-mail
   * is handled by `Madauth.initialize` when the page opens from it.
   */
  verify(options: { email: string; code: string }): Promise<Result<{ user: MadauthUser }>>;
  /**
   * Adds the e-mail link to the signed-in user's methods: from then on a link to their address signs them
   * in too. Within ten minutes of signing in only, else it fails with `reauth_required`. Fails with
   * `already_added` or `no_session`.
   */
  add(): Promise<Result>;
  /** Whether the method asks for a second factor; null until initialized, or when the server doesn't offer the method. */
  readonly policy: { secondFactor: SecondFactorPolicy } | null;
}

const notRegistered = () => fail('flow_not_enabled', 'Pass new EmailLink() to Madauth.initialize to use Madauth.emailLink.');

export function createEmailLinkApi(core: Core): EmailLinkApi {
  const registered = () => core.provider('email-link') instanceof EmailLink;

  /** Waits for initialize, checks that the EmailLink provider is registered, then calls the server. */
  async function call<T extends object>(path: string, body: Record<string, unknown>): Promise<Result<T>> {
    const ready = await core.whenReady();
    if (!ready.isSuccess) return ready;
    if (!registered()) return notRegistered();
    const res = await core.request<T>(path, { method: 'POST', body });
    return res.ok ? ok(res.data) : { isSuccess: false, error: res.error };
  }

  return {
    async send({ email, redirectTo }) {
      const result = await call('/auth/email-link/send', { email, redirectTo: redirectTo ?? currentPage(), locale: core.locale() });
      return result.isSuccess ? ok() : result;
    },

    async verify({ email, code }) {
      return signedIn(core, 'email-link', await call('/auth/email-link/verify', { email, code }));
    },

    async add() {
      const result = await call('/auth/email-link/add', {});
      return result.isSuccess ? ok() : result;
    },

    get policy() {
      return registered() ? (core.config()?.emailLink ?? null) : null;
    },
  };
}
