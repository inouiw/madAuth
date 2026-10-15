import type { PendingStep } from '../providers/provider.js';
import { fail, ok, type MadauthUser, type Result } from '../result.js';
import { serverCalls, type Core } from './core.js';

/**
 * SMS codes as a second factor, for custom login screens and account pages. The methods work whenever the
 * server has SMS codes on (`sms` in the sign-in methods, with a webhook that sends `sms.send_code`); no provider
 * is needed. A phone is never a sign-in method of its own: a signed-in user adds one, and from then on the
 * methods whose policy asks for a second factor can ask for a code sent to it, next to the authenticator app.
 */
export interface SmsApi {
  /**
   * Starts adding a phone number for the signed-in user (or for a sign-in whose policy requires a second
   * factor the user has not set up yet): sends a code to it. Resolves to the number as it is shown (masked).
   * A user who has a number already replaces it: without `code` this fails with `code_required`; call
   * {@link send} for a code to the current number and pass it. Fails with `invalid_phone`, `too_soon` (one
   * SMS per minute), `no_session`, `method_disabled` or `temporarily_unavailable` (the SMS could not be sent).
   */
  setUp(options: { phone: string; code?: string }): Promise<Result<{ phone: string }>>;
  /**
   * Confirms the number with the code sent to it. Signs the user in when the setup is the second step of
   * a sign-in (then `user` is set). Fails with `code_invalid`, `setup_expired` or `no_session`.
   */
  confirmSetup(options: { code: string }): Promise<Result<{ user?: MadauthUser }>>;
  /**
   * Sends a code to the user's number: for the second step of a sign-in that ended with `sms_required` (or
   * `totp_required` with `sms` among its `factors`), or, signed in, to approve replacing or removing the
   * number. Resolves to the masked number. Fails with `too_soon`, `no_phone`, `challenge_expired` or `no_session`.
   */
  send(): Promise<Result<{ phone: string }>>;
  /** Finishes the sign-in with the code from the SMS. Fails with `code_invalid`, `too_many_attempts` or `challenge_expired`. */
  verify(options: { code: string }): Promise<Result<{ user: MadauthUser }>>;
  /**
   * Removes the signed-in user's number, with a code sent to it by {@link send}. Fails with `code_invalid`,
   * `no_phone`, `required_by_policy` (a policy requires a second factor and the user has no authenticator app)
   * or `no_session`.
   */
  remove(options: { code: string }): Promise<Result>;
  /** Whether the signed-in user has a number, and which (masked). Fails with `no_session`. */
  status(): Promise<Result<{ enabled: boolean; phone: string | null }>>;
  /** What a sign-in under way still needs, see `Madauth.totp.pendingStep`: `step` is `sms` for a code by SMS. */
  readonly pendingStep: PendingStep | null;
  /** Whether the server has SMS codes on; false until initialized. */
  readonly available: boolean;
}

const switchedOff = () =>
  fail('flow_not_enabled', 'The madAuth server has SMS codes switched off: an admin lists sms in the settings (Madauth.admin.setSettings), and the webhook must send sms.send_code.');

export function createSmsApi(core: Core): SmsApi {
  const call = serverCalls(core, { isOn: (config) => !!config?.sms, switchedOff });

  return {
    async setUp({ phone, code }) {
      const result = await call<{ phone: string }>('/auth/sms/setup', { body: { phone, code, locale: core.locale() }, session: true });
      return result.isSuccess ? ok({ phone: result.phone }) : result;
    },

    async confirmSetup({ code }) {
      const result = await call<{ user?: MadauthUser }>('/auth/sms/confirm', { body: { code }, session: true });
      if (!result.isSuccess) return result;
      if (result.user) core.signedIn(result.user);
      return ok(result.user ? { user: result.user } : {});
    },

    async send() {
      const result = await call<{ phone: string }>('/auth/sms/send', { body: { locale: core.locale() }, session: true });
      return result.isSuccess ? ok({ phone: result.phone }) : result;
    },

    async verify({ code }) {
      const result = await call<{ user: MadauthUser }>('/auth/sms/verify', { body: { code } });
      if (!result.isSuccess) return result;
      core.signedIn(result.user);
      return { isSuccess: true, user: result.user };
    },

    async remove(options) {
      const result = await call('/auth/sms/remove', { body: { ...options }, session: true });
      return result.isSuccess ? ok() : result;
    },

    async status() {
      const result = await call<{ enabled: boolean; phone: string | null }>('/auth/sms/status', { method: 'GET', session: true });
      return result.isSuccess ? ok({ enabled: result.enabled, phone: result.phone }) : result;
    },

    get pendingStep() {
      return core.pendingStep();
    },

    get available() {
      return !!core.config()?.sms;
    },
  };
}
