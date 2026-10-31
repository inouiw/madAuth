import { ok, type Result, type SecondFactor } from '../result.js';
import { serverCalls, type Core } from './core.js';

/**
 * The signed-in user's second factors as a whole. Which ones they have, and which one they prefer, comes with
 * `Madauth.methods.list()`.
 */
export interface SecondFactorApi {
  /**
   * Which second factor a sign-in asks for first: `passkey`, `authenticator` or `sms`, one the user has and the
   * server has on; the others stay offered as a switch. `null` brings the usual order back (a passkey, then the
   * app, then SMS). While the preferred one is gone (removed, or switched off by an admin), the usual order
   * applies. Takes no recent sign-in. Fails with `method_not_found` (the user has no such factor, or it is off),
   * `invalid_options` or `no_session`.
   */
  setPreferred(factor: SecondFactor | null): Promise<Result>;
}

export function createSecondFactorApi(core: Core): SecondFactorApi {
  const call = serverCalls(core);

  return {
    async setPreferred(factor) {
      const result = await call('/auth/second-factor/preferred', { body: { factor }, session: true });
      return result.isSuccess ? ok() : result;
    },
  };
}
