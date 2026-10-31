import { ok, type Result } from '../result.js';
import { serverCalls, type Core } from './core.js';

/** What a device asks for, as `Madauth.device.lookup` finds it by the code the user typed. */
export interface DeviceRequest {
  /** The code as the device shows it, `BCDF-GHJK`. */
  code: string;
  /** The application on the device, as an admin registered it. */
  client: { id: string; name: string };
  /** The scopes it asks for, e.g. `['openid', 'email', 'offline_access']`. */
  scope: string[];
  /** When the code stops working (milliseconds since 1970). */
  expiresAt: number;
}

/**
 * Approving a device's sign-in (the device authorization grant, see "OpenID Connect provider" in docs/server.md):
 * a TV or a command-line tool shows a code, and the signed-in user types it here to let it sign in as them. With
 * madAuth's dialog, `Madauth.showDeviceApprovalDialog()` does all of it.
 */
export interface DeviceApi {
  /**
   * What the device with this code asks for, typed in any case, with or without the dash. From now on only this
   * user can approve or deny it. Fails with `no_session`, `device_code_invalid` (unknown, expired, used, or
   * someone else looked it up) or `too_many_attempts` (five wrong codes within ten minutes).
   */
  lookup(code: string): Promise<Result<DeviceRequest>>;
  /** Lets the device sign in as the user. Takes `lookup` first. Fails with `no_session` or `device_code_invalid`. */
  approve(code: string): Promise<Result>;
  /** Refuses the device, which is told so. Fails with `no_session` or `device_code_invalid`. */
  deny(code: string): Promise<Result>;
}

export function createDeviceApi(core: Core): DeviceApi {
  const call = serverCalls(core);
  return {
    async lookup(code) {
      const result = await call<DeviceRequest>('/auth/device/lookup', { body: { code }, session: true });
      return result.isSuccess ? ok({ code: result.code, client: result.client, scope: result.scope, expiresAt: result.expiresAt }) : result;
    },
    async approve(code) {
      const result = await call('/auth/device/approve', { body: { code }, session: true });
      return result.isSuccess ? ok() : result;
    },
    async deny(code) {
      const result = await call('/auth/device/deny', { body: { code }, session: true });
      return result.isSuccess ? ok() : result;
    },
  };
}
