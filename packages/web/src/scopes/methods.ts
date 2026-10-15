import type { LoginMethodId } from '../methods.js';
import { ok, type Result } from '../result.js';
import { serverCalls, type Core } from './core.js';

/** A sign-in method of the signed-in user, as `Madauth.methods.list` returns it. */
export interface SignInMethodInfo {
  /** The id (`acc_…`) that {@link MethodsApi.remove} takes. */
  id: string;
  method: LoginMethodId;
  /** Whether it signs the user in on its own right now: the server allows it as a sign-in method. */
  signIn: boolean;
  /** Whether {@link MethodsApi.remove} removes it; the authenticator app takes a code (`Madauth.authenticator.remove`). */
  removable: boolean;
  /** When it was added, in milliseconds since 1970. */
  createdAt: number;
  /** Google and GitHub: the provider's address at the last sign-in. */
  email?: string;
  /** A passkey: its name, and when it last signed in (0: never). */
  name?: string;
  lastUsedAt?: number;
}

/**
 * The signed-in user's sign-in methods: which they have, and removing one. A user adds one with the method's
 * own call: `Madauth.passkey.add()`, `Madauth.password.add()`, `Madauth.emailLink.add()`, the Google or GitHub
 * button with `purpose: 'link'`, or `Madauth.showSetUpAuthenticatorDialog()`. `Madauth.showManageSignInMethodsDialog()` opens
 * all of this in madAuth's dialog.
 */
export interface MethodsApi {
  /** The user's methods, the authenticator app among them (the phone for SMS codes is `Madauth.sms.status()`). Fails with `no_session`. */
  list(): Promise<Result<{ methods: SignInMethodInfo[] }>>;
  /**
   * Removes a password, Google, GitHub, the e-mail link or a passkey (the authenticator app takes a code:
   * `Madauth.authenticator.remove`). Only within ten minutes of signing in, else it fails with
   * `reauth_required`. Fails with `only_method` (the user would have no way left to sign in),
   * `required_by_policy` (the last passkey, when a policy requires a second factor), `method_not_found` or
   * `no_session`.
   */
  remove(id: string): Promise<Result>;
}

export function createMethodsApi(core: Core): MethodsApi {
  const call = serverCalls(core);

  return {
    async list() {
      const result = await call<{ methods: SignInMethodInfo[] }>('/auth/methods', { method: 'GET', session: true });
      return result.isSuccess ? ok({ methods: result.methods }) : result;
    },
    async remove(id) {
      const result = await call('/auth/methods/remove', { body: { id }, session: true });
      return result.isSuccess ? ok() : result;
    },
  };
}
