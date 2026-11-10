import { fail, ok, type MadauthUser, type Result } from '../result.js';
import { createButtonApi, type ButtonApi, type ButtonRenderOptions } from './button.js';
import { noSession, serverCalls, type Core } from './core.js';
import { signedIn } from './email.js';

export type AppleButtonOptions = ButtonRenderOptions;

/** The name as Apple's sheet gives it at the first sign-in (`fullName`, a `PersonNameComponents`): what the app passes along of it. */
export interface AppleName {
  firstName?: string;
  lastName?: string;
}

/** An Apple identity token the app obtained itself, for {@link AppleApi.signIn}. */
export interface AppleSignInOptions {
  /** The identity token (a JWT) Apple issued for the app's App ID, with the nonce from {@link AppleApi.nonce} in it. */
  credential: string;
  /**
   * The user's name, which Apple gives the app at the first authorization only (`fullName`), as its parts or
   * put together. Not in the token: pass it, or the user has no name.
   */
  name?: AppleName | string;
  /**
   * Apple's `authorizationCode` from the same sheet, so the server can keep the refresh token that gives the
   * authorization back to Apple when the user deletes their account or removes Apple from their methods (App
   * Store Review Guideline 5.1.1 (v)). Without it the sign-in works, but nothing is given back then.
   */
  authorizationCode?: string;
  /**
   * `signin` (default) signs in. `link` adds the Apple ID to the signed-in user's methods (within two minutes of
   * signing in, else `reauth_required`) and resolves with the user as they are.
   */
  purpose?: 'signin' | 'link';
}

/**
 * Sign in with Apple for custom login screens: the "Continue with Apple" button, or an identity token the app
 * obtained itself with Apple's own sheet, natively in an iOS or macOS app ({@link nonce} and {@link signIn}).
 */
export interface AppleApi extends ButtonApi {
  /** Renders the "Continue with Apple" button into `container`, which starts the redirect. Can be called before `initialize` has finished. */
  renderButton(container: HTMLElement, options?: AppleButtonOptions): ReturnType<ButtonApi['renderButton']>;
  /**
   * Starts a sign-in with an identity token the app obtains itself: resolves with the nonce to pass to Apple's
   * request (`ASAuthorizationAppleIDRequest.nonce`, as it is: Apple puts it into the token), so that the token
   * was asked for just now. The server keeps the nonce in a cookie for five minutes: get a new one for each
   * sign-in. The token then goes to {@link signIn}. Fails with `flow_not_enabled` when the server has no Apple
   * provider that is on.
   */
  nonce(): Promise<Result<{ nonce: string }>>;
  /**
   * Signs in with an Apple identity token the app obtained itself, issued for one of the provider's App IDs with
   * the nonce from {@link nonce}: the server verifies it (Apple's signature, the audience, the nonce, a verified
   * address), and the user arrives, through `onAuthStateChanged` as well. Fails with `verification_failed` (also
   * for a token without that nonce, or for an App ID the admin didn't list), `email_unverified`, `other_method`
   * (the address signs in another way), `signup_rejected`, `method_disabled` or `flow_not_enabled`; with
   * `passkey_required`, `authenticator_required`, `sms_required` or `second_factor_setup_required` the token was
   * right and the sign-in goes on with the second step, like `Madauth.password.signIn`. With `purpose: 'link'`,
   * it adds the Apple ID to the signed-in user's methods instead and resolves with the user as they are; fails
   * with `account_taken`, `reauth_required` or `no_session`.
   */
  signIn(options: AppleSignInOptions): Promise<Result<{ user: MadauthUser }>>;
}

const notOn = () =>
  fail('flow_not_enabled', 'The madAuth server has no Apple provider that is on, so Sign in with Apple is off: an admin adds it (Madauth.admin.addProvider) and switches it on (Madauth.admin.setSettings).');

export function createAppleApi(core: Core): AppleApi {
  const call = serverCalls(core, { isOn: (config) => !!config?.providers?.some((p) => p.id === 'apple'), switchedOff: notOn });
  return {
    ...createButtonApi(core, 'apple', 'The madAuth server offers no Apple provider: an admin adds it (Madauth.admin.addProvider) and switches it on.'),
    async nonce() {
      const result = await call<{ nonce: string }>('/auth/providers/apple/nonce');
      return result.isSuccess ? ok({ nonce: result.nonce }) : result;
    },
    async signIn({ credential, name, authorizationCode, purpose }) {
      const body = { credential, ...(name ? { name } : {}), ...(authorizationCode ? { authorizationCode } : {}) };
      if (purpose === 'link') {
        const linked = await call('/auth/providers/apple/link', { body, session: true });
        if (!linked.isSuccess) return linked;
        const user = core.currentUser();
        return user ? ok({ user }) : noSession();
      }
      return signedIn(core, 'apple', await call<{ user: MadauthUser }>('/auth/providers/apple/verify', { body: { ...body, locale: core.locale() } }));
    },
  };
}
