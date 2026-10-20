import { fail, ok, type MadauthUser, type Result } from '../result.js';
import { createButtonApi, type ButtonApi, type ButtonRenderOptions } from './button.js';
import { serverCalls, type Core } from './core.js';
import { signedIn } from './email.js';

export type GoogleButtonOptions = ButtonRenderOptions;

/** A Google ID token the app obtained itself, for {@link GoogleApi.signIn}. */
export interface GoogleSignInOptions {
  /** The ID token (a JWT) Google issued for the server's client ID, with the nonce from {@link GoogleApi.nonce} in it. */
  credential: string;
  /**
   * `signin` (default) signs in. `link` adds the Google account to the signed-in user's methods (within two
   * minutes of signing in, else `reauth_required`) and resolves with the user as they are.
   */
  purpose?: 'signin' | 'link';
}

/**
 * Google sign-in for custom login screens: Google's button (needs `GoogleFedcm` or `GoogleRedirect` in
 * `Madauth.initialize`), or an ID token the app obtained itself, e.g. natively in a Capacitor app
 * ({@link nonce} and {@link signIn}, which need no provider and don't load Google's script).
 */
export interface GoogleApi extends ButtonApi {
  /**
   * Renders Google's sign-in button into `container`: the FedCM button with `GoogleFedcm`, or a button that
   * starts the redirect with `GoogleRedirect`. Can be called before `initialize` has finished.
   */
  renderButton(container: HTMLElement, options?: GoogleButtonOptions): ReturnType<ButtonApi['renderButton']>;
  /**
   * Starts a sign-in with an ID token the app obtains itself: resolves with the nonce to pass to Google's
   * sign-in, so that Google puts it into the token, and the server's Google client ID, which the token must be
   * issued for. The server keeps the nonce in a cookie for five minutes and one attempt: get a new one for
   * each. The token then goes to {@link signIn}. Fails with `flow_not_enabled` when the server has no Google
   * provider that is on. A One Tap prompt of `GoogleFedcm` under way loses its nonce: don't mix the two.
   */
  nonce(): Promise<Result<{ nonce: string; clientId: string }>>;
  /**
   * Signs in with a Google ID token the app obtained itself, issued with the nonce from {@link nonce}: the
   * server verifies it (signature, audience, nonce, a verified address), and the user arrives, through
   * `onAuthStateChanged` as well. Fails with `verification_failed` (also for a token without that nonce),
   * `email_unverified`, `other_method` (the address signs in another way), `signup_rejected`, `method_disabled`
   * or `flow_not_enabled`; with `passkey_required`, `authenticator_required`, `sms_required` or
   * `second_factor_setup_required` the token was right and the sign-in goes on with the second step, like
   * `Madauth.password.signIn`. With `purpose: 'link'`, it adds the Google account to the signed-in user's
   * methods instead and resolves with the user as they are; fails with `account_taken`, `reauth_required` or `no_session`.
   */
  signIn(options: GoogleSignInOptions): Promise<Result<{ user: MadauthUser }>>;
}

const notOn = () =>
  fail('flow_not_enabled', 'The madAuth server has no Google provider that is on, so Google sign-in is off: an admin adds it (Madauth.admin.addProvider) and switches it on (Madauth.admin.setSettings).');

export function createGoogleApi(core: Core): GoogleApi {
  const call = serverCalls(core, { isOn: (config) => !!config?.google, switchedOff: notOn });
  return {
    ...createButtonApi(core, 'google', "Pass new GoogleFedcm() or new GoogleRedirect() to Madauth.initialize to render Google's button."),
    async nonce() {
      const result = await call<{ nonce: string }>('/auth/providers/google/nonce');
      return result.isSuccess ? ok({ nonce: result.nonce, clientId: core.config()!.google!.clientId }) : result;
    },
    async signIn({ credential, purpose }) {
      if (purpose === 'link') {
        const linked = await call('/auth/providers/google/link', { body: { credential }, session: true });
        if (!linked.isSuccess) return linked;
        const user = core.currentUser();
        return user ? ok({ user }) : fail('no_session', 'Nobody is signed in.');
      }
      return signedIn(core, 'google', await call<{ user: MadauthUser }>('/auth/providers/google/verify', { body: { credential, locale: core.locale() } }));
    },
  };
}
