import { Passkey } from '../providers/passkey.js';
import type { PendingStep, SecondFactorPolicy } from '../providers/provider.js';
import { fail, ok, type MadauthUser, type Result } from '../result.js';
import { ceremony, conditionalSupported, creationOptions, requestOptions, signalUnknown, webauthnSupported } from '../webauthn.js';
import { serverCalls, type Core } from './core.js';
import { currentPage, emailConfirmation, noteNextStep, signedIn, type SendEmailOptions } from './email.js';

/** A passkey of the signed-in user. */
export interface PasskeyInfo {
  /** Its id (`acc_…`), which renaming and `Madauth.methods.remove` take. */
  id: string;
  name: string;
  /** When it was added, and when it last signed in (0: never), in milliseconds since 1970. */
  createdAt: number;
  lastUsedAt: number;
}

export interface PasskeySignInOptions {
  /**
   * `true`: the passkeys appear in the autofill of a field with `autocomplete="username webauthn"` instead
   * of a dialog, and the call waits until the user picks one. Abort it with `signal` before another sign-in.
   */
  conditional?: boolean;
  signal?: AbortSignal;
}

export interface PasskeySignUpOptions {
  email: string;
  /** Shown to the user and in `MadauthUser.name`. */
  name?: string;
  /** The page the link in the e-mail opens. Default: the current page. Its origin must be in ALLOWED_ORIGINS. */
  redirectTo?: string;
}

/**
 * Passkeys (WebAuthn) for custom login screens and account pages. Adding one, and the second step with one,
 * work whenever the server has passkeys on; signing in or up with one alone ({@link signIn}, {@link signUp})
 * also needs `new Passkey()` in `Madauth.initialize`.
 */
export interface PasskeyApi {
  /**
   * Signs in with a passkey alone: the browser shows the user's passkeys for this site. Fails with
   * `cancelled` (the user closed the dialog), `passkey_unknown` (a passkey the server no longer has, which
   * the browser is told to forget), `verification_failed`, `method_disabled` or `passkey_unsupported`; with
   * `second_factor_setup_required` and the like the passkey was right and its policy asks for a second factor.
   */
  signIn(options?: PasskeySignInOptions): Promise<Result<{ user: MadauthUser }>>;
  /** Finishes a sign-in that ended with `passkey_required`. Fails with `cancelled`, `verification_failed` or `challenge_expired`. */
  verify(): Promise<Result<{ user: MadauthUser }>>;
  /**
   * Adds a passkey for the signed-in user, for a sign-in that ended with `second_factor_setup_required` and
   * `passkey` among its factors, or for a sign-up with a passkey alone that ended with
   * `passkey_setup_required` (then it finishes the sign-in or sign-up, and `user` is set; the sign-up's
   * passkey is the user's sign-in method). Only within two minutes of signing in:
   * later it fails with `reauth_required` (sign in again, then add it). Fails with `cancelled`,
   * `already_added` (this device holds one of the user's passkeys), `verification_failed`, `no_session`,
   * `setup_expired` or `passkey_unsupported`; in a sign-up whose passkey policy asks for a second factor, with
   * `second_factor_setup_required`: the passkey is created, and that factor is set up next.
   */
  add(options?: { name?: string }): Promise<Result<{ passkey: PasskeyInfo; user?: MadauthUser }>>;
  /**
   * Creates an account that signs in with a passkey alone (no password) and sends an e-mail with a link and
   * a code to confirm the address; confirming leads to the passkey's creation (`passkey_setup_required`:
   * call {@link add} next). Succeeds even if the address is registered, so nobody can
   * probe for accounts. Fails with `invalid_email`, `signup_rejected`, `temporarily_unavailable`,
   * `method_disabled`, or `flow_not_enabled` when the server offers no such sign-up (`policy.signUp`) or the
   * Passkey provider is not passed (or was left out: the browser has no passkeys).
   */
  signUp(options: PasskeySignUpOptions): Promise<Result>;
  /** Sends the confirmation e-mail of a sign-up again. Fails with `temporarily_unavailable`. */
  sendVerificationEmail(options: SendEmailOptions): Promise<Result>;
  /**
   * Confirms the address with the code from the e-mail. For a sign-up with a passkey it fails with
   * `passkey_setup_required`: call {@link add} next.
   */
  verifyEmail(options: { email: string; code: string }): Promise<Result<{ user: MadauthUser }>>;
  /** Renames a passkey of the signed-in user. Fails with `method_not_found`, `invalid_options` or `no_session`. */
  rename(options: { id: string; name: string }): Promise<Result<{ passkey: PasskeyInfo }>>;
  /** Whether the browser can offer passkeys in the autofill of an e-mail field, see {@link PasskeySignInOptions.conditional}. */
  conditionalAvailable(): Promise<boolean>;
  /** Whether the server has passkeys on and the browser supports them; false until initialized. */
  readonly available: boolean;
  /** Whether passkeys sign in on their own here (the server allows it and `new Passkey()` is passed). */
  readonly signInAvailable: boolean;
  /**
   * What passkeys do on this server: whether they sign in on their own, whether people can sign up with one
   * alone, and whether such a sign-in asks for a second factor. Null when off.
   */
  readonly policy: { signIn: boolean; signUp: boolean; secondFactor: SecondFactorPolicy } | null;
  /** What a sign-in under way still needs, see `Madauth.authenticator.pendingStep`: `step` is `passkey` for a passkey. */
  readonly pendingStep: PendingStep | null;
}

const switchedOff = () => fail('flow_not_enabled', 'The madAuth server has passkeys switched off: an admin lists them in the settings (Madauth.admin.setSettings).');
const notRegistered = () => fail('flow_not_enabled', 'Pass new Passkey() to Madauth.initialize to sign in or up with a passkey alone.');
const noSignUp = () =>
  fail(
    'flow_not_enabled',
    'The madAuth server offers no sign-up with a passkey alone: an admin allows passkeys as a sign-in method (Madauth.admin.setSettings), and the webhook must confirm addresses (email.send_verification).',
  );

export function createPasskeyApi(core: Core): PasskeyApi {
  const call = serverCalls(core, { isOn: (config) => !!config?.passkey, switchedOff });
  const signUpCall = serverCalls(core, { isOn: (config) => !!config?.passkey?.signUp, switchedOff: noSignUp });
  const registered = () => core.provider('passkey') instanceof Passkey;
  const confirmation = emailConfirmation(core, 'passkey', (path, body) => call(path, { body }));

  /** Asks the server for the options of an assertion, runs the browser's dialog, and sends the answer to `verifyPath`. */
  async function assert<T extends object>(optionsPath: string, verifyPath: string, init: PasskeySignInOptions = {}): Promise<Result<T>> {
    const options = await call<PublicKeyCredentialRequestOptionsJSON>(optionsPath, { body: {} });
    if (!options.isSuccess) return options;
    const { isSuccess: _, ...json } = options;
    const answer = await ceremony(() =>
      navigator.credentials.get({ publicKey: requestOptions(json), ...(init.conditional ? { mediation: 'conditional' as CredentialMediationRequirement } : {}), signal: init.signal }),
    );
    if (!answer.isSuccess) return answer;
    const result = await call<T>(verifyPath, { body: { response: answer.credential } });
    // The device offered a passkey the server no longer has: its password manager can forget it.
    if (!result.isSuccess && result.error.code === 'passkey_unknown') signalUnknown(json.rpId, (answer.credential as { id: string }).id);
    return result;
  }

  return {
    async signIn(options = {}) {
      if (!registered()) return notRegistered();
      return signedIn(core, 'passkey', await assert<{ user: MadauthUser }>('/auth/passkey/signin/options', '/auth/passkey/signin/verify', options));
    },

    async verify() {
      const result = await assert<{ user: MadauthUser }>('/auth/passkey/verify/options', '/auth/passkey/verify');
      if (!result.isSuccess) return result;
      core.signedIn(result.user);
      return { isSuccess: true, user: result.user };
    },

    async add(options = {}) {
      const json = await call<PublicKeyCredentialCreationOptionsJSON>('/auth/passkey/register/options', { body: {}, session: true });
      if (!json.isSuccess) return json;
      const { isSuccess: _, ...creation } = json;
      const answer = await ceremony(() => navigator.credentials.create({ publicKey: creationOptions(creation) }));
      if (!answer.isSuccess) return answer;
      const result = await call<{ passkey: PasskeyInfo; user?: MadauthUser }>('/auth/passkey/register/verify', { body: { response: answer.credential, name: options.name }, session: true });
      // A sign-up with a passkey whose policy asks for a second factor goes on with its setup.
      if (!result.isSuccess) return noteNextStep(core, 'passkey', result);
      if (result.user) core.signedIn(result.user);
      return ok(result.user ? { passkey: result.passkey, user: result.user } : { passkey: result.passkey });
    },

    async signUp({ email, name, redirectTo }) {
      // Only once initialize is done: a browser without passkeys has its provider left out by then, so nobody
      // confirms an address for a passkey they can't create.
      const ready = await core.whenReady();
      if (!ready.isSuccess) return ready;
      if (!registered()) return notRegistered();
      const result = await signUpCall('/auth/passkey/signup', { body: { email, name, redirectTo: redirectTo ?? currentPage(), locale: core.locale() } });
      return result.isSuccess ? ok() : result;
    },

    sendVerificationEmail: confirmation.sendVerificationEmail,
    verifyEmail: confirmation.verifyEmail,

    async rename({ id, name }) {
      const result = await call<{ passkey: PasskeyInfo }>('/auth/passkey/rename', { body: { id, name }, session: true });
      return result.isSuccess ? ok({ passkey: result.passkey }) : result;
    },

    conditionalAvailable: conditionalSupported,

    get available() {
      return !!core.config()?.passkey && webauthnSupported();
    },

    get signInAvailable() {
      return !!core.config()?.passkey?.signIn && core.provider('passkey') instanceof Passkey && webauthnSupported();
    },

    get policy() {
      return core.config()?.passkey ?? null;
    },

    get pendingStep() {
      return core.pendingStep();
    },
  };
}
