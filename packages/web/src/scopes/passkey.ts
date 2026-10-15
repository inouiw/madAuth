import { Passkey } from '../providers/passkey.js';
import type { PendingStep, SecondFactorPolicy } from '../providers/provider.js';
import { fail, ok, type MadauthUser, type Result } from '../result.js';
import { ceremony, conditionalSupported, creationOptions, requestOptions, signalUnknown, webauthnSupported } from '../webauthn.js';
import { serverCalls, type Core } from './core.js';
import { signedIn } from './email.js';

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

/**
 * Passkeys (WebAuthn) for custom login screens and account pages. Adding one, and the second step with one,
 * work whenever the server has passkeys on; signing in with one alone ({@link signIn}) also needs
 * `new Passkey()` in `Madauth.initialize`.
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
   * Adds a passkey for the signed-in user, or for a sign-in that ended with `second_factor_setup_required` and
   * `passkey` among its factors (then it finishes the sign-in, and `user` is set). Only within ten minutes of
   * signing in: later it fails with `reauth_required` (sign in again, then add it). Fails with `cancelled`,
   * `already_added` (this device holds one of the user's passkeys), `verification_failed`, `no_session` or
   * `passkey_unsupported`.
   */
  add(options?: { name?: string }): Promise<Result<{ passkey: PasskeyInfo; user?: MadauthUser }>>;
  /** Renames a passkey of the signed-in user. Fails with `method_not_found`, `invalid_options` or `no_session`. */
  rename(options: { id: string; name: string }): Promise<Result<{ passkey: PasskeyInfo }>>;
  /** Whether the browser can offer passkeys in the autofill of an e-mail field, see {@link PasskeySignInOptions.conditional}. */
  conditionalAvailable(): Promise<boolean>;
  /** Whether the server has passkeys on and the browser supports them; false until initialized. */
  readonly available: boolean;
  /** Whether passkeys sign in on their own here (the server allows it and `new Passkey()` is passed). */
  readonly signInAvailable: boolean;
  /** What passkeys do on this server: whether they sign in on their own, and whether that asks for a second factor. Null when off. */
  readonly policy: { signIn: boolean; secondFactor: SecondFactorPolicy } | null;
  /** What a sign-in under way still needs, see `Madauth.authenticator.pendingStep`: `step` is `passkey` for a passkey. */
  readonly pendingStep: PendingStep | null;
}

const switchedOff = () => fail('flow_not_enabled', 'The madAuth server has passkeys switched off: an admin lists them with set-methods passkey.');
const notRegistered = () => fail('flow_not_enabled', 'Pass new Passkey() to Madauth.initialize to sign in with a passkey alone.');

export function createPasskeyApi(core: Core): PasskeyApi {
  const call = serverCalls(core, { isOn: (config) => !!config?.passkey, switchedOff });

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
      if (!(core.provider('passkey') instanceof Passkey)) return notRegistered();
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
      if (!result.isSuccess) return result;
      if (result.user) core.signedIn(result.user);
      return ok(result.user ? { passkey: result.passkey, user: result.user } : { passkey: result.passkey });
    },

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
