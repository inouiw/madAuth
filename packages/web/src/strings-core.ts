import type { BuiltInMethodId } from './methods.js';
import type { MadauthErrorCode } from './result.js';

/**
 * The texts the client shows without the dialog (`@madauth/web/client`): the names of the sign-in methods,
 * the buttons of the redirect sign-ins (`GoogleRedirect`, `GitHub`, `OpenIdConnect`) and their errors. The
 * dialog's tables in `strings.ts` extend these, so a client without the dialog ships only this file. `coreDe`
 * has the same shape, so a text that is missing in one language fails the type check.
 */
export const coreEn = {
  /** The sign-in methods: `label` is the text of the button, `description` its tooltip. `loginMethods` has the English ones. */
  methods: {
    google: { label: 'Continue with Google', description: 'Use your Google account' },
    github: { label: 'Continue with GitHub', description: 'Use your GitHub account' },
    password: { label: 'Email & password', description: 'Sign in with your email address and password' },
    authenticator: { label: 'Authenticator app', description: 'One-time code from your authenticator' },
    'email-link': { label: 'Email link', description: 'Passwordless sign-in by email' },
    passkey: { label: 'Passkey', description: 'Sign in with your fingerprint, face or screen lock' },
  } satisfies Record<BuiltInMethodId, { label: string; description: string }>,
  /** The button of a sign-in provider, with the name an admin gave it. */
  continueWith: (name: string) => `Continue with ${name}`,
  /** The button of a provider (Google, GitHub) that adds it to the signed-in user's methods (`purpose: 'link'`). */
  connect: (name: string) => `Connect ${name}`,
  /**
   * A method's name inside a sentence, e.g. after "with" ("mit" in German): in the redirect errors and the
   * dialog's `otherMethod`, and in what a second factor will do (`authenticatorSetup.effects`, `smsSetup.effect`,
   * `passkeySetup.effect`). `methodName` names an OpenID Connect provider by the name an admin gave it.
   */
  methodNames: { google: 'Google', github: 'GitHub', password: 'a password', authenticator: 'an authenticator app', 'email-link': 'an email link', passkey: 'a passkey' } satisfies Record<BuiltInMethodId, string>,

  /** The redirect sign-ins (`GoogleRedirect`, `GitHub`, `OpenIdConnect`): why the sign-in failed, by the error code the server reported; `name` is the provider's. */
  redirectErrors: {
    cancelled: (name: string) => `The ${name} sign-in was cancelled.`,
    verification_failed: (name: string) => `The ${name} sign-in could not be verified. Please try again.`,
    email_unverified: (name: string) => `Your ${name} account’s email address is not verified.`,
    signup_rejected: (name: string) => `Signing up with this ${name} account is not possible.`,
    method_disabled: (name: string) => `${name} sign-in is switched off at the moment.`,
    temporarily_unavailable: (name: string) => `${name} sign-in is not available right now. Please try again later.`,
    other_method: (name: string) => `This email address signs in another way. Use that instead of ${name}.`,
    account_taken: (name: string) => `This ${name} account signs in another user. Connect another one.`,
    reauth_required: (name: string) => `To connect ${name}, sign in again first.`,
    no_session: (name: string) => `To connect ${name}, sign in first.`,
  } satisfies Partial<Record<MadauthErrorCode, (name: string) => string>>,
  redirectFailed: (name: string, code: string) => `${name} sign-in failed (${code}).`,
};

export type CoreStrings = typeof coreEn;

export const coreDe: CoreStrings = {
  methods: {
    google: { label: 'Weiter mit Google', description: 'Mit Ihrem Google-Konto anmelden' },
    github: { label: 'Weiter mit GitHub', description: 'Mit Ihrem GitHub-Konto anmelden' },
    password: { label: 'E-Mail-Adresse und Passwort', description: 'Mit E-Mail-Adresse und Passwort anmelden' },
    authenticator: { label: 'Authentifizierungs-App', description: 'Einmalcode aus Ihrer Authentifizierungs-App' },
    'email-link': { label: 'E-Mail-Link', description: 'Ohne Passwort per E-Mail anmelden' },
    passkey: { label: 'Passkey', description: 'Mit Fingerabdruck, Gesicht oder Bildschirmsperre anmelden' },
  },
  continueWith: (name) => `Weiter mit ${name}`,
  connect: (name) => `${name} verbinden`,
  methodNames: { google: 'Google', github: 'GitHub', password: 'einem Passwort', authenticator: 'einer Authentifizierungs-App', 'email-link': 'einem E-Mail-Link', passkey: 'einem Passkey' },

  redirectErrors: {
    cancelled: (name) => `Die Anmeldung mit ${name} wurde abgebrochen.`,
    verification_failed: (name) => `Die Anmeldung mit ${name} konnte nicht überprüft werden. Bitte versuchen Sie es erneut.`,
    email_unverified: (name) => `Die E-Mail-Adresse Ihres ${name}-Kontos ist nicht bestätigt.`,
    signup_rejected: (name) => `Mit diesem ${name}-Konto ist keine Registrierung möglich.`,
    method_disabled: (name) => `Die Anmeldung mit ${name} ist derzeit abgeschaltet.`,
    temporarily_unavailable: (name) => `Die Anmeldung mit ${name} ist derzeit nicht verfügbar. Bitte versuchen Sie es später erneut.`,
    other_method: (name) => `Diese E-Mail-Adresse meldet sich auf andere Weise an. Verwenden Sie diese statt ${name}.`,
    account_taken: (name) => `Mit diesem ${name}-Konto meldet sich ein anderer Benutzer an. Verbinden Sie ein anderes.`,
    reauth_required: (name) => `Um ${name} zu verbinden, melden Sie sich zuerst erneut an.`,
    no_session: (name) => `Um ${name} zu verbinden, melden Sie sich zuerst an.`,
  },
  redirectFailed: (name, code) => `Die Anmeldung mit ${name} ist fehlgeschlagen (${code}).`,
};

const languages = { en: coreEn, de: coreDe };

/** A language madAuth has texts in. */
export type Language = keyof typeof languages;

/**
 * The language for a BCP 47 locale such as `de-CH`, by its primary subtag. English when madAuth has no
 * texts in that language, or without a locale.
 */
export function languageOf(locale: string | undefined): Language {
  const primary = locale?.trim().split(/[-_]/)[0].toLowerCase() ?? '';
  return Object.hasOwn(languages, primary) ? (primary as Language) : 'en';
}

/** The client's texts in the language of `locale`; the dialog's are `stringsFor` in `strings.ts`. */
export function coreStringsFor(locale: string | undefined): CoreStrings {
  return languages[languageOf(locale)];
}
