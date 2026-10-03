import type { LoginMethodId } from './methods.js';
import type { MadauthErrorCode } from './result.js';

/**
 * Every text madAuth shows to the user: the sign-in dialog's, and the button and the errors of
 * `GoogleRedirect`. `de` has the same shape, so a text that is missing in one language fails the type check.
 */
export const en = {
  /** Default heading of the dialog, and the button of the sign-in form. */
  signIn: 'Sign in',
  /** Accessible name of the button with the cross. */
  close: 'Close',
  /** Between Google's button and the e-mail & password form. */
  or: 'or',
  otherWays: 'Other ways to sign in',
  /** The sign-in methods: `label` is the text of the button, `description` its tooltip. */
  methods: {
    google: { label: 'Continue with Google', description: 'Use your Google account' },
    password: { label: 'E-mail & password', description: 'Sign in with your e-mail address and password' },
    totp: { label: 'Authenticator app', description: 'One-time code from your authenticator' },
    email: { label: 'E-mail link', description: 'Passwordless sign-in by e-mail' },
    sms: { label: 'SMS code', description: 'One-time code sent to your phone' },
  } satisfies Record<LoginMethodId, { label: string; description: string }>,
  /** After picking a method that has no provider yet. */
  comingSoon: (method: string) => `“${method}” is coming soon.`,

  // Fields
  email: 'E-mail',
  password: 'Password',
  newPassword: 'New password',
  name: 'Name',
  optional: '(optional)',
  code: 'Code',
  minLength: (characters: number) => `At least ${characters} characters.`,

  // Buttons and links
  forgotPassword: 'Forgot password?',
  /** Link on the sign-in form, and heading and button of the form it leads to. */
  createAccount: 'Create account',
  haveAccount: 'Already have an account? Sign in',
  backToSignIn: 'Back to sign in',
  sendEmail: 'Send e-mail',
  sendEmailAgain: 'Send the e-mail again',
  continue: 'Continue',
  setPassword: 'Set password',

  // Headings and texts of the other views
  resetPassword: 'Reset password',
  forgotLead: 'Enter your e-mail address. We will send you a link and a code to choose a new password.',
  checkInbox: 'Check your inbox',
  /** The e-mail address is shown between the two parts. */
  inboxLead: {
    before: 'We sent an e-mail to ',
    after: '. Open the link in it, or enter the 6-digit code from the e-mail.',
  },
  emailSentAgain: 'We sent the e-mail again.',
  chooseNewPassword: 'Choose a new password',

  /** What the dialog shows for an error code. */
  errors: {
    network: 'Could not reach the sign-in service. Please check your connection and try again.',
    verification_failed: 'The sign-in could not be verified. Please try again.',
    email_unverified: 'The e-mail address of this account is not verified.',
    cancelled: 'The sign-in was cancelled.',
    not_initialized: 'Sign-in is not set up on this page.',
    invalid_credentials: 'E-mail or password is wrong.',
    invalid_email: 'Please enter a valid e-mail address.',
    link_invalid: 'This link is invalid or has expired. Please ask for a new e-mail.',
    code_invalid: 'The code is wrong or has expired.',
  } satisfies Partial<Record<MadauthErrorCode, string>>,
  /** For every other error code. */
  errorFallback: 'Sign-in is not available right now.',
  /** `email_unverified` after signing in with a password. */
  confirmEmailFirst: 'Please confirm your e-mail address first: open the link in the e-mail we sent you.',
  /** `temporarily_unavailable` when creating an account, and when asking for an e-mail. */
  signUpUnavailable: 'E-mail & password sign-up is not available right now. Please try again later.',
  emailsUnavailable: 'Sending e-mails is not available right now. Please try again later.',
  /**
   * `weak_password` and `too_many_attempts` come with a message from the server that is written for the
   * user, in English. `minLength` is given when the password is shorter than that.
   */
  weakPassword: (serverMessage: string, _minLength?: number) => serverMessage,
  tooManyAttempts: (serverMessage: string) => serverMessage,

  /** `GoogleRedirect`: why the sign-in failed, by the error code the server reported. */
  googleErrors: {
    cancelled: 'The Google sign-in was cancelled.',
    verification_failed: 'The Google sign-in could not be verified. Please try again.',
    email_unverified: 'Your Google account’s e-mail address is not verified.',
  } satisfies Partial<Record<MadauthErrorCode, string>>,
  googleFailed: (code: string) => `Google sign-in failed (${code}).`,
};

export type Strings = typeof en;

export const de: Strings = {
  signIn: 'Anmelden',
  close: 'Schließen',
  or: 'oder',
  otherWays: 'Weitere Anmeldemöglichkeiten',
  methods: {
    google: { label: 'Weiter mit Google', description: 'Mit Ihrem Google-Konto anmelden' },
    password: { label: 'E-Mail-Adresse und Passwort', description: 'Mit E-Mail-Adresse und Passwort anmelden' },
    totp: { label: 'Authentifizierungs-App', description: 'Einmalcode aus Ihrer Authentifizierungs-App' },
    email: { label: 'E-Mail-Link', description: 'Ohne Passwort per E-Mail anmelden' },
    sms: { label: 'SMS-Code', description: 'Einmalcode per SMS an Ihr Mobiltelefon' },
  },
  comingSoon: (method) => `„${method}“ ist bald verfügbar.`,

  email: 'E-Mail-Adresse',
  password: 'Passwort',
  newPassword: 'Neues Passwort',
  name: 'Name',
  optional: '(optional)',
  code: 'Bestätigungscode',
  minLength: (characters) => `Mindestens ${characters} Zeichen.`,

  forgotPassword: 'Passwort vergessen?',
  createAccount: 'Konto erstellen',
  haveAccount: 'Sie haben bereits ein Konto? Anmelden',
  backToSignIn: 'Zurück zur Anmeldung',
  sendEmail: 'E-Mail senden',
  sendEmailAgain: 'E-Mail erneut senden',
  continue: 'Weiter',
  setPassword: 'Passwort festlegen',

  resetPassword: 'Passwort zurücksetzen',
  forgotLead:
    'Geben Sie Ihre E-Mail-Adresse ein. Wir senden Ihnen einen Link und einen Bestätigungscode, mit denen Sie ein neues Passwort wählen können.',
  checkInbox: 'Posteingang prüfen',
  inboxLead: {
    before: 'Wir haben eine E-Mail an ',
    after: ' gesendet. Öffnen Sie den Link darin oder geben Sie den 6-stelligen Bestätigungscode aus der E-Mail ein.',
  },
  emailSentAgain: 'Wir haben die E-Mail erneut gesendet.',
  chooseNewPassword: 'Neues Passwort wählen',

  errors: {
    network: 'Der Anmeldedienst ist nicht erreichbar. Bitte prüfen Sie Ihre Internetverbindung und versuchen Sie es erneut.',
    verification_failed: 'Die Anmeldung konnte nicht überprüft werden. Bitte versuchen Sie es erneut.',
    email_unverified: 'Die E-Mail-Adresse dieses Kontos ist nicht bestätigt.',
    cancelled: 'Die Anmeldung wurde abgebrochen.',
    not_initialized: 'Die Anmeldung ist auf dieser Seite nicht eingerichtet.',
    invalid_credentials: 'E-Mail-Adresse oder Passwort ist falsch.',
    invalid_email: 'Bitte geben Sie eine gültige E-Mail-Adresse ein.',
    link_invalid: 'Dieser Link ist ungültig oder abgelaufen. Bitte fordern Sie eine neue E-Mail an.',
    code_invalid: 'Der Bestätigungscode ist falsch oder abgelaufen.',
  },
  errorFallback: 'Die Anmeldung ist derzeit nicht möglich.',
  confirmEmailFirst:
    'Bitte bestätigen Sie zuerst Ihre E-Mail-Adresse: Öffnen Sie den Link in der E-Mail, die wir Ihnen gesendet haben.',
  signUpUnavailable:
    'Derzeit kann kein Konto mit E-Mail-Adresse und Passwort erstellt werden. Bitte versuchen Sie es später erneut.',
  emailsUnavailable: 'Derzeit können keine E-Mails gesendet werden. Bitte versuchen Sie es später erneut.',
  weakPassword: (_serverMessage, minLength) =>
    minLength
      ? `Das Passwort muss mindestens ${minLength} Zeichen lang sein.`
      : 'Dieses Passwort ist nicht zulässig. Bitte wählen Sie ein anderes.',
  tooManyAttempts: () => 'Zu viele Versuche. Bitte warten Sie einen Moment und versuchen Sie es erneut.',

  googleErrors: {
    cancelled: 'Die Anmeldung mit Google wurde abgebrochen.',
    verification_failed: 'Die Anmeldung mit Google konnte nicht überprüft werden. Bitte versuchen Sie es erneut.',
    email_unverified: 'Die E-Mail-Adresse Ihres Google-Kontos ist nicht bestätigt.',
  },
  googleFailed: (code) => `Die Anmeldung mit Google ist fehlgeschlagen (${code}).`,
};

const languages = { en, de };

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

export function stringsFor(locale: string | undefined): Strings {
  return languages[languageOf(locale)];
}
