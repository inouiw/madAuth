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
  /** Under that lead when Google is one of the methods: a Google user has no password to reset. */
  forgotGoogleHint: 'Signed up with Google? There is no password to reset: use the Google button instead.',
  checkInbox: 'Check your inbox',
  /** The e-mail address is shown between the two parts. */
  inboxLead: {
    before: 'We sent an e-mail to ',
    after: '. Open the link in it, or enter the 6-digit code from the e-mail.',
  },
  emailSentAgain: 'We sent the e-mail again.',
  chooseNewPassword: 'Choose a new password',

  // The authenticator app
  cancel: 'Cancel',
  loading: 'Loading…',
  /** Label of the field for the code from the app (the e-mail code's label is `code`). */
  appCode: 'Code',
  recoveryCode: 'Recovery code',
  useRecoveryCode: 'Use a recovery code instead',
  useApp: 'Use the authenticator app instead',
  totpHint: 'Enter the 6-digit code from your authenticator app.',
  /** `invalid_credentials` on the authenticator app's own sign-in form. */
  totpInvalid: 'E-mail or code is wrong. To sign in with an authenticator app, set it up first while signed in another way.',
  /** On the "Create account" form of a sign-up with the app alone. */
  totpSignUpHint: 'You will set up your authenticator app after confirming your e-mail address.',
  /** The second step after a password or Google sign-in. */
  totpCode: { heading: 'Enter your code', lead: 'Enter the code from your authenticator app to finish signing in.' },
  totpSetup: {
    heading: 'Set up authenticator app',
    lead: 'Scan this QR code with your authenticator app (e.g. Google Authenticator or 1Password), then enter the code it shows.',
    /** When a sign-in requires the app and the user has none yet. */
    requiredLead:
      'Signing in requires an authenticator app. Scan this QR code with one (e.g. Google Authenticator or 1Password), then enter the code it shows.',
    qrLabel: 'QR code for your authenticator app',
    cantScan: 'Can’t scan? Enter this key in the app:',
    turnOn: 'Turn on',
    startAgain: 'Start again',
    /** What the app will do, from the server's policy, so the user knows what they turn on. */
    effects: {
      secondFactor: (methods: string) => `From then on, signing in with ${methods} also asks for a code from the app.`,
      standalone: 'You can then sign in with your e-mail address and a code from the app.',
    },
  },
  totpCodes: {
    heading: 'Save your recovery codes',
    lead: 'If you lose your authenticator app, one of these codes signs you in instead. Each works once. Keep them somewhere safe.',
    saved: 'I have saved them',
  },
  /** `other_method` with the methods the server named, e.g. "a password". */
  otherMethod: (how: string) => `This e-mail address signs in with ${how}. Use that instead of Google.`,
  methodNames: { google: 'Google', password: 'a password', totp: 'an authenticator app' },
  and: ' and ',

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
    codes_locked: 'Too many wrong codes. Please ask for a new e-mail and use the link in it.',
    method_disabled: 'This way of signing in is switched off at the moment.',
    no_session: 'You are not signed in. Please sign in first.',
    setup_expired: 'The setup took too long. Please start again.',
    challenge_expired: 'The sign-in took too long. Please sign in again.',
    required_by_policy: 'Signing in requires the authenticator app, so it can’t be removed.',
    code_required: 'Please enter a code from your authenticator app.',
    no_authenticator: 'No authenticator app is set up.',
    other_method: 'This e-mail address signs in another way. Use that instead of Google.',
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
    signup_rejected: 'Signing up with this Google account is not possible.',
    method_disabled: 'Google sign-in is switched off at the moment.',
    temporarily_unavailable: 'Google sign-in is not available right now. Please try again later.',
    other_method: 'This e-mail address signs in another way. Use that instead of Google.',
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
  forgotGoogleHint: 'Mit Google registriert? Es gibt kein Passwort zum Zurücksetzen: Verwenden Sie stattdessen den Google-Button.',
  checkInbox: 'Posteingang prüfen',
  inboxLead: {
    before: 'Wir haben eine E-Mail an ',
    after: ' gesendet. Öffnen Sie den Link darin oder geben Sie den 6-stelligen Bestätigungscode aus der E-Mail ein.',
  },
  emailSentAgain: 'Wir haben die E-Mail erneut gesendet.',
  chooseNewPassword: 'Neues Passwort wählen',

  cancel: 'Abbrechen',
  loading: 'Wird geladen …',
  appCode: 'Code aus der App',
  recoveryCode: 'Wiederherstellungscode',
  useRecoveryCode: 'Stattdessen einen Wiederherstellungscode verwenden',
  useApp: 'Stattdessen die Authentifizierungs-App verwenden',
  totpHint: 'Geben Sie den 6-stelligen Code aus Ihrer Authentifizierungs-App ein.',
  totpInvalid:
    'E-Mail-Adresse oder Code ist falsch. Um sich mit einer Authentifizierungs-App anzumelden, richten Sie diese zuerst ein, während Sie auf andere Weise angemeldet sind.',
  totpSignUpHint: 'Nach der Bestätigung Ihrer E-Mail-Adresse richten Sie Ihre Authentifizierungs-App ein.',
  totpCode: { heading: 'Code eingeben', lead: 'Geben Sie den Code aus Ihrer Authentifizierungs-App ein, um die Anmeldung abzuschließen.' },
  totpSetup: {
    heading: 'Authentifizierungs-App einrichten',
    lead: 'Scannen Sie diesen QR-Code mit Ihrer Authentifizierungs-App (z. B. Google Authenticator oder 1Password) und geben Sie dann den Code ein, den sie anzeigt.',
    requiredLead:
      'Für die Anmeldung ist eine Authentifizierungs-App erforderlich. Scannen Sie diesen QR-Code mit einer solchen App (z. B. Google Authenticator oder 1Password) und geben Sie dann den Code ein, den sie anzeigt.',
    qrLabel: 'QR-Code für Ihre Authentifizierungs-App',
    cantScan: 'Scannen nicht möglich? Geben Sie diesen Schlüssel in der App ein:',
    turnOn: 'Einschalten',
    startAgain: 'Neu beginnen',
    effects: {
      secondFactor: (methods) => `Die Anmeldung mit ${methods} fragt dann zusätzlich nach einem Code aus der App.`,
      standalone: 'Sie können sich dann mit Ihrer E-Mail-Adresse und einem Code aus der App anmelden.',
    },
  },
  totpCodes: {
    heading: 'Wiederherstellungscodes speichern',
    lead: 'Wenn Sie Ihre Authentifizierungs-App verlieren, meldet Sie stattdessen einer dieser Codes an. Jeder funktioniert einmal. Bewahren Sie sie sicher auf.',
    saved: 'Ich habe sie gespeichert',
  },
  otherMethod: (how) => `Diese E-Mail-Adresse meldet sich mit ${how} an. Verwenden Sie das statt Google.`,
  methodNames: { google: 'Google', password: 'einem Passwort', totp: 'einer Authentifizierungs-App' },
  and: ' und ',

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
    codes_locked: 'Zu viele falsche Bestätigungscodes. Bitte fordern Sie eine neue E-Mail an und öffnen Sie den Link darin.',
    method_disabled: 'Diese Anmeldeart ist derzeit abgeschaltet.',
    no_session: 'Sie sind nicht angemeldet. Bitte melden Sie sich zuerst an.',
    setup_expired: 'Die Einrichtung hat zu lange gedauert. Bitte beginnen Sie neu.',
    challenge_expired: 'Die Anmeldung hat zu lange gedauert. Bitte melden Sie sich erneut an.',
    required_by_policy: 'Für die Anmeldung ist die Authentifizierungs-App erforderlich, daher kann sie nicht entfernt werden.',
    code_required: 'Bitte geben Sie einen Code aus Ihrer Authentifizierungs-App ein.',
    no_authenticator: 'Es ist keine Authentifizierungs-App eingerichtet.',
    other_method: 'Diese E-Mail-Adresse meldet sich auf andere Weise an. Verwenden Sie diese statt Google.',
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
    signup_rejected: 'Mit diesem Google-Konto ist keine Registrierung möglich.',
    method_disabled: 'Die Anmeldung mit Google ist derzeit abgeschaltet.',
    temporarily_unavailable: 'Die Anmeldung mit Google ist derzeit nicht verfügbar. Bitte versuchen Sie es später erneut.',
    other_method: 'Diese E-Mail-Adresse meldet sich auf andere Weise an. Verwenden Sie diese statt Google.',
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
