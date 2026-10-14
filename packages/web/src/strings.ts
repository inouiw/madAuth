import type { LoginMethodId } from './methods.js';
import type { MadauthErrorCode } from './result.js';

/**
 * Every text madAuth shows to the user: the sign-in dialog's, and the buttons and the errors of the redirect
 * sign-ins (`GoogleRedirect`, `GitHub`). `de` has the same shape, so a text that is missing in one language
 * fails the type check.
 */
export const en = {
  /** Default heading of the dialog, and the button of the sign-in form. */
  signIn: 'Sign in',
  /** Accessible name of the button with the cross. */
  close: 'Close',
  /** Between the providers' buttons (Google, GitHub) and the e-mail & password form. */
  or: 'or',
  otherWays: 'Other ways to sign in',
  /** The sign-in methods: `label` is the text of the button, `description` its tooltip. */
  methods: {
    google: { label: 'Continue with Google', description: 'Use your Google account' },
    github: { label: 'Continue with GitHub', description: 'Use your GitHub account' },
    password: { label: 'Email & password', description: 'Sign in with your email address and password' },
    totp: { label: 'Authenticator app', description: 'One-time code from your authenticator' },
    'email-link': { label: 'Email link', description: 'Passwordless sign-in by email' },
    passkey: { label: 'Passkey', description: 'Sign in with your fingerprint, face or screen lock' },
  } satisfies Record<LoginMethodId, { label: string; description: string }>,

  // Fields
  email: 'Email',
  password: 'Password',
  newPassword: 'New password',
  name: 'Name',
  optional: '(optional)',
  code: 'Code',
  minLength: (characters: number) => `At least ${characters} characters.`,
  /** The eye button in a password field; it is a toggle, so the label stays the same while it is pressed. */
  showPassword: 'Show password',
  /** The strength meter under a new password: zxcvbn's score 0 to 4, and a score below what the server needs. */
  strength: {
    label: 'Password strength',
    levels: ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'],
    tooEasy: 'too easy to guess',
  },

  // Buttons and links
  forgotPassword: 'Forgot password?',
  /** Heading and button of the form for a new account. */
  createAccount: 'Create account',
  /** Links between the sign-in and the sign-up form: a question, and the action, which alone is underlined. */
  noAccount: { question: 'No account?', action: 'Create one' },
  haveAccount: { question: 'Already have an account?', action: 'Sign in' },
  backToSignIn: 'Back to sign in',
  sendEmail: 'Send email',
  sendEmailAgain: 'Send the email again',
  continue: 'Continue',
  setPassword: 'Set password',

  // Headings and texts of the other views
  resetPassword: 'Reset password',
  forgotLead: 'Enter your email address. We will send you a link and a code to choose a new password.',
  /** Under that lead when a provider (Google, GitHub) is one of the methods: its users have no password to reset. `names` is e.g. "Google or GitHub". */
  forgotProviderHint: (names: string) => `Signed up with ${names}? There is no password to reset: use that button instead.`,
  checkInbox: 'Check your inbox',
  /** The e-mail address is shown between the two parts. */
  inboxLead: {
    before: 'We sent an email to ',
    after: '. Open the link in it, or enter the 6-digit code from the email.',
  },
  emailSentAgain: 'We sent the email again.',
  chooseNewPassword: 'Choose a new password',

  // The e-mail link
  emailLink: {
    heading: 'Sign in with an email link',
    /** An unknown address is signed up on first use, so a new user learns that the link makes the account. */
    lead: 'We’ll email you a link to sign in. New here? The link creates your account.',
    /** Under the lead: what the code in the e-mail is for. */
    codeHint: 'The email also has a code, for when you open it on another device.',
    send: 'Send link',
  },
  /** The check-inbox lead after asking for a sign-in link; the e-mail address is shown between the two parts. */
  signInInboxLead: {
    before: 'We sent an email to ',
    after: '. Open the link in it to sign in, or enter the 6-digit code from the email.',
  },

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
  totpInvalid: 'Email or code is wrong. To sign in with an authenticator app, set it up first while signed in another way.',
  /** On the "Create account" form of a sign-up with the app alone. */
  totpSignUpHint: 'You will set up your authenticator app after confirming your email address.',
  /** The second step after a password, Google, GitHub or e-mail link sign-in. */
  totpCode: {
    heading: 'Enter your code',
    lead: 'Enter the code from your authenticator app to finish signing in.',
    /** Setting up a new app while one exists: the current one has to agree. */
    replaceLead: 'Enter the code from your current authenticator app, or a recovery code, to replace it with a new one.',
  },
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
    /** What the app will do, from the server's policy, so the user knows what they turn on. `methods` is e.g. "Google or a password" (`methodNames`). */
    effects: {
      secondFactor: (methods: string) => `From then on, signing in with ${methods} also asks for a code from the app.`,
    },
  },
  totpCodes: {
    heading: 'Save your recovery codes',
    lead: 'If you lose your authenticator app, one of these codes signs you in instead. Each works once. Keep them somewhere safe.',
    saved: 'I have saved them',
  },

  // SMS codes as a second factor
  useSms: 'Send a code by SMS instead',
  /** The second step with a code sent to the phone; `phone` is the masked number. */
  smsCode: {
    heading: 'Enter the code from the SMS',
    lead: (phone: string) => `Enter the code we sent to ${phone} to finish signing in.`,
    /** Replacing the number: the current one has to agree. */
    replaceLead: (phone: string) => `Enter the code we sent to ${phone}, your current number, to replace it with a new one.`,
    sending: 'Sending the code…',
    sendAgain: 'Send the code again',
    sentAgain: 'We sent the code again.',
  },
  smsSetup: {
    heading: 'Add your phone number',
    lead: 'Enter your mobile number. We will send you a code to confirm it.',
    /** When a sign-in requires a second factor and the user has none yet. */
    requiredLead: 'Signing in requires a second factor. Enter your mobile number, and we will send you a code to confirm it.',
    phone: 'Mobile number',
    phoneHint: 'With the country code, e.g. +41 79 123 45 67.',
    sendCode: 'Send code',
    codeLead: (phone: string) => `Enter the code we sent to ${phone}.`,
    confirm: 'Confirm',
    /** In the app's setup during a sign-in, when the server has SMS codes on. */
    usePhone: 'Use your phone number instead',
    /** In the phone's setup during a sign-in: back to the app. */
    useAppInstead: 'Set up an authenticator app instead',
    /** What the phone will do, from the server's policy. */
    effect: (methods: string) => `From then on, signing in with ${methods} can also ask for a code sent to your phone.`,
  },
  // Passkeys
  usePasskey: 'Use a passkey instead',
  /** The second step with a passkey. */
  passkeyStep: {
    heading: 'Confirm with your passkey',
    lead: 'Use your passkey to finish signing in.',
    button: 'Use passkey',
  },
  passkeySetup: {
    heading: 'Create a passkey',
    lead: 'A passkey signs you in with your fingerprint, face or screen lock. It is kept on your device or in your password manager.',
    /** When a sign-in requires a second factor and the user has none yet. */
    requiredLead: 'Signing in requires a second factor. Create a passkey: it uses your fingerprint, face or screen lock.',
    name: 'Name',
    /** Under the name field. */
    nameHint: 'So you can tell your passkeys apart, e.g. "Laptop".',
    create: 'Create passkey',
    /** In the setup of another factor during a sign-in. */
    useInstead: 'Create a passkey instead',
    /** What the passkey will do, from the server's policy. */
    effect: (methods: string) => `From then on, signing in with ${methods} can also ask for your passkey.`,
    signsIn: 'From then on, it signs you in by itself.',
  },
  /** The signed-in user's sign-in methods. */
  methodsView: {
    heading: 'Sign-in methods',
    lead: 'These are the ways you sign in. Add another one, so you can still sign in if you lose one.',
    labels: { google: 'Google', github: 'GitHub', password: 'Password', totp: 'Authenticator app', 'email-link': 'Email link', passkey: 'Passkey' } satisfies Record<LoginMethodId, string>,
    /** Next to a method the server allows only as a second factor. */
    secondFactorOnly: 'As a second factor',
    lastUsed: (date: string) => `Last used ${date}`,
    neverUsed: 'Not used yet',
    remove: 'Remove',
    removeLabel: (name: string) => `Remove ${name}`,
    add: 'Add a sign-in method',
    addPasskey: 'Add a passkey',
    addPassword: 'Add a password',
    addEmailLink: 'Sign in with email links',
    addApp: 'Set up an authenticator app',
    /** The button of a provider (Google, GitHub) that adds it. */
    connect: (name: string) => `Connect ${name}`,
    added: 'Added.',
    removed: 'Removed.',
    done: 'Done',
    loading: 'Loading…',
  },
  addPassword: {
    heading: 'Add a password',
    lead: 'From then on, you can also sign in with your email address and this password.',
  },
  /** `reauth_required`: adding or removing a method needs a recent sign-in. */
  signInAgain: 'Sign in again',

  /** `other_method` with the methods the server named, e.g. "a password", and the provider that was refused, if known. */
  otherMethod: (how: string, instead?: string) => `This email address signs in with ${how}. Use that instead${instead ? ` of ${instead}` : ''}.`,
  /** A method's name inside a sentence, e.g. after "with" ("mit" in German) in `otherMethod` and in what a second factor will do (`totpSetup.effects`, `smsSetup.effect`, `passkeySetup.effect`). */
  methodNames: { google: 'Google', github: 'GitHub', password: 'a password', totp: 'an authenticator app', 'email-link': 'an email link', passkey: 'a passkey' },
  /** Between alternatives in a sentence. */
  orList: ' or ',

  /** What the dialog shows for an error code. */
  errors: {
    network: 'Could not reach the sign-in service. Please check your connection and try again.',
    verification_failed: 'The sign-in could not be verified. Please try again.',
    email_unverified: 'The email address of this account is not verified.',
    cancelled: 'The sign-in was cancelled.',
    not_initialized: 'Sign-in is not set up on this page.',
    invalid_credentials: 'Email or password is wrong.',
    invalid_email: 'Please enter a valid email address.',
    link_invalid: 'This link is invalid or has expired. Please ask for a new email.',
    code_invalid: 'The code is wrong or has expired.',
    codes_locked: 'Too many wrong codes. Please ask for a new email and use the link in it.',
    method_disabled: 'This way of signing in is switched off at the moment.',
    no_session: 'You are not signed in. Please sign in first.',
    setup_expired: 'The setup took too long. Please start again.',
    challenge_expired: 'The sign-in took too long. Please sign in again.',
    required_by_policy: 'Signing in requires a second factor, so it can’t be removed.',
    code_required: 'Please enter a code from your authenticator app.',
    no_authenticator: 'No authenticator app is set up.',
    only_method: 'This is the only way you sign in, so it can’t be removed. Add another one first.',
    passkey_unknown: 'This passkey is not registered here any more. Sign in another way.',
    passkey_unsupported: 'This browser does not support passkeys.',
    reauth_required: 'For your security, sign in again to change how you sign in.',
    account_taken: 'This account signs in another user. Use another one.',
    already_added: 'You have added this already.',
    method_not_found: 'This sign-in method is gone already.',
    forbidden_origin: 'Passkeys can’t be used on this page.',
    other_method: 'This email address signs in another way. Use that instead.',
    invalid_phone: 'Please enter a valid mobile number with the country code, e.g. +41 79 123 45 67.',
    no_phone: 'No phone number is set up.',
    too_soon: 'We sent a code less than a minute ago. Enter that one, or wait a minute for a new one.',
  } satisfies Partial<Record<MadauthErrorCode, string>>,
  /** For every other error code. */
  errorFallback: 'Sign-in is not available right now.',
  /** `email_unverified` after signing in with a password. */
  confirmEmailFirst: 'Please confirm your email address first: open the link in the email we sent you.',
  /** `temporarily_unavailable` when creating an account, and when asking for an e-mail. */
  signUpUnavailable: 'Email & password sign-up is not available right now. Please try again later.',
  emailsUnavailable: 'Sending emails is not available right now. Please try again later.',
  smsUnavailable: 'Sending SMS is not available right now. Please try again later.',
  /**
   * `weak_password` and `too_many_attempts` come with a message from the server that is written for the
   * user, in English. With `weak_password`, `minLength` is set when the password is too short and `minScore`
   * when it is too easy to guess.
   */
  weakPassword: (serverMessage: string, _rule?: { minLength?: number; minScore?: number }) => serverMessage,
  tooManyAttempts: (serverMessage: string) => serverMessage,

  /** The redirect sign-ins (`GoogleRedirect`, `GitHub`): why the sign-in failed, by the error code the server reported; `name` is the provider's. */
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

export type Strings = typeof en;

export const de: Strings = {
  signIn: 'Anmelden',
  close: 'Schließen',
  or: 'oder',
  otherWays: 'Weitere Anmeldemöglichkeiten',
  methods: {
    google: { label: 'Weiter mit Google', description: 'Mit Ihrem Google-Konto anmelden' },
    github: { label: 'Weiter mit GitHub', description: 'Mit Ihrem GitHub-Konto anmelden' },
    password: { label: 'E-Mail-Adresse und Passwort', description: 'Mit E-Mail-Adresse und Passwort anmelden' },
    totp: { label: 'Authentifizierungs-App', description: 'Einmalcode aus Ihrer Authentifizierungs-App' },
    'email-link': { label: 'E-Mail-Link', description: 'Ohne Passwort per E-Mail anmelden' },
    passkey: { label: 'Passkey', description: 'Mit Fingerabdruck, Gesicht oder Bildschirmsperre anmelden' },
  },

  email: 'E-Mail-Adresse',
  password: 'Passwort',
  newPassword: 'Neues Passwort',
  name: 'Name',
  optional: '(optional)',
  code: 'Bestätigungscode',
  minLength: (characters) => `Mindestens ${characters} Zeichen.`,
  showPassword: 'Passwort anzeigen',
  strength: {
    label: 'Passwortstärke',
    levels: ['Sehr schwach', 'Schwach', 'Mittel', 'Gut', 'Stark'],
    tooEasy: 'zu leicht zu erraten',
  },

  forgotPassword: 'Passwort vergessen?',
  createAccount: 'Konto erstellen',
  noAccount: { question: 'Noch kein Konto?', action: 'Konto erstellen' },
  haveAccount: { question: 'Sie haben bereits ein Konto?', action: 'Anmelden' },
  backToSignIn: 'Zurück zur Anmeldung',
  sendEmail: 'E-Mail senden',
  sendEmailAgain: 'E-Mail erneut senden',
  continue: 'Weiter',
  setPassword: 'Passwort festlegen',

  resetPassword: 'Passwort zurücksetzen',
  forgotLead:
    'Geben Sie Ihre E-Mail-Adresse ein. Wir senden Ihnen einen Link und einen Bestätigungscode, mit denen Sie ein neues Passwort wählen können.',
  forgotProviderHint: (names) => `Mit ${names} registriert? Es gibt kein Passwort zum Zurücksetzen: Verwenden Sie stattdessen den entsprechenden Button.`,
  checkInbox: 'Posteingang prüfen',
  inboxLead: {
    before: 'Wir haben eine E-Mail an ',
    after: ' gesendet. Öffnen Sie den Link darin oder geben Sie den 6-stelligen Bestätigungscode aus der E-Mail ein.',
  },
  emailSentAgain: 'Wir haben die E-Mail erneut gesendet.',
  chooseNewPassword: 'Neues Passwort wählen',

  emailLink: {
    heading: 'Mit E-Mail-Link anmelden',
    lead: 'Wir senden Ihnen einen Link zum Anmelden per E-Mail. Neu hier? Der Link erstellt Ihr Konto.',
    codeHint: 'Die E-Mail enthält auch einen Bestätigungscode, falls Sie sie auf einem anderen Gerät öffnen.',
    send: 'Link senden',
  },
  signInInboxLead: {
    before: 'Wir haben eine E-Mail an ',
    after: ' gesendet. Öffnen Sie den Link darin, um sich anzumelden, oder geben Sie den 6-stelligen Bestätigungscode aus der E-Mail ein.',
  },

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
  totpCode: {
    heading: 'Code eingeben',
    lead: 'Geben Sie den Code aus Ihrer Authentifizierungs-App ein, um die Anmeldung abzuschließen.',
    replaceLead: 'Geben Sie den Code aus Ihrer bisherigen Authentifizierungs-App oder einen Wiederherstellungscode ein, um sie durch eine neue zu ersetzen.',
  },
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
    },
  },
  totpCodes: {
    heading: 'Wiederherstellungscodes speichern',
    lead: 'Wenn Sie Ihre Authentifizierungs-App verlieren, meldet Sie stattdessen einer dieser Codes an. Jeder funktioniert einmal. Bewahren Sie sie sicher auf.',
    saved: 'Ich habe sie gespeichert',
  },

  useSms: 'Stattdessen einen Code per SMS erhalten',
  smsCode: {
    heading: 'Code aus der SMS eingeben',
    lead: (phone) => `Geben Sie den Code ein, den wir an ${phone} gesendet haben, um die Anmeldung abzuschließen.`,
    replaceLead: (phone) => `Geben Sie den Code ein, den wir an Ihre bisherige Nummer ${phone} gesendet haben, um sie durch eine neue zu ersetzen.`,
    sending: 'Code wird gesendet …',
    sendAgain: 'Code erneut senden',
    sentAgain: 'Wir haben den Code erneut gesendet.',
  },
  smsSetup: {
    heading: 'Mobilnummer hinzufügen',
    lead: 'Geben Sie Ihre Mobilnummer ein. Wir senden Ihnen einen Code, um sie zu bestätigen.',
    requiredLead: 'Für die Anmeldung ist ein zweiter Faktor erforderlich. Geben Sie Ihre Mobilnummer ein, und wir senden Ihnen einen Code, um sie zu bestätigen.',
    phone: 'Mobilnummer',
    phoneHint: 'Mit Ländervorwahl, z. B. +41 79 123 45 67.',
    sendCode: 'Code senden',
    codeLead: (phone) => `Geben Sie den Code ein, den wir an ${phone} gesendet haben.`,
    confirm: 'Bestätigen',
    usePhone: 'Stattdessen Ihre Mobilnummer verwenden',
    useAppInstead: 'Stattdessen eine Authentifizierungs-App einrichten',
    effect: (methods) => `Die Anmeldung mit ${methods} kann dann zusätzlich nach einem Code fragen, der an Ihr Mobiltelefon gesendet wird.`,
  },
  usePasskey: 'Stattdessen einen Passkey verwenden',
  passkeyStep: {
    heading: 'Mit Passkey bestätigen',
    lead: 'Verwenden Sie Ihren Passkey, um die Anmeldung abzuschließen.',
    button: 'Passkey verwenden',
  },
  passkeySetup: {
    heading: 'Passkey erstellen',
    lead: 'Ein Passkey meldet Sie mit Fingerabdruck, Gesicht oder Bildschirmsperre an. Er wird auf Ihrem Gerät oder in Ihrem Passwortmanager gespeichert.',
    requiredLead: 'Für die Anmeldung ist ein zweiter Faktor erforderlich. Erstellen Sie einen Passkey: Er verwendet Fingerabdruck, Gesicht oder Bildschirmsperre.',
    name: 'Name',
    nameHint: 'Damit Sie Ihre Passkeys auseinanderhalten können, z. B. „Laptop“.',
    create: 'Passkey erstellen',
    useInstead: 'Stattdessen einen Passkey erstellen',
    effect: (methods) => `Die Anmeldung mit ${methods} kann dann zusätzlich nach Ihrem Passkey fragen.`,
    signsIn: 'Danach meldet er Sie auch allein an.',
  },
  methodsView: {
    heading: 'Anmeldemethoden',
    lead: 'So melden Sie sich an. Fügen Sie eine weitere Methode hinzu, damit Sie sich auch anmelden können, wenn Sie eine verlieren.',
    labels: { google: 'Google', github: 'GitHub', password: 'Passwort', totp: 'Authentifizierungs-App', 'email-link': 'E-Mail-Link', passkey: 'Passkey' },
    secondFactorOnly: 'Als zweiter Faktor',
    lastUsed: (date) => `Zuletzt verwendet am ${date}`,
    neverUsed: 'Noch nicht verwendet',
    remove: 'Entfernen',
    removeLabel: (name) => `${name} entfernen`,
    add: 'Anmeldemethode hinzufügen',
    addPasskey: 'Passkey hinzufügen',
    addPassword: 'Passwort hinzufügen',
    addEmailLink: 'Mit E-Mail-Links anmelden',
    addApp: 'Authentifizierungs-App einrichten',
    connect: (name) => `${name} verbinden`,
    added: 'Hinzugefügt.',
    removed: 'Entfernt.',
    done: 'Fertig',
    loading: 'Wird geladen …',
  },
  addPassword: {
    heading: 'Passwort hinzufügen',
    lead: 'Danach können Sie sich auch mit Ihrer E-Mail-Adresse und diesem Passwort anmelden.',
  },
  signInAgain: 'Erneut anmelden',

  otherMethod: (how, instead) => `Diese E-Mail-Adresse meldet sich mit ${how} an. Verwenden Sie das ${instead ? `statt ${instead}` : 'stattdessen'}.`,
  methodNames: { google: 'Google', github: 'GitHub', password: 'einem Passwort', totp: 'einer Authentifizierungs-App', 'email-link': 'einem E-Mail-Link', passkey: 'einem Passkey' },
  orList: ' oder ',

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
    required_by_policy: 'Für die Anmeldung ist ein zweiter Faktor erforderlich, daher kann er nicht entfernt werden.',
    code_required: 'Bitte geben Sie einen Code aus Ihrer Authentifizierungs-App ein.',
    no_authenticator: 'Es ist keine Authentifizierungs-App eingerichtet.',
    only_method: 'Dies ist Ihre einzige Anmeldemethode, daher kann sie nicht entfernt werden. Fügen Sie zuerst eine weitere hinzu.',
    passkey_unknown: 'Dieser Passkey ist hier nicht mehr registriert. Melden Sie sich auf andere Weise an.',
    passkey_unsupported: 'Dieser Browser unterstützt keine Passkeys.',
    reauth_required: 'Melden Sie sich zu Ihrer Sicherheit erneut an, um Ihre Anmeldemethoden zu ändern.',
    account_taken: 'Mit diesem Konto meldet sich ein anderer Benutzer an. Verwenden Sie ein anderes.',
    already_added: 'Sie haben dies bereits hinzugefügt.',
    method_not_found: 'Diese Anmeldemethode ist bereits entfernt.',
    forbidden_origin: 'Auf dieser Seite können keine Passkeys verwendet werden.',
    other_method: 'Diese E-Mail-Adresse meldet sich auf andere Weise an. Verwenden Sie diese stattdessen.',
    invalid_phone: 'Bitte geben Sie eine gültige Mobilnummer mit Ländervorwahl ein, z. B. +41 79 123 45 67.',
    no_phone: 'Es ist keine Mobilnummer eingerichtet.',
    too_soon: 'Wir haben vor weniger als einer Minute einen Code gesendet. Geben Sie diesen ein, oder warten Sie eine Minute auf einen neuen.',
  },
  errorFallback: 'Die Anmeldung ist derzeit nicht möglich.',
  confirmEmailFirst:
    'Bitte bestätigen Sie zuerst Ihre E-Mail-Adresse: Öffnen Sie den Link in der E-Mail, die wir Ihnen gesendet haben.',
  signUpUnavailable:
    'Derzeit kann kein Konto mit E-Mail-Adresse und Passwort erstellt werden. Bitte versuchen Sie es später erneut.',
  emailsUnavailable: 'Derzeit können keine E-Mails gesendet werden. Bitte versuchen Sie es später erneut.',
  smsUnavailable: 'Derzeit können keine SMS gesendet werden. Bitte versuchen Sie es später erneut.',
  weakPassword: (_serverMessage, rule) =>
    rule?.minLength
      ? `Das Passwort muss mindestens ${rule.minLength} Zeichen lang sein.`
      : rule?.minScore
        ? 'Dieses Passwort ist zu leicht zu erraten. Fügen Sie ein, zwei Wörter hinzu oder wählen Sie weniger gebräuchliche.'
        : 'Dieses Passwort ist nicht zulässig. Bitte wählen Sie ein anderes.',
  tooManyAttempts: () => 'Zu viele Versuche. Bitte warten Sie einen Moment und versuchen Sie es erneut.',

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
