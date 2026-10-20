import type { BuiltInMethodId } from './methods.js';
import type { MadauthErrorCode } from './result.js';
import { coreDe, coreEn, languageOf, methodTexts } from './strings-core.js';

/**
 * Every text the sign-in dialog shows: the client's (`strings-core.ts`: the methods' names, the buttons and
 * the errors of the redirect sign-ins), and the dialog's own views. `de` has the same shape, so a text that is
 * missing in one language fails the type check. A client without the dialog (`@madauth/web/client`) never
 * loads this file.
 */
export const en = {
  ...coreEn,
  /** Default heading of the dialog, and the button of the sign-in form. */
  signIn: 'Sign in',
  /** Accessible name of the button with the cross. */
  close: 'Close',
  /** Between the providers' buttons (Google, GitHub) and the e-mail & password form. */
  or: 'or',
  otherWays: 'Other ways to sign in',
  /** The tooltip of an OpenID Connect provider's button (`continueWith`). */
  useAccount: (name: string) => `Use your ${name} account`,
  /** The sign-in methods: `label` is the text of the button, `description` its tooltip. */
  methods: methodTexts,

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
  /** Under the inbox's lead after a sign-in through a provider that doesn't vouch for the address. */
  confirmProviderAddress: (name: string) => `${name} doesn’t confirm this address, so we confirm it once before you sign in with ${name}.`,
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
  authenticatorHint: 'Enter the 6-digit code from your authenticator app.',
  /** `invalid_credentials` on the authenticator app's own sign-in form. */
  authenticatorInvalid: 'Email or code is wrong. To sign in with an authenticator app, set it up first while signed in another way.',
  /** On the "Create account" form of a sign-up with the app alone. */
  authenticatorSignUpHint: 'You will set up your authenticator app after confirming your email address.',
  /** The second step after a password, Google, GitHub or e-mail link sign-in. */
  authenticatorCode: {
    heading: 'Enter your code',
    lead: 'Enter the code from your authenticator app to finish signing in.',
    /** Setting up a new app while one exists: the current one has to agree. */
    replaceLead: 'Enter the code from your current authenticator app, or a recovery code, to replace it with a new one.',
  },
  authenticatorSetup: {
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
  authenticatorCodes: {
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
  /** The button at the top of the sign-in view. */
  signInWithPasskey: 'Sign in with a passkey',
  usePasskey: 'Use a passkey instead',
  /** On the "Create account" form of a sign-up with a passkey alone. */
  passkeySignUpHint: 'You will create your passkey after confirming your email address. It signs you in with your fingerprint, face or screen lock.',
  /** Links on the "Create account" form, between the sign-up with a password and the one with a passkey. */
  passkeySignUpInstead: 'Use a passkey instead of a password',
  passwordSignUpInstead: 'Use a password instead',
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
    /** In a sign-up with a passkey alone, once the address is confirmed. */
    signUpLead: 'Your email address is confirmed. Create your passkey to finish signing up: it uses your fingerprint, face or screen lock.',
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
    labels: { google: 'Google', github: 'GitHub', password: 'Password', authenticator: 'Authenticator app', 'email-link': 'Email link', passkey: 'Passkey' } satisfies Record<BuiltInMethodId, string>,
    /** Next to a method the server allows only as a second factor. */
    secondFactorOnly: 'As a second factor',
    lastUsed: (date: string) => `Last used ${date}`,
    neverUsed: 'Not used yet',
    remove: 'Remove',
    removeLabel: (name: string) => `Remove ${name}`,
    /** On the password's row. */
    change: 'Change',
    add: 'Add a sign-in method',
    addPasskey: 'Add a passkey',
    addPassword: 'Add a password',
    addEmailLink: 'Sign in with email links',
    addApp: 'Set up an authenticator app',
    added: 'Added.',
    removed: 'Removed.',
    passwordChanged: 'Password changed. You are signed out on your other devices.',
    done: 'Done',
    loading: 'Loading…',
  },
  addPassword: {
    heading: 'Add a password',
    lead: 'From then on, you can also sign in with your email address and this password.',
  },
  changePassword: {
    heading: 'Change password',
    lead: 'You stay signed in here. Everywhere else, you are signed out.',
    current: 'Current password',
    submit: 'Change password',
    /** `invalid_credentials`. */
    wrongCurrent: 'The current password is wrong.',
  },
  apiKeysView: {
    heading: 'API keys',
    lead: 'A program that calls an API for you, e.g. a script, sends one of your API keys. It may do what you allowed the key, as long as you may do it yourself.',
    empty: 'You have no API keys.',
    lastUsed: (date: string) => `Last used ${date}`,
    neverUsed: 'Not used yet',
    expires: (date: string) => `Expires ${date}`,
    expired: (date: string) => `Expired ${date}`,
    noExpiry: 'Never expires',
    revoke: 'Revoke',
    revokeLabel: (name: string) => `Revoke ${name}`,
    create: 'Create an API key',
    revoked: 'Revoked.',
    done: 'Done',
    loading: 'Loading…',
  },
  apiKeyCreate: {
    heading: 'Create an API key',
    name: 'Name',
    nameHint: 'What it is for, e.g. “Deploy script”.',
    scopes: 'What it may do',
    /** Without a scope the user may give a key. */
    noScopes: 'There is nothing you can allow an API key to do.',
    expires: 'Expires',
    never: 'Never',
    inDays: (days: number) => (days === 365 ? 'In a year' : `In ${days} days`),
    create: 'Create key',
    /** `reauth_required` while creating a key. */
    reauth: 'For your security, sign in again to create an API key.',
  },
  apiKeyCreated: {
    heading: 'Your new API key',
    lead: 'Copy it now: it is shown only this once. Keep it as safe as a password.',
    copy: 'Copy',
    copied: 'Copied.',
    /** The page may not use the clipboard: the key is selected instead. */
    copyByHand: 'It could not be copied here: copy the selected key yourself.',
    done: 'Done',
  },
  /** The admin dialog (`Madauth.showAdminDialog`): the server's sign-in providers. */
  adminView: {
    heading: 'Sign-in providers',
    lead: 'The providers people sign in with, besides email, passkeys and the authenticator app. A new one is off until you switch it on.',
    empty: 'No providers yet.',
    loading: 'Loading…',
    add: 'Add a provider',
    /** A provider's state in the list; `policy` is one of `policies`. */
    on: (policy: string) => `On, ${policy}`,
    off: 'Off',
    policies: { none: 'no second factor', optional: 'second factor optional', required: 'second factor required' },
    kinds: { google: 'Google', github: 'GitHub', oidc: 'OpenID Connect' },
    chooseKind: 'Which kind of provider?',
    kindHints: { google: 'One Tap, and with a client secret the redirect sign-in', github: 'Through an OAuth App', oidc: 'GitLab, Keycloak, Okta, Auth0, your company’s own…' },
    addHeading: (kind: string) => `Add ${kind}`,
    id: 'Id',
    idHint: 'Lowercase letters, digits and dashes, e.g. “gitlab”. It can’t change later.',
    name: 'Name',
    nameHint: 'The button says “Continue with” it.',
    issuer: 'Issuer',
    issuerHint: 'Exactly as the provider’s discovery document names it, e.g. “https://gitlab.com”. It can’t change later.',
    clientId: 'Client ID',
    clientSecret: 'Client secret',
    secretKept: 'Leave empty to keep the current one.',
    googleSecret: 'Only for the redirect sign-in; without it, Google signs in with One Tap.',
    removeSecret: 'Remove the client secret',
    scopes: 'More scopes',
    scopesHint: 'Separated by spaces; openid, email and profile are always asked for.',
    trustEmail: 'Its addresses are verified',
    trustEmailHint: 'Signs in with addresses it doesn’t mark as verified. Only for a provider whose addresses its operator checks, e.g. your company’s own.',
    callbackUrl: 'Callback URL',
    callbackHint: 'Register it at the provider as the redirect URI.',
    copy: 'Copy',
    copied: 'Copied.',
    copyByHand: 'It could not be copied here: copy the selected URL yourself.',
    switchOn: 'On as a sign-in method',
    secondFactor: 'Second factor',
    save: 'Save',
    remove: 'Remove',
    added: 'Added.',
    saved: 'Saved.',
    removed: 'Removed.',
    done: 'Done',
    removeHeading: (name: string) => `Remove ${name}?`,
    /** `withIssuer`: an OpenID Connect provider, whose accounts come back only with its issuer. */
    removeLead: (withIssuer: boolean) => `Its users’ accounts stay: adding it again${withIssuer ? ' with the same issuer' : ''} brings their sign-ins back.`,
    /** How many users sign in with the provider and nothing else. */
    stranded: (count: number) =>
      count === 0
        ? 'Everyone who signs in with it has another way to sign in.'
        : `${count === 1 ? '1 user signs' : `${count} users sign`} in with it alone and can’t sign in until it is back, or an admin resets their sign-in.`,
    reauth: 'For your security, sign in again to change the providers.',
  },
  /** `reauth_required`: adding or removing a method needs a recent sign-in. */
  signInAgain: 'Sign in again',

  /** `other_method` with the methods the server named, e.g. "a password", and the provider that was refused, if known. */
  otherMethod: (how: string, instead?: string) => `This email address signs in with ${how}. Use that instead${instead ? ` of ${instead}` : ''}.`,
  /** Between alternatives in a sentence, e.g. the `methodNames` of `otherMethod`. */
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
    forbidden: 'Only admins can do this.',
    provider_exists: 'There is a provider with this id already.',
    provider_not_found: 'This provider is gone: another admin may have removed it.',
    other_method: 'This email address signs in another way. Use that instead.',
    invalid_phone: 'Please enter a valid mobile number with the country code, e.g. +41 79 123 45 67.',
    no_phone: 'No phone number is set up.',
    too_soon: 'We sent a code less than a minute ago. Enter that one, or wait a minute for a new one.',
    scope_not_allowed: 'An API key can only do what you may do yourself.',
    too_many_api_keys: 'You have as many API keys as you can have. Revoke one first.',
    api_key_not_found: 'This API key is gone already.',
    invalid_scopes: 'Something this key should do does not exist any more. Please try again.',
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
};

export type Strings = typeof en;

export const de: Strings = {
  ...coreDe,
  signIn: 'Anmelden',
  close: 'Schließen',
  or: 'oder',
  otherWays: 'Weitere Anmeldemöglichkeiten',
  useAccount: (name) => `Mit Ihrem ${name}-Konto anmelden`,
  methods: {
    google: { label: 'Weiter mit Google', description: 'Mit Ihrem Google-Konto anmelden' },
    github: { label: 'Weiter mit GitHub', description: 'Mit Ihrem GitHub-Konto anmelden' },
    password: { label: 'E-Mail-Adresse und Passwort', description: 'Mit E-Mail-Adresse und Passwort anmelden' },
    authenticator: { label: 'Authentifizierungs-App', description: 'Einmalcode aus Ihrer Authentifizierungs-App' },
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
  confirmProviderAddress: (name) => `${name} bestätigt diese Adresse nicht, deshalb bestätigen wir sie einmal, bevor Sie sich mit ${name} anmelden.`,
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
  authenticatorHint: 'Geben Sie den 6-stelligen Code aus Ihrer Authentifizierungs-App ein.',
  authenticatorInvalid:
    'E-Mail-Adresse oder Code ist falsch. Um sich mit einer Authentifizierungs-App anzumelden, richten Sie diese zuerst ein, während Sie auf andere Weise angemeldet sind.',
  authenticatorSignUpHint: 'Nach der Bestätigung Ihrer E-Mail-Adresse richten Sie Ihre Authentifizierungs-App ein.',
  authenticatorCode: {
    heading: 'Code eingeben',
    lead: 'Geben Sie den Code aus Ihrer Authentifizierungs-App ein, um die Anmeldung abzuschließen.',
    replaceLead: 'Geben Sie den Code aus Ihrer bisherigen Authentifizierungs-App oder einen Wiederherstellungscode ein, um sie durch eine neue zu ersetzen.',
  },
  authenticatorSetup: {
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
  authenticatorCodes: {
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
  signInWithPasskey: 'Mit Passkey anmelden',
  usePasskey: 'Stattdessen einen Passkey verwenden',
  passkeySignUpHint: 'Nach der Bestätigung Ihrer E-Mail-Adresse erstellen Sie Ihren Passkey. Er meldet Sie mit Fingerabdruck, Gesicht oder Bildschirmsperre an.',
  passkeySignUpInstead: 'Passkey statt Passwort verwenden',
  passwordSignUpInstead: 'Stattdessen ein Passwort verwenden',
  passkeyStep: {
    heading: 'Mit Passkey bestätigen',
    lead: 'Verwenden Sie Ihren Passkey, um die Anmeldung abzuschließen.',
    button: 'Passkey verwenden',
  },
  passkeySetup: {
    heading: 'Passkey erstellen',
    lead: 'Ein Passkey meldet Sie mit Fingerabdruck, Gesicht oder Bildschirmsperre an. Er wird auf Ihrem Gerät oder in Ihrem Passwortmanager gespeichert.',
    requiredLead: 'Für die Anmeldung ist ein zweiter Faktor erforderlich. Erstellen Sie einen Passkey: Er verwendet Fingerabdruck, Gesicht oder Bildschirmsperre.',
    signUpLead: 'Ihre E-Mail-Adresse ist bestätigt. Erstellen Sie Ihren Passkey, um die Registrierung abzuschließen: Er verwendet Fingerabdruck, Gesicht oder Bildschirmsperre.',
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
    labels: { google: 'Google', github: 'GitHub', password: 'Passwort', authenticator: 'Authentifizierungs-App', 'email-link': 'E-Mail-Link', passkey: 'Passkey' },
    secondFactorOnly: 'Als zweiter Faktor',
    lastUsed: (date) => `Zuletzt verwendet am ${date}`,
    neverUsed: 'Noch nicht verwendet',
    remove: 'Entfernen',
    removeLabel: (name) => `${name} entfernen`,
    change: 'Ändern',
    add: 'Anmeldemethode hinzufügen',
    addPasskey: 'Passkey hinzufügen',
    addPassword: 'Passwort hinzufügen',
    addEmailLink: 'Mit E-Mail-Links anmelden',
    addApp: 'Authentifizierungs-App einrichten',
    added: 'Hinzugefügt.',
    removed: 'Entfernt.',
    passwordChanged: 'Passwort geändert. Auf Ihren anderen Geräten sind Sie abgemeldet.',
    done: 'Fertig',
    loading: 'Wird geladen …',
  },
  addPassword: {
    heading: 'Passwort hinzufügen',
    lead: 'Danach können Sie sich auch mit Ihrer E-Mail-Adresse und diesem Passwort anmelden.',
  },
  changePassword: {
    heading: 'Passwort ändern',
    lead: 'Hier bleiben Sie angemeldet. Überall sonst werden Sie abgemeldet.',
    current: 'Aktuelles Passwort',
    submit: 'Passwort ändern',
    wrongCurrent: 'Das aktuelle Passwort ist falsch.',
  },
  apiKeysView: {
    heading: 'API-Schlüssel',
    lead: 'Ein Programm, das für Sie eine API aufruft, z. B. ein Skript, sendet einen Ihrer API-Schlüssel. Es darf, was Sie dem Schlüssel erlaubt haben, solange Sie es selbst dürfen.',
    empty: 'Sie haben keine API-Schlüssel.',
    lastUsed: (date) => `Zuletzt verwendet am ${date}`,
    neverUsed: 'Noch nicht verwendet',
    expires: (date) => `Läuft am ${date} ab`,
    expired: (date) => `Am ${date} abgelaufen`,
    noExpiry: 'Läuft nie ab',
    revoke: 'Widerrufen',
    revokeLabel: (name) => `${name} widerrufen`,
    create: 'API-Schlüssel erstellen',
    revoked: 'Widerrufen.',
    done: 'Fertig',
    loading: 'Wird geladen …',
  },
  apiKeyCreate: {
    heading: 'API-Schlüssel erstellen',
    name: 'Name',
    nameHint: 'Wofür er ist, z. B. „Deploy-Skript“.',
    scopes: 'Was er darf',
    noScopes: 'Es gibt nichts, was Sie einem API-Schlüssel erlauben können.',
    expires: 'Läuft ab',
    never: 'Nie',
    inDays: (days) => (days === 365 ? 'In einem Jahr' : `In ${days} Tagen`),
    create: 'Schlüssel erstellen',
    reauth: 'Melden Sie sich zu Ihrer Sicherheit erneut an, um einen API-Schlüssel zu erstellen.',
  },
  apiKeyCreated: {
    heading: 'Ihr neuer API-Schlüssel',
    lead: 'Kopieren Sie ihn jetzt: Er wird nur dieses eine Mal angezeigt. Bewahren Sie ihn so sicher auf wie ein Passwort.',
    copy: 'Kopieren',
    copied: 'Kopiert.',
    copyByHand: 'Er konnte hier nicht kopiert werden: Kopieren Sie den markierten Schlüssel selbst.',
    done: 'Fertig',
  },
  adminView: {
    heading: 'Anmeldeanbieter',
    lead: 'Die Anbieter, mit denen sich Nutzer anmelden, neben E-Mail, Passkeys und der Authentifizierungs-App. Ein neuer ist aus, bis Sie ihn einschalten.',
    empty: 'Noch keine Anbieter.',
    loading: 'Wird geladen…',
    add: 'Anbieter hinzufügen',
    on: (policy) => `An, ${policy}`,
    off: 'Aus',
    policies: { none: 'kein zweiter Faktor', optional: 'zweiter Faktor optional', required: 'zweiter Faktor erforderlich' },
    kinds: { google: 'Google', github: 'GitHub', oidc: 'OpenID Connect' },
    chooseKind: 'Welche Art von Anbieter?',
    kindHints: { google: 'One Tap, und mit Client-Secret die Anmeldung per Weiterleitung', github: 'Über eine OAuth App', oidc: 'GitLab, Keycloak, Okta, Auth0, der Ihres Unternehmens…' },
    addHeading: (kind) => `${kind} hinzufügen`,
    id: 'ID',
    idHint: 'Kleinbuchstaben, Ziffern und Bindestriche, z. B. „gitlab“. Sie lässt sich später nicht ändern.',
    name: 'Name',
    nameHint: 'Die Schaltfläche lautet „Weiter mit“ diesem Namen.',
    issuer: 'Aussteller (Issuer)',
    issuerHint: 'Genau so, wie ihn das Discovery-Dokument des Anbieters nennt, z. B. „https://gitlab.com“. Er lässt sich später nicht ändern.',
    clientId: 'Client-ID',
    clientSecret: 'Client-Secret',
    secretKept: 'Leer lassen, um das bisherige zu behalten.',
    googleSecret: 'Nur für die Anmeldung per Weiterleitung; ohne meldet Google mit One Tap an.',
    removeSecret: 'Client-Secret entfernen',
    scopes: 'Weitere Scopes',
    scopesHint: 'Durch Leerzeichen getrennt; openid, email und profile werden immer angefragt.',
    trustEmail: 'Seine Adressen sind bestätigt',
    trustEmailHint: 'Meldet auch mit Adressen an, die er nicht als bestätigt kennzeichnet. Nur für einen Anbieter, dessen Betreiber die Adressen prüft, z. B. den Ihres Unternehmens.',
    callbackUrl: 'Callback-URL',
    callbackHint: 'Tragen Sie sie beim Anbieter als Weiterleitungs-URI ein.',
    copy: 'Kopieren',
    copied: 'Kopiert.',
    copyByHand: 'Sie konnte hier nicht kopiert werden: Kopieren Sie die markierte URL selbst.',
    switchOn: 'Als Anmeldemethode an',
    secondFactor: 'Zweiter Faktor',
    save: 'Speichern',
    remove: 'Entfernen',
    added: 'Hinzugefügt.',
    saved: 'Gespeichert.',
    removed: 'Entfernt.',
    done: 'Fertig',
    removeHeading: (name) => `${name} entfernen?`,
    removeLead: (withIssuer) => `Die Konten seiner Nutzer bleiben: Fügen Sie ihn${withIssuer ? ' mit demselben Aussteller' : ''} wieder hinzu, können sie sich wieder anmelden.`,
    stranded: (count) =>
      count === 0
        ? 'Alle, die sich damit anmelden, haben noch einen anderen Weg.'
        : `${count === 1 ? '1 Nutzer meldet' : `${count} Nutzer melden`} sich nur damit an und ${count === 1 ? 'kann' : 'können'} sich nicht anmelden, bis er wieder da ist oder ein Admin ${count === 1 ? 'seine' : 'ihre'} Anmeldung zurücksetzt.`,
    reauth: 'Melden Sie sich zu Ihrer Sicherheit erneut an, um die Anbieter zu ändern.',
  },
  signInAgain: 'Erneut anmelden',

  otherMethod: (how, instead) => `Diese E-Mail-Adresse meldet sich mit ${how} an. Verwenden Sie das ${instead ? `statt ${instead}` : 'stattdessen'}.`,
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
    forbidden: 'Das dürfen nur Admins.',
    provider_exists: 'Es gibt schon einen Anbieter mit dieser ID.',
    provider_not_found: 'Diesen Anbieter gibt es nicht mehr: Vielleicht hat ihn ein anderer Admin entfernt.',
    other_method: 'Diese E-Mail-Adresse meldet sich auf andere Weise an. Verwenden Sie diese stattdessen.',
    invalid_phone: 'Bitte geben Sie eine gültige Mobilnummer mit Ländervorwahl ein, z. B. +41 79 123 45 67.',
    no_phone: 'Es ist keine Mobilnummer eingerichtet.',
    too_soon: 'Wir haben vor weniger als einer Minute einen Code gesendet. Geben Sie diesen ein, oder warten Sie eine Minute auf einen neuen.',
    scope_not_allowed: 'Ein API-Schlüssel kann nur, was Sie selbst dürfen.',
    too_many_api_keys: 'Sie haben so viele API-Schlüssel, wie möglich sind. Widerrufen Sie zuerst einen.',
    api_key_not_found: 'Dieser API-Schlüssel ist bereits entfernt.',
    invalid_scopes: 'Etwas, was dieser Schlüssel dürfen soll, gibt es nicht mehr. Bitte versuchen Sie es erneut.',
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
};

const languages = { en, de };

/** The dialog's texts in the language of `locale` (`languageOf`). */
export function stringsFor(locale: string | undefined): Strings {
  return languages[languageOf(locale)];
}
