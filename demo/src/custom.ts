// A custom login screen: everything madAuth's dialog does, built with the headless API.
import { EmailLink, GitHub, GoogleFedcm, Madauth, Password, Totp, type MadauthError, type MadauthUser, type Result, type SecondFactor } from '@madauth/web';

type View =
  | 'signin'
  | 'signup'
  | 'forgot'
  | 'code'
  | 'reset'
  | 'totp'
  | 'totp-signup'
  | 'totp-code'
  | 'totp-setup'
  | 'totp-codes'
  | 'email-link'
  | 'sms-code'
  | 'sms-setup'
  | 'sms-setup-code';

const $ = <T extends HTMLElement = HTMLElement>(selector: string) => document.querySelector<T>(selector)!;

const titles: Record<View, string> = {
  signin: 'Sign in',
  signup: 'Create account',
  forgot: 'Reset password',
  code: 'Check your inbox',
  reset: 'Choose a new password',
  totp: 'Authenticator app',
  'totp-signup': 'Create account',
  'totp-code': 'Enter your code',
  'totp-setup': 'Set up authenticator app',
  'totp-codes': 'Save your recovery codes',
  'email-link': 'Sign in with an e-mail link',
  'sms-code': 'Enter the code from the SMS',
  'sms-setup': 'Add your phone number',
  'sms-setup-code': 'Add your phone number',
};

/** The second factors the sign-in under way can finish with, from the error that asked for the step. */
let factors: SecondFactor[] = [];
/** The number typed into the phone setup, for the setup after the current number agreed. */
let pendingPhone = '';

/** The address the e-mail went to, and what it was for; `app` for a sign-up with the authenticator app alone. */
let pending: { email: string; purpose: 'verify' | 'reset' | 'signin'; code?: string; app?: boolean } | undefined;
/** The recovery codes are on the screen: the login card stays although the user is signed in. */
let showingCodes = false;

// ui: 'custom' — this page shows its own screen, so madAuth's dialog never opens.
void Madauth.initialize({ providers: [new GoogleFedcm(), new GitHub(), new Password(), new Totp(), new EmailLink()], ui: 'custom' }).then((result) => {
  // The hint under "forgot password" names the providers the server offers (their users have no password); without any, it goes.
  const providers = (['google', 'github'] as const).filter((method) => !result.leftOut.includes(method)).map((method) => ({ google: 'Google', github: 'GitHub' })[method]);
  $('#provider-hint').textContent = `Signed up with ${providers.join(' or ')}? There is no password to reset: use that button instead.`;
  $('#provider-hint').hidden = !providers.length;
  // Opened from the link in a reset e-mail: ask for the new password right away.
  if (Madauth.password.pendingReset) show('reset');
  const policy = Madauth.password.policy;
  if (policy) $('#password-hint').textContent = `At least ${policy.minLength} characters.`;
  // The authenticator app on its own, and signing up with it, only when the server lets it.
  $('#go-totp').hidden = !Madauth.totp.policy?.signIn;
  $('#go-totp-signup').hidden = !Madauth.totp.policy?.signUp;
  // The e-mail link, only when the server offers it (its link is handled by initialize, like the confirmation links).
  $('#go-email-link').hidden = !Madauth.emailLink.policy;
  // A sign-in that goes on with a second step: after the redirect flow, or a link from an e-mail.
  const step = Madauth.totp.pendingStep;
  factors = step?.factors ?? [];
  if (step?.step === 'code') showTotpCode();
  if (step?.step === 'sms') void startSmsStep();
  if (step?.step === 'setup') void startSetup();
});
Madauth.onAuthStateChanged(handleAuthStateChanged);
Madauth.google.renderButton($('#google-button'), { onResult: report });
Madauth.github.renderButton($('#github-button'), { onResult: report });

function handleAuthStateChanged(user: MadauthUser | null): void {
  $('#login').hidden = !!user && !showingCodes;
  $('#account').hidden = !user;
  $('#user-name').textContent = user?.name ?? user?.email ?? '';
  $('#user-email').textContent = user?.email ?? '';
  // What admins attached to the user, e.g. { roles: ['admin'] }.
  $('#claims').hidden = !user?.claims;
  $('#claims').textContent = user?.claims ? JSON.stringify(user.claims, null, 2) : '';
  if (!user) show('signin');
  else {
    void refreshAuthenticator();
    void refreshPhone();
  }
}

function show(view: View, message = ''): void {
  for (const el of document.querySelectorAll<HTMLElement>('[data-view]')) el.hidden = el.dataset.view !== view;
  $('#title').textContent = titles[view];
  say(message);
}

function say(message: string, isError = false): void {
  const el = $('#message');
  el.hidden = !message;
  el.textContent = message;
  el.className = isError ? 'error' : '';
  el.setAttribute('role', isError ? 'alert' : 'status');
}

/**
 * Shows a failed result; returns whether it succeeded. A sign-in that goes on with the authenticator app
 * (`totp_required`, `totp_setup_required`) is not a failure: the next step is shown.
 */
function report(result: Result): boolean {
  if (result.isSuccess) return true;
  factors = result.error.factors ?? [];
  if (result.error.code === 'totp_required') showTotpCode();
  else if (result.error.code === 'sms_required') void startSmsStep();
  else if (result.error.code === 'totp_setup_required') void startSetup();
  else say(messageFor(result.error), true);
  return false;
}

/** The app's code step; the user can switch to the SMS when they have a phone as well. */
function showTotpCode(): void {
  show('totp-code');
  $('#use-sms').hidden = !factors.includes('sms');
}

function messageFor(error: MadauthError): string {
  switch (error.code) {
    case 'invalid_credentials':
      return 'E-mail or password is wrong.';
    case 'email_unverified':
      return 'Please confirm your e-mail address first. We sent you a new e-mail.';
    case 'code_invalid':
      return 'The code is wrong or has expired.';
    case 'codes_locked':
      return 'Too many wrong codes. Please ask for a new e-mail and use the link in it.';
    case 'invalid_phone':
      return 'Please enter a valid mobile number with the country code, e.g. +41 79 123 45 67.';
    case 'too_soon':
      return 'We sent a code less than a minute ago. Enter that one, or wait a minute for a new one.';
    case 'no_phone':
      return 'No phone number is set up.';
    case 'link_invalid':
      return 'The link has expired. Please ask for a new e-mail.';
    case 'temporarily_unavailable':
      return 'Sending e-mails is not available right now. Please try again later.';
    case 'challenge_expired':
      return 'The sign-in took too long. Please sign in again.';
    case 'setup_expired':
      return 'The setup took too long. Please start again.';
    case 'other_method':
      return `This e-mail address signs in with ${(error.methods ?? []).join(' or ') || 'another method'}. Use that instead.`;
    // signup_rejected: the message comes from your sign-up check and is shown as it is.
    default:
      return error.message;
  }
}

function fields(form: HTMLFormElement): Record<string, string> {
  return Object.fromEntries([...new FormData(form)].map(([k, v]) => [k, String(v)]));
}

/** A 6-digit code from the app, or a recovery code (two groups with a dash), as the API takes them. */
function codeOptions(value: string): { code: string } | { recoveryCode: string } {
  return value.includes('-') ? { recoveryCode: value.trim() } : { code: value.replace(/\s/g, '') };
}

/** Handles a form's submit with the inputs as an object, with its button disabled meanwhile. */
function onSubmit(selector: string, handler: (values: Record<string, string>) => Promise<void>): void {
  const form = $<HTMLFormElement>(selector);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const button = form.querySelector('button')!;
    button.disabled = true;
    try {
      await handler(fields(form));
    } finally {
      button.disabled = false;
    }
  });
}

function checkInbox(email: string, purpose: 'verify' | 'reset' | 'signin', app = false): void {
  pending = { email, purpose, app };
  $('#code-email').textContent = email;
  show('code');
}

onSubmit('#signin-form', async ({ email, password }) => {
  const result = await Madauth.password.signIn({ email, password });
  if (!result.isSuccess && result.error.code === 'email_unverified') {
    await Madauth.password.sendVerificationEmail({ email });
    checkInbox(email, 'verify');
  }
  report(result);
});

onSubmit('#signup-form', async ({ name, email, password }) => {
  if (report(await Madauth.password.signUp({ email, password, name: name || undefined }))) checkInbox(email, 'verify');
});

onSubmit('#forgot-form', async ({ email }) => {
  if (report(await Madauth.password.sendResetEmail({ email }))) checkInbox(email, 'reset');
});

onSubmit('#code-form', async ({ code }) => {
  if (!pending) return;
  if (pending.purpose === 'reset') {
    // The reset code is sent together with the new password.
    pending.code = code;
    show('reset');
    return;
  }
  if (pending.purpose === 'signin') {
    report(await Madauth.emailLink.verify({ email: pending.email, code }));
    return;
  }
  // The same confirmation for both sign-ups; one with the app alone goes on with its setup.
  const scope = pending.app ? Madauth.totp : Madauth.password;
  report(await scope.verifyEmail({ email: pending.email, code }));
});

onSubmit('#reset-form', async ({ password }) => {
  const result = pending?.code
    ? await Madauth.password.confirmReset({ newPassword: password, email: pending.email, code: pending.code })
    : await Madauth.password.confirmReset({ newPassword: password });
  report(result);
});

// --- The e-mail link ---

onSubmit('#email-link-form', async ({ email }) => {
  if (report(await Madauth.emailLink.send({ email }))) checkInbox(email, 'signin');
});

// --- The authenticator app ---

onSubmit('#totp-form', async ({ email, code }) => {
  report(await Madauth.totp.signIn({ email, ...codeOptions(code) }));
});

onSubmit('#totp-signup-form', async ({ name, email }) => {
  if (report(await Madauth.totp.signUp({ email, name: name || undefined }))) checkInbox(email, 'verify', true);
});

onSubmit('#totp-code-form', async ({ code }) => {
  const result = await Madauth.totp.verify(codeOptions(code));
  // Too late: the sign-in starts over.
  if (!result.isSuccess && result.error.code === 'challenge_expired') show('signin', messageFor(result.error));
  else report(result);
});

/** Asks the server for a new key and shows it as a QR code (an SVG from the library) and as text. */
async function startSetup(): Promise<void> {
  show('totp-setup');
  // During a sign-in, a phone can be added instead of the app when the server has SMS codes on; a sign-up
  // with the app sets the app up, never a phone.
  const pending = Madauth.totp.pendingStep;
  $('#use-phone').hidden = !(pending?.step === 'setup' && pending.method !== 'totp' && Madauth.sms.available);
  $('#qr').innerHTML = '';
  $('#secret').textContent = '';
  let result = await Madauth.totp.startSetup();
  // An app exists already: the current one has to agree to being replaced.
  if (!result.isSuccess && result.error.code === 'code_required') {
    const code = prompt('A current code from your authenticator app, or a recovery code, to replace it:');
    if (!code) {
      $('#login').hidden = !!Madauth.currentUser;
      show('signin');
      return;
    }
    result = await Madauth.totp.startSetup(codeOptions(code));
  }
  if (!result.isSuccess) {
    report(result);
    return;
  }
  $('#qr').innerHTML = result.qrSvg;
  $('#secret').textContent = result.secret;
  $<HTMLInputElement>('#totp-setup-form input').focus();
}

onSubmit('#totp-setup-form', async ({ code }) => {
  const result = await Madauth.totp.confirmSetup({ code: code.replace(/\s/g, '') });
  if (!result.isSuccess) {
    // The key on the screen is of no use any more.
    if (result.error.code === 'setup_expired') $('#qr').innerHTML = '';
    report(result);
    return;
  }
  // The codes are shown once; a setup that finished a sign-in has signed the user in meanwhile.
  showingCodes = true;
  $('#recovery-codes').replaceChildren(
    ...result.recoveryCodes.map((code) => {
      const li = document.createElement('li');
      li.textContent = code;
      return li;
    }),
  );
  $('#login').hidden = false;
  show('totp-codes');
});

$('#codes-saved').addEventListener('click', () => {
  showingCodes = false;
  $('#recovery-codes').replaceChildren();
  $('#login').hidden = !!Madauth.currentUser;
  show('signin');
  void refreshAuthenticator();
});

$('#totp-setup-cancel').addEventListener('click', () => {
  $('#login').hidden = !!Madauth.currentUser;
  show('signin');
});

// --- SMS codes as a second factor ---

/** The SMS step: asks the server for the code, and shows where it went. */
async function startSmsStep(): Promise<void> {
  show('sms-code');
  $('#sms-phone').textContent = '…';
  $('#use-app').hidden = !factors.includes('totp');
  const sent = await Madauth.sms.send();
  if (sent.isSuccess) $('#sms-phone').textContent = sent.phone;
  else say(messageFor(sent.error), true);
}

$('#sms-resend').addEventListener('click', () => void startSmsStep());
$('#use-sms').addEventListener('click', () => void startSmsStep());
$('#use-app').addEventListener('click', () => showTotpCode());
$('#use-phone').addEventListener('click', () => show('sms-setup'));

onSubmit('#sms-code-form', async ({ code }) => {
  const result = await Madauth.sms.verify({ code: code.replace(/\s/g, '') });
  if (!result.isSuccess && result.error.code === 'challenge_expired') show('signin', messageFor(result.error));
  else report(result);
});

/** Starts adding a number: the code goes to it; a user who has one approves with a code sent to the current number first. */
async function startSmsSetup(phone: string): Promise<void> {
  pendingPhone = phone;
  let result = await Madauth.sms.setUp({ phone });
  if (!result.isSuccess && result.error.code === 'code_required') {
    const sent = await Madauth.sms.send();
    if (!sent.isSuccess) {
      report(sent);
      return;
    }
    const code = prompt(`The code we sent to ${sent.phone}, your current number, to replace it:`);
    if (!code) return;
    result = await Madauth.sms.setUp({ phone, code: code.replace(/\s/g, '') });
  }
  if (!result.isSuccess) {
    report(result);
    return;
  }
  $('#sms-setup-phone').textContent = result.phone;
  show('sms-setup-code');
  $<HTMLInputElement>('#sms-setup-code-form input').focus();
}

onSubmit('#sms-setup-form', ({ phone }) => startSmsSetup(phone));

onSubmit('#sms-setup-code-form', async ({ code }) => {
  const result = await Madauth.sms.confirmSetup({ code: code.replace(/\s/g, '') });
  if (!result.isSuccess) {
    if (result.error.code === 'setup_expired') void startSmsSetup(pendingPhone);
    report(result);
    return;
  }
  // A setup that finished a sign-in has signed the user in meanwhile; otherwise back to the account.
  $('#login').hidden = !!Madauth.currentUser;
  show('signin');
  void refreshPhone();
});

for (const id of ['#sms-setup-cancel', '#sms-setup-cancel-code']) {
  $(id).addEventListener('click', () => {
    $('#login').hidden = !!Madauth.currentUser;
    show('signin');
  });
}

/** Shows whether the signed-in user has a phone number, and the buttons that apply. */
async function refreshPhone(): Promise<void> {
  const status = await Madauth.sms.status();
  const offered = status.isSuccess || status.error.code !== 'flow_not_enabled';
  $('#sms-status').textContent = !status.isSuccess
    ? status.error.code === 'flow_not_enabled'
      ? 'SMS codes are not offered by this server.'
      : status.error.message
    : status.enabled
      ? `Phone: ${status.phone}.`
      : 'Phone: none.';
  $('#sms-setup').hidden = !offered;
  $('#sms-setup').textContent = status.isSuccess && status.enabled ? 'Replace the phone number' : 'Add a phone number';
  $('#sms-remove').hidden = !(status.isSuccess && status.enabled);
}

// The signed-in user adds the number in the login card's setup view, shown next to the account.
$('#sms-setup').addEventListener('click', () => {
  $('#login').hidden = false;
  show('sms-setup');
});

$('#sms-remove').addEventListener('click', async () => {
  const sent = await Madauth.sms.send();
  if (!sent.isSuccess) {
    alert(messageFor(sent.error));
    return;
  }
  const code = prompt(`The code we sent to ${sent.phone}:`);
  if (!code) return;
  const result = await Madauth.sms.remove({ code: code.replace(/\s/g, '') });
  if (!result.isSuccess) alert(messageFor(result.error));
  void refreshPhone();
});

/** Shows whether the signed-in user has the app, and the buttons that apply. */
async function refreshAuthenticator(): Promise<void> {
  const status = await Madauth.totp.status();
  const offered = status.isSuccess || status.error.code !== 'flow_not_enabled';
  $('#totp-status').textContent = !status.isSuccess
    ? status.error.code === 'flow_not_enabled'
      ? 'The authenticator app is not offered by this server.'
      : status.error.message
    : status.enabled
      ? `Authenticator app: set up, ${status.recoveryCodesLeft} recovery codes left.`
      : 'Authenticator app: not set up.';
  $('#totp-setup').hidden = !offered;
  $('#totp-remove').hidden = !(status.isSuccess && status.enabled);
}

// The signed-in user sets the app up in the login card's setup view, shown next to the account.
$('#totp-setup').addEventListener('click', () => {
  $('#login').hidden = false;
  void startSetup();
});

$('#totp-remove').addEventListener('click', async () => {
  const code = prompt('A current code from your authenticator app, or a recovery code:');
  if (!code) return;
  const result = await Madauth.totp.remove(codeOptions(code));
  if (!result.isSuccess) alert(messageFor(result.error));
  void refreshAuthenticator();
});

for (const button of document.querySelectorAll<HTMLButtonElement>('[data-go]')) {
  button.addEventListener('click', () => show(button.dataset.go as View));
}
$('#sign-out').addEventListener('click', () => void Madauth.signOut());
