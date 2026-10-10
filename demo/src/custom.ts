// A custom login screen: everything madAuth's dialog does, built with the headless API.
import { GoogleFedcm, Madauth, Password, Totp, type MadauthError, type MadauthUser, type Result } from '@madauth/web';

type View = 'signin' | 'signup' | 'forgot' | 'code' | 'reset' | 'totp' | 'totp-signup' | 'totp-code' | 'totp-setup' | 'totp-codes';

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
};

/** The address the e-mail went to, and what it was for; `app` for a sign-up with the authenticator app alone. */
let pending: { email: string; purpose: 'verify' | 'reset'; code?: string; app?: boolean } | undefined;
/** The recovery codes are on the screen: the login card stays although the user is signed in. */
let showingCodes = false;

// ui: 'custom' — this page shows its own screen, so madAuth's dialog never opens.
void Madauth.initialize({ providers: [new GoogleFedcm(), new Password(), new Totp()], ui: 'custom' }).then((result) => {
  // Without Google on the server there is no Google button, so the hint about it goes.
  $('#google-hint').hidden = result.leftOut.includes('google');
  // Opened from the link in a reset e-mail: ask for the new password right away.
  if (Madauth.password.pendingReset) show('reset');
  const policy = Madauth.password.policy;
  if (policy) $('#password-hint').textContent = `At least ${policy.minLength} characters.`;
  // The authenticator app on its own, and signing up with it, only when the server lets it.
  $('#go-totp').hidden = !Madauth.totp.policy?.signIn;
  $('#go-totp-signup').hidden = !Madauth.totp.policy?.signUp;
  // A sign-in that goes on with the app: after the redirect flow, or the link of a sign-up with the app.
  const step = Madauth.totp.pendingStep;
  if (step?.step === 'code') show('totp-code');
  if (step?.step === 'setup') void startSetup();
});
Madauth.onAuthStateChanged(handleAuthStateChanged);
Madauth.google.renderButton($('#google-button'), { onResult: report });

function handleAuthStateChanged(user: MadauthUser | null): void {
  $('#login').hidden = !!user && !showingCodes;
  $('#account').hidden = !user;
  $('#user-name').textContent = user?.name ?? user?.email ?? '';
  $('#user-email').textContent = user?.email ?? '';
  // What admins attached to the user, e.g. { roles: ['admin'] }.
  $('#claims').hidden = !user?.claims;
  $('#claims').textContent = user?.claims ? JSON.stringify(user.claims, null, 2) : '';
  if (!user) show('signin');
  else void refreshAuthenticator();
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
  if (result.error.code === 'totp_required') show('totp-code');
  else if (result.error.code === 'totp_setup_required') void startSetup();
  else say(messageFor(result.error), true);
  return false;
}

function messageFor(error: MadauthError): string {
  switch (error.code) {
    case 'invalid_credentials':
      return 'E-mail or password is wrong.';
    case 'email_unverified':
      return 'Please confirm your e-mail address first. We sent you a new e-mail.';
    case 'code_invalid':
      return 'The code is wrong or has expired.';
    case 'link_invalid':
      return 'The link has expired. Please ask for a new e-mail.';
    case 'temporarily_unavailable':
      return 'Sending e-mails is not available right now. Please try again later.';
    case 'challenge_expired':
      return 'The sign-in took too long. Please sign in again.';
    case 'setup_expired':
      return 'The setup took too long. Please start again.';
    case 'other_method':
      return `This e-mail address signs in with ${(error.methods ?? []).join(' or ') || 'another method'}. Use that instead of Google.`;
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

function checkInbox(email: string, purpose: 'verify' | 'reset', app = false): void {
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
  $('#qr').innerHTML = '';
  $('#secret').textContent = '';
  const result = await Madauth.totp.startSetup();
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
