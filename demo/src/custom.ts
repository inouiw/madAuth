// A custom login screen: everything madAuth's dialog does, built with the headless API.
import { GoogleFedcm, Madauth, Password, type MadauthError, type MadauthUser, type Result } from '@madauth/web';

type View = 'signin' | 'signup' | 'forgot' | 'code' | 'reset';

const $ = <T extends HTMLElement = HTMLElement>(selector: string) => document.querySelector<T>(selector)!;

const titles: Record<View, string> = {
  signin: 'Sign in',
  signup: 'Create account',
  forgot: 'Reset password',
  code: 'Check your inbox',
  reset: 'Choose a new password',
};

/** The address the e-mail went to, and what it was for. */
let pending: { email: string; purpose: 'verify' | 'reset'; code?: string } | undefined;

// ui: 'custom' — this page shows its own screen, so madAuth's dialog never opens.
void Madauth.initialize({ providers: [new GoogleFedcm(), new Password()], ui: 'custom' }).then(() => {
  // Opened from the link in a reset e-mail: ask for the new password right away.
  if (Madauth.password.pendingReset) show('reset');
  const policy = Madauth.password.policy;
  if (policy) $('#password-hint').textContent = `At least ${policy.minLength} characters.`;
});
Madauth.onAuthStateChanged(handleAuthStateChanged);
Madauth.google.renderButton($('#google-button'), { onResult: report });

function handleAuthStateChanged(user: MadauthUser | null): void {
  $('#login').hidden = !!user;
  $('#account').hidden = !user;
  $('#user-name').textContent = user?.name ?? user?.email ?? '';
  $('#user-email').textContent = user?.email ?? '';
  // What admins attached to the user, e.g. { roles: ['admin'] }.
  $('#claims').hidden = !user?.claims;
  $('#claims').textContent = user?.claims ? JSON.stringify(user.claims, null, 2) : '';
  if (!user) show('signin');
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

/** Shows a failed result; returns whether it succeeded. */
function report(result: Result): boolean {
  if (!result.isSuccess) say(messageFor(result.error), true);
  return result.isSuccess;
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
    // signup_rejected: the message comes from your sign-up check and is shown as it is.
    default:
      return error.message;
  }
}

function fields(form: HTMLFormElement): Record<string, string> {
  return Object.fromEntries([...new FormData(form)].map(([k, v]) => [k, String(v)]));
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

function checkInbox(email: string, purpose: 'verify' | 'reset'): void {
  pending = { email, purpose };
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
  report(await Madauth.password.verifyEmail({ email: pending.email, code }));
});

onSubmit('#reset-form', async ({ password }) => {
  const result = pending?.code
    ? await Madauth.password.confirmReset({ newPassword: password, email: pending.email, code: pending.code })
    : await Madauth.password.confirmReset({ newPassword: password });
  report(result);
});

for (const button of document.querySelectorAll<HTMLButtonElement>('[data-go]')) {
  button.addEventListener('click', () => show(button.dataset.go as View));
}
$('#sign-out').addEventListener('click', () => void Madauth.signOut());
