import { GoogleFedcm, GoogleRedirect, Madauth, Password, Totp, type MadauthUser, type MethodsToSet, type Settings } from '@madauth/web';

const $ = <T extends HTMLElement = HTMLElement>(selector: string) => document.querySelector<T>(selector)!;

// --- Two demos: Google sign-in in the browser (One Tap / FedCM), or through the server (the redirect flow) ---

// `?google=redirect` picks the server-side flow; the links in #flow switch between the two. The redirect
// brings the browser back to this URL, so the choice survives it.
const flow = new URLSearchParams(location.search).get('google') === 'redirect' ? 'redirect' : 'fedcm';

for (const link of document.querySelectorAll<HTMLAnchorElement>('#flow a')) {
  if (link.dataset.flow === flow) link.setAttribute('aria-current', 'page');
}
for (const description of document.querySelectorAll<HTMLElement>('.flow-description')) {
  description.hidden = description.dataset.flow !== flow;
}

const google = flow === 'redirect' ? new GoogleRedirect() : new GoogleFedcm();

// The public demo gives nobody the role admin: an admin could change every visitor's claims and switch
// sign-in methods off for everyone. Visitors are told so, and how to try the admin API on their machine.
const { hostname } = location;
$('[data-hosted]').hidden = !(hostname === 'madauth.com' || hostname.endsWith('.madauth.com'));

// No serverUrl: Vite proxies /auth to the madAuth server, so it is on this page's origin. The authenticator
// app is left out when the server has it switched off (no policy asks for it, and it signs in nobody alone).
void Madauth.initialize({ providers: [google, new Password(), new Totp()] }).then((result) => {
  // The server offers the redirect flow only with a client secret (and Google switched on); otherwise
  // initialize left GoogleRedirect out and the dialog has no Google button.
  if (flow === 'redirect' && result.leftOut.includes('google')) $('#flow-note').hidden = false;
});
Madauth.onAuthStateChanged(handleAuthStateChanged);

$('#sign-in').addEventListener('click', () => void Madauth.signIn());
$('#sign-out').addEventListener('click', () => void Madauth.signOut());

function handleAuthStateChanged(user: MadauthUser | null): void {
  $('#sign-in').hidden = !!user;
  $('#account').hidden = !user;
  $('#api').hidden = !user;
  $('#user-name').textContent = user?.name ?? user?.id ?? '';
  $('#user-email').textContent = user?.email ?? '';
  const avatar = $<HTMLImageElement>('#avatar');
  avatar.hidden = !user?.picture;
  if (user?.picture) avatar.src = user.picture;
  // What admins attached to the user, e.g. { roles: ['admin'] }; the session token carries it to your backends too.
  $('#claims').textContent = user?.claims ? JSON.stringify(user.claims, null, 2) : 'none';
  // How the session was authenticated, e.g. pwd and otp: a backend can ask for otp before a sensitive action.
  $('#amr').textContent = user?.amr?.join(', ') ?? '';

  const email = $<HTMLInputElement>('#claims-email');
  if (!user) {
    // Nothing of the previous user stays on the page: the admin fields, the last result, the settings.
    email.value = '';
    $('#output').hidden = true;
    $('#output').textContent = '';
    $<HTMLInputElement>('#totp-code').value = '';
    settingsLoadedFor = undefined;
    showSettings(null);
    return;
  }
  if (!email.value) email.value = user.email ?? '';
  $('#admin-note').hidden = isAdmin(user);
  void refreshAuthenticator();
  // An admin sees the server's settings in the controls before they can send them back.
  if (isAdmin(user) && settingsLoadedFor !== user.id) {
    settingsLoadedFor = user.id;
    void Madauth.admin.getSettings().then((result) => {
      // Not if they signed out meanwhile: the next user must not see them.
      if (Madauth.currentUser?.id === user.id) showSettings(result);
    });
  }
}

const isAdmin = (user: MadauthUser) => Array.isArray(user.claims?.roles) && user.claims.roles.includes('admin');

// --- The authenticator app of the signed-in user ---

/** Whether the signed-in user has the app; decides which buttons make sense, and whether deleting the account takes a code. */
let authenticatorOn = false;

/** Shows whether the user has the app, and the buttons that apply. */
async function refreshAuthenticator(): Promise<void> {
  const user = Madauth.currentUser;
  const status = await Madauth.totp.status();
  if (Madauth.currentUser?.id !== user?.id) return;
  authenticatorOn = status.isSuccess && status.enabled;
  const offered = status.isSuccess || status.error.code !== 'flow_not_enabled';
  $('#totp-status').textContent = !status.isSuccess
    ? status.error.code === 'flow_not_enabled'
      ? 'Not offered by this madAuth server: no sign-in method asks for it, and it signs in nobody on its own.'
      : status.error.message
    : status.enabled
      ? `Set up, ${status.recoveryCodesLeft} recovery codes left.`
      : 'Not set up.';
  $('.authenticator .code-field').hidden = !authenticatorOn;
  $('[data-call="setUpAuthenticator"]').hidden = !offered;
  $('[data-call="newRecoveryCodes"]').hidden = !authenticatorOn;
  $('[data-call="removeAuthenticator"]').hidden = !authenticatorOn;
}

/** The code typed next to the buttons: a 6-digit code from the app, or a recovery code (with a dash). */
function codeOptions(): { code: string } | { recoveryCode: string } {
  const value = $<HTMLInputElement>('#totp-code').value.trim();
  return value.includes('-') || value.length > 7 ? { recoveryCode: value } : { code: value.replace(/\s/g, '') };
}

// --- The rest of the API a signed-in user can call. Each button shows what the call resolved to. ---

const output = $('#output');
const claimsEmail = () => $<HTMLInputElement>('#claims-email').value.trim();
const methodBox = (method: 'google' | 'password' | 'totp') => $<HTMLInputElement>(`#method-${method}`);
const policySelect = (method: 'google' | 'password') => $<HTMLSelectElement>(`#policy-${method}`);
/** The user whose sign-in loaded the settings, so a claims change (which also notifies) doesn't load them again. */
let settingsLoadedFor: string | undefined;
/** Whether the controls show the server's settings; only then may setSettings send them. */
let settingsLoaded = false;

/**
 * Shows the server's settings in the controls and lets them be sent back; until then (or with null) the
 * controls are empty and setSettings is off, so the page never sends defaults the server doesn't have. A
 * method the server is not configured for can't be switched on.
 */
function showSettings<T extends Awaited<ReturnType<typeof Madauth.admin.getSettings>> | null>(result: T): T {
  const methods: Settings['methods'] | undefined = result?.isSuccess ? result.methods : undefined;
  for (const method of ['google', 'password', 'totp'] as const) {
    methodBox(method).checked = methods?.[method].enabled ?? false;
    methodBox(method).disabled = !methods?.[method].configured;
  }
  for (const method of ['google', 'password'] as const) {
    policySelect(method).value = methods?.[method].secondFactor ?? 'none';
    policySelect(method).disabled = !methods?.[method].configured;
  }
  settingsLoaded = !!methods;
  $<HTMLButtonElement>('[data-call="setSettings"]').disabled = !settingsLoaded;
  return result;
}

/** The list to send: what is checked is on, with the policy next to it; the rest is off. */
function methodsToSet(): MethodsToSet {
  const policy = (method: 'google' | 'password') => ({ secondFactor: policySelect(method).value as 'none' | 'optional' | 'required' });
  return {
    google: methodBox('google').checked ? policy('google') : false,
    password: methodBox('password').checked ? policy('password') : false,
    totp: methodBox('totp').checked,
  };
}

const calls: Record<string, () => Promise<unknown>> = {
  getSession: () => Madauth.getSession(),
  sessionReady: () => Madauth.sessionReady(),
  // One click would be too easy on a public demo: the user, their claims and their sign-in methods go for good.
  // Once the authenticator app is set up, the server also wants a current code from it.
  deleteAccount: async () =>
    confirm('Delete your account on this madAuth server? Your user, claims and sign-in methods are deleted for good.')
      ? Madauth.deleteAccount(authenticatorOn ? codeOptions() : undefined)
      : 'Cancelled.',
  // The dialog shows the QR code, asks for the first code and shows the recovery codes.
  setUpAuthenticator: () => Madauth.setUpAuthenticator().then(async (result) => (await refreshAuthenticator(), result)),
  newRecoveryCodes: () => Madauth.totp.newRecoveryCodes(codeOptions()).then(async (result) => (await refreshAuthenticator(), result)),
  removeAuthenticator: () => Madauth.totp.remove(codeOptions()).then(async (result) => (await refreshAuthenticator(), result)),
  getClaims: () => Madauth.admin.getClaims(claimsEmail()),
  setClaims: async () => {
    let claims: unknown;
    try {
      claims = JSON.parse($<HTMLTextAreaElement>('#claims-json').value);
    } catch {
      return 'The claims must be JSON, e.g. { "roles": ["admin"] }.';
    }
    // Anything but an object of claims is answered by the server with invalid_claims.
    return Madauth.admin.setClaims(claimsEmail(), claims as Record<string, unknown>);
  },
  getSettings: () => Madauth.admin.getSettings().then(showSettings),
  setSettings: () =>
    Madauth.admin
      .setSettings({ methods: methodsToSet() })
      // A refused change (e.g. every method switched off) leaves the controls as the user set them.
      .then((result) => (result.isSuccess ? showSettings(result) : result)),
};

for (const button of document.querySelectorAll<HTMLButtonElement>('[data-call]')) {
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      const result = await calls[button.dataset.call!]();
      output.hidden = false;
      output.textContent = `${button.textContent}\n${typeof result === 'string' ? result : JSON.stringify(result, null, 2)}`;
    } finally {
      // setSettings stays off until the settings were loaded.
      button.disabled = button.dataset.call === 'setSettings' && !settingsLoaded;
    }
  });
}

// --- Theme ---

type Theme = 'light' | 'dark';

const themeToggle = $<HTMLButtonElement>('#theme-toggle');

function setTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  themeToggle.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`);
}

// Start with the system preference; the button then overrides it for this page.
setTheme(matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

themeToggle.addEventListener('click', () => {
  setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
});
