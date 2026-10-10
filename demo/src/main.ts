import { GoogleFedcm, GoogleRedirect, Madauth, Password, type MadauthUser, type Settings } from '@madauth/web';

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
$('[data-hosted]').hidden = !location.hostname.endsWith('madauth.com');

// No serverUrl: Vite proxies /auth to the madAuth server, so it is on this page's origin.
void Madauth.initialize({ providers: [google, new Password()] }).then((result) => {
  // The server offers the redirect flow only with a client secret (and Google switched on); otherwise
  // initialize left GoogleRedirect out and the dialog has no Google button.
  if (flow === 'redirect' && result.isSuccess && result.leftOut.includes('google')) $('#flow-note').hidden = false;
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

  const email = $<HTMLInputElement>('#claims-email');
  if (!user) {
    // Nothing of the previous user stays on the page: the admin fields, the last result, the settings.
    email.value = '';
    $('#output').hidden = true;
    $('#output').textContent = '';
    settingsLoadedFor = undefined;
    showSettings(null);
    return;
  }
  if (!email.value) email.value = user.email ?? '';
  $('#admin-note').hidden = isAdmin(user);
  // An admin sees the server's settings in the checkboxes before they can send them back.
  if (isAdmin(user) && settingsLoadedFor !== user.id) {
    settingsLoadedFor = user.id;
    void Madauth.admin.getSettings().then(showSettings);
  }
}

const isAdmin = (user: MadauthUser) => Array.isArray(user.claims?.roles) && user.claims.roles.includes('admin');

// --- The rest of the API a signed-in user can call. Each button shows what the call resolved to. ---

const output = $('#output');
const claimsEmail = () => $<HTMLInputElement>('#claims-email').value.trim();
const methodBox = (method: 'google' | 'password') => $<HTMLInputElement>(`#method-${method}`);
/** The user whose sign-in loaded the settings, so a claims change (which also notifies) doesn't load them again. */
let settingsLoadedFor: string | undefined;

/**
 * Shows the server's settings in the checkboxes and lets them be sent back; until then (or with null) the
 * boxes are empty and setSettings is off, so the page never sends defaults the server doesn't have. A method
 * the server is not configured for can't be switched on.
 */
function showSettings<T extends Awaited<ReturnType<typeof Madauth.admin.getSettings>> | null>(result: T): T {
  const methods: Settings['methods'] | undefined = result?.isSuccess ? result.methods : undefined;
  for (const method of ['google', 'password'] as const) {
    methodBox(method).checked = methods?.[method].enabled ?? false;
    methodBox(method).disabled = !methods?.[method].available;
  }
  $<HTMLButtonElement>('[data-call="setSettings"]').disabled = !methods;
  return result;
}

const calls: Record<string, () => Promise<unknown>> = {
  getSession: () => Madauth.getSession(),
  sessionReady: () => Madauth.sessionReady(),
  // One click would be too easy on a public demo: the user, their claims and their sign-in methods go for good.
  deleteAccount: async () =>
    confirm('Delete your account on this madAuth server? Your user, claims and sign-in methods are deleted for good.')
      ? Madauth.deleteAccount()
      : 'Cancelled.',
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
      .setSettings({ methods: { google: methodBox('google').checked, password: methodBox('password').checked } })
      .then(showSettings),
};

for (const button of document.querySelectorAll<HTMLButtonElement>('[data-call]')) {
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      const result = await calls[button.dataset.call!]();
      output.hidden = false;
      output.textContent = `${button.textContent}\n${typeof result === 'string' ? result : JSON.stringify(result, null, 2)}`;
    } finally {
      // setSettings stays off until the settings were loaded (showSettings decides).
      if (button.dataset.call !== 'setSettings') button.disabled = false;
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
