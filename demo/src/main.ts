import { GoogleFedcm, GoogleRedirect, Madauth, Password, type MadauthUser } from '@madauth/web';

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

// No serverUrl: Vite proxies /auth to the madAuth server, so it is on this page's origin.
void Madauth.initialize({ providers: [google, new Password()] }).then(() => void checkRedirectFlow());
Madauth.onAuthStateChanged(handleAuthStateChanged);

/** The redirect flow needs GOOGLE_CLIENT_SECRET on the server; without it, initialize left GoogleRedirect out. */
async function checkRedirectFlow(): Promise<void> {
  if (flow !== 'redirect') return;
  const config = (await fetch('/auth/config')
    .then((res) => res.json())
    .catch(() => null)) as { google: { codeFlow: boolean } | null } | null;
  $('#flow-note').hidden = !!config?.google?.codeFlow;
}

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
  if (user?.email && !email.value) email.value = user.email;
}

// --- The rest of the API a signed-in user can call. Each button shows what the call resolved to. ---

const output = $('#output');
const claimsEmail = () => $<HTMLInputElement>('#claims-email').value.trim();
const methodBox = (method: 'google' | 'password') => $<HTMLInputElement>(`#method-${method}`);

/** Shows the server's settings in the checkboxes: a method the server is not configured for can't be switched on. */
function showSettings<T extends Awaited<ReturnType<typeof Madauth.admin.getSettings>>>(result: T): T {
  if (result.isSuccess) {
    for (const method of ['google', 'password'] as const) {
      methodBox(method).checked = result.methods[method].enabled;
      methodBox(method).disabled = !result.methods[method].available;
    }
  }
  return result;
}

const calls: Record<string, () => Promise<unknown>> = {
  getSession: () => Madauth.getSession(),
  sessionReady: () => Madauth.sessionReady(),
  deleteAccount: () => Madauth.deleteAccount(),
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
      button.disabled = false;
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
