import { GoogleFedcm, GoogleRedirect, Madauth, Password, type MadauthUser } from '@madauth/web';

// VITE_GOOGLE_FLOW=redirect uses the server-side flow (needs GOOGLE_CLIENT_SECRET on the server).
const google = import.meta.env.VITE_GOOGLE_FLOW === 'redirect' ? new GoogleRedirect() : new GoogleFedcm();

// No serverUrl: Vite proxies /auth to the madAuth server, so it is on this page's origin.
void Madauth.initialize({ providers: [google, new Password()] });
Madauth.onAuthStateChanged(handleAuthStateChanged);

document.querySelector('#sign-in')!.addEventListener('click', () => void Madauth.signIn());
document.querySelector('#sign-out')!.addEventListener('click', () => void Madauth.signOut());

function handleAuthStateChanged(user: MadauthUser | null): void {
  document.querySelector<HTMLElement>('#sign-in')!.hidden = !!user;
  document.querySelector<HTMLElement>('#account')!.hidden = !user;
  document.querySelector('#user-name')!.textContent = user?.name ?? user?.id ?? '';
  document.querySelector('#user-email')!.textContent = user?.email ?? '';
  const avatar = document.querySelector<HTMLImageElement>('#avatar')!;
  avatar.hidden = !user?.picture;
  if (user?.picture) avatar.src = user.picture;
}

type Theme = 'light' | 'dark';

const themeToggle = document.querySelector<HTMLButtonElement>('#theme-toggle')!;

function setTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  themeToggle.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`);
}

// Start with the system preference; the button then overrides it for this page.
setTheme(matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

themeToggle.addEventListener('click', () => {
  setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
});
