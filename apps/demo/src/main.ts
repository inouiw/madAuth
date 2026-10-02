import '@madauth/web';

const login = document.querySelector('madauth-login')!;

document.querySelector('#sign-in')!.addEventListener('click', () => login.open());

login.addEventListener('madauth-signed-in', (e) => {
  console.log('Signed in', e.detail);
});

login.addEventListener('madauth-cancel', () => {
  console.log('Sign-in cancelled');
});

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
