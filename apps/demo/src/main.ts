import '@madauth/web';

const login = document.querySelector('madauth-login')!;

document.querySelector('#sign-in')!.addEventListener('click', () => login.open());

login.addEventListener('madauth-signed-in', (e) => {
  console.log('Signed in', e.detail);
});

login.addEventListener('madauth-cancel', () => {
  console.log('Sign-in cancelled');
});
