# @madauth/web

The browser side of [madAuth](https://github.com/inouiw/madAuth), a self-hostable alternative to Cognito / Auth0: a sign-in client and a sign-in dialog as framework-agnostic web components. It works in plain HTML, React, Angular, Vue, Svelte and Capacitor apps.

It talks to a running madAuth server, see [`@madauth/server`](https://www.npmjs.com/package/@madauth/server).

## Install

```bash
npm install @madauth/web
```

## Usage

```ts
import { Madauth, GoogleFedcm, Password, Totp } from '@madauth/web';

Madauth.initialize({ providers: [new GoogleFedcm(), new Password(), new Totp()] });
Madauth.onAuthStateChanged(handleAuthStateChanged); // (user | null) => void
signInButton.onclick = () => Madauth.signIn();
```

The server is expected on the page's own origin (`/auth/...`). Pass `serverUrl: 'https://auth.example.com'` to `initialize` if it runs elsewhere on the same site.

## Documentation

- [Using madAuth in your app](https://github.com/inouiw/madAuth#using-madauth-in-your-app)
- [Building your own login screen](https://github.com/inouiw/madAuth/blob/main/docs/custom-ui.md)
- [Styling the login form](https://github.com/inouiw/madAuth/blob/main/docs/styling.md)

## License

MIT
