# @madauth/web

The browser side of [madAuth](https://github.com/inouiw/madAuth), a self-hostable alternative to Cognito / Auth0: a sign-in client and a sign-in dialog as framework-agnostic web components, for Google, GitHub, OpenID Connect providers, e-mail & password, e-mail links, passkeys, the authenticator app and SMS codes. It works in plain HTML, React, Angular, Vue, Svelte and Capacitor apps, and adds about 53 kB (gzipped) to your app with the dialog and every method, Lit included.

It talks to a running madAuth server, see [`@madauth/server`](https://www.npmjs.com/package/@madauth/server).

## Install

```bash
npm install @madauth/web
```

## Usage

```ts
import { Madauth, GoogleFedcm, GitHub, Password, Passkey, Authenticator, EmailLink } from '@madauth/web';

Madauth.initialize({ providers: [new GoogleFedcm(), new GitHub(), new Password(), new Passkey(), new Authenticator(), new EmailLink()] });
Madauth.onAuthStateChanged(handleAuthStateChanged); // (user | null) => void
signInButton.onclick = () => Madauth.showSignInDialog();
```

The server is expected on the page's own origin (`/auth/...`). Pass `serverUrl: 'https://auth.example.com'` to `initialize` if it runs elsewhere on the same site.

## Without the dialog

An app with a login screen of its own imports from `@madauth/web/client`: the same `Madauth` and providers, without the dialog. Neither the dialog nor Lit, which only the dialog uses, ends up in your bundle: about 18 kB gzipped instead of about 53 kB with the dialog and every sign-in method.

```ts
import { Madauth, Password } from '@madauth/web/client';

Madauth.initialize({ providers: [new Password()], ui: 'custom' });
const result = await Madauth.password.signIn({ email, password });
```

See [Building your own login screen](https://github.com/inouiw/madAuth/blob/main/docs/custom-ui.md).

## Documentation

- [Using madAuth in your app](https://github.com/inouiw/madAuth#using-madauth-in-your-app)
- [Building your own login screen](https://github.com/inouiw/madAuth/blob/main/docs/custom-ui.md)
- [Styling the login form](https://github.com/inouiw/madAuth/blob/main/docs/styling.md)

## License

MIT
