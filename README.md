# madAuth

A self-hostable alternative to Cognito / Auth0: run the madAuth server in your own cloud account, keep your users in your own database, and add a ready-made sign-in dialog to any web app.

**Try it: [madauth.com/demo](https://madauth.com/demo/)** – the live demo: sign in and see the signed-in user's claims.

## Why madAuth

- **Small in the browser.** The sign-in dialog with every sign-in method adds about 49 kB (gzipped) to your app, Lit included. With your own login screen, `@madauth/web/client` is about 18 kB. The password-strength check loads only on a screen that asks for a new password.
- **Any framework.** The dialog is a standard web component: plain HTML, React, Angular, Vue, Svelte and Capacitor apps.
- **Your infrastructure.** Node, Docker, AWS Lambda or Azure Functions; SQLite, Postgres, DynamoDB or a store of your own. The AWS Lambda bundle is one file of under 2 MB, without `node_modules`. See [the table below](#runs-on-your-infrastructure).
- **Keys outside the process.** On AWS, madAuth's signing, hashing and encryption keys can stay in AWS KMS and never leave it: someone who breaks into the server can't take them away. The AWS template creates and rotates them. See [Key service](docs/server.md#key-service).
- **Secure by default.** Failed sign-ins are slowed down per account, answers don't reveal which addresses have an account, and sensitive changes (a new sign-in method, removing the second factor, deleting the account) need a sign-in within the last two minutes. Webhooks are signed, on AWS with IAM instead of a shared secret. The container runs as an unprivileged user, and the `docker-compose.yml` adds a read-only file system and no Linux capabilities. See [Password security](docs/password-security.md) and [Hardening](docs/server.md#hardening).
- **MIT licensed.**

## Sign-in methods

| Method | Status |
| --- | --- |
| Google sign-in (FedCM / One Tap, server-side redirect, or an ID token the app obtained itself, e.g. natively in Capacitor) | available |
| GitHub sign-in (server-side redirect) | available |
| OpenID Connect providers: GitLab, Keycloak, Okta, a company's own… (server-side redirect; an address the provider doesn't vouch for is confirmed by e-mail) | available |
| E-mail & password (with e-mail confirmation and password reset) | available |
| Passwordless e-mail link (a link and a code by e-mail, sign-up on first use) | available |
| Passkeys (WebAuthn): on their own (with sign-up by e-mail confirmation), in the e-mail field's autofill, and as a second factor | available |
| Authenticator app (TOTP): as a second factor with recovery codes, and on its own | available |
| SMS code (as a second factor) | available |
| Microsoft (personal accounts and Entra ID) | open ([#48](https://github.com/inouiw/madAuth/issues/48)) |
| Enterprise SSO with SAML 2.0 | open ([#51](https://github.com/inouiw/madAuth/issues/51)) |

A user can have several of these: they sign up with one and add more while signed in. The admin decides which methods sign in on their own and which ask for a second factor, and manages the providers in a dialog of their own (`Madauth.showAdminDialog()`).

Users can also make **API keys** for programs that call your API, or madAuth's admin API, in their name, each limited to scopes; your backend checks them with `createApiKeyVerifier`. See [API keys](docs/api-keys.md).

## Runs on your infrastructure

| Part | Option | Status |
| --- | --- | --- |
| Hosting | Node (`npx @madauth/server start`) | available |
| | Docker (`ghcr.io/inouiw/madauth-server`) | available |
| | AWS Lambda, with an [AWS CDK template](deploy/aws/README.md) | available |
| | Azure Functions | available |
| | Your own Node server (`createApp`, a Hono app) | available |
| | Cloudflare Workers | open |
| | Deployment templates for Azure and Google Cloud | open |
| Database | SQLite | available |
| | Postgres | available |
| | Amazon DynamoDB | available |
| | Your own database, with a [custom store adapter](docs/server.md#custom-store-adapter) | available |
| | MySQL / MariaDB, MongoDB, Azure Cosmos DB, Google Firestore (built in) | open |
| Keys | In the server's memory, from `MADAUTH_SIGNING_KEY` | available |
| | AWS KMS | available |
| | A key service of your own, passed to `createApp` | available |
| | Azure Key Vault, Google Cloud KMS (built in) | open ([#74](https://github.com/inouiw/madAuth/issues/74)) |
| E-mail and SMS (a [webhook receiver](https://github.com/inouiw/madAuth-webhooks) sends them) | Development receiver that prints them | available |
| | Amazon SES (e-mail) and Amazon SNS (SMS) | available |
| | Any other service, with a receiver of your own | available |
| | Ready-made receivers for other services (e.g. SendGrid, Twilio, Azure Communication Services) | open |

New to madAuth? [Getting started](docs/getting-started.md) walks you through the server and the library on your machine.

## Using madAuth in your app

madAuth has two parts: the sign-in library for your web app, and the madAuth server it talks to.

Install the library:

```bash
npm install @madauth/web
```

Run the server with Node. `init` asks a few questions and writes the configuration to `.env`:

```bash
npm install @madauth/server
```

```bash
npx @madauth/server init
```

```bash
npx @madauth/server start --env-file .env
```

Or with Docker (see [Running the madAuth server](docs/server.md) for the configuration and other hosting options):

```bash
docker run --rm -p 8787:8787 --env-file .env -v madauth-data:/data ghcr.io/inouiw/madauth-server
```

Then sign users in:

```ts
import { Madauth, GoogleFedcm, GitHub, Password, Passkey, Authenticator, EmailLink } from '@madauth/web';

Madauth.initialize({ providers: [new GoogleFedcm(), new GitHub(), new Password(), new Passkey(), new Authenticator(), new EmailLink()] });
Madauth.onAuthStateChanged(handleAuthStateChanged); // (user | null) => void
signInButton.onclick = () => Madauth.showSignInDialog();
```

- **`initialize`** checks the server and loads the current session. You don't need to await it. Problems are logged to the console and returned as `{ isSuccess: false, error }`. A provider whose method the server doesn't offer (e.g. `GoogleRedirect` on a development server without a Google client) is left out with a warning and named in the result's `leftOut`, and the other methods work; `initialize` fails only when no method is left.
- **Google sign-in:** `new GoogleFedcm()` shows Google One Tap on page load ("Continue as …"). `Madauth.showSignInDialog()` opens the sign-in dialog with Google's button, which keeps working when Chrome holds One Tap back. For the server-side redirect flow use `new GoogleRedirect()`. An app that obtains the ID token itself, e.g. natively in a Capacitor app, signs in with `Madauth.google.nonce()` and `Madauth.google.signIn({ credential })`, see [Custom UI](docs/custom-ui.md#an-id-token-the-app-obtained-itself).
- **GitHub sign-in:** a "Continue with GitHub" button that starts the server-side redirect flow, shown by itself when the server has a GitHub provider that is on (`new GitHub()` also gives `Madauth.github`). An admin adds the provider with a GitHub OAuth App's client ID and secret (`Madauth.admin.addProvider`, see [Providers](docs/server.md#providers)). See [GitHub security](docs/github-security.md).
- **OpenID Connect providers:** an admin adds any provider with a discovery document (its issuer, client ID and secret), with an id of its own such as `gitlab`; the dialog shows a "Continue with <name>" button for it by itself, and `Madauth.provider(id)` renders it on a custom screen. See [OpenID Connect provider setup](docs/server.md#openid-connect-provider-setup).
- **E-mail & password:** `new Password()` adds the form to the dialog, with "Create account" and "Forgot password?". New accounts confirm their address with a link or a code from an e-mail. The links in the e-mails lead back to your page: `initialize` handles them, and opens the dialog to choose a new password after a reset link. See [Password security](docs/password-security.md).
- **E-mail link:** `new EmailLink()` adds "E-mail link" to the dialog: the user enters their address and gets an e-mail with a link that signs them in and a 6-digit code. An unknown address is signed up on first use (your sign-up check permitting); the owner of an address that signs in another way gets an e-mail that says so instead. The policy for the authenticator app applies as for a password. See [E-mail link security](docs/email-link-security.md).
- **Passkeys:** `Madauth.showSetUpPasskeyDialog()` lets a signed-in user add a passkey (the browser's dialog: a fingerprint, the face or the screen lock). With the server allowing passkeys as a sign-in method, `new Passkey()` adds "Passkey" to the dialog and offers the user's passkeys in the e-mail field's autofill, and, where the server confirms addresses by e-mail, a sign-up with a passkey alone (the address is confirmed first, then the passkey is created; `Madauth.passkey.signUp` on a custom screen); as a second factor, the dialog asks for one by itself. See [Passkey security](docs/passkey-security.md).
- **Several sign-in methods:** `Madauth.showManageSignInMethodsDialog()` opens the dialog on the signed-in user's methods, to add a passkey, a password, the e-mail link, Google, GitHub, an OpenID Connect provider or the app, and to remove one. See [Several sign-in methods](docs/sign-in-methods.md).
- **SMS codes:** a second factor only, never a sign-in on its own. A signed-in user adds a phone number with `Madauth.showSetUpSmsDialog()` (a code confirms it); from then on, Google, the password and the e-mail link ask for a code sent to it when the policy is `optional` or `required`. A user who has the app as well is asked for the app first and can switch. `Madauth.sms.status()` and `remove({ code })` manage it from your account page. Your webhook receiver sends the SMS (`sms.send_code`). See [SMS code security](docs/sms-security.md).
- **Authenticator app** (TOTP: Google Authenticator, 1Password and the like). What it does is the server's [sign-in policy](docs/server.md#sign-in-methods): a second factor after another method (`optional`: for users who have one; `required`: everyone sets one up at their next sign-in), which the dialog handles by itself, and/or a method of its own (the e-mail address and a code, with sign-up by e-mail confirmation), which `new Authenticator()` adds to the dialog. `Madauth.showSetUpAuthenticatorDialog()` opens the dialog with the QR code and shows the recovery codes once; `Madauth.authenticator.status()`, `newRecoveryCodes(...)` and `remove(...)` manage it from your account page, the last two with a current code. See [Authenticator app security](docs/authenticator-security.md).
- **Sign-in providers for admins:** `Madauth.showAdminDialog()` opens the dialog on the server's providers: add Google, GitHub or an OpenID Connect provider (with the callback URL to register at it), change one, switch it on with its second-factor policy, and remove one after a confirmation that says how many users sign in with it alone. It doesn't open for users without the role `admin`. See [Providers](docs/server.md#providers).
- **API keys:** `Madauth.showManageApiKeysDialog()` opens the dialog on the signed-in user's API keys, to make one (its name, scopes and expiry; the key is shown once) and to revoke one; `Madauth.apiKeys` does the same on your own screen. See [API keys](docs/api-keys.md).
- **The dialog:** `showSignInDialog()` adds a `<madauth-login>` to the page; put one in your HTML only to customize it. `showSignInDialog({ email })` opens it with the e-mail address filled in, e.g. from a link like `/?email=…`, so the user only types the password.
- **Language:** the dialog has English and German texts. It follows the page's `<html lang>`, then the browser's language. To set the language yourself, pass `locale: 'de'` (or e.g. `'de-CH'`) to `initialize`, and call `Madauth.setLocale('en')` when the user switches the language of your app; an open dialog changes at once. Every other language shows English. The same locale goes to your e-mail webhook, so the e-mails can match the dialog.
- **Your own login screen:** import from `@madauth/web/client` (the same exports without the dialog, so neither it nor Lit ends up in your bundle), pass `ui: 'custom'` and use `Madauth.password`, `Madauth.google`, `Madauth.github`, `Madauth.passkey`, `Madauth.authenticator`, `Madauth.emailLink`, `Madauth.sms`, `Madauth.methods` and `Madauth.apiKeys` instead of the dialog. See [Building your own login screen](docs/custom-ui.md).
- **Other methods:** `signOut()`, `getSession()`, `currentUser`, `deleteAccount()` to [delete the signed-in user's account](docs/server.md#deleting-an-account) (with a code from the authenticator app once it is set up), and `sessionReady()` to wait for a fresh session before calling your own backend (see [Sessions](docs/server.md#sessions)). All methods resolve to `{ isSuccess, ... }` and never throw for expected failures.
- **Claims:** `currentUser.claims` holds what admins attached to the user, e.g. `{ roles: ['admin'] }`; it is in the session token for your backends too, as is `currentUser.amr`, how the session was authenticated (e.g. `['pwd', 'otp']`, or `['email']` after an e-mail link). Admins set claims with `Madauth.admin.setClaims(email, claims)`, the sign-in methods and their policies with `Madauth.admin.setSettings(...)`, reset the sign-in of a user who lost every way in with `Madauth.admin.resetSignIn(email)`, and find users by role, address or sign-up date with `Madauth.admin.searchUsers(...)`. See [Claims](docs/server.md#claims) and [Sign-in methods](docs/server.md#sign-in-methods).
- **Server URL:** the server is expected on the page's own origin (`/auth/...`). Pass `serverUrl: 'https://auth.example.com'` to `initialize` if it runs elsewhere on the same site.

### Running the server

See [Running the madAuth server](docs/server.md) for:
- the configuration
- Google Cloud Console setup, and GitHub OAuth App setup
- the database (SQLite, Postgres or Amazon DynamoDB) that stores every user, and webhooks for sending e-mails (with ready-made receivers in [madAuth-webhooks](https://github.com/inouiw/madAuth-webhooks), e.g. for Amazon SES), checking sign-ups and receiving events
- Node, Docker, AWS Lambda and Azure Functions
- storing users in your own database (custom store adapter)
- verifying the session in your own backend

### Styling

The login form can be styled to match your app (colors, corner radius, font, and individual parts of the dialog). See [Styling the login form](docs/styling.md) for all available settings.

## Contributing

Contributions are welcome! Open an issue to discuss an idea or report a bug, or send a pull request. [Developing madAuth](docs/development.md) describes the repository, how to run the demo from it, the tests, and how to add a sign-in method. Please make sure `npm run typecheck` and `npm test` pass.

## License

madAuth is released under the [MIT License](LICENSE).
