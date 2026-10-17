# Getting started

This guide adds madAuth to a web app on your machine: the madAuth server runs next to your app's dev server, and your app signs users in with the sign-in library. You need Node.js 22.13 or newer.

## 1. Install

In your app's folder:

```bash
npm install @madauth/web @madauth/server
```

`@madauth/web` is the sign-in library for the browser. `@madauth/server` is the server it talks to.

## 2. Create the configuration

```bash
npx @madauth/server init
```

`init` asks a few questions and writes the configuration to `.env`, with a new signing key:

| Question | Default | Description |
| --- | --- | --- |
| App URL | `http://localhost:5173` | The address your users open. Here it is your dev server. madAuth is served on the same origin through a proxy (step 5), so its cookies are first-party. |
| E-mail & password sign-in? | yes | |
| Sign-up with the authenticator app alone? | no | Accounts without a password: the address is confirmed by e-mail, then the app is set up. The app as a second factor needs no answer here; admins set that [policy](server.md#sign-in-methods) while the server runs. |
| Passwordless sign-in with an e-mail link? | no | The user enters their address and gets an e-mail with a link that signs them in and a code. A new address is signed up on first use. |
| SMS codes as a second factor? | no | Your webhook receiver sends the SMS (`sms.send_code`). A signed-in user adds a phone number; the policy then asks for a code sent to it, next to the authenticator app. |
| Database | `sqlite:./madauth.db` | Where the users are stored, whichever way they sign in: this SQLite file, or e.g. `postgres://<user>:<password>@<host>:5432/<database>` (see [Postgres](server.md#postgres)). |
| Webhook URL | `http://localhost:8790/webhook` | Only with e-mail & password sign-in, the e-mail link, sign-up with the app or a passkey alone, or SMS codes: where madAuth hands over its e-mails and SMS (step 4). |
| Your e-mail address, to become the first admin | none | Who signs up with it gets the role `admin` (`INITIAL_ADMIN_EMAIL`), once the address is proven, and manages [claims](server.md#claims) and [sign-in methods](server.md#sign-in-methods) from your app (step 7). |

Choose at least one way to create users. At the end, `init` prints the next steps for your answers. They are the steps below.

Never commit `.env`: it holds the signing key and your secrets.

Every question is also an option, so a script needs no prompts. `--yes` takes the default for everything you don't pass:

```bash
npx @madauth/server init --yes --app-url http://localhost:3000
```

The options are `--app-url`, `--password` or `--no-password`, `--authenticator` or `--no-authenticator`, `--email-link` or `--no-email-link`, `--sms` or `--no-sms`, `--database`, `--webhook-url` and `--initial-admin-email`. `init` does not overwrite an existing file: pass `--force` to allow it, or `--out <path>` to write another file.

## 3. Start the server

```bash
npx @madauth/server start --env-file .env
```

The server listens on port 8787. All its settings are in `.env`; see [Configuration](server.md#configuration) for what each one does.

## 4. Start the e-mail receiver

Skip this step without e-mail & password sign-in.

madAuth does not send e-mails itself: it hands each one to your [webhook](server.md#webhooks) receiver. For development, run the [development receiver](https://github.com/inouiw/madAuth-webhooks/tree/main/dev-receiver) from the madAuth-webhooks repository. It prints each e-mail in the terminal, with its link and code.

Get it once, in a folder of its own:

```bash
git clone https://github.com/inouiw/madAuth-webhooks.git && cd madAuth-webhooks/dev-receiver && npm install
```

Start it in a second terminal, with the `WEBHOOK_URL` and `WEBHOOK_SECRET` from your `.env`:

```bash
WEBHOOK_URL=http://localhost:8790/webhook WEBHOOK_SECRET=whsec_... npm run dev
```

## 5. Proxy madAuth through your app

The session is a cookie, so the browser must reach madAuth on your app's own origin. Let your dev server pass `/auth` and `/.well-known` on to the madAuth server. With Vite, in `vite.config.ts`:

```ts
import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    proxy: {
      '/auth': 'http://localhost:8787',
      '/.well-known': 'http://localhost:8787',
    },
  },
});
```

Other dev servers have a similar setting. In production, your reverse proxy or CDN does the same.

## 6. Sign users in

Pass the providers that match your answers: `Password`, `GoogleFedcm` or `GoogleRedirect`, `GitHub`, `EmailLink` for the e-mail link, `Passkey` for signing in with a passkey, and `Authenticator` for signing in with the authenticator app on its own (once an admin allows it in the settings). Second factors need no provider: once an admin sets the policy, the dialog asks for a passkey, a code from the app or a code by SMS by itself, and a user adds one from your app with `Madauth.showSetUpPasskeyDialog()`, `Madauth.showSetUpAuthenticatorDialog()` or `Madauth.showSetUpSmsDialog()`, or all of their sign-in methods with `Madauth.showManageSignInMethodsDialog()`.

```ts
import { Madauth, Password, Passkey, Authenticator, EmailLink } from '@madauth/web';

Madauth.initialize({ providers: [new Password(), new Passkey(), new Authenticator(), new EmailLink()] });
Madauth.onAuthStateChanged((user) => console.log(user)); // the user, or null
signInButton.onclick = () => Madauth.showSignInDialog();
```

Google, GitHub and [OpenID Connect](server.md#openid-connect-provider-setup) sign-in are [providers](server.md#providers) in the store, not settings in `.env`. Until the first admin exists, the server prints a setup token at its start, with which you add them ([First setup](server.md#first-setup)); afterwards an admin does it with `Madauth.admin.addProvider`. The dialog then shows their buttons by itself. With Google, add your app URL under **Authorized JavaScript origins** in the Google Cloud Console (for `http://localhost:5173`, add `http://localhost` as well), and for the redirect flow `<app URL>/auth/providers/google/callback` under **Authorized redirect URIs**. With GitHub, the OAuth App's callback URL is `<app URL>/auth/providers/github/callback`, and with an OpenID Connect provider `<app URL>/auth/providers/<id>/callback`.

## 7. Sign up once

Open your app and click your sign-in button. In the dialog, choose "Create account" and enter an e-mail address and a password. The confirmation e-mail appears in the receiver's terminal: open its link, or type its code into the dialog. You are signed in, and your `onAuthStateChanged` listener gets the user.

If you gave `init` your address, sign up with it: once it is confirmed, you have the role `admin` and manage [claims](server.md#claims) and [sign-in methods](server.md#sign-in-methods) from your app with `Madauth.admin`. Otherwise add `INITIAL_ADMIN_EMAIL=you@example.com` to `.env` and start the server again; your next sign-in with that address makes you the admin. See [The first admin](server.md#the-first-admin).

To ask every password user for a second factor (a passkey or the authenticator app), with the e-mail link on and passkeys signing in on their own as well, as the admin in your app:

```ts
const signIn = (secondFactor: 'none' | 'required' = 'none') => ({ allowAsSignInMethod: true, secondFactor });
await Madauth.admin.setSettings({
  methods: { google: signIn(), password: signIn('required'), 'email-link': signIn(), passkey: signIn(), authenticator: { allowAsSignInMethod: false, secondFactor: 'none' } },
});
```

## Next

- [Using madAuth in your app](../README.md#using-madauth-in-your-app): what `initialize`, `signIn` and the other methods do.
- [Styling the login form](styling.md) and [Building your own login screen](custom-ui.md).
- [Upgrading](upgrading.md) from an earlier madAuth.
- [Running the madAuth server](server.md): all settings, sending real e-mails, hosting with Docker, AWS Lambda or Azure Functions, and verifying the session in your backend.
- For production, run `init` again with your app's https URL. Each environment needs keys of its own: `init` writes `MADAUTH_KEY_SERVICE=local`, with the key in `.env`; in production keep the keys in a key service that never gives them out, e.g. `MADAUTH_KEY_SERVICE=aws-kms`, see [Key service](server.md#key-service).
