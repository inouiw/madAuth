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
| Google client ID | none | Turns on Google sign-in. See [Google Cloud Console setup](server.md#google-cloud-console-setup). |
| Google client secret | none | Only asked with a client ID. Enables the redirect flow (`GoogleRedirect`). Without it, Google sign-in runs in the browser (`GoogleFedcm`). |
| E-mail & password sign-in? | yes | |
| Database | `sqlite:./madauth.db` | The SQLite file that stores the users. |
| Webhook URL | `http://localhost:8790/webhook` | Where madAuth hands over its e-mails (step 4). |

Choose at least one sign-in method. At the end, `init` prints the next steps for your answers. They are the steps below.

Never commit `.env`: it holds the signing key and your secrets.

Every question is also an option, so a script needs no prompts. `--yes` takes the default for everything you don't pass:

```bash
npx @madauth/server init --yes --app-url http://localhost:3000
```

The options are `--app-url`, `--google-client-id`, `--google-client-secret`, `--password` or `--no-password`, `--database` and `--webhook-url`. `init` does not overwrite an existing file: pass `--force` to allow it, or `--out <path>` to write another file.

## 3. Start the server

```bash
npx @madauth/server start --env-file .env
```

The server listens on port 8787. All its settings are in `.env`; see [Configuration](server.md#configuration) for what each one does.

## 4. Start the e-mail receiver

Skip this step without e-mail & password sign-in.

madAuth does not send e-mails itself: it hands each one to your [webhook](server.md#webhooks) receiver. For development, run the [example receiver](https://github.com/inouiw/madAuth/tree/main/examples/dev-webhook-receiver). It prints each e-mail in the terminal, with its link and code.

Get it once, in a folder of its own:

```bash
git clone https://github.com/inouiw/madAuth.git && cd madAuth && npm install
```

Start it in a second terminal, with the `WEBHOOK_URL` and `WEBHOOK_SECRET` from your `.env`:

```bash
WEBHOOK_URL=http://localhost:8790/webhook WEBHOOK_SECRET=whsec_... npm run dev:webhooks
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

Pass the providers that match your answers: `Password`, and `GoogleFedcm` or `GoogleRedirect`.

```ts
import { Madauth, Password } from '@madauth/web';

Madauth.initialize({ providers: [new Password()] });
Madauth.onAuthStateChanged((user) => console.log(user)); // the user, or null
signInButton.onclick = () => Madauth.signIn();
```

With Google sign-in, add your app URL under **Authorized JavaScript origins** in the Google Cloud Console (for `http://localhost:5173`, add `http://localhost` as well). For the redirect flow, also add `<app URL>/auth/google/callback` under **Authorized redirect URIs**.

## 7. Sign up once

Open your app and click your sign-in button. In the dialog, choose "Create account" and enter an e-mail address and a password. The confirmation e-mail appears in the receiver's terminal: open its link, or type its code into the dialog. You are signed in, and your `onAuthStateChanged` listener gets the user.

To create a user without the e-mail, e.g. a first admin:

```bash
npx @madauth/server create-user admin@example.com --env-file .env
```

## Next

- [Using madAuth in your app](../README.md#using-madauth-in-your-app): what `initialize`, `signIn` and the other methods do.
- [Styling the login form](styling.md) and [Building your own login screen](custom-ui.md).
- [Running the madAuth server](server.md): all settings, sending real e-mails, hosting with Docker, AWS Lambda or Azure Functions, and verifying the session in your backend.
- For production, run `init` again with your app's https URL. Each environment needs a signing key of its own.
