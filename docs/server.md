# Running the madAuth server

`@madauth/server` signs users in with Google, with GitHub, with e-mail & password, with a passwordless e-mail link or with an authenticator app (TOTP), asks for a second factor (the app, or a code by SMS) when the policy says so, and issues the madAuth session. You can run it with Node, as a Docker container, an AWS Lambda function or an Azure Function.

To set it up on your machine step by step, see [Getting started](getting-started.md).

Every user is stored, whichever way they sign in, through a [store adapter](#custom-store-adapter): SQLite, [Postgres](#postgres) and [Amazon DynamoDB](#dynamodb) are built in, and other databases need a small adapter of your own. A user has one id (`usr_…`) and one e-mail address, and one account per sign-in method they have: the password, the Google account (known by Google's stable `sub`), the GitHub account (known by GitHub's user id), the authenticator app, the e-mail link, and the phone number for SMS codes. A method signs in only users who have it: a Google or GitHub sign-in with the address of a user who signs in with a password (and perhaps the authenticator app) is refused (`403 other_method`; after a redirect flow, `madauth_error=other_method`), since whoever controls that account must not get past them. The one exception is a sign-up nobody finished (its e-mail link was never used, or the app was never set up): a Google or GitHub sign-in with its address takes that user over and drops the unproven password. "Forgot password?" only resets a password that exists: a user who signs in with Google or GitHub alone gets an e-mail that says how they sign in instead (`email.send_password_reset_no_password`), and the answer is the same as for any address.

## How it works

1. The browser signs in:
   - with Google, either in the browser with FedCM / One Tap (`GoogleFedcm`), through the server-side redirect flow (`GoogleRedirect`), or with an ID token the app obtained itself, e.g. natively in a Capacitor app (`Madauth.google.signIn`, see [Custom UI](custom-ui.md#an-id-token-the-app-obtained-itself)). The server verifies Google's ID token: signature, issuer, audience, expiry, nonce and a verified e-mail address.
   - or with GitHub (`GitHub`), through the server-side redirect flow: GitHub has no other. The server exchanges the code, reads the account from GitHub's API and takes an address GitHub has verified. See [GitHub security](github-security.md).
   - or with an e-mail address and password (`Password`). The server checks the password against its scrypt hash; new accounts confirm their address first. See [Password security](password-security.md).
   - or with an e-mail link (`EmailLink`): the address, then the link or the code from the e-mail madAuth sends. A new address is signed up on first use. See [E-mail link security](email-link-security.md).
   - or with a code from the authenticator app (`Authenticator`): as the second step after Google, GitHub, the password or the e-mail link, when the [sign-in policy](#sign-in-methods) asks for it, or on its own with the e-mail address. See [Authenticator app](#authenticator-app).
   - The second step can also be a code sent by SMS to a phone the user added, next to the app. See [SMS codes](#sms-codes).
2. The server finds or creates the user, and sets its own session: an ES256-signed JWT in an HttpOnly cookie named `madauth_session`, with the user's [claims](#claims). It is short-lived and renewed without the user noticing; see [Sessions](#sessions).
3. Your app backends verify that JWT with [`createSessionVerifier`](#verifying-the-session-in-your-backend) or any JWT library, using the public key at `/.well-known/jwks.json`.

> **Same site required.** The session is a cookie, so the madAuth server must be on the same site as your app, for example `auth.example.com` and `app.example.com`, or the same origin behind a reverse proxy. Browsers block third-party cookies, so cross-site setups do not work.

## Configuration

All settings are environment variables. `npx @madauth/server init` asks for the main ones and writes them to a `.env` file, with a new signing key and webhook secret (see [Getting started](getting-started.md)).

| Variable | Required | Description |
| --- | --- | --- |
| `MADAUTH_ISSUER` | yes | Public base URL of the server, e.g. `https://auth.example.com`. Used as the JWT issuer and for the callbacks of the redirect flows, `<issuer>/auth/providers/<id>/callback` (e.g. `google`, `github`). |
| `MADAUTH_KEY_SERVICE` | yes | Where madAuth keeps its keys: `aws-kms`, in AWS KMS, where they never leave it (see [AWS KMS](#aws-kms)), or `local`, in the server's memory, from `MADAUTH_SIGNING_KEY`. There is no default: see [Key service](#key-service). |
| `MADAUTH_SIGNING_KEY` | with `local` | Private ES256 key (JWK JSON) that signs the sessions; the keys that hash the codes and encrypt the stored secrets are derived from it. Or a set of keys, the newest first, to [rotate](#rotating-the-signing-key) it: `{"keys":[<new>,<old>]}`. Use the same value on every instance and keep it secret. |
| `ALLOWED_ORIGINS` | yes | Comma-separated origins of your apps, e.g. `https://app.example.com`. Only these may call the server or be redirected back to. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | no | From madAuth before 0.7: imported once into the [providers](#providers) in the store when it has none of that kind, and ignored when it has one; either way the log says to remove them. Google and GitHub are providers now, which admins manage. |
| `DATABASE_URL` | yes | Where the users are stored: `sqlite:<path>`, e.g. `sqlite:/data/madauth.db`, `postgres://<user>:<password>@<host>:5432/<database>` or `postgresql://…` (see [Postgres](#postgres)), or `dynamodb:<table>` (see [DynamoDB](#dynamodb)). For other databases pass your own [store adapter](#custom-store-adapter) instead. |
| `DATABASE_MIGRATE` | no | With a Postgres `DATABASE_URL`: `true` (default) creates and upgrades madAuth's tables at start, `false` only checks that they are up to date, for a database user that may not change tables. See [Postgres](#postgres). |
| `INITIAL_ADMIN_EMAIL` | no | Who signs in with this address gets the role `admin`, once the address is proven: confirmed by e-mail, or verified by Google or GitHub. Once per value; see [The first admin](#the-first-admin). |
| `WEBHOOK_URL` | for the e-mail methods | Your [webhook](#webhooks) receiver, which sends the e-mails and can check sign-ups and receive events. Must be https, except `localhost`, `127.0.0.1` and `host.docker.internal`. |
| `WEBHOOK_SECRET` | with `WEBHOOK_URL`, without `WEBHOOK_AUTH` | Signs every webhook call; your receiver needs the same one. Start without it once and the error message contains a new one, or run `npx @madauth/server generate-webhook-secret`. |
| `WEBHOOK_PREVIOUS_SECRET` | no | While you change `WEBHOOK_SECRET`: the secret it had before. Every call is then signed with both, so a receiver that still has the old one accepts the calls too. Remove it once the receiver has the new secret. See [Changing the webhook secret](#changing-the-webhook-secret). |
| `WEBHOOK_AUTH` | no | `aws-iam`: madAuth signs the webhook calls with its AWS role instead of `WEBHOOK_SECRET`, which must not be set then, for a receiver behind a Lambda Function URL with `AWS_IAM` auth. See [AWS IAM](#aws-iam). Not set: `WEBHOOK_SECRET` signs them. |
| `WEBHOOK_EVENTS` | with `WEBHOOK_URL` | Comma-separated [types](#webhooks) your receiver handles; only these are sent. E-mail & password sign-in is on when they include `email.send_verification` and `email.send_password_reset`, the e-mail link when they include `email.send_signin_link`, SMS codes when they include `sms.send_code`, e.g. `email.send_verification,email.send_password_reset,email.send_signin_link,email.send_already_registered,email.send_password_reset_no_password,sms.send_code`. |
| `AUTHENTICATOR_ISSUER` | no | The name authenticator apps show next to the account, e.g. `My App`; the browser's passkey dialog shows it too (the WebAuthn relying party's name). Default: the host of the app that asked for the setup, e.g. `app.example.com`. See [Authenticator app](#authenticator-app). |
| `PASSKEY_RP_ID` | no | The domain [passkeys](#passkeys) belong to, e.g. `example.com` so that they work on `app.example.com` and `www.example.com` alike. It must be the host of an app in `ALLOWED_ORIGINS` or a domain above it. Default: the host of the app that adds or uses the passkey, so a passkey works on that host only. Changing it later makes existing passkeys stop working, and locks out the users who sign in with passkeys alone until an admin [resets their sign-in](#resetting-a-users-sign-in) and they sign up again. |
| `API_KEY_SCOPES_URL` | no | Where your app lists the scopes of its API as JSON, which users can give their [API keys](api-keys.md) next to madAuth's own, e.g. `https://app.example.com/api/scopes`. Must be https, except `localhost`, `127.0.0.1` and `host.docker.internal`. madAuth reads it again every five minutes. Without it, keys only have madAuth's scopes, for the admin API. |
| `SESSION_TTL` | no | Lifetime of a session token in seconds: how long your backends accept it. Default `28800` (8 hours). The web library renews it when needed, see [Sessions](#sessions). |
| `SESSION_RENEWAL_TTL` | no | How long a user stays signed in without opening your app, in seconds: a session can be renewed this long after its last renewal. Default `2592000` (30 days). Not less than `SESSION_TTL`. |
| `COOKIE_DOMAIN` | no | Cookie domain, e.g. `.example.com`, so backends on sibling subdomains receive the session cookie. By default the cookie belongs to the server's host only. |
| `PORT` | no | Port for the Node / Docker server. Default `8787`. |

A server needs no sign-in method to start. Google and GitHub are [providers](#providers) in the store, which an admin adds, or, before the first admin exists, whoever has the [setup token](#first-setup). The e-mail methods come with a webhook that sends the e-mails: e-mail & password sign-in needs `email.send_verification` and `email.send_password_reset` among its events, the e-mail link needs `email.send_signin_link`, sign-up with the authenticator app alone needs `email.send_verification`. Which configured methods are on, and whether they ask for the authenticator app, admins set while the server runs, see [Sign-in methods](#sign-in-methods).

### Key service

madAuth does everything it needs a key for through a key service ([`key-service.ts`](../packages/server/src/key-service.ts)): it signs the tokens (sessions, renewals and the cookies of a sign-in under way), hashes the e-mail and recovery codes (HMAC-SHA256), and encrypts the authenticator secrets and GitHub tokens it must read again. Whoever has these keys can sign sessions for anyone, so `MADAUTH_KEY_SERVICE` must say where they are; madAuth doesn't start without it:

- **`aws-kms`**: the keys are in AWS KMS and never leave it; madAuth asks KMS to sign, hash and encrypt. Someone who breaks into the server can use the keys only while they are in, never take them away, and every use is logged in CloudTrail. The way to run madAuth in production; see [AWS KMS](#aws-kms).
- **`local`**: the keys are in the server's memory, made from `MADAUTH_SIGNING_KEY` (see [Signing key](#signing-key)). Whoever can read that memory (a break-in, a core dump, a heap snapshot) can read them; see [Hardening](#hardening). For development, or where no key service is available; madAuth warns about it at every start.

With [`createApp`](#your-own-node-server) you can pass a key service of your own as `keyService`, e.g. for another cloud's key vault.

#### AWS KMS

With `MADAUTH_KEY_SERVICE=aws-kms`, madAuth finds its keys by itself, under aliases named after the host of `MADAUTH_ISSUER` (e.g. `auth-example-com` for `https://auth.example.com`); nothing else is configured:

| Alias | Key |
| --- | --- |
| `alias/madauth/<deployment>/signing` | The ES256 key (`ECC_NIST_P256`) that signs now |
| `alias/madauth/<deployment>/signing/<time>` | Every signing key, by when it was made, e.g. `…/signing/20261017T120000Z`: all of them verify, and `/.well-known/jwks.json` publishes them |
| `alias/madauth/<deployment>/mac`, `…/mac/<time>` | The same for the HMAC keys (`HMAC_256`) that hash the codes |
| `alias/madauth/<deployment>/encryption` | The symmetric key that encrypts the secrets, bound to their purpose (the encryption context); KMS gives it new material every year by itself and keeps the old to decrypt |

madAuth reads the aliases when it starts and every five minutes after, so a rotation reaches every running instance; it doesn't start when the keys are missing.

**Who creates the keys.** Never the server: whatever can create a key that madAuth trusts could make one its own AWS account may use too, and so forge sessions for anyone, also after the break-in that let it in is over. So the server's role may only *use* the keys of its deployment, which it finds by their aliases, and can't create keys or aliases:

```json
[
  {
    "Effect": "Allow",
    "Action": ["kms:GetPublicKey", "kms:Sign", "kms:GenerateMac", "kms:Encrypt", "kms:Decrypt"],
    "Resource": "*",
    "Condition": { "ForAnyValue:StringLike": { "kms:ResourceAliases": "alias/madauth/<deployment>/*" } }
  },
  { "Effect": "Allow", "Action": "kms:ListAliases", "Resource": "*" }
]
```

The [AWS template](../deploy/aws/README.md) does all of this itself: it creates the keys at the first deploy and rotates them every day with a function of its own, and gives the server's role this policy. Otherwise an admin creates the keys once with their own AWS credentials, which prints this policy for the deployment:

```bash
npx @madauth/server kms-setup --env-file .env
```

**Rotation.** The signing and hash keys get a successor once a year, through `npx @madauth/server kms-rotate` with an admin's credentials, run every day (e.g. by a scheduled job with a role of its own). A new key is published first, and used from a run at least two hours later, since backends may cache the list of signing keys for an hour. An old signing key is disabled 32 days after its successor began to sign, when the sessions it signed can't be renewed any more (the default `SESSION_RENEWAL_TTL`), and its generation alias is removed, so madAuth stops reading it (the key stays in KMS, disabled); old hash keys stay, since recovery codes hashed with them may be kept for years. The encryption key KMS rotates in place. A run exits with code 1 when a key or its alias is missing, so a failing scheduled job is noticed. The role that rotates needs `kms:ListAliases`, `kms:CreateKey`, `kms:CreateAlias`, `kms:UpdateAlias`, `kms:DeleteAlias`, `kms:DescribeKey` and `kms:DisableKey`.

**Moving from `local` to `aws-kms`** is a clean cut: `MADAUTH_SIGNING_KEY` must be gone (madAuth refuses to start while it is set), so no key stays in a variable. What the old key made can't be read any more:

- every session ends, and the users sign in again;
- authenticator apps and recovery codes set up before stop working: their users set the app up again, and users whose sign-in asks for the app ask an admin to [reset their sign-in](#resetting-a-users-sign-in);
- the stored GitHub tokens can't be revoked: each is replaced at its user's next sign-in.

Each KMS key costs a monthly fee, also when disabled: three keys, plus one for each rotation of the signing and hash keys a year. Every signature, hash and encryption is a KMS request: a sign-in makes a few.

### Signing key

With `MADAUTH_KEY_SERVICE=local`, `MADAUTH_SIGNING_KEY` holds the keys: the signing key itself, and a hash key and an encryption key per purpose derived from it (HKDF). `init` writes a new key into `.env`. Otherwise, start the server without `MADAUTH_SIGNING_KEY` and the error message contains a freshly generated key to copy. You can also generate one directly:

```bash
npx @madauth/server generate-key
```

#### Rotating the signing key

`MADAUTH_SIGNING_KEY` can hold several keys: the first signs, hashes and encrypts, and every listed one still verifies tokens, finds code hashes and decrypts secrets. `/.well-known/jwks.json` publishes all of them, so backends with [`createSessionVerifier`](#verifying-the-session-in-your-backend) accept the tokens of each; they fetch the list again when they meet a key they don't know.

1. **Publish the new key.** Generate one and add it after the current key, which still signs:

   ```bash
   MADAUTH_SIGNING_KEY='{"keys":[<current key>,<new key>]}'
   ```

   Deploy it to every instance and wait an hour: `/.well-known/jwks.json` may be cached that long (`Cache-Control: max-age=3600`), and a backend that hasn't seen the new key would refuse the sessions it signs. (`createSessionVerifier` also fetches the list again when it meets an unknown key, but a cache in between may still answer the old list.)
2. **Let it sign.** Put the new key first and deploy again:

   ```bash
   MADAUTH_SIGNING_KEY='{"keys":[<new key>,<current key>]}'
   ```

   From then on, new sessions and renewals are signed with the new key, and existing ones keep working.
3. **Data moves to the new key when it's used:** an authenticator secret is re-encrypted the next time its user enters a code, a GitHub token is replaced at the next sign-in, new recovery codes are hashed with the new key, and e-mail codes live minutes.
4. **Remove the old key once nothing needs it.** Sessions need it until the last renewal it signed has expired (`SESSION_RENEWAL_TTL`, 30 days by default); removing it earlier signs those users out. Authenticator secrets, GitHub tokens and recovery codes that weren't used since need it as long as they exist: without it, those apps and recovery codes stop working (the log says so) and those GitHub grants can't be revoked. A pass that moves all stored data at once is planned.

After a suspected leak, skip the wait and put the new key alone. Every session ends, the users whose authenticator app hasn't moved yet set it up again, and backends whose cached list lacks the new key refuse the new sessions until they fetch it again.

## Providers

Google, GitHub and [OpenID Connect](#openid-connect-provider-setup) sign-in are providers: madAuth keeps them in its store, as the setting `providers`, and admins add, change and remove them through the admin API while the server runs, for every instance at once. A provider's client secret is encrypted by the [key service](#key-service), so the store alone doesn't reveal it, and the admin API never answers it, only whether one is set.

- **Add one** with `Madauth.admin.addProvider({ kind: 'google', clientId, clientSecret })` or `{ kind: 'github', clientId, clientSecret }` (`POST /auth/admin/providers/add`). Google and GitHub exist once each, with the kind as the id. Google's client secret is optional: without it, Google signs in with One Tap / FedCM only (`GoogleFedcm`), with it, also with the redirect flow (`GoogleRedirect`). GitHub needs it: it only has the redirect flow.
- **Or an OpenID Connect provider**, as many as needed, each with an id of its own that becomes its method's: `{ kind: 'oidc', id: 'gitlab', name: 'GitLab', issuer: 'https://gitlab.com', clientId, clientSecret }`, optionally with `scopes` and `trustEmail`, see [OpenID Connect provider setup](#openid-connect-provider-setup).
- **It is off until switched on** in the [sign-in settings](#sign-in-methods), with its own policy for a second factor. On a server whose settings were never saved, the methods that are on are saved as they are first, so adding a provider switches nothing else on or off.
- **The sign-in dialog shows its button by itself.** `GET /auth/config` lists the providers that are on, with their names, and the button says "Continue with <name>". GitHub's, Google's redirect and the OpenID Connect providers' buttons appear whether or not the app passes `new GitHub()` or `new GoogleRedirect()`; a custom screen renders any of them with `Madauth.provider(id)`. Google's One Tap the app passes itself (`new GoogleFedcm()`), since it loads Google's script and prompts.
- **The answer gives the callback URL** to register at the provider: `<MADAUTH_ISSUER>/auth/providers/<id>/callback`. Before adding one, `listProviders()` answers its start as `callbackBase`, since most providers want the callback URL before they give out the client ID.
- **Change one** with `updateProvider(id, { name, clientId, clientSecret })`, each optional, and an OpenID Connect provider's `scopes` and `trustEmail`; `clientSecret: null` removes Google's. The kind, the id and an OpenID Connect provider's issuer don't change: its accounts belong to it.
- **Remove one** with `removeProvider(id)`. Its users' accounts stay, so adding it again brings their sign-ins back; the answer's `usersWithoutSignIn` says how many users have no other way in meanwhile. It goes out of the [sign-in settings](#sign-in-methods) as well: added again, it is off until switched on, like a new provider. An OpenID Connect provider's id comes back only with its issuer (see below).

**In the admin dialog:** `Madauth.showAdminDialog()` does all of this in madAuth's dialog. It lists the providers with their state ("On, second factor optional" / "Off"), adds one (Google, GitHub or an OpenID Connect provider, showing the callback URL to register as the id is typed), changes one, switches it on or off with its second-factor policy in the same form (with `setMethod`, which changes only that provider's entry), and removes one after a confirmation that says how many users sign in with it alone. It asks the admin to sign in again when a change needs it. For a user without the role `admin`, or nobody signed in, it resolves to `forbidden` or `no_session` and doesn't open.

Changing providers takes an admin's session (no API key) with a sign-in within the last two minutes, like every [sensitive change](sign-in-methods.md#only-within-two-minutes-of-signing-in). Listing them (`listProviders()`, `POST /auth/admin/providers/list`) and a dry run of a removal (`removeProvider(id, { dryRun: true })`, which only counts the users who sign in with nothing else) also work with an API key with the scope `madauth:providers:read`. Each change sends `provider.added`, `provider.changed` or `provider.removed` to the webhook (opt in with `WEBHOOK_EVENTS`), with the admin's address as `by`.

Code: [`providers.ts`](../packages/server/src/providers.ts).

### First setup

A new deployment has no admin, so nobody could sign in to add the first provider. While no admin exists, the server prints a setup token in its log at every start:

```
[madauth] No admin yet. This setup token configures the sign-in providers and settings until the first admin exists: send it as "Authorization: Bearer madauth_setup_…" to POST /auth/admin/providers/* and /auth/admin/settings/*, then sign in as you@example.com (INITIAL_ADMIN_EMAIL), which makes you the first admin and ends the setup.
```

With it, add a provider and switch it on (`methods` lists every method that is on, see [Sign-in methods](#sign-in-methods)):

```bash
curl -X POST https://app.example.com/auth/admin/providers/add -H 'Authorization: Bearer madauth_setup_…' \
  -H 'Content-Type: application/json' -d '{"kind":"google","clientId":"…apps.googleusercontent.com","clientSecret":"…"}'
```

```bash
curl -X POST https://app.example.com/auth/admin/settings/set -H 'Authorization: Bearer madauth_setup_…' \
  -H 'Content-Type: application/json' -d '{"methods":{"google":{"allowAsSignInMethod":true,"secondFactor":"none"}}}'
```

Then sign in with the address in `INITIAL_ADMIN_EMAIL`, which makes you the first admin (see [The first admin](#the-first-admin)).

- The token works on the provider and settings calls of the admin API only, not on users, claims, API keys or resets, and needs no recent sign-in. Its changes have `by: null` and `bySetupToken: true` in their webhook events.
- It is computed with the key service's hash key, so every instance prints the same one and nothing is stored; it changes when that key is rotated.
- The setup closes for good, recorded in the setting `setup`, once the first admin exists: `INITIAL_ADMIN_EMAIL` was applied, an admin used the admin API, or, on a deployment from before 0.7, a user with the role `admin` is in the store. Then the token stops working and isn't printed any more.
- Whoever can read the server's log during the setup can configure a provider, so keep the setup short: sign in as the first admin right after adding the provider.

Code: [`setup.ts`](../packages/server/src/setup.ts).

### Google Cloud Console setup

1. Open [Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials) and create an **OAuth client ID** of type **Web application**.
2. Under **Authorized JavaScript origins**, add every origin your app runs on (e.g. `https://app.example.com`, and `http://localhost:3000` plus `http://localhost` for development). The FedCM / One Tap flow needs only this.
3. For the redirect flow, add `<MADAUTH_ISSUER>/auth/providers/google/callback` under **Authorized redirect URIs**, and give the provider the client secret.
4. Add the provider with the client ID (see [Providers](#providers)).

### GitHub OAuth App setup

1. Open [GitHub → Settings → Developer settings → OAuth Apps](https://github.com/settings/developers) and register a **New OAuth App** (an OAuth App, not a GitHub App: madAuth only needs to know who signs in).
2. Set the **Homepage URL** to your app and a **Redirect URI** of `<MADAUTH_ISSUER>/auth/providers/github/callback`, e.g. `https://app.example.com/auth/providers/github/callback` (an OAuth App takes up to ten, so one app can serve `http://localhost:3000/auth/providers/github/callback` for development as well; a production app of its own keeps the secrets apart). Leave **Allow wildcard matching** and **Enable Device Flow** off.
3. Untick **Expire user access tokens**, which GitHub ticks by default: madAuth keeps the token to revoke the app's authorization when a user deletes their account, and an expiring token (eight hours) could not do that any more.
4. Generate a client secret and add the provider with the client ID and the secret (see [Providers](#providers)). Both are needed: GitHub only has the server-side redirect flow, in which the server exchanges the code.

Users are asked to grant the scope `user:email`, which lets madAuth read their e-mail addresses: it takes the primary one if GitHub has verified it, else another verified one, and refuses an account without one (`email_unverified`). The public address on the profile is not used. The access token is kept on the user's account, encrypted like the authenticator secrets, for one thing: revoking the OAuth App's authorization when the user deletes their account. See [GitHub security](github-security.md).

### OpenID Connect provider setup

Any provider that speaks OpenID Connect with a discovery document signs in through the kind `oidc`: GitLab, Keycloak, Okta, Auth0, Authentik, Zitadel, a company's own identity provider. madAuth is a confidential client of it, with the authorization-code flow.

1. Register a web application (a confidential client, with a client secret) at the provider, with the redirect URI `<MADAUTH_ISSUER>/auth/providers/<id>/callback`, where `<id>` is the id you will give the provider, e.g. `https://app.example.com/auth/providers/gitlab/callback`. It needs the scopes `openid`, `email` and `profile`.
2. Add it (see [Providers](#providers)):

   ```bash
   curl -X POST https://app.example.com/auth/admin/providers/add -H 'Authorization: Bearer madauth_setup_…' \
     -H 'Content-Type: application/json' \
     -d '{"kind":"oidc","id":"gitlab","name":"GitLab","issuer":"https://gitlab.com","clientId":"…","clientSecret":"…"}'
   ```

   - `id`: 2 to 32 lowercase letters, digits and dashes, starting with a letter. It is the provider's method in the [settings](#sign-in-methods), in `amr` and in the webhooks' `method`, and part of the callback URL. madAuth's own methods' ids (`password`, `authenticator`, `email-link`, `passkey`, `sms`, `totp`, `google`, `github`, `microsoft`) are taken.
   - `name`: what the button says, "Continue with <name>", and what the dialog calls it.
   - `issuer`: exactly as the provider's discovery document (`<issuer>/.well-known/openid-configuration`) names it, with its trailing slash if it has one. https, or http on `localhost` for development. It can't change later: the accounts belong to it. The id stays bound to the issuer for good, also after the provider is removed (the setting `provider-issuers`), since another issuer's users would sign in to its accounts by their `sub`: adding the id with another issuer is refused (`invalid_provider`), so a provider at another issuer takes another id.
   - `scopes` (optional): more scopes to ask for, separated by spaces, e.g. `"read_user"`; `openid email profile` are always asked for.
   - `trustEmail` (optional, default `false`): see below.
3. Switch it on in the [sign-in settings](#sign-in-methods) with its id, e.g. `{"methods":{"gitlab":{"allowAsSignInMethod":true,"secondFactor":"none"}}}`. The settings refuse an id that is no provider of the server.

How madAuth signs in with it:

- **Discovery:** when the provider is added, the server reads its discovery document and refuses the provider (`invalid_provider`) when it can't be read, names another issuer, or lacks an https authorization, token or keys endpoint. Each instance keeps the endpoints for an hour.
- **The flow:** the authorization request has a `state`, a `nonce` and PKCE (`S256`). The code exchange authenticates with the client secret as HTTP Basic (`client_secret_basic`), or in the form (`client_secret_post`) when the provider supports only that.
- **The ID token** must be signed with one of the provider's published keys (`jwks_uri`), with an asymmetric algorithm (RS, PS, ES or EdDSA; never HS256 or `none`), by the issuer, for the client ID (`azp`, required with several audiences, must be the client ID whenever it is there), unexpired, with the sign-in's `nonce` and a `sub`.
- **The address** comes from the ID token, or, when it has none, from the provider's userinfo endpoint (whose answer must be JSON, not signed, and about the same `sub`). It counts as verified when the same claims say `email_verified: true` (or `"true"`), or with `trustEmail: true`: only for a provider whose addresses its operator verifies, such as a company's own.
- **An address the provider doesn't vouch for** is confirmed by e-mail once, before it signs anyone up, since whoever controls the provider's account may not own it. The callback creates the sign-up with the provider's account and an unconfirmed address, sends the confirmation e-mail (`email.send_verification`, the link and the code, as for a password), and sends the browser back with `#madauth_next=email-confirmation&madauth_email=<the address, masked>&madauth_method=<id>`; madAuth's dialog then asks for the code. A short-lived cookie (`madauth_confirmation`, HttpOnly, only sent to `/auth/email`) says whose sign-up it is, so the code goes without the address; the link works in any browser. Once confirmed, the session's `amr` and the webhooks' `method` are the provider's id, and the account signs in at once from then on. Until then it signs nobody in, and another sign-up for the address (a password, an e-mail link, another provider) drops it, as an unconfirmed password goes. An address that signs in another way is refused (`other_method`) before anything is sent. A server whose webhook sends no e-mails refuses such an address (`email_unverified`).
- **Confirmed by the provider later** (it now says `email_verified`, or an admin set `trustEmail`), a sign-up that waited for its address is confirmed at its next sign-in.
- **The account** is the provider's `sub` (`oidc:<id>:<sub>`), not the address: a user whose address changes at the provider keeps their account. An address that signs in another way is refused (`other_method`), as with Google and GitHub, see [Several sign-in methods](sign-in-methods.md). A signed-in user adds the provider to their methods with its button's `purpose: 'link'`, whatever its address: the account signs them in by its `sub`, and the address is only noted.

## E-mail & password sign-in

Set `WEBHOOK_URL`, `WEBHOOK_SECRET` (or `WEBHOOK_AUTH`, see [AWS IAM](#aws-iam)) and `WEBHOOK_EVENTS` with `email.send_verification` and `email.send_password_reset` among the events: e-mail & password sign-in is on exactly when your webhook sends those e-mails. The users are in `DATABASE_URL`: with `sqlite:<path>` in that SQLite file (with Docker, keep it on a volume; the `docker-compose.yml` does this), with `postgres://…` in a [Postgres database](#postgres), with `dynamodb:<table>` in a [DynamoDB table](#dynamodb).

madAuth does not send e-mails itself: it hands each one to your [webhook](#webhooks) receiver. There are three: the address confirmation, the password reset, and a note to the owner when someone tries to sign up with an address that already has an account. The confirmation and reset e-mails contain a link to the app page that asked for them (its origin must be in `ALLOWED_ORIGINS`) and a 6-digit code, for when the e-mail is read on another device.

Ready-made receivers are in the [madAuth-webhooks](https://github.com/inouiw/madAuth-webhooks) repository:
- [`dev-receiver`](https://github.com/inouiw/madAuth-webhooks/tree/main/dev-receiver) prints the e-mails in the terminal, for development.
- [`aws-ses-mailer`](https://github.com/inouiw/madAuth-webhooks/tree/main/aws-ses-mailer) sends them with Amazon SES from an AWS Lambda function, with a step-by-step AWS setup.

Brute-force protection is per account. Limit requests per IP address in your reverse proxy, load balancer or WAF as well. See [Password security](password-security.md) for all rules.

### DynamoDB

On AWS, and always on AWS Lambda, store the users in a DynamoDB table. madAuth keeps all its records in one table.

1. Create the table, with the partition key `pk` and the sort key `sk`, both strings:

   ```bash
   aws dynamodb create-table --table-name madauth \
     --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
     --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
     --billing-mode PAY_PER_REQUEST
   ```

2. Set `DATABASE_URL=dynamodb:madauth` on the server.
3. Allow the server these actions on the table: `dynamodb:GetItem`, `dynamodb:Query`, `dynamodb:PutItem`, `dynamodb:UpdateItem`, `dynamodb:DeleteItem`, `dynamodb:TransactWriteItems`, and `dynamodb:Scan` for [searching users](#searching-users). On Lambda, add them to the function's role.

The region and the credentials come from the environment, as for every AWS SDK: on Lambda from the function itself, elsewhere e.g. from `AWS_REGION` and `aws configure`.

The adapter needs the `@aws-sdk/client-dynamodb` package. AWS Lambda's Node.js runtimes and the madAuth Docker image contain it. Anywhere else, install it next to madAuth:

```bash
npm install @aws-sdk/client-dynamodb
```

In your own entry file, create the adapter yourself, e.g. to pass a configured client:

```ts
import { createHandler } from '@madauth/server/lambda';
import { createDynamoDbAdapter } from '@madauth/server/dynamodb';

export const handler = createHandler({ store: createDynamoDbAdapter({ tableName: 'madauth' }) });
```

How the records are stored: each record is one item (`pk` = `r|<model>|<id>`), with one more item per unique value (`u|user|emailNormalized|<address>`) and per indexed value (`i|account|userId|<id>`). A record and these items are always written in one transaction, and every read is strongly consistent, so the table needs no secondary index.

### Postgres

Store the users in PostgreSQL with `DATABASE_URL=postgres://<user>:<password>@<host>:5432/<database>`; `postgresql://` works as well, so the `uri` that e.g. CloudNativePG puts in its `<cluster>-app` Secret can be passed on unchanged. The madAuth Docker image and the Lambda and Azure bundles contain the driver; with madAuth from npm, install it next to it:

```bash
npm install pg
```

**The tables create themselves.** At start, madAuth creates its tables (`madauth_user`, `madauth_account`, …, see [Custom store adapter](#custom-store-adapter)) in an empty database and upgrades those of an older madAuth, in one transaction. The schema version they have is in the table `madauth_schema`. An advisory lock makes instances that start at the same time take turns: one creates or upgrades the tables, the others wait and find them done. A database that a newer madAuth has upgraded is refused, as is one that has madAuth's tables but no `madauth_schema` (the error says how to record their version). The tables go into the first schema of the user's `search_path`; to choose another, add `?options=-c%20search_path%3D<schema>` to the URL. The database user needs to create tables there (`CREATE` on the schema) and to read and write them.

**Without the right to change tables**, set `DATABASE_MIGRATE=false`: madAuth then only checks that the tables are up to date and doesn't start if they are not, with the SQL to run in its message. Create them yourself with the SQL from `npx @madauth/server schema --dialect postgres`, and before you deploy a newer madAuth run the changes since your version, `schema --dialect postgres --from <version>` (see [Schema versions](#schema-versions)); then record the version in `madauth_schema`.

**Connections.** Each instance keeps a pool of up to 10 connections to the database, e.g. to CloudNativePG's `-rw` Service. On AWS Lambda every function instance has its own pool, so many concurrent instances can use up the database's `max_connections`: put RDS Proxy in front of it, or create the adapter yourself with a smaller pool (`pool: { max: 1 }`, see below). A connection that breaks, e.g. when the primary fails over, is dropped and replaced by a new one at the next query, and the log says so; a request that was using it at that moment fails once with `500`. Nothing is sent again: a write sent twice could count twice, e.g. a single-use code. The database must be reachable at start: madAuth doesn't start without it, and your orchestrator starts it again.

**TLS.** The URL's `sslmode` follows the [`pg`](https://node-postgres.com/features/ssl) driver: `sslmode=require` checks the server's certificate as `verify-full` does. With a certificate of your own CA, e.g. CloudNativePG's, mount the CA file in the container and add `sslrootcert=<path>`; `uselibpqcompat=true&sslmode=require` encrypts without checking the certificate, as libpq's `require` does. Without `sslmode`, the connection is not encrypted.

To create the adapter in your own entry file, e.g. with other pool settings:

```ts
import { start } from '@madauth/server/node';
import { openPostgresAdapter } from '@madauth/server/postgres';

await start({ store: await openPostgresAdapter(process.env.PG_URL!, { pool: { max: 5 } }) });
```

On Kubernetes, the image runs as the numeric user `1000`, so `runAsNonRoot` works, and it runs with `readOnlyRootFilesystem`: with Postgres, madAuth writes no files. Use `GET /health` for the readiness probe: it answers without asking the database, so a failover doesn't take every instance out of the Service at once. Every instance needs the same `MADAUTH_SIGNING_KEY` (or the same [AWS KMS](#aws-kms) keys).

## Hosting

Ready-made deployment templates are in [`deploy/`](../deploy/README.md). On AWS, [`deploy/aws`](../deploy/aws/README.md) creates the Lambda function, the DynamoDB table and the secrets in the Parameter Store with one `cdk deploy`.

### Node

With Node.js 22.13 or newer, install the package and start the server:

```bash
npm install @madauth/server
```

```bash
npx @madauth/server start --env-file .env
```

`--env-file` reads the settings from a file. A variable that is already set in the environment wins, so `PORT=9000 npx @madauth/server start --env-file .env` listens on another port. Every command takes it. Without it, the server reads the environment only.

`npx @madauth/server init` writes such a file. It asks for your app's URL and the sign-in methods, and every question is also an option (`--yes` takes the defaults); see [Getting started](getting-started.md). Run `npx @madauth/server` for all commands.

In production, run it as in [Hardening](#hardening).

### Docker

Run the published image (for `linux/amd64` and `linux/arm64`). Pin a version, e.g. `ghcr.io/inouiw/madauth-server:0.1.0`, in production:

```bash
docker run --rm -p 8787:8787 --env-file .env -v madauth-data:/data ghcr.io/inouiw/madauth-server
```

The `madauth-data` volume keeps a SQLite database (`DATABASE_URL=sqlite:/data/madauth.db`) when the container is removed. With [Postgres](#postgres) the container needs no volume. In production, add the flags from [Hardening](#hardening).

To build the image yourself, run this from the repository root:

```bash
docker build -f packages/server/Dockerfile -t madauth-server .
```

There is also a `docker-compose.yml` in `packages/server` that builds and runs it from the repository, with the settings from [Hardening](#hardening). The container exposes `GET /health` for health checks.

With e-mail & password sign-in, the container must reach your webhook receiver. A receiver on your own machine, e.g. the development receiver, is `http://host.docker.internal:8790/webhook` from inside the container.

### AWS Lambda

Download `madauth-server-lambda.mjs` from a [GitHub release](https://github.com/inouiw/madAuth/releases), or take `dist/standalone/lambda.mjs` from the `@madauth/server` npm package. In this repository, build it with:

```bash
npm run build -w packages/server
```

The [AWS CDK template](../deploy/aws/README.md) does all of the following for you. By hand: deploy the bundle, as `lambda.mjs`, with the handler `lambda.handler` on a Node.js 22 or newer runtime. Put it behind a Function URL, API Gateway (HTTP API) or an ALB, and set the environment variables on the function.

Environment variables of a function can be read by everyone who may view its configuration. To keep `MADAUTH_SIGNING_KEY` and the other secrets in the Parameter Store or Secrets Manager instead, write a small entry file and pass `env`: a function that loads the settings. It runs once, before the first request:

```ts
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { createHandler } from '@madauth/server/lambda';

const ssm = new SSMClient({});
const secret = async (name: string) =>
  (await ssm.send(new GetParameterCommand({ Name: name, WithDecryption: true }))).Parameter?.Value;

export const handler = createHandler({
  env: async () => {
    const [signingKey, webhookSecret] = await Promise.all([
      secret('/madauth/signing-key'),
      secret('/madauth/webhook-secret'),
    ]);
    return { ...process.env, MADAUTH_SIGNING_KEY: signingKey, WEBHOOK_SECRET: webhookSecret };
  },
});
```

`register` (Azure Functions) and `start` (Node) take the same `env` option.

A receiver that is a Lambda function too needs no webhook secret: see [AWS IAM](#aws-iam).

### Azure Functions

Get `madauth-server-azure.mjs` (or `dist/standalone/azure.mjs`) as above, then deploy it as `azure.mjs`, the main file of a Node.js (v4 programming model) function app. It registers one HTTP function for all routes.

Add a `host.json` that removes the default `/api` route prefix:

```json
{
  "version": "2.0",
  "extensions": { "http": { "routePrefix": "" } }
}
```

And a `package.json` that points to the bundle:

```json
{ "type": "module", "main": "azure.mjs" }
```

Set the environment variables as application settings.

For e-mail & password sign-in on Lambda or Azure, SQLite does not fit: their file system is not persistent. On Lambda, use [DynamoDB](#dynamodb): `DATABASE_URL=dynamodb:<table>` works with the bundle as it is. On Azure, use [Postgres](#postgres) (`DATABASE_URL=postgres://…`, in the bundle as well) or a [custom store adapter](#custom-store-adapter). Password hashing needs about 32 MB per sign-in; give a Lambda function at least 256 MB.

### Your own Node server

`start` runs madAuth as a server of its own. To serve it from your own Node server instead, create the app:

```ts
import { createApp, loadConfig } from '@madauth/server';

const app = createApp(await loadConfig(process.env)); // a Hono app: app.fetch(request) → response
```

### Hardening

Whoever can read the server's memory, or plant a file that it runs, gets what the server has: every record it reads and, with the `local` [key service](#key-service), its keys. On a host you run yourself, the ways in are a core dump, a debugger, swap and a writable file system. Close them.

In the container, the `docker-compose.yml` in `packages/server` sets these. The image already runs as the unprivileged `node` user, by its number (`1000:1000`, so Kubernetes' `runAsNonRoot` accepts it), with `--disable-sigusr1` (see below):

- **`read_only: true`** (`--read-only`): the container's file system is read-only, so nobody can change the image's files, the server's code among them. Only the data volume, for the SQLite database and its WAL files (`-wal`, `-shm`), and `/tmp` stay writable. With Postgres, madAuth writes no files at all.
- **`tmpfs: [/tmp]`** (`--tmpfs /tmp`): temporary files go to memory, and are gone when the container stops.
- **`cap_drop: [ALL]`** (`--cap-drop ALL`): no Linux capabilities, not even for a process that becomes root. The server needs none.
- **`security_opt: [no-new-privileges:true]`** (`--security-opt no-new-privileges`): no process gains privileges through a setuid program such as `su`, so the `node` user stays unprivileged.
- **`ulimits: { core: 0 }`** (`--ulimit core=0`): no core dumps. A core dump is a copy of the server's memory, written to a file when it crashes.

With `docker run`:

```bash
docker run --rm -p 8787:8787 --env-file .env -v madauth-data:/data \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  ghcr.io/inouiw/madauth-server
```

On the host, for Docker and for Node alike:

- **No swap, or encrypted swap.** The kernel may write any part of the server's memory to swap, where it stays after the server stops. Turn swap off (`swapoff -a`, and remove it from `/etc/fstab`) or encrypt it. In Docker, you can keep just the container out of swap instead: give `--memory-swap` the same value as `--memory` (`memswap_limit` and `mem_limit` in compose).
- **Never `--inspect`, and no heap snapshots in production.** `--inspect` opens a debugger that reads all of the server's memory; a heap snapshot (`--heapsnapshot-signal`, `--heapsnapshot-near-heap-limit`, `v8.writeHeapSnapshot()`) writes it to a file. Check `NODE_OPTIONS` too. Node also starts the debugger when it gets the signal `SIGUSR1`, which any process of the same user can send; `--disable-sigusr1` (Node 22.14 or newer) turns that off: `NODE_OPTIONS=--disable-sigusr1 npx @madauth/server start --env-file .env`.
- **No core dumps.** In Docker, the `ulimits` setting above. With Node on the host, run `ulimit -c 0` before you start it, or set `LimitCORE=0` in its systemd unit. When `/proc/sys/kernel/core_pattern` starts with `|`, the kernel hands each crash to that program whatever the limit, for containers too. systemd-coredump keeps no dump at a limit of 0; check any other.

AWS Lambda and Azure Functions need none of this: the platform runs the code in managed, isolated environments.

## Webhooks

madAuth calls one URL of yours, `WEBHOOK_URL`, to send e-mails, to let you decide on sign-ups, and to tell you what happened. This works the same in Docker, Lambda and Azure, and the receiver can be written in any language.

Each call is a `POST` with a JSON body `{ "type": "…", "data": { … } }`:

| `type` | When | `data` | Your answer | If it fails (no 2xx within the time, or unreachable) |
| --- | --- | --- | --- | --- |
| `email.send_verification` | Sign-up, or "send the e-mail again" | `to`, `link`, `code`, `expiresAt`, `site`, `locale`, `user { id, name }` | 2xx within 10 s, once you have taken over the e-mail (e.g. your mail service accepted it) | The request fails with `503 temporarily_unavailable`, and the user sees that e-mails can't be sent right now. They can retry at once. |
| `email.send_password_reset` | "Forgot password?" | the same | the same | the same |
| `email.send_signin_link` | A sign-in with the [e-mail link](email-link-security.md): the link signs in, the code too | the same (the link lives 15 minutes) | the same | the same |
| `email.send_already_registered` | Sign-up with an address that already has a confirmed account | `to`, `link` (the sign-in page), `site`, `locale`, `user`, `methods` (how the user signs in, e.g. `["google"]`) | the same | the same |
| `email.send_password_reset_no_password` | "Forgot password?" for a user without a password, who signs in with Google, GitHub, the e-mail link or the authenticator app: tell them so | the same | the same | the same |
| `sms.send_code` | An [SMS code](sms-security.md): confirming a new number (`setup`), the second step of a sign-in (`signin`), or approving a change to the number (`approve`) | `to` (the number, E.164), `code`, `purpose`, `expiresAt`, `site`, `locale`, `user { id, name }` | 2xx within 10 s, once your SMS service accepted it | `503 temporarily_unavailable`; the user can retry at once |
| `user.signing_up` | Before a user is created: a sign-up with a password, with the authenticator app or with a passkey, the first Google or GitHub sign-in of an address nobody has, or the first e-mail link for one | `email`, `name`, `locale`, `method` (`password`, `google`, `github`, `authenticator`, `email-link` or `passkey`) | 2xx within 10 s. `{ "allow": false, "message": "…" }` refuses the sign-up and the user sees your message (`403 signup_rejected`); any other 2xx allows it. | The sign-up is refused with `503 temporarily_unavailable`: without your answer, nobody signs up. |
| `user.signed_up` | A user's sign-up is complete: their first session started, so they have their sign-in method and every second factor its policy requires. Sent once per user, before that sign-in's `user.signed_in`. | `user`, `method` | 2xx within 5 s | Logged; the request still succeeds. |
| `user.email_verified` | An address was confirmed with the link or code of `email.send_verification` or `email.send_signin_link` | `user`, `method` (`password`, `authenticator`, `passkey` or `email-link`), `via` (`link` or `code`) | the same | the same |
| `user.password_reset` | A password was reset (older sessions end) | `user` | the same | the same |
| `user.password_changed` | A signed-in user changed their password (their other sessions end) | `user` | the same | the same |
| `user.signed_in` | Someone signed in, including after confirming or resetting | `user`, `method` (`password`, `google`, `github`, `authenticator`, `email-link` or `passkey`), `secondFactor` (`passkey`, `authenticator`, `recovery_code` or `sms`, when there was a second step) | the same | the same |
| `user.deleted` | A user deleted their account | `user` | the same | the same |
| `user.claims_changed` | An admin set the claims of a user, or [`INITIAL_ADMIN_EMAIL`](#the-first-admin) gave a user the role `admin` | `user` (with the new claims), `claims`, `by` (the admin's address, or `INITIAL_ADMIN_EMAIL`), `byApiKey { id, name }` (when the admin used an [API key](api-keys.md)) | the same | the same |
| `user.second_factor_enabled` | A user set up or replaced a second factor: the authenticator app as the second step of their sign-in method, or a phone number for SMS codes | `user`, `method` (`authenticator` or `sms`), `phone` (for `sms`) | the same | the same |
| `user.second_factor_disabled` | A user removed a second factor | `user`, `method` (`authenticator` or `sms`) | the same | the same |
| `user.recovery_code_used` | A recovery code was used instead of the app | `user`, `remaining` (recovery codes left) | the same | the same |
| `user.method_added` | A signed-in user added a [sign-in method](sign-in-methods.md): a password, the e-mail link, Google, GitHub or a passkey | `user`, `method`, `email` (Google's or GitHub's address), `passkey { id, name }` (for a passkey) | the same | the same |
| `user.method_removed` | A user removed one | `user`, `method`, `passkey { id, name }` (for a passkey) | the same | the same |
| `user.sign_in_reset` | An admin [reset the sign-in](#resetting-a-users-sign-in) of a user: their methods and second factors are gone, and they sign up again | `user`, `by` (the admin's address), `byApiKey { id, name }` (when the admin used an API key) | the same | the same |
| `user.api_key_created` | A user made an [API key](api-keys.md) | `user`, `apiKey { id, name, scopes, createdAt, expiresAt, lastUsedAt }` (never the key itself) | the same | the same |
| `user.api_key_revoked` | A user or an admin revoked one | `user`, `apiKey { id, name }`, `by` (the admin's address, when an admin revoked it) | the same | the same |
| `provider.added`, `provider.changed`, `provider.removed` | An admin, or the [setup token](#first-setup), added, changed or removed a [sign-in provider](#providers) | `provider { id, kind, name, clientId, hasClientSecret, callbackUrl, createdAt, updatedAt }` (never its secret), `by` (the admin's address; null for the setup token, with `bySetupToken: true`) | the same | the same |

- The prefix says what a call is: `email.send_*` and `sms.send_*` hand over a message for you to send, `user.signing_up` asks you to decide, and the other `user.*` types tell you what happened.
- A user signs up with one method and can [add more](sign-in-methods.md) while signed in (`user.method_added`). The authenticator app and SMS codes are told as second factors (`user.second_factor_*`), whether or not the app also signs in on its own; setting up or replacing the app a user signed up with is part of their sign-up (`user.signed_up`), so no `user.second_factor_*` is sent for it, nor `user.method_added` for the passkey a user signs up with.
- `link` already contains the token: send it as it is. `code` is the 6-digit code, `site` the app's host (e.g. `app.example.com`), `locale` the user's language (e.g. `de-CH`) if known: the `locale` your app passed to `Madauth.initialize`, else the page's or the browser's language.
- Only the types in `WEBHOOK_EVENTS` are sent, so list what your receiver handles. E-mail & password sign-in is on when `email.send_verification` and `email.send_password_reset` are in the list, the e-mail link when `email.send_signin_link` is, SMS codes when `sms.send_code` is; a receiver that only wants events (e.g. `user.signed_in`) is fine on a Google-only server.
- Without `email.send_already_registered` in the list, a sign-up with an address that already has a confirmed account is answered like any other and no e-mail is sent; the same goes for `email.send_password_reset_no_password` and "Forgot password?" for a user without a password. Keep both in the list unless your receiver can't send them: without them the answer comes faster for such an address, see [Password security](password-security.md#no-account-enumeration). Without `user.signing_up`, every sign-up is allowed.
- madAuth waits for each call before it answers the browser, because AWS Lambda stops a function as soon as it has answered. Keep receivers fast.

### Signatures

With `WEBHOOK_SECRET`, every call is signed in the [Standard Webhooks](https://www.standardwebhooks.com/) format, so you can use their libraries in many languages. The headers are `webhook-id`, `webhook-timestamp` and `webhook-signature` (`v1,` and the base64 HMAC-SHA256 of `<id>.<timestamp>.<body>`, keyed with the base64 part of `WEBHOOK_SECRET` after `whsec_`).

Verify each call against the **raw** body before you trust it, and reject calls older than five minutes. In JavaScript:

```ts
import { verifyWebhook } from '@madauth/server/webhook';

const body = await request.text();
if (!verifyWebhook(process.env.WEBHOOK_SECRET!, request.headers, body)) return new Response(null, { status: 401 });
const { type, data } = JSON.parse(body);
```

The calls contain e-mail links and codes, so `WEBHOOK_URL` must be https, except for a receiver on the same machine (`localhost`, `127.0.0.1`, or `host.docker.internal` from a Docker container). Calls with the same `webhook-id` are the same call; madAuth does not retry by itself.

### Changing the webhook secret

madAuth and the receiver share `WEBHOOK_SECRET`, so changing it in one place would make the receiver refuse every call until the other has it too: no e-mails, and with `user.signing_up` no sign-ups. To change it without such a gap, e.g. after it may have leaked:

1. Generate a new secret (`npx @madauth/server generate-webhook-secret`). Set it as `WEBHOOK_SECRET`, and the old one as `WEBHOOK_PREVIOUS_SECRET`, and restart madAuth (every instance). Each call now carries two signatures in its `webhook-signature` header, separated by a space, as [Standard Webhooks](https://www.standardwebhooks.com/) allows; a receiver with either secret accepts it. madAuth logs a reminder at start while the previous secret is set.
2. Give the receiver the new secret.
3. Remove `WEBHOOK_PREVIOUS_SECRET` and restart madAuth.

This needs a receiver that accepts any one of several signatures, as the specification says: `verifyWebhook` does, and so do the Standard Webhooks libraries and the receivers of [madAuth-webhooks](https://github.com/inouiw/madAuth-webhooks). On AWS with the template, see [Changing the webhook secret](../deploy/aws/README.md#changing-the-webhook-secret).

### AWS IAM

When madAuth runs on AWS and the receiver is a Lambda function with a Function URL, IAM replaces the shared secret. With `WEBHOOK_AUTH=aws-iam`, madAuth signs each call with [Signature Version 4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html) (service `lambda`), with the credentials of its environment: on Lambda its function's role, elsewhere what the AWS SDK's default chain finds, e.g. the role of an ECS task or EC2 instance. The Function URL has `AWS_IAM` auth, so AWS refuses a call that isn't signed by a principal allowed to invoke it before the receiver runs. Nobody has a secret that could make the receiver act as if madAuth called: the role's credentials are temporary, AWS rotates them, and nobody copies them.

- `WEBHOOK_URL` is the Function URL, `https://<id>.lambda-url.<region>.on.aws/`; madAuth signs for its region.
- `WEBHOOK_SECRET` and `WEBHOOK_PREVIOUS_SECRET` must not be set: madAuth refuses to start with a secret and `WEBHOOK_AUTH=aws-iam`. The calls carry `webhook-id` and `webhook-timestamp` as before, and no `webhook-signature`.
- madAuth's role needs both of these on the receiver's function (Lambda checks both for Function URLs made since October 2025):

  ```json
  [
    {
      "Effect": "Allow",
      "Action": "lambda:InvokeFunctionUrl",
      "Resource": "<the receiver's function ARN>",
      "Condition": { "StringEquals": { "lambda:FunctionUrlAuthType": "AWS_IAM" } }
    },
    {
      "Effect": "Allow",
      "Action": "lambda:InvokeFunction",
      "Resource": "<the receiver's function ARN>",
      "Condition": { "Bool": { "lambda:InvokedViaFunctionUrl": "true" } }
    }
  ]
  ```

- The receiver checks who called: AWS lets every principal of its account whose policy allows it invoke the URL, e.g. an admin, and passes the caller in the event (`requestContext.authorizer.iam.userArn`, for a role `arn:aws:sts::<account>:assumed-role/<role name>/<session>`). The [aws-ses-mailer](https://github.com/inouiw/madAuth-webhooks/tree/main/aws-ses-mailer) accepts only madAuth's role, whose ARN it gets as `MADAUTH_ROLE_ARN`.
- The two AWS SDK packages it takes are loaded only then: `@smithy/signature-v4` and `@aws-sdk/credential-provider-node`. The Lambda bundle and the Docker image have them; with the npm package elsewhere, install them next to madAuth.

The [AWS template](../deploy/aws/README.md) sets this up for a receiver in the same account.

## Sessions

A session has two lifetimes: how long your backends trust it, and how long the user stays signed in. They are separate, so the first can be short without making users sign in again.

Signing in sets three cookies:

| Cookie | Lifetime | What it is |
| --- | --- | --- |
| `madauth_session` | `SESSION_TTL` (8 hours) | The session token, a signed JWT. Your backends verify it without asking madAuth. HttpOnly. |
| `madauth_renewal` | `SESSION_RENEWAL_TTL` (30 days) | The renewal token. It gets a new session token when the old one has expired or is about to. HttpOnly, and only sent to the madAuth server: its path is `/auth`, and it has no domain even with `COOKIE_DOMAIN`. Your backends never see it. |
| `madauth_session_expires` | `SESSION_RENEWAL_TTL` | When the session token expires, in seconds since 1970, for the web library. Scripts can read it; it holds no secret. |

**Renewal.** `GET /auth/session` renews the session when its token is missing, has expired or has passed half of its lifetime, if the request carries a valid renewal token. Before it does, the server checks again: the user still exists, no password reset happened since, and which [claims](#claims) they have now. Then it sets all three cookies anew. So a password reset, a deleted account and changed claims reach your backends within `SESSION_TTL` at the latest, while an active user stays signed in.

Each renewal starts the renewal time again: a user who opens your app at least every 30 days stays signed in. Without a visit in that time, they sign in again.

**In the browser**, the web library renews the session when the page loads and when you call `Madauth.sessionReady()`. A page that has been open for hours, or is opened after hours, may hold an expired session token. Wait for the renewal before you call your own backend:

```ts
await Madauth.sessionReady(); // at once while the session is valid, or when nobody is signed in
const response = await fetch('/api/orders');
```

A backend that answers 401 although the user is signed in met a session that expired in between: call `Madauth.sessionReady()` and send the request once more.

**What renewal can't do.** Whoever has both cookies stays signed in until the renewal token expires or the password is reset. A password reset ends every session of the user, also those started with Google. A session token issued by madAuth 0.1 has no renewal token, and one issued by madAuth 0.2 for a Google user belongs to an id that no longer exists: either lasts until it expires, and then the user signs in again.

## Claims

Claims are what admins attach to a user, as a JSON object, e.g. `{ "roles": ["admin"], "plan": "pro" }`. madAuth puts them into the session, so your app and your backends can tell what a user may do or has. What a claim means is up to you; madAuth only knows the role `admin` in `claims.roles`: the role that may manage claims and settings, and [reset a user's sign-in](#resetting-a-users-sign-in).

- Claims belong to the **user**, whichever way they sign in: with Google as well as with a password.
- The session carries them as `claims` (a `claims` claim in the JWT). `createSessionVerifier` returns them as `user.claims`, and the web library as `Madauth.currentUser.claims`. A user without claims has no `claims` field.
- A claims object has at most 2048 characters as JSON. Its keys are names: letters, digits and `_`, starting with a letter, at most 64 characters. `roles`, if present, is a list of role names: lower-case letters, digits, `-` and `_`, starting with a letter, at most 32 characters, at most 20 of them. Other values can be anything JSON carries.

**Admins manage claims** from your app with the web library, or with the HTTP API:

```ts
await Madauth.admin.setClaims('ada@example.com', { roles: ['editor'], plan: 'pro' }); // replaces her claims; {} removes them
const result = await Madauth.admin.getClaims('ada@example.com'); // { isSuccess: true, userId: 'usr_…', claims: { … } }
```

Whether the caller is an admin is asked from the store each time, not read from their session, so a removed `admin` role stops counting at once.

A program calls the admin API with an admin's [API key](api-keys.md#on-madauths-admin-api) instead of a session (`Authorization: Bearer madauth_…`), limited to the key's scopes, one per admin task, e.g. `madauth:claims:read`.

**When a change shows.** The claims of a session token are from the moment it was issued. The madAuth server reads them again whenever the app checks the session (`GET /auth/session`, e.g. on page load) and at every [renewal](#sessions), and issues a new session token if they changed. Your own backends, which verify the token offline, see the change from that moment, and after `SESSION_TTL` at the latest.

### The first admin

Set `INITIAL_ADMIN_EMAIL` to your address, like every other variable: in `.env` (`init` asks for it), in the container's environment, or on AWS in `cdk.json` (see [`deploy/aws`](../deploy/aws/README.md#3-configure-and-deploy)). When the user with that address signs in and the address is proven (confirmed by e-mail, or verified by Google or GitHub; a sign-up nobody finished gets nothing), madAuth adds `admin` to their `roles`, keeps their other claims, and tells your webhook: `user.claims_changed` with `by: "INITIAL_ADMIN_EMAIL"`. Their session carries the role from that sign-in on; a user who is signed in already when you set the variable gets it at their next sign-in. See [`admins.ts`](../packages/server/src/admins.ts).

- **Once per value.** madAuth records in the settings which values it applied, and the write decides, so two sign-ins at once apply a value once. A value that was applied does nothing afterwards, also when it names someone who is no longer an admin, or no longer a user: from then on, roles are managed through the admin API only. A new value applies again: that is the way back in when no admin is left, or the only one is locked out.
- **Existing admins keep their role**: it is stored in their claims. A deployment without an admin sets the variable.
- **No admin takes the role from themselves.** The admin API refuses to take `admin` from the admin who calls it, and an admin can't delete their own account while they have the role (`403 own_admin_role`): another admin has to. So a lone admin keeps the role. Give a second user the role, so that one admin can help the other, e.g. [reset their sign-in](#resetting-a-users-sign-in). Two admins who take the role from each other at the same moment can still leave no admin; then set a new `INITIAL_ADMIN_EMAIL` value.

## Sign-in methods

madAuth has these methods, named by these ids in the settings:

| Id | Method | In the web library |
| --- | --- | --- |
| `google` | Google sign-in (One Tap / FedCM, the redirect flow, or an ID token the app obtained itself) | `GoogleFedcm`, `GoogleRedirect`, `Madauth.google` |
| `github` | [GitHub sign-in](github-security.md) (the redirect flow) | `GitHub`, `Madauth.github` |
| the provider's id, e.g. `gitlab` | An [OpenID Connect provider](#openid-connect-provider-setup) an admin added (the redirect flow) | `Madauth.provider(id)` |
| `password` | E-mail & password | `Password`, `Madauth.password` |
| `email-link` | The passwordless [e-mail link](email-link-security.md) (the address, then the link or the code from the e-mail) | `EmailLink`, `Madauth.emailLink` |
| `passkey` | [Passkeys](#passkeys) (WebAuthn): on their own, and as a second factor | `Passkey`, `Madauth.passkey`, `Madauth.showSetUpPasskeyDialog()` |
| `authenticator` | The [authenticator app](#authenticator-app): on its own (the e-mail address and a code from the app), and as a second factor | `Authenticator`, `Madauth.authenticator`, `Madauth.showSetUpAuthenticatorDialog()` |
| `sms` | [SMS codes](sms-security.md): a second factor only | `Madauth.sms`, `Madauth.showSetUpSmsDialog()` |

Which methods the server can offer: Google, GitHub and the OpenID Connect providers when they are [providers](#providers) in the store, the webhook that sends the e-mails for password sign-in, for the e-mail link and for sign-up with the app or a passkey alone, and `sms.send_code` for SMS codes; the app and passkeys need nothing but the store. Which of them are on is a setting in the database that admins change while the server runs, at once and for every instance: the list of the methods that are on, each with two settings, both always given. A method that is not in the list is off.

| Setting | Values | |
| --- | --- | --- |
| `allowAsSignInMethod` | `true`, `false` | Whether the method signs a user in on its own. Google, GitHub, the OpenID Connect providers, password and the e-mail link always do (`true`), SMS codes never (`false`). The authenticator app and passkeys either sign in on their own (`true`), or are only a second factor (`false`). |
| `secondFactor` | `none`, `optional`, `required` | Whether a sign-in with the method asks for a second factor; `none` for a method that does not sign in, and for the app, which is a second factor itself. |

| `secondFactor` | |
| --- | --- |
| `none` | The method signs in on its own. |
| `optional` | A user who has a second factor (a passkey, the app, a phone) is asked for it after this method; a user with none signs in as before. Setting a factor up never makes an account weaker. |
| `required` | Everyone is asked for a second factor. A user with none sets one up at their next sign-in, before they are in: a passkey, the app or a phone, whichever are on. |

The second factors are passkeys, the app and SMS codes: each one is a second factor when its method is on, whether or not it also signs in on its own. A policy other than `none` needs one of them on, other than the method itself: a passkey is no second factor of a passkey sign-in. When a user has several, the sign-in asks for the one they prefer (`Madauth.secondFactor.setPreferred`, or the select in the methods dialog), otherwise for the first of passkey, app and phone, and the dialog offers the switch.

A user can have [several sign-in methods](sign-in-methods.md): the one they signed up with, and those they added while signed in. Each of them signs the user in while the settings allow it as a sign-in method. So allowing the app or passkeys as a sign-in method lets every user who has one sign in with it alone, also those who set it up as a second factor: that is the admin's decision, and a policy (`authenticator` takes none; `passkey=required`) keeps asking for more.

Until an admin sets the list, a server runs its configured methods Google, GitHub, password and/or the e-mail link, without a second factor, and SMS codes when the webhook sends them; a server that only has the webhook runs the authenticator app alone. Passkeys and the app are off until they are listed. A list stored by madAuth before 0.6 keeps its meaning, except for the app on its own next to other methods: it is a second factor only until an admin saves the methods again, see [Upgrading](upgrading.md#to-06).

A method that is off is not shown by the web library (`GET /auth/config` reports it as `null`), and its routes answer `403 method_disabled` (the `start` and `callback` routes of the redirect flows send the browser back to the app with `madauth_error=method_disabled` instead, since it is on its way there); a sign-in that was between its two steps ends too. Existing sessions continue. At least one method that creates users stays on: Google, GitHub, an OpenID Connect provider, e-mail & password, the e-mail link, or the app or passkeys allowed as a sign-in method on a server whose webhook confirms addresses (on another server, the app or passkeys alone would let in only the users who have one).

From your app with the web library, or with the HTTP API:

```ts
// The list replaces the old one: what is sent is what is on, each with both settings.
const signIn = (secondFactor: 'none' | 'optional' | 'required' = 'none') => ({ allowAsSignInMethod: true, secondFactor });
const secondFactorOnly = { allowAsSignInMethod: false, secondFactor: 'none' } as const;
await Madauth.admin.setSettings({
  methods: { google: signIn(), github: signIn('optional'), password: signIn('optional'), 'email-link': signIn('required'), passkey: signIn(), authenticator: secondFactorOnly, sms: secondFactorOnly },
});
const result = await Madauth.admin.getSettings();
// { isSuccess: true, methods: { google: { configured, enabled, allowAsSignInMethod, secondFactor }, github: { … }, … } }
```

To switch one method on or off without sending the whole list, `setMethod` changes only its entry, so what another admin changes meanwhile stays (`POST /auth/admin/settings/method`):

```ts
await Madauth.admin.setMethod('gitlab', { allowAsSignInMethod: true, secondFactor: 'optional' });
await Madauth.admin.setMethod('gitlab', null); // off
```

## Password rules

The rules for new passwords, at sign-up, at a reset and when a user adds a password, are a setting too, so admins change them while the server runs and the ready-made bundles need no code for them:

| Rule | Default | |
| --- | --- | --- |
| `minLength` | `8` | The fewest characters, from 1 to 128. A password has at most 256. |
| `minScore` | `2` | How hard to guess it must be, 0 to 4, as [zxcvbn-ts](https://zxcvbn-ts.github.io/zxcvbn/) rates it: `0` checks the length only, `2` refuses common passwords and simple patterns, `3` asks for noticeably stronger ones. |

The rating knows about 49,000 common passwords, keyboard patterns (`qwertz`), repeats and sequences, dates, l33t (`P@ssw0rd`) and passwords close to these, and counts the user's e-mail address and name as easy to guess. It runs inside madAuth: the password goes nowhere. `password1234` and `summer2024` score 1, `Sommer2024!` 3, `correct horse battery` 4. There are no rules like "one digit and one symbol", see [Password security](password-security.md#password-rules).

```ts
// What is left out takes its default.
await Madauth.admin.setSettings({ password: { minLength: 10, minScore: 3 } });
const result = await Madauth.admin.getSettings();
// { isSuccess: true, methods: { … }, password: { minLength: 10, minScore: 3 } }
```

The web library gets the rules with the configuration, as `Madauth.password.policy`, for the hint under the field. The dialog shows a strength meter under a new password, rated with the same zxcvbn-ts options, so it says before sending whether the server will accept the password; it loads zxcvbn-ts (about 220 kB compressed) only when the user starts typing one. A password that breaks them is answered `400 weak_password`, with `minLength` (too short) or `minScore` (too easy to guess) next to the English `message`, so the dialog can say it in the user's language. The rules apply to new passwords only: existing ones keep working.

## Authenticator app

The authenticator app (TOTP, RFC 6238: Google Authenticator, 1Password, Microsoft Authenticator and the like) needs no configuration beyond the store; `AUTHENTICATOR_ISSUER` only sets the name the app shows next to the account (and the one the browser shows for a new passkey). What it does is the [sign-in policy](#sign-in-methods) above.

**Setting it up.** A signed-in user calls `Madauth.showSetUpAuthenticatorDialog()` (within two minutes of signing in, like every [sensitive change](sign-in-methods.md#only-within-two-minutes-of-signing-in)) (a custom screen: `Madauth.authenticator.startSetup()` and `confirmSetup()`). The server makes a new secret and the web library shows it as a QR code (an `otpauth://` URI) and as text; the first code from the app proves the setup. The user then gets ten recovery codes to save, each good for one sign-in without the app. A new setup replaces an earlier app and its recovery codes, so it takes a current code from the old app (or a recovery code) first, like removing it. With a `required` policy, a user without the app is taken into the setup at their next sign-in, before they are in. A sign-up with the app alone (`Madauth.authenticator.signUp`; the server must confirm addresses by e-mail) confirms the address first and then sets the app up.

**Signing in.** After a method whose policy asks for it, the server answers `401 authenticator_required` (or `second_factor_setup_required`, with the `factors` the user can set up) instead of a session and sets a ten-minute challenge cookie; the dialog asks for the code, and `POST /auth/authenticator/verify` finishes the sign-in. With the app allowed as a sign-in method, `POST /auth/authenticator/signin` takes the e-mail address and a code, for every user who has the app. A recovery code works wherever a code does, once; `user.recovery_code_used` tells your webhook how many are left.

**Removing it.** `Madauth.authenticator.remove(...)` and `newRecoveryCodes(...)` take a current code from the app or a recovery code, so a stolen session can't switch the protection off; while any method's policy is `required`, the app can only go if the user keeps another second factor, a passkey or a phone for [SMS codes](#sms-codes) (`403 required_by_policy`), and it can't go as the user's last way to sign in (`403 only_method`; they add another method, or delete the account). Deleting the account takes a code as well once the app is set up, while the app is on. A user who lost both the phone and the recovery codes needs an admin, who [resets their sign-in](#resetting-a-users-sign-in).

The session says how it was authenticated: `amr` is `["pwd", "otp"]`, `["google", "otp"]`, `["github", "otp"]`, `["email", "otp"]` or `["passkey", "otp"]` after the second step and `["otp"]` for the app alone, as `user.amr` in the web library and in [`createSessionVerifier`](#verifying-the-session-in-your-backend). A backend can require `otp` before a sensitive action.

The secrets are stored encrypted by the [key service](#signing-key): a copy of the database alone gives no codes. Rotating the signing key keeps them working (see [Rotating the signing key](#rotating-the-signing-key)); replacing it with an unrelated key makes every enrolled app stop working until it is set up again. See [Authenticator app security](authenticator-security.md) for the rules in detail.

## SMS codes

With `sms` among the [sign-in methods](#sign-in-methods) and a webhook that sends `sms.send_code`, a code sent to the user's phone is a second factor next to the app, for the methods whose policy asks for one. It is never a sign-in method of its own: a phone is added to an account that has a first factor.

**Setting it up.** A signed-in user calls `Madauth.showSetUpSmsDialog()` (a custom screen: `Madauth.sms.setUp({ phone })` and `confirmSetup({ code })`): the server sends a code to the number, and the code confirms it; nothing is stored before. The number must be given with the country code and is kept in E.164 form; madAuth shows only its beginning and last two digits. Replacing the number takes a code sent to the current one first (`Madauth.sms.send()`, then `setUp({ phone, code })`), like removing it. With a `required` policy, a user without any factor can add a phone at their next sign-in instead of the app.

**Signing in.** After the first step, a user with only a phone gets `401 sms_required`; one with the app and a phone gets `authenticator_required` with `factors: ["authenticator", "sms"]` and can switch (a passkey comes first: `passkey_required`). The SMS goes when the client asks for it (`POST /auth/sms/send` with the challenge cookie), and `POST /auth/sms/verify` finishes the sign-in with `amr` ending in `sms`. One SMS per minute goes to a user (`429 too_soon`); a code lives ten minutes.

**Removing it.** `Madauth.sms.remove({ code })` takes a code sent to the number (`Madauth.sms.send()` while signed in). While a policy is `required`, the phone can only go if the user keeps another second factor, the app or a passkey (`403 required_by_policy`). A user who lost the phone needs an admin, who [resets their sign-in](#resetting-a-users-sign-in). Deleting the account takes no SMS code (only the app protects the deletion). See [SMS code security](sms-security.md) for the rules in detail.

## Passkeys

A passkey (WebAuthn) signs in with the device's screen lock: a fingerprint, the face, or a PIN, which the device checks before it signs; the private key never leaves the device or the user's password manager, and it only answers the site it was made for, so it can't be phished. With `passkey` among the [sign-in methods](#sign-in-methods), passkeys need no configuration but, optionally, the domain they belong to:

- `PASSKEY_RP_ID` (optional): the domain of the passkeys, e.g. `example.com` for apps on `example.com` and its subdomains. Without it, a passkey belongs to the host of the app that made it and works there only. Changing it later makes existing passkeys stop working: set it before users add any. **Users who signed up with a passkey alone and have no other method are locked out by a change** until an admin [resets their sign-in](#resetting-a-users-sign-in) and they sign up again.

**Adding one.** A signed-in user calls `Madauth.showSetUpPasskeyDialog()` (a custom screen: `Madauth.passkey.add({ name })`), within two minutes of signing in: later, `401 reauth_required` asks them to sign in again first, so a session someone took over gives them no passkey of their own. The browser shows its passkey dialog; the passkey is stored with its public key and a name the user can change. With a `required` policy and passkeys on, a user without a second factor can add one at their next sign-in instead of the app or a phone. Every user can have several passkeys: a phone, a laptop, a security key.

**Signing up with one.** With passkeys allowed as a sign-in method and a webhook that confirms addresses (`email.send_verification`), people can sign up with a passkey alone, like with the [authenticator app](#authenticator-app) alone: `Madauth.passkey.signUp({ email, name? })` (`POST /auth/passkey/signup`) sends the confirmation e-mail, and the link or the code (`/auth/email/verify`) leads to the creation of the passkey (`401 passkey_setup_required`, see [The second step](#the-second-step)); the new passkey is the user's sign-in method and signs them in. In the dialog, "Create account" offers it as "Use a passkey instead of a password" (and under the passkey button when there is no password form). With a `passkey` policy that asks for a second factor, the sign-up goes on with its setup. `GET /auth/config` says whether the server offers it (`passkey.signUp`).

**Signing in.** With passkeys allowed as a sign-in method and `new Passkey()` in `Madauth.initialize`, the dialog shows a "Sign in with a passkey" button above all other methods and offers the user's passkeys in the e-mail field's autofill (`Madauth.passkey.signIn()`, with `{ conditional: true }` for the autofill): no address is asked for. The `passkey` policy may ask for a second factor after it, the app or a phone. As a second factor, a passkey comes first: `401 passkey_required`, and `Madauth.passkey.verify()` finishes the sign-in. The session's `amr` is `["passkey"]`, or e.g. `["pwd", "passkey"]` after the second step.

**Removing one.** The user removes a passkey with `Madauth.methods.remove(id)`, within two minutes of signing in; not their last one while a `required` policy has no other second factor of theirs to ask for (`403 required_by_policy`), nor their last way to sign in (`403 only_method`). A user who lost their passkeys needs another method, or an admin, who [resets their sign-in](#resetting-a-users-sign-in); they then sign up again, with a passkey too, and keep their id. There is no recovery by e-mail alone, which would make a passkey-only account only as strong as the inbox. See [Passkey security](passkey-security.md) for the rules in detail.

## A user's sign-in methods

A user signs up with one method and can add more while signed in: a passkey, a password (`Madauth.password.add`), the e-mail link (`Madauth.emailLink.add`), Google or GitHub (their buttons with `purpose: 'link'`), the authenticator app. `Madauth.showManageSignInMethodsDialog()` opens all of this in the dialog: the user's methods, buttons to add another and to remove one, and for the authenticator app a view with the recovery codes left, new recovery codes, a new app in its place, and removing it. See [Several sign-in methods](sign-in-methods.md) for the rules.

## Resetting a user's sign-in

A user who lost every way in, or a second factor they can't sign in without (the app and its recovery codes, the phone for SMS codes, the passkeys), needs an admin. `Madauth.admin.resetSignIn(email)` in the web library (`POST /auth/admin/sign-in/reset`) resets their sign-in, whatever they had:

- Every sign-in method and second factor of the user goes: the password, Google, GitHub, the e-mail link, the authenticator app with its recovery codes, the phone, the passkeys. GitHub's authorization is taken back at GitHub, as when the user removes GitHub or deletes the account; a failure is logged, and the reset goes ahead.
- Every session of the user ends, and every sign-in that waits for its second step (the session version goes up). Their pending confirmation, reset and sign-in links and SMS codes stop working, and wrong codes count from zero.
- The address counts as unconfirmed, so the next sign-up proves the inbox again.
- The user stays: their id (`usr_…`), address, name, claims and roles. Their sign-up stays complete: no second `user.signed_up`.

The user then signs up again with any method that is on, and gets the same id. The rules for a sign-up nobody finished apply: until one proves the address, the latest sign-up wins, and a Google or GitHub sign-in with the address takes the user over. `user.sign_in_reset` tells your webhook, with the admin's address as `by`. There is no command for it: an admin calls it from your app. An admin who resets themselves is signed out. An admin who lost their own way in is reset by another admin. With no admin who can sign in, set a new `INITIAL_ADMIN_EMAIL` value (see [The first admin](#the-first-admin)): the new admin then resets the old one.

**Check who is asking before a reset.** Afterwards the address is all it takes: whoever proves it next (with the e-mail, or a Google or GitHub account with the address) gets the account, with its id, your app's data under that id, and its roles, `admin` too. Someone who took over the user's mailbox and asks for a reset gets past the app, the phone and the passkeys that protected it. Confirm that the request comes from the user in a way that doesn't rest on the mailbox alone.

Code: `resetSignIn` in [`users.ts`](../packages/server/src/users.ts), `/auth/admin/sign-in/reset` in [`app.ts`](../packages/server/src/app.ts).

## Searching users

`Madauth.admin.searchUsers(search)` in the web library (`POST /auth/admin/users/search`) finds users for admins: who has a role, the user with an address, who signed up when, or every user, e.g. for a list on an admin screen. Every filter given must match:

- `role`: users whose `claims.roles` hold the role.
- `email`: the user with this address (exact, ignoring case).
- `signedUpAfter`, `signedUpBefore`: users whose sign-up was complete after or before this time, in milliseconds since 1970. Users whose sign-up is older than madAuth 0.5, which records the time, count from when they were created. A pending sign-up has no time, so it matches neither.
- `pending`: `true` for sign-ups whose address isn't confirmed yet, `false` for complete ones; both without it.

Each user comes with `id`, `email`, `name`, `emailVerified`, `claims`, `methods` (their sign-in methods and second factors, e.g. `["passkey", "password"]`), `signedUpAt` (`null` while pending) and `pending`. A page holds at most `limit` users (1 to 100, default 50), in no particular order. With a `cursor` in the answer, there may be more: pass it in the next search. A search reads at most a thousand users per call, so a page may hold fewer users than `limit`, or none, and still have a cursor. A filter madAuth doesn't have is refused (`400 invalid_search`), so a typo never finds everyone. Programs search with an admin's [API key](api-keys.md) with the scope `madauth:users:read`.

**It reads every user.** Except for an address, which is one lookup, the search reads the users page by page (the adapter's [`scan`](#custom-store-adapter)) and filters them. That works on every store and needs no index, but its cost grows with the number of users. On DynamoDB a scan reads the whole table, the sign-in methods and pending links too, strongly consistent: 10,000 users are about 40,000 items, read in a second or two for a fraction of a cent. That is fine for admins now and then, not for a page every visitor opens.

**What it finds is for showing.** It may be outdated by the time it is shown. Of a search through several pages, each user who exists all along is in it once; one who signs up or is deleted meanwhile may be in it or not. No rule relies on it: e.g. that an admin can't take their own role is checked when the claims are set.

Code: [`user-search.ts`](../packages/server/src/user-search.ts).

## Deleting an account

`Madauth.deleteAccount()` in the web library (`POST /auth/account/delete`) lets a signed-in user delete their account:

- The user is deleted with all their sign-in methods (the password, the Google account, the GitHub account, the authenticator app with its recovery codes, the e-mail link, the phone number), their claims, and their pending confirmation, reset and sign-in links and SMS codes. The session proves who they are, whichever way they signed in.
- Once the user has an authenticator app, and while the app is on (a policy asks for it, or it signs in on its own), the request needs a current code from it or a recovery code (`Madauth.deleteAccount({ code })`; `401 code_required` without one): like removing the app, so a stolen session can't destroy the account.
- If the user had a Google account, the answer is `200 { googleSub }` (otherwise `204`). With `GoogleFedcm`, the web library revokes the app's access to that Google account by its id (`google.accounts.id.revoke`): the app leaves their connected apps at Google, and the Google button says "Sign in with Google" again instead of "Continue as …". A user without a Google account is never sent to Google.
- If the user had a GitHub account, the server revokes the OAuth App's authorization at GitHub with the access token it kept from their last sign-in (`DELETE /applications/{client_id}/grant`): madAuth leaves their authorized apps. This is best effort: when GitHub can't be reached or refuses, the deletion goes ahead and the server's log says so; the user can then remove the app under GitHub → Settings → Applications.
- The session cookie is cleared, and `user.deleted` is sent to the webhook if it is in `WEBHOOK_EVENTS`, with the user as the session held them.
- A user with the role `admin` can't delete their account (`403 own_admin_role`): another admin takes the role from them first, see [The first admin](#the-first-admin).

Delete the user's data in your own backend first, while the user is still signed in. Sessions on other devices end when the app next checks them; your own backends accept them until they expire (see [Password security](password-security.md#sessions)).

## Custom store adapter

Users are stored through a `StoreAdapter`. madAuth does all the security work (hashing, throttling, single-use links); an adapter only stores records. It has six methods:

```ts
interface StoreAdapter {
  create(model: string, data: Row): Promise<boolean>; // false, writing nothing, if a unique value or primary key exists
  findOne(model: string, where: Where): Promise<Row | null>;
  findMany(model: string, where: Where, opts?: { limit?: number }): Promise<Row[]>;
  update(model: string, where: Where, patch: Row): Promise<number>; // records changed
  delete(model: string, where: Where): Promise<number>; // records deleted; must be exact under concurrency
  scan(model: string, opts: { after?: string; limit: number }): Promise<Row[]>; // a page of all records of the model
}
// Row: { field: string | number | boolean | null }. Where: every field equals the value (null: is empty).
```

`scan` returns a model's records a page at a time, for admins only (it is how [searching users](#searching-users) reads them): at most `limit`, in an order of your choosing that stays the same, starting after the record whose id is `after`, which may have been deleted since. Fewer than `limit` means there are no more. Ordering by the primary key does all of this in SQL (`where id > $after order by id limit $limit`); the DynamoDB adapter scans the table, whose order is fixed, from the key of `after`.

The models and their fields are in `madauthSchema` (exported by `@madauth/server`): `user`, `account` (one per sign-in method of a user), `verification`, `setting`, `recoveryCode` and `apiKey`. The schema says nothing about how records are stored, so it fits any database. For SQL databases there are helpers: rows use the schema's camelCase field names, while the SQL tables use `madauth_<model>` and snake_case columns (`madauth_recovery_code`; `tableName()` and `columnName()` convert), and `createTablesSql()` creates them. Print the SQL to create the tables:

```bash
npx @madauth/server schema --dialect postgres
```

`mysql` and `sqlite` work as well. The built-in SQLite and [Postgres](#postgres) adapters ([`sqlite.ts`](../packages/server/src/store/sqlite.ts), [`postgres.ts`](../packages/server/src/store/postgres.ts)) use only this public API, so they are complete examples, e.g. for MySQL. The DynamoDB adapter ([`dynamodb.ts`](../packages/server/src/store/dynamodb.ts)) is one for a database without SQL.

### Schema versions

`madauthSchema.version` increases when a madAuth release adds a model or a field. The built-in SQLite and Postgres adapters upgrade their database by themselves. For your own SQL tables, print the changes since the version they were created for and run them before you deploy the new madAuth version:

```bash
npx @madauth/server schema --dialect postgres --from 1
```

| Version | Change |
| --- | --- |
| 2 | `user.wrongCodes`: wrong e-mail codes in a row, see [Password security](password-security.md#links-and-codes-in-e-mails). Number, starts at 0. |
| 3 | New model `role`: the roles of an e-mail address. A new table; existing ones don't change. |
| 4 | Every user is stored, with their [claims](#claims): `user.claims` (JSON string, empty without claims) and `account.email` (the address the provider reported, e.g. Google's; empty for passwords). New model `setting` (the [sign-in methods](#sign-in-methods)). The `role` table is dropped: roles are a claim now, set them again (the first admin with [`INITIAL_ADMIN_EMAIL`](#the-first-admin), the others with the admin API). |
| 5 | The [authenticator app](#authenticator-app): `account.lastUsedStep` (the time step of the last accepted code, so a code works once; number, starts at 0), `account.setupId` (the setup the secret came from; empty for other accounts) and the new model `recoveryCode` (a user's recovery codes, by their keyed hash, each with the `setupId` it belongs to; a record goes when its code is used). |
| 6 | [SMS codes](#sms-codes): `account.phone` (the number of an `sms:` account in E.164 form; empty for other accounts) and `user.lastSmsAt` (when the last SMS went to the user, so at most one per minute goes; empty before the first). |
| 7 | One sign-in method per user, and when a sign-up was complete: `account.primaryUserId` (the user's id on the account they sign in with, empty for a second factor; **unique**, so an adapter must refuse a second record with the same value while allowing many empty ones), `account.secondFactor` (true for an authenticator app that is a step of the user's method and for SMS codes, false for a sign-in method) and `user.signedUpAt` (when the user's first session started, 0 until then; it makes [`user.signed_up`](#webhooks) go once). |
| 8 | [Passkeys](#passkeys) and [several sign-in methods per user](sign-in-methods.md): `account.name`, `account.credentialId`, `account.signCount`, `account.transports`, `account.lastUsedAt` and `account.rpId` (the domain the passkey belongs to; all empty for other accounts). `account.primaryUserId` now marks the account a user signed up with (unique still), and the accounts they added later have none. |
| 9 | [Sign-up with a passkey alone](#passkeys): `user.signUpMethod`, the method the user's pending sign-up confirms the address for (`password`, `authenticator` or `passkey`; string, empty before; `totp`, the app's id before it was named `authenticator`, is read as `authenticator`). Each sign-up that sends a confirmation e-mail sets it, and the confirmation reads it. |
| 10 | New model `apiKey`: the users' [API keys](api-keys.md), each with its `userId` (indexed), `hash` (the SHA-256 of the key; **unique**), `name`, `scopes` (separated by spaces), `createdAt`, `expiresAt` (empty: never) and `lastUsedAt` (0: never). A new table; existing ones don't change. |
| 11 | `user.preferredSecondFactor`: the second factor the user wants to be asked for first (`authenticator`, `passkey` or `sms`; empty: the usual order). Records from before read as empty. |
| 13 | The [device authorization grant](#devices-without-a-browser): `oidcClient.deviceFlow` (whether the application may use it; empty: no), `user.wrongDeviceCodes` and `user.wrongDeviceCodeAt` (wrong codes the user typed within ten minutes; empty: none), and the new model `oidcDeviceCode` (a device's pending sign-in, by the SHA-256 of its device code, with the `userCode` (**unique**), the client, the scope, the status, the user it is bound to (indexed), how they signed in, and when it expires and was last polled). |
| 12 | madAuth as an [OpenID Connect provider](#openid-connect-provider): the new models `oidcClient` (the registered applications: `name`, `secretHash`, the SHA-256 of the secret, empty for a public one; `redirectUris` and `postLogoutRedirectUris` as JSON lists; `createdAt`, `updatedAt`, `updatedBy`), `oidcCode` (the authorization codes, by the code's SHA-256, with `userId` indexed; a record goes when its code is used) and `oidcRefreshToken` (a chain of refresh tokens, with `hash`, the SHA-256 of its token of now, and `clientId` and `userId` indexed). New tables; existing ones don't change. |

Stores without fixed columns need no change: madAuth reads a missing `wrongCodes`, `lastUsedStep` or `lastSmsAt` as 0, and a missing `claims`, `email` or `phone` as empty. Records from before version 9 keep working without being changed: without `signUpMethod`, a pending sign-up is one with a password when the user has a password, else one with the authenticator app, as before. Records from before version 7 keep working without being changed: with both `primaryUserId` and `secondFactor` missing, a password, Google or e-mail link account is the user's sign-in method and an authenticator app is one when the user has none of those (they signed up with it), and a missing `signedUpAt` means the sign-up was complete long ago, so no `user.signed_up` is sent for it. A sign-up from then that was never finished gets `signedUpAt` 0 when it is finished or started again, so its `user.signed_up` comes. Records of the `role` model are simply not read any more.

### Testing your adapter

`@madauth/server/testing` checks an adapter against everything madAuth relies on, e.g. that duplicates are refused and that only one of several concurrent deletes of a record counts. It works with any test runner that has `describe`, `it` and `expect`, and only adds records with fresh IDs, so a shared test database is fine:

```ts
// my-adapter.test.ts
import { describe, expect, it } from 'vitest';
import { storeAdapterContract } from '@madauth/server/testing';
import { createMyAdapter } from './my-adapter.js';

storeAdapterContract({ describe, it, expect }, () => createMyAdapter(process.env.TEST_DATABASE_URL!));
```

### Registering your adapter

Every entry point takes a `store` instead of `DATABASE_URL`. Build and deploy your entry file like any Lambda function, Azure Function or Node app.

AWS Lambda:

```ts
import { createHandler } from '@madauth/server/lambda';
import { createMyAdapter } from './my-adapter.js';

export const handler = createHandler({ store: createMyAdapter(process.env.MY_DB_URL!) });
```

Azure Functions:

```ts
import { register } from '@madauth/server/azure';
import { createMyAdapter } from './my-adapter.js';

register({ store: createMyAdapter(process.env.MY_DB_URL!) });
```

Node / Docker:

```ts
import { start } from '@madauth/server/node';
import { createMyAdapter } from './my-adapter.js';

await start({ store: createMyAdapter(process.env.MY_DB_URL!) });
```

With `createApp`, pass it to `loadConfig`: `createApp(await loadConfig(process.env, { store }))`.

## Verifying the session in your backend

`createSessionVerifier` checks the madAuth session cookie (or an `Authorization: Bearer` token) in any backend that has the Web `Request` API. The public key is fetched from `<issuer>/.well-known/jwks.json` once and then cached.

```ts
import { createSessionVerifier } from '@madauth/server/verify';

const verifySession = createSessionVerifier({ issuer: 'https://auth.example.com' });

const user = await verifySession(request); // or a Cookie header, or the token itself
if (!user) return new Response('Unauthorized', { status: 401 });
console.log(user.id, user.email, user.claims, user.amr); // claims: e.g. { roles: ['admin'] }; amr: e.g. ['pwd', 'otp']
```

`user.amr` says how the session was authenticated: `pwd` (password), `google`, `github`, `email` (the [e-mail link](email-link-security.md)), `passkey` (a [passkey](#passkeys), on its own or as the second step), `otp` (the [authenticator app](#authenticator-app), as the second step or on its own), `sms` (a code by SMS as the second step). Require `otp` or `passkey` before a sensitive action if your users have them.

A session token is valid for `SESSION_TTL`. When `verifySession` finds none, answer 401: the web library then renews the session, and the app sends the request again (see [Sessions](#sessions)).

Other languages can verify the JWT with any JOSE library:
- algorithm `ES256`
- issuer `MADAUTH_ISSUER`
- header `typ` `madauth-session+jwt`
- keys from `/.well-known/jwks.json`

The claims are `sub` (the user's id), `email`, `name`, `picture`, `amr` (how the session was authenticated: `pwd`, `google`, `github`, `email`, `passkey`, `otp`, `sms`), `auth_time` (when the user signed in, kept across renewals) and `claims` (what admins attached, see [Claims](#claims)).

## Verifying an API key in your backend

A program that calls your API in a user's name sends one of the user's [API keys](api-keys.md) (`Authorization: Bearer madauth_…`). `createApiKeyVerifier` asks the madAuth server whom it acts for and which of its scopes count now, and reuses the answer for a minute:

```ts
import { createApiKeyVerifier } from '@madauth/server/verify';

const verifyApiKey = createApiKeyVerifier({ issuer: 'https://auth.example.com' });

const caller = await verifyApiKey(request); // { user, apiKey: { id, name, scopes } } or null
if (!caller?.apiKey.scopes.includes('orders:read')) return new Response('Forbidden', { status: 403 });
```

Your app lists the scopes of its API at `API_KEY_SCOPES_URL`; see [API keys](api-keys.md#your-apps-scopes).

## OpenID Connect provider

Other applications can sign their users in with madAuth as their OpenID Connect provider, as they would with Keycloak, Auth0 or Cognito: Grafana, Nextcloud, an internal tool, a native or command-line app. The user signs in on your app's login page with madAuth's dialog and every method that is on; the application gets an ID token, an access token and, with `offline_access`, a refresh token. A device without a browser (a TV, a command-line tool) signs in with a code the user approves, see [Devices without a browser](#devices-without-a-browser). madAuth's own session and the web library don't change: OpenID Connect is for the other applications.

**Register an application** with the admin API: `Madauth.admin.addClient({ name, redirectUris, postLogoutRedirectUris?, public? })` (`POST /auth/admin/clients/add`). The answer has its `client.id`, the client ID, and for a confidential application (one with a server) its `clientSecret`, which only this answer shows: madAuth keeps its SHA-256. A public application (`public: true`: a native, command-line or browser app) has no secret and proves itself with PKCE alone. `listClients()`, `updateClient(id, { name, redirectUris, postLogoutRedirectUris, deviceFlow, newSecret })` and `removeClient(id)` do the rest; `newSecret: true` replaces the secret at once, and `deviceFlow: true` lets the application sign in from a [device without a browser](#devices-without-a-browser). Changes take an admin's session with a sign-in within the last two minutes, not an API key; listing also works with an API key with the scope `madauth:clients:read`.

**Redirect URIs** match exactly, as registered. They are https, an app's own scheme (`vscode://my.extension/callback`, `com.example.app:/callback`), or http on the user's computer: `http://127.0.0.1`, `http://[::1]` and `http://localhost` match with any port (RFC 8252), since a native app listens on whichever port is free. A fragment (`#`), plain http elsewhere and schemes such as `javascript:` are refused (`invalid_client`).

**Give the application the issuer**, `MADAUTH_ISSUER`. Its discovery document, `<issuer>/.well-known/openid-configuration`, names everything else:

| Endpoint | |
| --- | --- |
| `<issuer>/auth/oidc/authorize` | The authorization request (GET or POST) |
| `<issuer>/auth/oidc/token` | Tokens for a code, a refresh token or a device code |
| `<issuer>/auth/oidc/device` | A device's codes (the device authorization grant) |
| `<issuer>/auth/oidc/userinfo` | The user's claims for an access token (GET or POST) |
| `<issuer>/auth/oidc/logout` | Signing the user out (RP-initiated logout) |
| `<issuer>/.well-known/jwks.json` | The keys of the tokens, the same as the sessions' |

Your app's origin passes these on to the madAuth server like the rest of `/auth` and `/.well-known`.

**The flow** is the authorization code flow with PKCE (`S256`), required for every application, also those with a secret. A confidential application authenticates at the token endpoint with `client_secret_basic` or `client_secret_post`. madAuth supports `response_type=code` and `response_mode=query`, the scopes `openid` (required), `profile`, `email` and `offline_access` (a refresh token), `nonce`, `state`, `prompt` (`none`, `login`) and `max_age`; it answers with `iss` (RFC 9207). Applications are first-party: an admin registered them, so there is no consent screen. It doesn't support the implicit and hybrid flows, request objects, dynamic client registration, the client credentials grant, token introspection or revocation endpoints.

**The login page.** madAuth serves no HTML page of its own. When an authorization request finds nobody signed in, madAuth sends the browser to your app's login page with `madauth_return`, the authorization request to go back to: `/?madauth_return=<issuer>/auth/oidc/authorize?…`. The page signs the user in and goes back:

```ts
// Only to madAuth's authorization endpoint, never to another address.
const back = new URLSearchParams(location.search).get('madauth_return');
const returnTo = back && URL.canParse(back) && new URL(back).origin === location.origin && new URL(back).pathname === '/auth/oidc/authorize' ? back : null;
Madauth.onAuthStateChanged((user) => {
  if (!returnTo) return;
  if (user) location.assign(returnTo);
  else void Madauth.showSignInDialog();
});
```

(With the login page on another origin than the issuer, compare with the issuer's origin instead.) The login page is `/` on the issuer's origin until an admin sets another one: `Madauth.admin.setSettings({ loginUrl: '/login' })`, a path on the issuer's origin or a URL on one of `ALLOWED_ORIGINS`; `null` goes back to `/`. A request with `prompt=login`, or with `max_age` older than the user's sign-in, ends the session at the browser first, so the page shows the dialog; the way back asks for neither again. `prompt=none` answers `login_required` instead of showing the page. A request whose `client_id` or `redirect_uri` is unknown gets a page with the error (400), never a redirect.

**The tokens**, all signed with ES256 by the [key service](#key-service) (madAuth signs no RS256 yet, [#112](https://github.com/inouiw/madAuth/issues/112)):

- **ID token** (`typ: JWT`, valid an hour): `iss`, `sub` (the user's id, as in the session), `aud` (the client ID), `auth_time`, `amr` (as in the session), `nonce`, `at_hash`; with the scope `email`, `email` and `email_verified`; with `profile`, `name`; and `claims`, what admins attached to the user (see [Claims](#claims)), when there are any.
- **Access token**: a JWT (RFC 9068, `typ: at+jwt`), valid 15 minutes, with `sub`, `aud` and `client_id` (the client ID), `scope`, `auth_time`, `jti` and `claims`. An API checks it offline like a session, with the JWKS, the issuer, `typ` `at+jwt` and, as `aud`, the client IDs of the applications it serves. It can't be taken back before it expires; the user info endpoint refuses it once the user's sessions ended.
- **Refresh token**, only with the scope `offline_access`: opaque, valid 30 days after its last use. Each use gives a new one and ends the one used; using one twice ends the whole chain, so whoever holds the newer one (the application, or whoever took a token) signs in again (RFC 9700). A narrower `scope` at the refresh is allowed, a wider one is not (`invalid_scope`).

**Ending what an application holds:** a password reset or change, [resetting the user's sign-in](#resetting-a-users-sign-in) and deleting the user end every refresh token of the user and stop the user info endpoint answering their access tokens. Removing an application ends its refresh tokens. The application's sign-out, `logout` with `id_token_hint` (an ID token madAuth issued it, also an expired one), ends that application's refresh tokens of the user and the session at the browser when it is the same user's, then redirects to `post_logout_redirect_uri` (with `state`) when it is one of the application's registered `postLogoutRedirectUris`, or to the issuer's `/`. Without a valid `id_token_hint`, madAuth answers 400: it has no page to ask the user.

madAuth aims at the Basic OP profile of the OpenID Foundation and is tested with the `openid-client` library; it hasn't run the conformance suite yet ([#111](https://github.com/inouiw/madAuth/issues/111)).

### Devices without a browser

A smart TV, a console or a command-line tool has no browser to sign in with, or no keyboard to type a password on. The device authorization grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) lets it sign in through another device: it shows a code, the user opens your app on their phone or computer, types the code, sees which application asks, and approves it. Auth0, Keycloak and Okta offer the same.

**Allow it per application:** `addClient({ …, deviceFlow: true })` or `updateClient(id, { deviceFlow: true })`. Off by default: whoever can start the flow can send the code to a victim (see below). A public application (`public: true`) is the usual case; a confidential one sends its secret.

**On the device:**

1. `POST <issuer>/auth/oidc/device` with `client_id` (and `client_secret`, or HTTP Basic, for a confidential application) and `scope`, e.g. `openid email offline_access`. The answer: `{ device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval }`. The `user_code` is eight letters, `BCDF-GHJK`, without vowels or letters that look alike; it works ten minutes. `verification_uri` is your app's [login page](#openid-connect-provider) and `verification_uri_complete` the same with `?madauth_device=BCDF-GHJK`, for a QR code.
2. The device shows the code and the URL (or the QR code), and polls `POST <issuer>/auth/oidc/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code` and the client's authentication, every `interval` seconds (five). Until the user decided it answers `400 authorization_pending`; polled faster, `slow_down`; after ten minutes, `expired_token` (start again); once the user refused, `access_denied`. Once approved, it answers the tokens like the code flow: the ID token with the scope `openid`, the access token, and a refresh token with `offline_access`. The device code works once.

**On the user's device,** your app's page, with a session: a user who isn't signed in signs in first.

- `Madauth.showDeviceApprovalDialog()` opens madAuth's dialog: the code's form, then the application's name and the code to compare with the device, with "Approve" and "Deny". With `{ code }` from the URL it skips the form. It resolves with `approved` once the user decided.
- On a custom screen, `Madauth.device.lookup(code)` finds what the device asks for (`client.name`, `scope`, `expiresAt`), typed in any case, with or without the dash; from then on only this user can decide it. `approve(code)` and `deny(code)` decide. See [Custom UI](custom-ui.md#a-devices-sign-in-madauthdevice).
- A page that handles the QR code's URL: `const code = new URLSearchParams(location.search).get('madauth_device'); if (code) void Madauth.showDeviceApprovalDialog({ code });`. The demo does this.

**Against guessing and phishing:** a code of eight letters from twenty (34 bits) is guessable with enough tries, so the lookup takes a session, and a user who typed five wrong codes within ten minutes waits (`429 too_many_attempts`). The code binds to the user who looked it up, so nobody else approves a code the user is looking at. The other way round, an attacker can start the flow and send the victim the code or the QR link: the dialog names the application and tells the user to approve only what they started on a device of theirs. That is why an admin allows the grant per application, and the approval shows the application's name as the admin registered it.

The device's tokens carry the approving user's `auth_time` and `amr`. What ends them is what ends the code flow's: a password reset or change, a sign-in reset, deleting the user, removing the application.

## HTTP API

| Method & path | Description |
| --- | --- |
| `GET /auth/config` | Public settings for the web library: `{ google: { clientId, codeFlow, secondFactor } \| null, github: { secondFactor } \| null, password: { minLength, minScore, secondFactor } \| null, authenticator: { signIn, signUp } \| null, email: { verification }, emailLink: { secondFactor } \| null, sms, passkey: { signIn, signUp, secondFactor } \| null, providers: [{ id, kind, name, secondFactor }] }` (`sms`: whether SMS codes are on as a second factor; `signIn`: whether the app or passkeys sign in on their own; `signUp`: whether people can sign up with them alone; `providers`: the [providers](#providers) that are on). A method is `null` when it is not configured or [switched off](#sign-in-methods). |
| `POST /auth/providers/google/nonce` | Starts a sign-in with an ID token (FedCM / One Tap, or one the app obtains itself: `Madauth.google.nonce()`): returns `{ nonce }` and sets a 5-minute nonce cookie |
| `POST /auth/providers/google/verify` | `{ credential, locale? }` (a Google ID token with that nonce; `Madauth.google.signIn`) → `{ user }` and the session cookie, or the [second step](#the-second-step); 403 `signup_rejected` (a first sign-in the sign-up check refused), 403 `other_method` (the address signs in another way; `methods` says how), 503 `temporarily_unavailable` |
| `POST /auth/providers/google/link` | `{ credential }` (an ID token, with the nonce cookie; `Madauth.google.signIn` with `purpose: 'link'`), signed in within two minutes → `{}`: adds the Google account to the user's [methods](sign-in-methods.md); 401 `reauth_required` or `no_session`, 409 `account_taken` (it signs in another user) |
| `GET /auth/providers/google/start?return_to=` | Starts the redirect flow (needs the Google provider's client secret); with `&link=1`, for a user signed in within two minutes, it adds the Google account to their methods instead |
| `GET /auth/providers/google/callback` | Google redirects here; redirects back to `return_to`, to `return_to#madauth_error=<code>`, or to `return_to#madauth_next=passkey` / `authenticator` / `sms` / `second-factor-setup` (`passkey-setup` for the passkey of a sign-up with one, which no redirect flow reaches today) for the second step, with `&madauth_factors=passkey,authenticator,sms` naming the factors that can finish it (or be set up); `&madauth_method=google` names the method in both cases. After `link=1`: `return_to#madauth_linked=google`, or the error (`account_taken`, `reauth_required`, `no_session`) |
| `GET /auth/providers/github/start?return_to=` | Starts GitHub's redirect flow; `&link=1` adds GitHub to the signed-in user's methods, like Google's |
| `GET /auth/providers/github/callback` | GitHub redirects here; redirects back like Google's callback, with `&madauth_method=github`; `email_unverified` when the GitHub account has no verified e-mail address |
| `GET /auth/providers/<id>/start?return_to=` | Starts an [OpenID Connect provider's](#openid-connect-provider-setup) redirect flow; `&link=1` adds it to the signed-in user's methods, like Google's. 404 for an id that is no OpenID Connect provider |
| `GET /auth/providers/<id>/callback` | The provider redirects here; redirects back like Google's callback, with `&madauth_method=<id>`; for an address the provider doesn't vouch for, `#madauth_next=email-confirmation&madauth_email=<masked>` and the confirmation e-mail (see [OpenID Connect provider setup](#openid-connect-provider-setup)); `email_unverified` when the claims have no address, or the server sends no e-mails; `temporarily_unavailable` when its discovery document can't be read |
| `POST /auth/password/signin` | `{ email, password }` → `{ user }` and the session cookie, or the second step; 401 `invalid_credentials`, 403 `email_unverified`, 429 `too_many_attempts` |
| `POST /auth/password/signup` | `{ email, password, name?, redirectTo, locale? }` → 202, and the confirmation e-mail; 400 `invalid_email` or `weak_password`, 403 `signup_rejected`, 503 `temporarily_unavailable` |
| `POST /auth/password/add` | `{ password }`, signed in within two minutes → `{}`: adds a password to the user's methods; 400 `weak_password`, 401 `reauth_required` or `no_session`, 409 `already_added` |
| `POST /auth/password/change` | `{ current, password }`, signed in (no recent sign-in needed: `current` proves it) → `{}` and new session cookies for the same sign-in: changes the user's password, ends their other sessions and deletes their unused e-mail links and codes; a wrong `current` counts toward the [lockout](password-security.md#brute-force) like a sign-in. 400 `weak_password` (checked first, so it is not counted), 401 `invalid_credentials` or `no_session`, 404 `method_not_found` (no password), 429 `too_many_attempts` |
| `POST /auth/password/send-reset` | `{ email, redirectTo, locale? }` → 202, and the reset e-mail if the address has a password (`email.send_password_reset_no_password` if its user has none); 503 `temporarily_unavailable` |
| `POST /auth/password/reset` | `{ password, token }` or `{ password, email, code }` → `{ user }` and the session cookie, or the second step; ends all older sessions; 400 `weak_password`, `link_invalid` or `code_invalid`, 429 `codes_locked` |
| `POST /auth/email/send-verification` | `{ email, redirectTo, locale? }` → 202, and the confirmation e-mail again, for a sign-up with a password, the authenticator app or a passkey; without `email`, for the sign-up through a provider that the `madauth_confirmation` cookie names; 503 `temporarily_unavailable` |
| `POST /auth/email/verify` | `{ token }`, `{ email, code }`, or `{ code }` with the `madauth_confirmation` cookie (a sign-up through a provider) → `{ user }` and the session cookie, or the second step (a sign-up with the app: `authenticator_setup_required` with `factors: ["authenticator"]`; with a passkey: `passkey_setup_required` with `factors: ["passkey"]`); 400 `link_invalid` or `code_invalid`, 429 `codes_locked` |
| `POST /auth/email-link/send` | `{ email, redirectTo, locale? }` → 202, and the sign-in e-mail (`email.send_signin_link`) with a link and a code; a new address is signed up first (`user.signing_up`), the owner of an address that signs in another way gets `email.send_already_registered` instead; 400 `invalid_email`, 403 `signup_rejected`, 503 `temporarily_unavailable` |
| `POST /auth/email-link/add` | `{}`, signed in within two minutes → `{}`: adds the e-mail link to the user's methods; 401 `reauth_required` or `no_session`, 409 `already_added` |
| `POST /auth/email-link/verify` | `{ token }` or `{ email, code }` → `{ user }` and the session cookie (`amr: ["email"]`), or the second step; 400 `link_invalid` or `code_invalid`, 429 `codes_locked` |
| `POST /auth/authenticator/setup` | `{}`, signed in within two minutes or in the second step → `{ secret, uri }` (base32, and the `otpauth://` URI for the QR code) and a 10-minute setup cookie; a user who has an app sends `{ code }` or `{ recoveryCode }` from it, since the new one replaces it (401 `code_required`, `code_invalid`); the approval holds for ten minutes in the setup cookie, so a setup started again needs no second code; 401 `reauth_required` or `no_session` |
| `POST /auth/authenticator/confirm` | `{ code }` → `{ recoveryCodes }`, or `{ user, recoveryCodes }` and the session cookie when the setup finished a sign-in; 400 `setup_expired` (also when the app was set up or removed elsewhere since the setup started) or `code_invalid`, 401 `no_session` |
| `POST /auth/authenticator/verify` | `{ code }` or `{ recoveryCode }`, with the challenge cookie → `{ user }` and the session cookie; 401 `challenge_expired` or `code_invalid`, 429 `too_many_attempts` |
| `POST /auth/authenticator/signin` | `{ email, code }` or `{ email, recoveryCode }` → `{ user }` and the session cookie, when the app is allowed as a sign-in method; 401 `invalid_credentials`, 429 `too_many_attempts` |
| `POST /auth/authenticator/signup` | `{ email, name?, redirectTo, locale? }` → 202, and the confirmation e-mail; the setup follows the confirmation; 400 `invalid_email`, 403 `signup_rejected`, 503 `temporarily_unavailable` |
| `POST /auth/authenticator/remove` | `{ code }` or `{ recoveryCode }`, signed in within two minutes → `{}`; 401 `code_invalid` or `reauth_required`, 403 `required_by_policy` (a required policy, and no other second factor) or `only_method` (the app is the user's last way to sign in) |
| `POST /auth/authenticator/recovery-codes` | `{ code }` or `{ recoveryCode }`, signed in within two minutes → `{ recoveryCodes }` (the old ones stop working); 400 `no_authenticator`, 401 `code_invalid` or `reauth_required` |
| `GET /auth/authenticator/status` | `{ enabled, recoveryCodesLeft }` for the signed-in user; 401 `no_session` |
| `POST /auth/sms/setup` | `{ phone, locale?, code? }`, signed in (a first number within two minutes, else 401 `reauth_required`) or in the setup step of a sign-in → 202 `{ phone }` (masked), the SMS (`sms.send_code`, `purpose: "setup"`) and a 10-minute setup cookie; a user who has a number sends `{ code }` from an SMS to the current one (401 `code_required`, `code_invalid`); 400 `invalid_phone`, 401 `no_session`, 429 `too_soon`, 503 `temporarily_unavailable` |
| `POST /auth/sms/confirm` | `{ code }` → `{}`, or `{ user }` and the session cookie when the setup finished a sign-in; 400 `setup_expired`, 401 `code_invalid`, 429 `too_many_attempts` |
| `POST /auth/sms/send` | `{ locale? }`, with the challenge cookie (the second step) or signed in within two minutes (to approve a change, which this starts) → 202 `{ phone }` and the SMS; 400 `no_phone`, 401 `challenge_expired`, `reauth_required` or `no_session`, 429 `too_soon`, 503 `temporarily_unavailable` |
| `POST /auth/sms/verify` | `{ code }`, with the challenge cookie → `{ user }` and the session cookie; 401 `challenge_expired` or `code_invalid`, 429 `too_many_attempts` |
| `POST /auth/sms/remove` | `{ code }` (from an SMS sent with `send`), signed in → `{}`; 400 `no_phone`, 401 `code_invalid`, 403 `required_by_policy` (a required policy, and no other second factor) |
| `GET /auth/sms/status` | `{ enabled, phone }` (masked, or null) for the signed-in user; 401 `no_session` |
| `POST /auth/passkey/signup` | `{ email, name?, redirectTo, locale? }` → 202, and the confirmation e-mail; the passkey is created after the confirmation; 400 `invalid_email`, 403 `signup_rejected`, `method_disabled` (passkeys don't sign in on their own) or `forbidden_origin` (the app, or the page of `redirectTo`, is outside `PASSKEY_RP_ID`), 503 `temporarily_unavailable`. See [Passkeys](#passkeys). |
| `POST /auth/passkey/register/options` | `{}`, signed in within two minutes, in the setup step of a sign-in, or in a sign-up with a passkey → the options for `navigator.credentials.create()` (JSON) and a 5-minute ceremony cookie; 401 `reauth_required` or `no_session`, 403 `forbidden_origin` (the app is outside `PASSKEY_RP_ID`) |
| `POST /auth/passkey/register/verify` | `{ response, name? }` (the browser's answer, as `PublicKeyCredential.toJSON()` gives it) → `{ passkey: { id, name, createdAt, lastUsedAt } }`, or `{ passkey, user }` and the session cookie when it finished a sign-in or a sign-up (the step of `passkey_setup_required`; in a sign-up whose `passkey` policy asks for a second factor, it answers `second_factor_setup_required` with the factors to set up next); 400 `setup_expired` (also when a sign-up got another method meanwhile), 401 `verification_failed`, 409 `already_added`. See [Passkeys](#passkeys). |
| `POST /auth/passkey/signin/options` | `{}` → the options for `navigator.credentials.get()` (no list of passkeys: the browser offers the user's own) and the ceremony cookie, when passkeys are allowed as a sign-in method |
| `POST /auth/passkey/signin/verify` | `{ response }` → `{ user }` and the session cookie (`amr: ["passkey"]`), or the second step; 400 `setup_expired`, 401 `passkey_unknown` (the server doesn't know the passkey) or `verification_failed` |
| `POST /auth/passkey/verify/options` | `{}`, with the challenge cookie → the options for `navigator.credentials.get()` with the user's passkeys; 401 `challenge_expired` |
| `POST /auth/passkey/verify` | `{ response }`, with the challenge and the ceremony cookie → `{ user }` and the session cookie; 401 `challenge_expired` or `verification_failed` |
| `POST /auth/passkey/rename` | `{ id, name }`, signed in → `{ passkey }`; 400 `invalid_options`, 404 `method_not_found` |
| `GET /auth/methods` | `{ methods: [{ id, method, signIn, removable, createdAt, email?, name?, lastUsedAt? }], secondFactors, preferredSecondFactor }`: the signed-in user's [sign-in methods](sign-in-methods.md), the authenticator app among them (`signIn`: whether it signs in on its own now; `removable`: whether `/auth/methods/remove` takes it), and their second factors that are on, in the order a sign-in asks for them, with the preferred one (null for the usual order); 401 `no_session` |
| `POST /auth/second-factor/preferred` | `{ factor }`, signed in (no recent sign-in needed) → `{}`: the second factor (`passkey`, `authenticator`, `sms`) a sign-in asks for first, or `null` for the usual order; 400 `invalid_options`, 401 `no_session`, 404 `method_not_found` (the user has no such factor, or it is off) |
| `POST /auth/methods/remove` | `{ id }`, signed in within two minutes → `{}`: removes a password, Google, GitHub (its authorization at GitHub too), an OpenID Connect provider, the e-mail link or a passkey; 400 `invalid_options` (the app: `/auth/authenticator/remove`), 401 `reauth_required`, 403 `only_method` or `required_by_policy`, 404 `method_not_found` |
| `GET /auth/api-keys/scopes` | `{ scopes: [{ name, description, role, endpoints, allowed }] }`: every scope an [API key](api-keys.md) can have, madAuth's and your app's (`role`: the role a user needs for it, or null; `allowed`: whether the signed-in user may give a key it). Public. |
| `GET /auth/api-keys` | `{ apiKeys: [{ id, name, scopes, createdAt, expiresAt, lastUsedAt }] }`: the signed-in user's keys; 401 `no_session` |
| `POST /auth/api-keys/create` | `{ name, scopes, expiresAt? }`, signed in within two minutes → `{ key, apiKey }` (the key, shown this once); 400 `invalid_options` or `invalid_scopes`, 401 `reauth_required` or `no_session`, 403 `scope_not_allowed` (a scope whose role the user doesn't hold), 409 `too_many_api_keys`, 503 `temporarily_unavailable` (your app's scopes can't be read) |
| `POST /auth/api-keys/revoke` | `{ id }`, signed in → `{}`; 404 `api_key_not_found` |
| `POST /auth/api-keys/verify` | With `Authorization: Bearer madauth_…`, for your backend → `{ user, apiKey: { id, name, scopes } }` (the scopes that count now); 401 `invalid_api_key` |
| `GET /auth/session` | `{ user }` for the current session, [renewing](#sessions) it if needed; 401 `no_session`, which also clears the cookies |
| `POST /auth/logout` | Clears the cookies of the session |
| `POST /auth/admin/users/search` | `{ role?, email?, signedUpAfter?, signedUpBefore?, pending?, limit?, cursor? }` → `{ users: [{ id, email, name, emailVerified, claims, methods, signedUpAt, pending }], cursor? }`, for admins; 400 `invalid_search`, `invalid_email`. See [Searching users](#searching-users). |
| `POST /auth/admin/claims/get` | `{ email }` → `{ email, userId, claims }`, for users with the role `admin`; 401 `no_session`, 403 `forbidden`, 400 `invalid_email`, 404 `user_not_found`. See [Claims](#claims). |
| `POST /auth/admin/claims/set` | `{ email, claims }` → `{ email, userId, claims }`: replaces the claims of the user (a session within two minutes of its sign-in, else 401 `reauth_required`; an API key with the scope needs none, as for every admin change but the providers'); also 400 `invalid_claims`, 403 `own_admin_role` (it would take the role `admin` from the caller, see [The first admin](#the-first-admin)) |
| `POST /auth/admin/settings/get` | `{}` → `{ methods: { google: { configured, enabled, allowAsSignInMethod, secondFactor }, github: { … }, password: { … }, authenticator: { … }, 'email-link': { … }, passkey: { … }, sms: { … } }, password: { minLength, minScore }, loginUrl }` (`loginUrl`: the [login page](#openid-connect-provider) an admin set, or `null`), for admins. See [Sign-in methods](#sign-in-methods) and [Password rules](#password-rules). |
| `POST /auth/admin/settings/set` | `{ methods?: { <id>: { allowAsSignInMethod, secondFactor } }, password?: { minLength?, minScore? }, loginUrl?: string \| null }`, any of them (`methods` is the list of the methods that are on, each with both settings; what `password` leaves out takes its default) → the same; 400 `invalid_settings` when a setting doesn't fit its method, a policy has no second factor that is on, or no method that creates users would stay on, and then nothing is changed; with a session, 401 `reauth_required` more than two minutes after its sign-in |
| `POST /auth/admin/settings/method` | `{ method, setting }`, `setting` as in `settings/set` or `null` (off) → like `settings/set`: changes only that method's entry in the stored list, so what another admin changes meanwhile stays; checked like `settings/set` (400 `invalid_settings`) |
| `POST /auth/admin/providers/list` | `{}` → `{ providers: [{ id, kind, name, clientId, hasClientSecret, callbackUrl, createdAt, updatedAt }], callbackBase }` (`callbackBase`: `<MADAUTH_ISSUER>/auth/providers/`, a new provider's callback URL is `<callbackBase><id>/callback`), for admins (an API key needs `madauth:providers:read`), or with the [setup token](#first-setup). See [Providers](#providers). |
| `POST /auth/admin/providers/add` | `{ kind, name?, clientId, clientSecret? }`, for `oidc` also `{ id, name, issuer, scopes?, trustEmail? }` → `{ provider }`: adds a provider, off until switched on (an OpenID Connect provider only when its discovery document can be read); an admin's session with a sign-in within ten minutes (401 `reauth_required`; an API key gets 403 `forbidden`), or the setup token; 400 `invalid_provider`, 409 `provider_exists`, 401 `invalid_setup_token` |
| `POST /auth/admin/providers/update` | `{ id, name?, clientId?, clientSecret?, scopes?, trustEmail? }` (`clientSecret: null` removes Google's; `scopes` and `trustEmail` for `oidc`) → `{ provider }`; like `add`, and 404 `provider_not_found` |
| `POST /auth/admin/providers/remove` | `{ id }` → `{ provider, usersWithoutSignIn }`: removes a provider, its users' accounts stay; like `update`. With `dryRun: true` → `{ provider, usersWithoutSignIn, dryRun: true }`: only counts, like `list` (no recent sign-in needed); 400 `invalid_options` for a `dryRun` that is no boolean |
| `POST /auth/admin/sign-in/reset` | `{ email }` → `{ email, userId }` (a session within two minutes of its sign-in, else 401 `reauth_required`): removes all of the user's sign-in methods and second factors, ends their sessions and marks the address unconfirmed, for admins; they sign up again. See [Resetting a user's sign-in](#resetting-a-users-sign-in). |
| `POST /auth/admin/api-keys/list` | `{ email }` → `{ email, userId, apiKeys }`: the user's [API keys](api-keys.md), for admins with a session (an API key gets 403 `forbidden`) |
| `POST /auth/admin/api-keys/revoke` | `{ email, id }` → `{ email, userId }`; 404 `api_key_not_found` |
| `POST /auth/account/delete` | Deletes the account of the user signed in within two minutes (else 401 `reauth_required`) and clears the session cookie; `200 { googleSub }` if they had a Google account, otherwise `204`; with an authenticator app `{ code }` or `{ recoveryCode }` is needed (401 `code_required`, `code_invalid`); 401 `no_session`, 403 `own_admin_role` (the user has the role `admin`). See [Deleting an account](#deleting-an-account). |
| `POST /auth/admin/clients/list` | `{}` → `{ clients: [{ id, name, public, redirectUris, postLogoutRedirectUris, deviceFlow, createdAt, updatedAt }] }`: the applications that sign in with madAuth, for admins (an API key needs `madauth:clients:read`). See [OpenID Connect provider](#openid-connect-provider). |
| `POST /auth/admin/clients/add` | `{ name, redirectUris, postLogoutRedirectUris?, public?, deviceFlow? }` → `{ client, clientSecret? }` (the secret, shown this once; none for a public client): an admin's session with a sign-in within two minutes (401 `reauth_required`; an API key gets 403 `forbidden`); 400 `invalid_client` |
| `POST /auth/admin/clients/update` | `{ id, name?, redirectUris?, postLogoutRedirectUris?, deviceFlow?, newSecret? }` → `{ client, clientSecret? }` (`newSecret: true`: a new secret, the old one stops working); like `add`, and 404 `client_not_found` |
| `POST /auth/admin/clients/remove` | `{ id }` → `{ client }`: removes the application and ends its refresh tokens; like `update` |
| `GET /.well-known/openid-configuration` | The discovery document of madAuth as an [OpenID Connect provider](#openid-connect-provider) |
| `GET`, `POST /auth/oidc/authorize` | The authorization request: redirects to the `redirect_uri` with `code`, `state` and `iss`, or with `error`; to the app's login page with `madauth_return` when nobody is signed in; a page (400) for an unknown `client_id` or `redirect_uri` |
| `POST /auth/oidc/token` | `grant_type=authorization_code` (`code`, `redirect_uri`, `code_verifier`), `refresh_token` (`refresh_token`, `scope?`) or `urn:ietf:params:oauth:grant-type:device_code` (`device_code`), the client authenticated by HTTP Basic, `client_id` and `client_secret`, or for a public client `client_id` alone → `{ access_token, token_type, expires_in, id_token, refresh_token, scope }` (`id_token` when `scope` has `openid`, `refresh_token` when it has `offline_access`); 400 `invalid_grant`, `invalid_scope`, `unsupported_grant_type`, `invalid_request`, and for a device `authorization_pending`, `slow_down`, `expired_token`, `access_denied`; 401 `invalid_client` |
| `POST /auth/oidc/device` | The client's authentication and `scope?` → `{ device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval }` (the [device authorization grant](#devices-without-a-browser)); 400 `unauthorized_client` (the application's `deviceFlow` is off), 401 `invalid_client` |
| `POST /auth/device/lookup` | `{ code }`, signed in → `{ code, client: { id, name }, scope, expiresAt }`: what the device with this user code asks for, bound to this user from now on; 401 `no_session`, 404 `device_code_invalid`, 429 `too_many_attempts` (five wrong codes within ten minutes) |
| `POST /auth/device/approve`, `deny` | `{ code }`, signed in, after `lookup` → `{}`; 401 `no_session`, 404 `device_code_invalid` |
| `GET`, `POST /auth/oidc/userinfo` | With `Authorization: Bearer <access token>` → `{ sub, email?, email_verified?, name?, claims? }`; 401 `invalid_token` |
| `GET`, `POST /auth/oidc/logout` | `id_token_hint`, `post_logout_redirect_uri?`, `state?`, `client_id?`: signs the user out of the application and redirects (see [OpenID Connect provider](#openid-connect-provider)); 400 for a missing or wrong `id_token_hint` or an unregistered `post_logout_redirect_uri` |
| `GET /.well-known/jwks.json` | Public key to verify sessions, and the tokens of the OpenID Connect provider |
| `GET /health` | `ok` |

POST requests must come from an origin in `ALLOWED_ORIGINS`, except those with an `Authorization` header (a program's [API key](api-keys.md)) and those to `/auth/oidc/*`, which other applications call from anywhere (with CORS for any origin, without cookies). The admin routes take an admin's API key with the route's scope instead of a session, except those that manage keys. The e-mail endpoints answer 202 whether or not the address has an account, and at most one e-mail per minute is sent to an account. The routes of Google, of GitHub, of e-mail & password, of the e-mail link and of SMS codes return 404 when the method is not configured; the routes that change a signed-in user's methods need a sign-in within the last two minutes (renewals don't count) and answer `401 reauth_required` otherwise; every method's routes return 403 `method_disabled` when it is not on, except the redirect flows' `start` and `callback`, which send the browser back to `return_to` with `madauth_error=method_disabled`.

### The second step

When the [policy](#sign-in-methods) of a method asks for a second factor, `google/verify`, `password/signin`, `password/reset`, `email/verify`, `email-link/verify` and `passkey/signin/verify` answer `401 { "error": "passkey_required", "method": "password", "factors": ["passkey", "authenticator"] }` (the user has a passkey; `factors` lists what they can finish with, in the order passkey, app, phone), `401 { "error": "authenticator_required", …, "factors": ["authenticator", "sms"] }` (the app first), `401 { "error": "sms_required", …, "factors": ["sms"] }` (a phone only) or `401 { "error": "second_factor_setup_required", …, "factors": ["passkey", "authenticator", "sms"] }` (they set up one of these first) instead of `{ user }` (a sign-up with a passkey alone: `email/verify` answers `401 { "error": "passkey_setup_required", "method": "passkey", "factors": ["passkey"] }`, and `POST /auth/passkey/register/options` and `verify` create its passkey), and set a 10-minute challenge cookie on `/auth`; the session there was at that browser, if any, is cleared, so whoever was signed in is signed out until the step is done. The sign-in then goes on with `POST /auth/passkey/verify/options` and `verify`, `POST /auth/authenticator/verify` or `POST /auth/sms/send` and `verify` (each for a factor in `factors`), or with the setup of a passkey, the app or a phone; if an admin switched the method off meanwhile, they answer `403 method_disabled`. The redirect flows (Google's code flow, GitHub) return with `#madauth_next=passkey`, `authenticator`, `sms`, `second-factor-setup` or `passkey-setup` instead, with `madauth_factors` and `madauth_method`. A sign-up with the app alone answers `authenticator_setup_required` (`factors: ["authenticator"]`) once the address is confirmed: the app is set up next, nothing else (a setup step is named `<method>_setup_required` when one method is being created, `second_factor_setup_required` when the user chooses a second factor). The web library handles the second step by itself, with or without `new Authenticator()` and `new Passkey()`.
