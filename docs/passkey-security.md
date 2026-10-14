# Passkey security

How madAuth handles passkeys (WebAuthn), for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules mention this file, so update it when you change them. What passkeys do on a server, on their own or as a second factor, is the [sign-in policy](server.md#sign-in-methods).

## What a passkey proves

A passkey is a key pair the user's device or password manager makes for one site. madAuth keeps the public key; the private key never leaves the authenticator. To sign in, the authenticator signs a fresh challenge from the server, together with the site it was asked from.

- **The user was verified.** madAuth asks for user verification (`userVerification: 'required'`) and refuses an answer without it: the authenticator checked a fingerprint, a face or a PIN before it signed. A security key without a PIN can't be used: it would be possession alone.
- **It can't be phished.** The browser puts the page's origin into what the authenticator signs, and madAuth checks it against the app that asked (one of `ALLOWED_ORIGINS`), and the hash of the domain the passkey belongs to (`PASSKEY_RP_ID`, else the app's host). A look-alike site gets no answer that works here.
- **It names its user.** A passkey made by madAuth carries the user's id (`usr_…`) as its user handle, which says nothing about the user; signing in alone, the handle must be the one of the passkey's user.

Passkeys sign in without the address: the browser offers the user's own passkeys for the site (they are discoverable), so nothing tells whether an address has an account.

Code: [`packages/server/src/routes/passkey.ts`](../packages/server/src/routes/passkey.ts), on top of [`@simplewebauthn/server`](https://simplewebauthn.dev).

## An answer counts once

Every ceremony starts with options from the server: a random challenge, signed into a cookie (`madauth_passkey`, HttpOnly, `SameSite=Strict`, five minutes, only sent to `/auth/passkey`) together with what the ceremony is for (adding a passkey, signing in alone, the second step), the domain, the app and, except for signing in alone, the user. The answer is checked against that cookie and the cookie is deleted. A browser that keeps the cookie can't use an answer twice either: an accepted answer is noted under its challenge (in the `verification` model, for the user whose passkey it was), and the note decides, so the same answer sent twice at once signs in once. Only accepted answers are noted, so nobody fills the store without a passkey; a user's notes go once their ceremonies have expired, and not before (a password reset, which clears the user's links and codes, keeps them).

An authenticator that keeps a signature counter (a security key) sends a higher count each time; one that comes back with a count that isn't higher is a copy and is refused. Passkeys that sync between devices keep no counter (0).

Code: `finish` in [`routes/passkey.ts`](../packages/server/src/routes/passkey.ts), `useCeremony` in [`users.ts`](../packages/server/src/users.ts).

## Adding a passkey

- Only a signed-in user adds a passkey, and only within ten minutes of signing in (the session's `auth_time`, which renewals keep): later, the answer is `401 reauth_required`, and the user signs in again first. A session someone took over (a stolen cookie, a browser left open) must not give them a way in of their own that outlives it.
- Or the sign-in whose policy requires a second factor the user doesn't have yet (`authenticator_setup_required` with `passkey` among its `factors`): the new passkey finishes that sign-in. A sign-up with the authenticator app alone has no first factor yet, so it sets the app up, never a passkey.
- The options leave out the passkeys the user has (`excludeCredentials`), so an authenticator that holds one says so instead of making another. A passkey is stored by the SHA-256 of its credential id (the id itself can be longer than a key column holds), with its public key, its transports, its counter and a name the user gives it (`Passkey` by default, at most 64 characters, changed with `Madauth.passkey.rename`).
- madAuth asks for no attestation (`none`): it doesn't check which device made the passkey, only that it was verified and answers for this site.

## Signing in, and the second step

With passkeys allowed as a sign-in method (`allowAsSignInMethod`), every passkey of a user signs them in on its own, as `["passkey"]`; the `passkey` policy can ask for a second factor after it, which is then the app or a phone, never a passkey. Only as a second factor (`allowAsSignInMethod: false`), a passkey is asked for after another method, and comes first of the user's second factors: `passkey_required`, with the user's passkeys in the options (`allowCredentials`). A passkey counts as a second factor only on the domain it was made for (it is stored with it): on an app of another domain it couldn't answer, so there the user is asked for another factor, or sets one up under a `required` policy. The challenge cookie of the sign-in and the ceremony cookie both have to fit, and the passkey must be one of the user's.

A passkey the server no longer has (the user removed it) is `401 passkey_unknown`; the web library then tells the browser to forget it, where the browser supports that (the WebAuthn Signal API).

## Removing a passkey

- Within ten minutes of signing in, like adding one: `Madauth.methods.remove(id)` or `POST /auth/methods/remove`.
- Not the last way the user signs in (`403 only_method`): they add another method first, or delete the account.
- Not the last second factor a `required` policy can ask them for (`403 required_by_policy`): a policy needs a factor the user keeps, other than the method itself. One of several passkeys may always go, and the passkeys' own policy doesn't keep the last one: without it, the user signs in with no passkey.
- A user who lost their passkeys signs in another way and removes them, or asks the operator: `npx @madauth/server remove-passkeys <email>` (it calls no webhook) or `POST /auth/admin/passkey/remove` (`user.method_removed` with `by`).

## The domain

A passkey belongs to a domain (the WebAuthn relying party id), and the browser offers it only on that domain and its subdomains. Without `PASSKEY_RP_ID`, it is the host of the app that adds the passkey, so a passkey made on `app.example.com` works there only. With `PASSKEY_RP_ID=example.com`, the passkeys work on every app under `example.com`; an app outside it is refused (`403 forbidden_origin`). The server refuses to start when no app of `ALLOWED_ORIGINS` is within it. A new `PASSKEY_RP_ID` makes every existing passkey stop working: the users sign in another way and add new ones.

## Not covered yet

- Passkeys in native apps (Capacitor): WebAuthn in a WebView needs the app's associated domains (iOS) or asset links (Android) for the domain, and an origin in `ALLOWED_ORIGINS` for it.
- Signing up with a passkey alone: a passkey is always added to a user who signed up another way.
- Attestation, or allowing only certain authenticators (e.g. security keys of one maker).
- Deleting the account asks for no passkey (the authenticator app protects the deletion, see [Authenticator app security](authenticator-security.md#removing-the-app)).
