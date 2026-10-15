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
- Or the sign-in whose policy requires a second factor the user doesn't have yet (`totp_setup_required` with `passkey` among its `factors`): the new passkey finishes that sign-in.
- Or a sign-up with a passkey alone, once its address is confirmed (see below). A sign-up with the authenticator app alone has no first factor either, so it sets the app up, never a passkey; and a sign-up with a passkey sets up a passkey, never the app or a phone.
- The options leave out the passkeys the user has (`excludeCredentials`), so an authenticator that holds one says so instead of making another. A passkey is stored by the SHA-256 of its credential id (the id itself can be longer than a key column holds), with its public key, its transports, its counter and a name the user gives it (`Passkey` by default, at most 64 characters, changed with `Madauth.passkey.rename`).
- madAuth asks for no attestation (`none`): it doesn't check which device made the passkey, only that it was verified and answers for this site.

## Signing up with a passkey

Every user has one confirmed e-mail address, and a passkey gives none: the authenticator only names the user by madAuth's id. So a sign-up with a passkey alone confirms the address first, then creates the passkey, like the [sign-up with the authenticator app alone](totp-security.md#setting-the-app-up):

1. `POST /auth/passkey/signup` with the address (and a name) sends the confirmation e-mail (`email.send_verification`). It is offered only while passkeys are on, allowed as a sign-in method, and the server confirms addresses (`passkey.signUp` in `GET /auth/config`), and only to an app within the passkeys' domain (`403 forbidden_origin` otherwise: the address would be confirmed for a passkey that can't be made there). The same rules as for every sign-up apply: the operator's check first (`user.signing_up` with `method: "passkey"`, failing closed), the "you already have an account" e-mail for an address that signs in another way, the same answer for every address, and the latest sign-up nobody finished wins: it drops the password or e-mail link an earlier, unconfirmed sign-up set.
2. The link or the code confirms the address and answers with the step that creates the passkey (`401 passkey_setup_required`, `method: "passkey"`, `factors: ["passkey"]`). The user records which method a pending sign-up confirms its address for (`user.signUpMethod`), so the confirmation knows it is a passkey's.
3. `/auth/passkey/register/*` accepts that step, and only that step of a sign-in without a first factor: the new passkey becomes the user's sign-in method (the account they signed up with), and signs them in (`amr: ["passkey"]`, `user.signed_up` with `method: "passkey"`, no `user.method_added`). With a `passkey` policy that asks for a second factor, the sign-up goes on with its setup (`totp_setup_required`: the app or a phone), as a passkey sign-in would; that setup never takes another passkey.

A password sign-up for the address after the confirmation needs its own e-mail: until it is used, the passkey's setup wins and the password goes; once it is used, the password is the user's method and the passkey of the sign-up is refused (`setup_expired`).

**Recovery.** A user who lost every passkey and has no other method asks the operator to remove their passkeys (`remove-passkeys`, or `POST /auth/admin/passkey/remove`), and signs up again with their address: the same user, with a new passkey. There is no recovery by e-mail: it would make the account only as strong as the inbox. Users who want one add another method, e.g. the e-mail link.

Code: `signUpThenSetUp` in [`routes/email.ts`](../packages/server/src/routes/email.ts), `/auth/passkey/register/verify` in [`routes/passkey.ts`](../packages/server/src/routes/passkey.ts), `whoSetsUp` in [`routes/challenge.ts`](../packages/server/src/routes/challenge.ts).

## Signing in, and the second step

With passkeys allowed as a sign-in method (`allowAsSignInMethod`), every passkey of a user signs them in on its own, as `["passkey"]`; the `passkey` policy can ask for a second factor after it, which is then the app or a phone, never a passkey. Only as a second factor (`allowAsSignInMethod: false`), a passkey is asked for after another method, and comes first of the user's second factors: `passkey_required`, with the user's passkeys in the options (`allowCredentials`). A passkey counts as a second factor only on the domain it was made for (it is stored with it): on an app of another domain it couldn't answer, so there the user is asked for another factor, or sets one up under a `required` policy. The challenge cookie of the sign-in and the ceremony cookie both have to fit, and the passkey must be one of the user's.

A passkey the server no longer has (the user removed it) is `401 passkey_unknown`; the web library then tells the browser to forget it, where the browser supports that (the WebAuthn Signal API).

## Removing a passkey

- Within ten minutes of signing in, like adding one: `Madauth.methods.remove(id)` or `POST /auth/methods/remove`.
- Not the last way the user signs in (`403 only_method`): they add another method first, or delete the account.
- Not the last second factor a `required` policy can ask them for (`403 required_by_policy`): a policy needs a factor the user keeps, other than the method itself. One of several passkeys may always go, and the passkeys' own policy doesn't keep the last one: without it, the user signs in with no passkey.
- A user who lost their passkeys signs in another way and removes them, or asks the operator: `npx @madauth/server remove-passkeys <email>` (it calls no webhook) or `POST /auth/admin/passkey/remove` (`user.method_removed` with `by`). A user who signed up with a passkey and has no other method then signs up again (see [Signing up with a passkey](#signing-up-with-a-passkey)).

## The domain

A passkey belongs to a domain (the WebAuthn relying party id), and the browser offers it only on that domain and its subdomains. Without `PASSKEY_RP_ID`, it is the host of the app that adds the passkey, so a passkey made on `app.example.com` works there only. With `PASSKEY_RP_ID=example.com`, the passkeys work on every app under `example.com`; an app outside it is refused (`403 forbidden_origin`). The server refuses to start when no app of `ALLOWED_ORIGINS` is within it. A new `PASSKEY_RP_ID` makes every existing passkey stop working: the users sign in another way and add new ones, and those who sign in with passkeys alone are locked out until the operator removes their passkeys and they sign up again.

## Not covered yet

- Passkeys in native apps (Capacitor): WebAuthn in a WebView needs the app's associated domains (iOS) or asset links (Android) for the domain, and an origin in `ALLOWED_ORIGINS` for it.
- Attestation, or allowing only certain authenticators (e.g. security keys of one maker).
- Deleting the account asks for no passkey (the authenticator app protects the deletion, see [Authenticator app security](totp-security.md#removing-the-app)).
