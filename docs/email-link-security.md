# E-mail link security

How madAuth protects the passwordless e-mail link, for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules mention this file, so update it when you change them.

The e-mail link is the sign-in method `email-link` (`new EmailLink()` in the web library): the user enters their address and gets an e-mail with a link that signs them in and a 6-digit code. Whoever can read the inbox can sign in, so the method is as strong as the inbox, like a password reset. Where that is not enough, the [sign-in policy](server.md#sign-in-methods) adds the authenticator app as a second factor.

## Links and codes

The sign-in e-mail uses the same record as the confirmation and reset e-mails of e-mail & password sign-in, with the same rules (see [Password security](password-security.md#links-and-codes-in-e-mails)): the link token is 32 random bytes of which only the SHA-256 is stored, the code is kept as a keyed hash, both work once (the delete count decides), 5 wrong codes delete the record, and 10 wrong codes in a row lock the account's codes (`429 codes_locked`) until a link is used. A sign-in link lives **15 minutes**, like a reset link rather than a confirmation link: it lets whoever has it in.

The link points to the app page that asked for it (`redirectTo`, an origin in `ALLOWED_ORIGINS`), with the token in the URL's hash (`#madauth_signin=…`), which browsers never send to servers; `Madauth.initialize` removes it from the address bar right away. A new e-mail replaces the previous one.

Code: `sendLinkEmail` in [`packages/server/src/routes/emails.ts`](../packages/server/src/routes/emails.ts), `issueVerification`, `consumeLinkToken` and `consumeCode` in [`users.ts`](../packages/server/src/users.ts).

## No account enumeration

Asking for a link always answers `202`, whether the address is new, has a link account, or signs in another way:

- A new address is signed up on first use (see below) and gets the link.
- An address that signs in another way, e.g. with a password or with Google, gets the `email.send_already_registered` e-mail instead, which says how it signs in. Nothing is revealed to the person who asked. This needs `email.send_already_registered` in `WEBHOOK_EVENTS`; without it no e-mail is sent, and the answer comes faster for such an address.
- A wrong code answers `code_invalid` for any address, a used or expired link `link_invalid`.

Two things are still visible: `codes_locked` after ten wrong codes only happens for existing accounts, and when the operator's sign-up check refuses an address (`403 signup_rejected`), that address has no link account yet. The check only runs for addresses that are not link users, because it is a sign-up check, not a sign-in check: a user who signed up before is not asked again.

Code: `POST /auth/email-link/send` in [`packages/server/src/routes/email-link.ts`](../packages/server/src/routes/email-link.ts).

## Sign-up on first use

An address nobody has is signed up by its first link: the user is created unconfirmed, with an account of the `email-link` method and no name; `user.signed_up` is sent at the first session, once the link is used. The operator's sign-up check (`user.signing_up`, `method: "email-link"`) runs before anything is stored and fails closed. The address counts as confirmed once the link or the code is used (`user.email_verified`); until then it looks like any unfinished sign-up, and another method can take it over: a sign-up with a password or with the authenticator app for the address, or a Google sign-in with it, drops the link account, so the link stops working (`link_invalid`) and the address signs in with the method that proved it.

A sign-up with a password that nobody confirmed is taken over the other way round, as with Google and the authenticator app: the first link drops the unproven password. Until the address is proven, the latest sign-up counts, as between two password sign-ups: a password sign-up after the link drops the link account again, and the link stops working. Whoever proves the address first, with the e-mail of their sign-up, is the one it ends up with.

Code: `POST /auth/email-link/send` and `verify` in [`email-link.ts`](../packages/server/src/routes/email-link.ts), `dropUnprovenAccounts` and `verifyByProvider` in [`users.ts`](../packages/server/src/users.ts).

## A method signs in only users who have it

A link never signs into an account that signs in with a password, Google, GitHub or the authenticator app alone, unless the user added the e-mail link while signed in (see [Several sign-in methods](sign-in-methods.md)): such a user gets the "you already have an account" e-mail. Otherwise a link would turn every password account into a passwordless one, and the authenticator app a user set up would count for nothing when they are signed in by e-mail. The other way round, a password sign-up or a Google or GitHub sign-in with a link user's address is refused the same way (`email.send_already_registered`, `403 other_method`), and "Forgot password?" tells them they have no password (`email.send_password_reset_no_password`).

Code: [`email-link.ts`](../packages/server/src/routes/email-link.ts), `resolveProviderUser` in [`oauth.ts`](../packages/server/src/routes/oauth.ts).

## The second step

With a policy of `optional` or `required` for the method, the link or the code does not sign in by itself: the sign-in goes on with the authenticator app (`401 totp_required` or `totp_setup_required`), exactly as after a password. See [Authenticator app security](totp-security.md#the-second-step). The session then says `amr: ["email", "otp"]`; the link alone gives `["email"]`.

Code: `secondStep` in [`packages/server/src/app.ts`](../packages/server/src/app.ts).

## Brute force

At most one e-mail per minute is sent to an account, whoever asks; a request within that minute is answered the same without an e-mail. The codes are limited as described above. Per-IP limits in front of madAuth (see [Password security](password-security.md#brute-force)) slow down anyone who asks for links to many addresses.

## Switching the method off

While an admin has the method off, its routes answer `403 method_disabled` before a link or code is used up, so they keep working once the method is on again. The method is configured only when the webhook sends `email.send_signin_link`; without that type the routes are not there (404).

Code: the middleware in [`email-link.ts`](../packages/server/src/routes/email-link.ts).

## Sessions and cross-site requests

A link user gets the same madAuth session as every other user, with `amr: ["email"]`, and the same session version mechanism; see [Password security](password-security.md#sessions). All endpoints are `POST` requests accepted only from an `Origin` in `ALLOWED_ORIGINS`.

## Not covered yet

- Binding the link to the browser that asked for it: a link opened on another device signs in there, which is also what makes the code unnecessary on the same device. The short lifetime limits the risk.
- Remembering a device, so a second factor is not asked every time.
