# Authenticator app security

How madAuth handles the authenticator app (TOTP), for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules mention this file, so update it when you change them. What the app does on a server, as a second factor or on its own, is the [sign-in policy](server.md#sign-in-methods).

## Codes

Codes follow RFC 6238 (TOTP) on RFC 4226 (HOTP): HMAC-SHA1 of the time step, 6 digits, a new code every 30 seconds. This is what every authenticator app does by default, and what the `otpauth://` URI in the QR code says (`algorithm=SHA1&digits=6&period=30`).

- A code is accepted one step before and after the current one, so a phone whose clock is up to 30 seconds off, and a code typed just before it changed, still work. Codes further off are refused.
- The secret is 20 random bytes (160 bits), as RFC 4226 recommends for HMAC-SHA1. It is shown as 32 base32 characters for apps that can't scan the QR code.
- Codes are compared in constant time, and every candidate step is compared, so the time taken says nothing about which one matched.

Code: [`packages/server/src/authenticator.ts`](../packages/server/src/authenticator.ts).

## A code works once

Once a code was accepted, it and every earlier code are refused: the account remembers the time step of the last accepted code (`account.lastUsedStep`). The write that records it only lands if no other request accepted a code meanwhile, so the same code sent twice at once signs in once. Setting the app up records the step of the first code as well: that code can't sign in afterwards.

Code: `useAuthenticatorStep` in [`packages/server/src/users.ts`](../packages/server/src/users.ts), `checkCode` in [`routes/authenticator.ts`](../packages/server/src/routes/authenticator.ts).

## Secrets at rest

A TOTP secret must be readable to check codes, so it can't be hashed like a password. It is stored encrypted with AES-256-GCM under a key derived (HKDF) from the server's signing key, with a random IV per secret: a copy of the database alone gives no codes, and a tampered record is refused. The price is that a new `MADAUTH_SIGNING_KEY` makes every enrolled app stop working, with an error in the log; the users set their app up again. Keep the key.

Code: `deriveAuthenticatorKey`, `encryptSecret` and `decryptSecret` in [`authenticator.ts`](../packages/server/src/authenticator.ts).

## Setting the app up

- Only a signed-in user sets the app up, or a sign-in whose first step is done (a `required` policy, or a sign-up with the app whose address was just confirmed). While the app is allowed as a sign-in method, a signed-in user's first app is a way in of its own, so it needs a sign-in within the last ten minutes (`reauth_required`), like a passkey. Nobody can set an app up for someone else. When both are at one browser (someone is signed in, and another sign-in waits for its setup), the setup is for the sign-in that waits, and any session that starts, or signing out, ends the wait.
- A user who has an app gives a current code from it (or a recovery code) before a new key is issued: a new app replaces the old one and its recovery codes, and a stolen session alone must not swap them for the thief's. The approval holds for ten minutes in the setup cookie, so starting the setup again costs no second code and no second recovery code.
- The new secret is not stored until the first code proves that the app has it. Until then it travels in a cookie (`madauth_authenticator_setup`, HttpOnly, ten minutes, only sent to `/auth/authenticator`), as a signed token that carries the user's id and the encrypted secret. A setup expires, is bound to its user, and can't be confirmed from another browser or by another user.
- A new setup replaces the earlier app and its recovery codes, and resets the failed attempts. It confirms only the state it started in: the recovery codes are written first, under the setup's id, and the secret only if the account still has the setup it had when this one started (a compare-and-set write). Of two setups confirmed at once, exactly one wins; the other drops its codes and is told to start again. So the app and its recovery codes always belong together, and a code of a replaced app never works.
- The setup screen says what the app will do: that signing in with the password (or Google, GitHub, or the e-mail link) then asks for a code. Setting it up is the user's consent; an admin's policy can't make an account weaker than what the user agreed to, only ask for more.
- Whether the app signs in on its own is the admin's setting (`allowAsSignInMethod`), for every user who has one. Only as a second factor, it never signs in alone: a password and a code never become a code alone. Allowed as a sign-in method, it does, also for a user who set it up as the second factor of a password: that makes their account a code alone, which is why it is the admin's explicit choice and not the default. A user who signed up with the app alone needs it allowed to sign in at all. The account records whether the user signed up with it (`primaryUserId`), for the webhook: setting up that app is part of the sign-up, not a second factor.

Code: `/auth/authenticator/setup` and `/auth/authenticator/confirm` in [`routes/authenticator.ts`](../packages/server/src/routes/authenticator.ts).

## Recovery codes

Setting the app up gives the user ten recovery codes, shown once: ten lower-case letters and digits from 2 to 7 each (no 0, 1, 8 or 9, which are easy to misread), in two groups of five. Each signs in once in place of a code from the app, wherever a code is asked for.

- Only a keyed hash of each code is stored (HMAC-SHA256 with the key derived from the signing key), so a copy of the database gives no codes. The delete count decides when a code is used, so the same code sent twice signs in once.
- Using one tells your webhook how many are left (`user.recovery_code_used`), so your app can remind the user to get new ones. New codes replace the whole set and take a current code.
- A user who lost both the phone and the codes needs an admin, who [resets their sign-in](server.md#resetting-a-users-sign-in): every method and factor goes, and the user signs up again. Nothing in madAuth hands such a user a way in by e-mail on its own: the inbox is what a password reset proves, and the app exists to ask for more than the inbox. So the admin checks who is asking first: after a reset, the inbox is all it takes.

Code: `generateRecoveryCodes`, `hashRecoveryCode` in [`authenticator.ts`](../packages/server/src/authenticator.ts); `replaceRecoveryCodes`, `consumeRecoveryCode` in [`users.ts`](../packages/server/src/users.ts).

## The second step

After Google, GitHub, a password or an e-mail link whose policy asks for a second factor, the first step gives no session. Instead the server sets a challenge cookie (`madauth_challenge`, HttpOnly, ten minutes, sent to `/auth`): a signed token with the user's id, their session version, how they signed in so far, what comes next, and which factors can finish it (the app, and the phone when the user has one and [SMS codes](sms-security.md) are on; the app comes first). The code, or the setup, turns it into the session.

- The challenge is bound to the user and to its step: a challenge for the setup can't be used to skip the setup with a code, and the other way round.
- It finishes only while its method is still on: an admin who switches Google, GitHub, password or the e-mail link off also ends the sign-ins that were between their two steps.
- Issuing it clears the session there was at that browser: a sign-in that reaches the second step signs out whoever was signed in until the step is done, so an abandoned step can't be taken for that user's own setup later.
- A password reset in between ends the challenge (the session version changed), as it ends every session.
- The session issued afterwards says how it was authenticated: `amr: ["pwd", "otp"]` or `["google", "otp"]`. The web library's `user.amr` and `createSessionVerifier` expose it, so a backend can require `otp` before a sensitive action. A webhook `user.signed_in` carries `secondFactor: "authenticator"` or `"recovery_code"`.

Code: `secondStep` in [`packages/server/src/app.ts`](../packages/server/src/app.ts), `/auth/authenticator/verify` in [`routes/authenticator.ts`](../packages/server/src/routes/authenticator.ts).

## No account enumeration

Signing in with the app alone answers `401 invalid_credentials` for an unknown address, an address without the app, an address whose app is a second factor, an address nobody confirmed, and a wrong code alike. Nothing slow happens in any of these cases, so the answer takes about as long for each of them. Sign-up with the app answers `202` whether or not the address has an account, like a password sign-up: an address that is registered gets the `email.send_already_registered` e-mail (saying how it signs in) instead.

What stays visible, as with passwords: after five wrong codes the answer becomes `too_many_attempts`, only for an address that has the app. A Google or GitHub sign-in with the address of a user who signs in another way is told so (`403 other_method`, or `madauth_error=other_method` after a redirect), to the owner of an account whose address the provider verified.

## Brute force

The lock is the same as for passwords, and shared with them in the code: failed attempts are counted per account, from the fifth on each further attempt waits 1, 2, 4, 8 … seconds, up to 15 minutes, and the attempt is counted before the code is checked, so attempts sent at the same time can't get around the wait. Three of a million codes are valid at any moment; with the lock, guessing is hopeless. The lock also covers the second step, removing the app, new recovery codes and deleting the account, which all take a code. Confirming a setup is not locked: whoever holds the session (or the challenge) already holds the secret they are confirming.

**Limit requests per IP address in front of madAuth** too, as for [passwords](password-security.md#brute-force).

Code: [`packages/server/src/routes/lockout.ts`](../packages/server/src/routes/lockout.ts).

## Removing the app

Removing the app, and new recovery codes, take a current code from the app or a recovery code: a stolen session alone can't switch the protection off. While the policy of any method that is on is `required`, the app can only go if the user keeps another second factor that is on, a passkey or a phone (`403 required_by_policy`); otherwise they can only replace it. Nor can it go as the user's last way to sign in (`403 only_method`): without it nobody could, and the record would be taken over by the next sign-up for the address; they add another [sign-in method](sign-in-methods.md) first, or delete the account. Otherwise the app can go, whatever methods are on. Deleting the whole account takes a code as well once the app is set up, for the same reason; an app that an admin switched off server-wide protects nothing and is not asked for. An admin removes no app alone: a user who lost it is reset, with all their methods, and signs up again (see [Resetting a user's sign-in](server.md#resetting-a-users-sign-in)).

## A method signs in only users who have it

A Google or GitHub sign-in with the address of a user who signs in with a password, with the app, or both, is refused (`403 other_method`): whoever controls that account for the address must not get past the password and the app. The user adds Google or GitHub while signed in instead, and a Google or GitHub user adds a password the same way ("Forgot password?" only resets a password that exists); see [Several sign-in methods](sign-in-methods.md). The authenticator app is added only by the user, while signed in, or when a policy requires it. The one takeover that remains is of a sign-up nobody finished, since nobody has proven it: the latest unproven sign-up wins, so a sign-up with the app drops the password an earlier unconfirmed sign-up set, and a password sign-up replaces an unfinished app sign-up. A password sign-up for an address whose app sign-up is confirmed but whose app is not set up yet needs its own e-mail as well (so does a new sign-up with the app or a passkey: the address counts as unconfirmed again): until that is used, the password doesn't sign in, and the pending app setup (the confirmed sign-up) wins and drops it. Once the password's e-mail is used, the password is the user's method and the setup is refused.

Code: `resolveProviderUser` in [`packages/server/src/routes/oauth.ts`](../packages/server/src/routes/oauth.ts).

## Cross-site requests

All `POST` routes of the app are accepted only from an `Origin` in `ALLOWED_ORIGINS`, and CORS requests are answered only for those origins. The challenge and setup cookies are `SameSite=Strict`; the setup cookie is sent only to `/auth/authenticator`, the challenge cookie to `/auth`.

## Not covered yet

- Trusted devices ("remember this browser for 30 days"): the code is asked for at every sign-in.
- Apps that want SHA-256 or 8-digit codes; the QR code asks for the defaults every app supports.
- A code from the app can be phished like a password; [passkeys](passkey-security.md) can't.
