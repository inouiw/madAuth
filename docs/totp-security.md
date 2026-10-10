# Authenticator app security

How madAuth handles the authenticator app (TOTP), for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules mention this file, so update it when you change them. What the app does on a server, as a second factor or on its own, is the [sign-in policy](server.md#sign-in-methods).

## Codes

Codes follow RFC 6238 (TOTP) on RFC 4226 (HOTP): HMAC-SHA1 of the time step, 6 digits, a new code every 30 seconds. This is what every authenticator app does by default, and what the `otpauth://` URI in the QR code says (`algorithm=SHA1&digits=6&period=30`).

- A code is accepted one step before and after the current one, so a phone whose clock is up to 30 seconds off, and a code typed just before it changed, still work. Codes further off are refused.
- The secret is 20 random bytes (160 bits), as RFC 4226 recommends for HMAC-SHA1. It is shown as 32 base32 characters for apps that can't scan the QR code.
- Codes are compared in constant time, and every candidate step is compared, so the time taken says nothing about which one matched.

Code: [`packages/server/src/totp.ts`](../packages/server/src/totp.ts).

## A code works once

Once a code was accepted, it and every earlier code are refused: the account remembers the time step of the last accepted code (`account.lastUsedStep`). The write that records it only lands if no other request accepted a code meanwhile, so the same code sent twice at once signs in once. Setting the app up records the step of the first code as well: that code can't sign in afterwards.

Code: `useTotpStep` in [`packages/server/src/users.ts`](../packages/server/src/users.ts), `checkCode` in [`routes/totp.ts`](../packages/server/src/routes/totp.ts).

## Secrets at rest

A TOTP secret must be readable to check codes, so it can't be hashed like a password. It is stored encrypted with AES-256-GCM under a key derived (HKDF) from the server's signing key, with a random IV per secret: a copy of the database alone gives no codes, and a tampered record is refused. The price is that a new `MADAUTH_SIGNING_KEY` makes every enrolled app stop working, with an error in the log; the users set their app up again. Keep the key.

Code: `deriveTotpKey`, `encryptSecret` and `decryptSecret` in [`totp.ts`](../packages/server/src/totp.ts).

## Setting the app up

- Only a signed-in user sets the app up, or a sign-in whose first step is done (a `required` policy, or a sign-up with the app whose address was just confirmed). Nobody can set an app up for someone else.
- The new secret is not stored until the first code proves that the app has it. Until then it travels in a cookie (`madauth_totp_setup`, HttpOnly, ten minutes, only sent to `/auth/totp`), as a signed token that carries the user's id and the encrypted secret. A setup expires, is bound to its user, and can't be confirmed from another browser or by another user.
- A new setup replaces the earlier app and its recovery codes, and resets the failed attempts.
- The setup screen says what the app will do: that signing in with the password (or Google) then asks for a code, and whether the app signs in on its own. Setting it up is the user's consent; an admin's policy can't make an account weaker than what the user agreed to, only ask for more.

Code: `/auth/totp/setup` and `/auth/totp/confirm` in [`routes/totp.ts`](../packages/server/src/routes/totp.ts).

## Recovery codes

Setting the app up gives the user ten recovery codes, shown once: ten lower-case letters and digits from 2 to 7 each (no 0, 1, 8 or 9, which are easy to misread), in two groups of five. Each signs in once in place of a code from the app, wherever a code is asked for.

- Only a keyed hash of each code is stored (HMAC-SHA256 with the key derived from the signing key), so a copy of the database gives no codes. The delete count decides when a code is used, so the same code sent twice signs in once.
- Using one tells your webhook how many are left (`totp.recovery_code_used`), so your app can remind the user to get new ones. New codes replace the whole set and take a current code.
- A user who lost both the phone and the codes needs the operator: `npx @madauth/server remove-totp <email>`, or the admin API. Nothing in madAuth hands such a user a way in by e-mail: the inbox is what a password reset proves, and the app exists to ask for more than the inbox.

Code: `generateRecoveryCodes`, `hashRecoveryCode` in [`totp.ts`](../packages/server/src/totp.ts); `replaceRecoveryCodes`, `consumeRecoveryCode` in [`users.ts`](../packages/server/src/users.ts).

## The second step

After Google or a password whose policy asks for the app, the first step gives no session. Instead the server sets a challenge cookie (`madauth_challenge`, HttpOnly, ten minutes, only sent to `/auth/totp`): a signed token with the user's id, their session version, how they signed in so far and what comes next. The code, or the setup, turns it into the session.

- The challenge is bound to the user and to its step: a challenge for the setup can't be used to skip the setup with a code, and the other way round.
- A password reset in between ends the challenge (the session version changed), as it ends every session.
- The session issued afterwards says how it was authenticated: `amr: ["pwd", "otp"]` or `["google", "otp"]`. The web library's `user.amr` and `createSessionVerifier` expose it, so a backend can require `otp` before a sensitive action. A webhook `user.signed_in` carries `secondFactor: "totp"` or `"recovery_code"`.

Code: `secondStep` in [`packages/server/src/app.ts`](../packages/server/src/app.ts), `/auth/totp/verify` in [`routes/totp.ts`](../packages/server/src/routes/totp.ts).

## No account enumeration

Signing in with the app alone answers `401 invalid_credentials` for an unknown address, an address without the app, an address nobody confirmed, and a wrong code alike. Nothing slow happens in any of these cases, so the answer takes about as long for each of them. Sign-up with the app answers `202` whether or not the address has an account, like a password sign-up: an address that is registered gets the `email.already_registered` e-mail (saying how it signs in) instead.

What stays visible, as with passwords: after five wrong codes the answer becomes `too_many_attempts`, only for an address that has the app. A Google sign-in with the address of a user who signs in another way is told so (`403 other_method`), to the owner of a Google account that Google verified for that address.

## Brute force

The lock is the same as for passwords, and shared with them in the code: failed attempts are counted per account, from the fifth on each further attempt waits 1, 2, 4, 8 … seconds, up to 15 minutes, and the attempt is counted before the code is checked, so attempts sent at the same time can't get around the wait. Three of a million codes are valid at any moment; with the lock, guessing is hopeless. The lock also covers the second step, removing the app, new recovery codes and deleting the account, which all take a code. Confirming a setup is not locked: whoever holds the session (or the challenge) already holds the secret they are confirming.

**Limit requests per IP address in front of madAuth** too, as for [passwords](password-security.md#brute-force).

Code: [`packages/server/src/routes/lockout.ts`](../packages/server/src/routes/lockout.ts).

## Removing the app

Removing the app, and new recovery codes, take a current code from the app or a recovery code: a stolen session alone can't switch the protection off. While the policy of any method that is on is `required`, nobody can remove the app (`403 required_by_policy`); they can only replace it. Deleting the whole account takes a code as well once the app is set up, for the same reason. An admin can remove a user's app without a code (`POST /auth/admin/totp/remove`, or `remove-totp` on the command line); the webhook learns who did it (`totp.disabled` with `by`).

## A method signs in only users who have it

A Google sign-in with the address of a user who signs in with a password, with the app, or both, is refused (`403 other_method`): whoever controls the Google account for the address must not get past the password and the app. A password can't be added to a Google user either ("Forgot password?" only resets a password that exists). The authenticator app is added only by the user, while signed in, or when a policy requires it. The one takeover that remains is of a sign-up nobody finished, since nobody has proven it.

Code: `resolveUser` in [`packages/server/src/routes/google.ts`](../packages/server/src/routes/google.ts).

## Cross-site requests

All `POST` routes of the app are accepted only from an `Origin` in `ALLOWED_ORIGINS`, and CORS requests are answered only for those origins. The challenge and setup cookies are `SameSite=Strict` and sent only to `/auth/totp`.

## Not covered yet

- Trusted devices ("remember this browser for 30 days"): the code is asked for at every sign-in.
- Apps that want SHA-256 or 8-digit codes; the QR code asks for the defaults every app supports.
- SMS codes as a second factor.
- Passkeys, which would also resist phishing; a code from the app can be phished like a password.
