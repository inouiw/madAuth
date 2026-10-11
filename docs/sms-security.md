# SMS code security

How madAuth handles SMS codes as a second factor, for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules mention this file, so update it when you change them.

SMS codes are **only a second factor**: a signed-in user adds a phone number, and from then on the sign-in methods whose [policy](server.md#sign-in-methods) asks for a second factor (Google, password, the e-mail link) can ask for a code sent to it, next to the [authenticator app](totp-security.md). A phone never signs anyone in by itself, and never creates a user: SMS can be intercepted (SIM swapping, SS7) and a number changes hands, so it protects an account that already has a first factor and is not one. Where that is not enough, the operator leaves SMS codes off, and the app is the only second factor.

## Codes

A code is 6 random digits, made and checked like the codes in madAuth's e-mails (see [Password security](password-security.md#links-and-codes-in-e-mails)): only its keyed hash is stored, it lives **ten minutes**, it works once (the delete count decides), and after 5 wrong codes the record is deleted, so a new code has to be sent. A new code replaces the previous one.

Unlike the e-mail codes, SMS codes are not counted per user across messages: that lock is only lifted by an e-mail link or a password reset, which a Google user with a phone never has. Instead, the attempts are counted on the user's sms account like failed passwords (see below), and only one SMS per minute is sent.

Code: `issueVerification` and `consumeCode` in [`packages/server/src/users.ts`](../packages/server/src/users.ts).

## Setting the phone up

A user adds a number while signed in (`Madauth.setUpSms()`, or `Madauth.sms.setUp()` and `confirmSetup()` on a custom screen), or in the setup step of a sign-in whose policy requires a second factor they have not set up yet. The number must be given in international form (`+41 79 …`) and is stored as E.164; madAuth never shows it in full again, only its beginning and last two digits.

- The server sends a code to the new number and keeps the number in a signed, short-lived setup cookie (`madauth_sms_setup`, ten minutes, only sent to `/auth/sms`). Nothing is stored until the code proves that the number receives the SMS.
- Replacing a number takes a code sent to the **current** number first, like removing it (`Madauth.sms.send()` while signed in, then `setUp({ phone, code })`): a stolen session alone must not swap the number for the thief's. The approval holds for ten minutes in the setup cookie, so a mistyped number or a code sent again costs no second approval.
- A sign-up with the authenticator app alone has no first factor yet: it sets the app up, never a phone. SMS codes are never the only factor of an account.

Code: `setup` and `confirm` in [`packages/server/src/routes/sms.ts`](../packages/server/src/routes/sms.ts).

## The second step

After the first step of a method whose policy is `optional` or `required`, the server looks at what the user has: with the app, it asks for a code from the app (`401 totp_required`); with a phone only, for the SMS code (`401 sms_required`); with both, for the app, and the answer's `factors` (`["totp", "sms"]`) lets the dialog offer "send a code by SMS instead". The challenge cookie (see [Authenticator app security](totp-security.md#the-second-step)) carries the factors, so `/auth/sms/verify` and `/auth/totp/verify` each accept it only for a factor the user has.

The SMS goes when the client asks for it (`POST /auth/sms/send` with the challenge), not with the first step: a user who has the app as well gets no SMS unless they switch. The session then says `amr: ["pwd", "sms"]` (or `["google", "sms"]`, `["email", "sms"]`), and `user.signed_in` carries `secondFactor: "sms"`. A backend that requires the app can ask for `otp` in `amr`.

With a `required` policy and neither factor, the sign-in goes to the app's setup (`totp_setup_required`); when SMS codes are on, the dialog offers adding a phone instead, in the same pending sign-in. The user decides which factor to set up; an admin can't prescribe one.

Code: `secondStep` in [`packages/server/src/app.ts`](../packages/server/src/app.ts), [`challenge.ts`](../packages/server/src/routes/challenge.ts), `send` and `verify` in [`sms.ts`](../packages/server/src/routes/sms.ts).

## Sending

madAuth sends no SMS itself: it hands the code to your [webhook](server.md#webhooks) as `sms.code` (`to`, `code`, `purpose`, `expiresAt`, `site`, `locale`, `user`), and your receiver sends it, e.g. through Amazon SNS or Twilio. The call is signed like every webhook call, and `WEBHOOK_URL` must be https (except on the same machine), since the call carries the code. If the receiver does not take the SMS over within ten seconds, the request fails with `503 temporarily_unavailable` and nothing is stored; the user can retry at once.

At most one SMS per minute goes to a user (`429 too_soon` otherwise), whoever asks, counted apart from the e-mails: the link of a sign-in and the SMS of its second step may follow each other at once. The code is the same for that minute, so a sign-in that repeats within it still works with the code already sent. Per-IP limits in front of madAuth (see [Password security](password-security.md#brute-force)) slow down anyone who makes madAuth send SMS, which cost money.

Code: `sendCode` in [`sms.ts`](../packages/server/src/routes/sms.ts).

## Brute force

Wrong SMS codes are counted on the user's sms account with the lock shared by passwords and the authenticator app (see [Password security](password-security.md#brute-force)): from the fifth failure on, each further attempt waits 1, 2, 4, 8 … seconds up to 15 minutes, with `429 too_many_attempts`. Together with the 5 attempts per code and one code per minute, the million possible codes are out of reach.

Code: [`packages/server/src/routes/lockout.ts`](../packages/server/src/routes/lockout.ts).

## Removing the phone

`Madauth.sms.remove({ code })` takes a code sent to the number (`Madauth.sms.send()` while signed in), so a stolen session can't switch the protection off. While a method's policy is `required`, the phone can only go if the user has the authenticator app (`403 required_by_policy`), and the app can only go if the user has a phone while SMS codes are on. A user who lost the phone needs the operator: `npx @madauth/server remove-sms <email>` (with `DATABASE_URL`; it calls no webhook), or `POST /auth/admin/sms/remove` as an admin; with a `required` policy they set a factor up again at their next sign-in.

An admin who switches SMS codes off (`sms` left out of the methods) ends the sign-ins that wait for an SMS code, and the phones no longer count: a user with only a phone signs in with the first factor alone under an `optional` policy, and sets the app up under a `required` one.

Code: `remove` in [`sms.ts`](../packages/server/src/routes/sms.ts), `POST /auth/admin/sms/remove` in [`app.ts`](../packages/server/src/app.ts).

## Cross-site requests

Every SMS endpoint that changes something is a `POST` request accepted only from an `Origin` in `ALLOWED_ORIGINS` (`GET /auth/sms/status` only reads), and the challenge and setup cookies are `SameSite=Strict`.

## Not covered yet

- SMS codes as a sign-in method on its own (a phone as the identity), and phone-only users.
- A code by SMS when deleting the account: only the authenticator app protects the deletion.
- Remembering a device, so the second step is not asked every time.
- Limits per phone number across accounts, and country or carrier restrictions: do that in your receiver.
