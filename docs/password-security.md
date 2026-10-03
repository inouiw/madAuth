# Password security

How madAuth protects e-mail & password accounts, for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules mention this file, so update it when you change them.

## Hashing

Passwords are hashed with **scrypt** from Node's built-in `node:crypto`, with N = 2^15, r = 8, p = 3, a 16-byte random salt and a 64-byte key. This is one of the equivalent settings [OWASP recommends](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt). It needs 32 MB per hash instead of 128 MB for N = 2^17, so several sign-ins at once can't run a small container out of memory. scrypt needs no native module, so it works in every hosting target.

- A hash is stored as `scrypt$15$8$3$<salt>$<hash>`. The parameters are part of the hash, so they can be raised later: after a successful sign-in, a hash with older parameters is replaced by a new one.
- Passwords are compared in constant time.
- Passwords are Unicode-normalized (NFC) before hashing, so the same password typed on different keyboards matches.
- Hashing takes about 200 ms on one CPU core. Give an AWS Lambda function at least 256 MB of memory.

Code: [`packages/server/src/password.ts`](../packages/server/src/password.ts).

### Why madAuth hashes, and not the store

Auth0's custom-database scripts work the other way round: the customer's database checks the password itself. That lets a customer keep an existing user table with its own hash format as the source of truth. The price is that every implementation has to get hashing, equal timing, throttling and verification right.

madAuth keeps all of this in one tested place. A [store adapter](server.md#custom-store-adapter) only saves records, so it is short and can't weaken the security. Moving existing users with their old hashes into madAuth may later get an optional hook that checks a legacy hash on the first sign-in and then rehashes the password.

## Password rules

As [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) recommends, only the length is checked: at least `PASSWORD_MIN_LENGTH` characters (default 8) and at most 256. There are no rules like "one digit and one symbol". Spaces and any Unicode characters are allowed, and leading and trailing spaces are kept.

Code: `checkPasswordPolicy` in [`password.ts`](../packages/server/src/password.ts).

## E-mail addresses

Addresses are looked up trimmed and lower-cased, so `Ada@Example.com` and `ada@example.com` are the same account. The address is kept as typed for display and for sending e-mails.

## No account enumeration

Nobody should be able to find out through madAuth whether an address has an account:

- Sign-in answers `invalid_credentials` both for an unknown address and for a wrong password. For an unknown address the password is still hashed against a dummy hash, so the answer takes as long.
- Sign-up, "send the confirmation e-mail again" and "send a reset e-mail" always answer `202`. The address is hashed before it is looked up, so sign-up takes as long for new and existing addresses.
- Signing up with an address that already has a confirmed account sends its owner a "you already have an account" e-mail instead of revealing anything to the person signing up.
- An address that signed up but never confirmed can sign up again: the latest sign-up sets the password, and only the latest e-mail works. This prevents someone from blocking an address by signing it up first.

Two things are still visible:

- After five wrong passwords for an address, the answer becomes `too_many_attempts`, which only happens for existing accounts. Per-IP limits in front of madAuth (see below) make this slow to use.
- While your [webhook](server.md#webhooks) receiver is down, "send a reset e-mail" and "send the confirmation e-mail again" fail with `temporarily_unavailable` for existing accounts, but answer `202` for unknown addresses, which get no e-mail. Answering `202` for existing accounts too would leave users waiting for an e-mail that never comes. Sign-up is not affected: every sign-up sends an e-mail, so it fails the same way for every address.

## Sign-up check

Your webhook receiver can refuse sign-ups, e.g. to allow only company addresses or to block disposable ones (`signup.before`). It runs before anything is stored, and it fails closed: if the receiver does not answer, nobody can sign up. Its refusal message is shown to the user as it is, so don't put anything in it that the user shouldn't see.

Code: [`packages/server/src/routes/password.ts`](../packages/server/src/routes/password.ts).

## Brute force

- Failed sign-ins are counted per account. From the fifth failure on, each further attempt must wait: 1 second, then 2, 4, 8 … up to 15 minutes. Meanwhile the answer is `429 too_many_attempts`, even with the right password. A successful sign-in resets the count.
- Each account gets at most one e-mail per minute, so nobody can flood an inbox through madAuth. The answer is the same whether or not an e-mail was sent.
- Absurdly long passwords (over 1024 characters) are rejected before hashing.

**Limit requests per IP address in front of madAuth** too, e.g. in your reverse proxy, load balancer, API Gateway or a WAF. madAuth can't do this reliably itself: it runs stateless on several instances, and only the proxy knows the client's real address.

## Links and codes in e-mails

The confirmation and reset e-mails contain a link and a 6-digit code. The link is the easiest way; the code helps when the e-mail is read on another device.

- The link token is 32 random bytes. Only its SHA-256 is stored, so a copy of the database contains no usable links.
- The code is stored as an HMAC-SHA256 with a key derived (HKDF) from the server's signing key. A plain hash of a 6-digit number could be reversed by trying all million values; without the signing key this is not possible.
- The link and the code share one record. It expires after 24 hours for a confirmation and after 30 minutes for a reset.
- They work once. The record is deleted when it is used, and the number of deleted records decides, so two requests with the same link can't both succeed.
- After 5 wrong codes the record is deleted, and the link stops working too.
- A new e-mail replaces the previous one for the same purpose; older links and codes stop working.
- The link points to the app page that asked for it (`redirectTo`), which must be on an origin in `ALLOWED_ORIGINS`. The token is in the URL's **hash** (`#madauth_reset=…`). Browsers never send the hash to servers or in the `Referer` header, and `Madauth.initialize` removes it from the address bar right away.

Code: `issueVerification`, `consumeLinkToken` and `consumeCode` in [`packages/server/src/users.ts`](../packages/server/src/users.ts).

## E-mail confirmation

A new account can't sign in until its address is confirmed (`403 email_unverified`); the dialog then offers to send the e-mail again. Confirming with the link or the code signs the user in. A completed password reset also confirms the address, since it proves access to the inbox.

## Sessions

Password users get the same madAuth session as Google users: a signed JWT in an HttpOnly cookie, with `sub` = `usr_<id>` and `amr: ["pwd"]`. It also carries `sv`, the user's session version.

A password reset increases the session version. The madAuth server then rejects older sessions when the app checks them (`GET /auth/session`, e.g. on page load), and doesn't renew them.

**Limit:** your own backends usually check the JWT offline with [`createSessionVerifier`](server.md#verifying-the-session-in-your-backend), without asking madAuth. They accept an older session until it expires. A shorter `SESSION_TTL` shortens this window; the session is renewed when the app checks it after half of that time.

Code: `GET /auth/session` in [`packages/server/src/app.ts`](../packages/server/src/app.ts).

## Cross-site requests

All password endpoints are `POST` requests. madAuth only accepts them from an `Origin` in `ALLOWED_ORIGINS` and answers CORS requests only for those origins. Another site therefore can't sign a visitor in or out, and can't sign them in to an attacker's account (login CSRF).

## Not covered yet

- Checking new passwords against lists of leaked passwords (e.g. Have I Been Pwned).
- Changing the password while signed in (use "Forgot password?" meanwhile).
- Linking a Google account and a password account with the same address. They are separate users for now.
- Moving users with existing password hashes from another system.
