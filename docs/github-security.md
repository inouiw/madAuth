# GitHub sign-in security

How madAuth protects GitHub sign-in, for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules mention this file, so update it when you change them.

GitHub sign-in is the method `github` (`new GitHub()` in the web library): the browser is sent to GitHub, the user agrees, and GitHub sends them back to the madAuth server with a code, which the server exchanges for an access token and uses to read the account. There is no ID token and no browser-side flow: the server does everything, with the client secret of an OAuth App ([setup](server.md#github-oauth-app-setup)). The method is as strong as the user's GitHub account; where that is not enough, the [sign-in policy](server.md#sign-in-methods) adds a second factor.

## The redirect and the callback

`GET /auth/providers/github/start` keeps a random `state`, a PKCE verifier and the page to return to (`return_to`, an origin in `ALLOWED_ORIGINS`) in a cookie signed with the server's key, valid for ten minutes and sent back only on `/auth/providers/github` with `SameSite=Lax`, so it comes along on GitHub's top-level redirect and on nothing else. The callback accepts a code only with that cookie and the same `state`; the code is exchanged with the PKCE verifier, the client secret and the callback URL. A callback without the cookie, with a `state` that doesn't match, or that GitHub answers with an error sends the user back to the page with `madauth_error` (`verification_failed`, or `cancelled` when they declined), and nothing is stored. The cookie is used up by the first callback.

GitHub matches the callback URL against the OAuth App's registered one, so a code never reaches another server; `return_to` is checked against `ALLOWED_ORIGINS`, so the user is never sent on to a page outside your app.

Code: `startOAuth`, `takeOAuthState` and `redirectBack` in [`packages/server/src/routes/oauth.ts`](../packages/server/src/routes/oauth.ts), [`routes/github.ts`](../packages/server/src/routes/github.ts).

## Only a verified address

The address that identifies the user comes from `GET /user/emails` (scope `user:email`): the primary address if GitHub has verified it, else another verified one, never GitHub's `noreply` stand-in address (`<id>+<login>@users.noreply.github.com`, which is verified but delivers nothing). The address on the public profile is never used: anyone can type any address there. A GitHub account without a verified address is refused (`email_unverified`). A returning account is known by GitHub's numeric user id, not by its login (which can change) or its address (which may too): the address noted on the account follows, the user's own stays.

Code: `fetchGitHubAccount` in [`packages/server/src/github.ts`](../packages/server/src/github.ts).

## A method signs in only users who have it

A GitHub sign-in never joins a user who signs in another way: an address that has a password, a Google account, an e-mail link account or the authenticator app alone is refused: the callback sends the user back with `madauth_error=other_method`, and the page says the address signs in another way. Whoever controls the GitHub account must not get past them. The one exception is a sign-up nobody finished (a password that was never confirmed, an e-mail link never used): GitHub proved the address, so that user is taken over and the unproven method goes. The other way round, a password sign-up or an e-mail link for a GitHub user's address gets `email.send_already_registered`, and "Forgot password?" gets `email.send_password_reset_no_password`, both naming `github` among the user's `methods`. A user adds GitHub to their methods while signed in instead (`/auth/providers/github/start?link=1`), and a GitHub user adds a password or a passkey the same way: see [Several sign-in methods](sign-in-methods.md#google-and-github).

The operator's sign-up check (`user.signing_up`, `method: "github"`) runs before a new user is created and fails closed; `user.signed_up` comes with the user's first session.

Code: `resolveProviderUser` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts).

## The second step

With a policy of `optional` or `required` for the method, the callback does not sign in by itself: the sign-in goes on with the authenticator app or an SMS code (`#madauth_next=authenticator`, `sms` or `second-factor-setup` in the hash of the page the user comes back to, with `madauth_method=github`), exactly as after Google's redirect flow. See [Authenticator app security](authenticator-security.md#the-second-step). The session then says `amr: ["github", "otp"]` or `["github", "sms"]`; GitHub alone gives `["github"]`.

Code: `secondStep` in [`packages/server/src/app.ts`](../packages/server/src/app.ts).

## The access token

The exchange yields an access token with the scope `user:email`, which GitHub does not expire by default. madAuth keeps it on the user's GitHub account, encrypted with AES-256-GCM by the key service, with a key of its own (see [Signing key](server.md#signing-key)), and replaces it at every sign-in. It is read for one thing: when the user deletes their account, the server revokes the OAuth App's authorization at GitHub with it (`DELETE /applications/{client_id}/grant`, authenticated as the app), so madAuth leaves the user's authorized apps. The revocation is best effort: when GitHub can't be reached or refuses, the deletion goes ahead, the log says so, and the user can remove the app under GitHub → Settings → Applications.

A leaked database alone does not expose the tokens; the key is needed as well. [Rotating the signing key](server.md#rotating-the-signing-key) keeps them readable while the old key is listed; a token whose key is gone can't be read: the next sign-in stores a fresh one, and a deletion in between leaves the authorization at GitHub.

Code: `deriveKey`, `encrypt` and `decrypt` in [`packages/server/src/crypto.ts`](../packages/server/src/crypto.ts), `deriveTokenKey` and `revokeGitHubGrant` in [`github.ts`](../packages/server/src/github.ts), `revokeGrant` in [`routes/github.ts`](../packages/server/src/routes/github.ts).

## Switching the method off

While an admin has the method off, both routes send the browser back to the app with `madauth_error=method_disabled` (they are top-level navigations, so a JSON error would strand the user on the server's origin), and a sign-in that was between its two steps ends. The method is there only with a GitHub [provider](server.md#providers) in the store, which an admin adds with the OAuth App's client ID and secret (the secret encrypted by the key service); without one the routes answer 404.

Code: the middleware in [`routes/github.ts`](../packages/server/src/routes/github.ts).

## Sessions and cross-site requests

A GitHub user gets the same madAuth session as every other user, with `amr: ["github"]`, and the same session version mechanism; see [Password security](password-security.md#sessions). The two routes are `GET` requests, as a redirect flow needs: they change nothing by themselves (the state cookie protects the callback, see above), and every other endpoint is a `POST` accepted only from an `Origin` in `ALLOWED_ORIGINS`.

## Not covered yet

- Remembering a device, so a second factor is not asked every time.
- Expiring tokens: with **Expire user access tokens** on (GitHub's default for a new OAuth App, see the [setup](server.md#github-oauth-app-setup)), tokens expire in eight hours, and madAuth does not refresh them. The stored token has then usually expired when the user deletes their account, and the authorization stays at GitHub; signing in is not affected.
