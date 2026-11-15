# X sign-in security

How madAuth protects X sign-in, for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules (`packages/server/src/social.test.ts`) mention this file, so update it when you change them.

X sign-in is the method `x`: X's OAuth 2.0 authorization-code flow, without OpenID Connect, of which madAuth is a confidential client, and the X API v2 for the account ([setup](server.md#x-setup)). The method is as strong as the user's X account; where that is not enough, the [sign-in policy](server.md#sign-in-methods) adds a second factor.

## The redirect and the callback

`GET /auth/providers/x/start` keeps a random `state`, a PKCE verifier and the page to return to (`return_to`, an origin in `ALLOWED_ORIGINS`) in a cookie signed with the server's key, valid for ten minutes and sent back only on `/auth/providers/x` with `SameSite=Lax`. The callback accepts a code only with that cookie and the same `state`; a callback without it, with another `state`, or that X answers with an error sends the user back with `madauth_error` (`verification_failed`, or `cancelled` when they declined), and nothing is stored. The authorization request has PKCE (`S256`), which X requires, and the scopes `tweet.read users.read users.email`; the code is exchanged with the PKCE verifier and the client secret as HTTP Basic. X matches the callback URI exactly against the app's, so a code never reaches another server.

Code: [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `startOAuth` and `takeOAuthState` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts).

## No ID token: the API's answer

X has no OpenID Connect, so there is no ID token to check: the account is what `GET /2/users/me` answers for the access token madAuth got from X's token endpoint itself, over TLS, with its client secret. The access token is used for that one call and not kept. The account is X's numeric user id (`x:<id>`), which stays when the user changes their @username.

Code: [`x.ts`](../packages/server/src/x.ts), `SOCIAL_FLOWS` in [`social.ts`](../packages/server/src/social.ts), `socialAccountOf` in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `xAccountKey` in [`users.ts`](../packages/server/src/users.ts).

## Only the address X confirmed

The address counts as verified when X sends it as `confirmed_email` (the scope `users.email`): the address X confirmed. Without it (an account made with a phone number, or an app without **Request email from users**), the user types one.

## An address X doesn't vouch for, or none

An address X doesn't vouch for is confirmed by e-mail once, at the first sign-in, before it signs anyone up: the confirmation e-mail goes to it, the browser comes back with `#madauth_next=email-confirmation`, and the account signs in by itself only once the link or the code was used. An account without an address types one, which its confirmation e-mail proves (`#madauth_next=email-address`, then `POST /auth/providers/x/address`, which answers the same for every address), as described in [Microsoft security](microsoft-security.md#an-account-without-an-address). An address that signs in another way is refused (`other_method`) before anything is sent. A server whose webhook sends no e-mails refuses both (`email_unverified`), unless the account is a returning one.

Code: `resolveProviderUser` and `resolveUnconfirmedProviderUser` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts), the `/callback` and `/address` routes in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts).

## A method signs in only users who have it

A X sign-in never joins a user who signs in another way: whoever controls the X account must not get past the user's password or authenticator app. A signed-in user adds X to their methods instead (`/auth/providers/x/start?link=1`), also an account without an address or with one X doesn't vouch for: the account signs them in by its id, and the address is only noted. See [Several sign-in methods](sign-in-methods.md). The operator's sign-up check (`user.signing_up`, `method: "x"`) runs before a new user is created and fails closed.

## The second step, switching it off, sessions

As for every provider: with a policy of `optional` or `required`, the sign-in goes on with a second factor (`amr: ["x", "otp"]`; X alone gives `["x"]`). While an admin has the method off, the routes send the browser back with `madauth_error=method_disabled`; without the provider in the store they answer 404. The client secret is encrypted by the key service in the store.

## Not covered yet

- Giving the authorization back: madAuth keeps no X token; the user removes the app under X's **Connected apps**.
