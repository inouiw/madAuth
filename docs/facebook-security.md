# Facebook sign-in security

How madAuth protects Facebook sign-in, for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules (`packages/server/src/social.test.ts`) mention this file, so update it when you change them.

Facebook sign-in is the method `facebook`: Facebook Login's manual redirect flow, OAuth 2.0 without OpenID Connect, of which madAuth is a confidential client with the Meta app's App Secret, and the Graph API (`v26.0`) for the account ([setup](server.md#facebook-setup)). The method is as strong as the user's Facebook account; where that is not enough, the [sign-in policy](server.md#sign-in-methods) adds a second factor.

## The redirect and the callback

`GET /auth/providers/facebook/start` keeps a random `state` and the page to return to (`return_to`, an origin in `ALLOWED_ORIGINS`) in a cookie signed with the server's key, valid for ten minutes and sent back only on `/auth/providers/facebook` with `SameSite=Lax`. The callback accepts a code only with that cookie and the same `state`; a callback without it, with another `state`, or that Facebook answers with an error sends the user back with `madauth_error` (`verification_failed`, or `cancelled` when they declined), and nothing is stored. The login dialog asks for the permissions `email` and `public_profile`. Facebook's OpenID Connect code flow with PKCE is still marked "in testing" by Meta, so madAuth uses the manual flow, which has no PKCE: the code is protected by the `state`, the redirect URI Facebook matches against the app's, and the App Secret, which the exchange needs. Facebook sends the browser to the callback with `#_=_`; the way back to the app ends with an empty `#`, so the page doesn't keep it.

Code: [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `startOAuth` and `takeOAuthState` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts).

## The App Secret and the access token

The code exchange sends the App Secret in a form (`POST /oauth/access_token`), never in a URL, where logs would keep it. The account comes from `GET /me` (id, name, address), with the access token in the `Authorization` header and `appsecret_proof` (the token's HMAC-SHA256 with the App Secret), so the app's **Require App Secret** setting can be on. The access token is used for that one call and not kept. The session gets no picture: Facebook's picture links expire within days.

Code: [`facebook.ts`](../packages/server/src/facebook.ts), `SOCIAL_FLOWS` in [`social.ts`](../packages/server/src/social.ts), `socialAccountOf` in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts).

## The account: the app-scoped id

A returning account is known by Facebook's app-scoped user id (`facebook:<id>`), not by its address. The id is this Meta app's only: a new app gives every user another id, so keep the app.

Code: `facebookAccountKey` in [`users.ts`](../packages/server/src/users.ts).

## The address is never trusted

Facebook's documentation only says `email` is the profile's primary address when it has a valid one, not that Facebook confirmed it, so madAuth never counts it as verified: it is confirmed by e-mail once, at the first sign-in. An account without one (made with a phone number, or the user didn't grant `email`) types an address.

## An address Facebook doesn't vouch for, or none

An address Facebook doesn't vouch for is confirmed by e-mail once, at the first sign-in, before it signs anyone up: the confirmation e-mail goes to it, the browser comes back with `#madauth_next=email-confirmation`, and the account signs in by itself only once the link or the code was used. An account without an address types one, which its confirmation e-mail proves (`#madauth_next=email-address`, then `POST /auth/providers/facebook/address`, which answers the same for every address), as described in [Microsoft security](microsoft-security.md#an-account-without-an-address). An address that signs in another way is refused (`other_method`) before anything is sent. A server whose webhook sends no e-mails refuses both (`email_unverified`), unless the account is a returning one.

Code: `resolveProviderUser` and `resolveUnconfirmedProviderUser` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts), the `/callback` and `/address` routes in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts).

## A method signs in only users who have it

A Facebook sign-in never joins a user who signs in another way: whoever controls the Facebook account must not get past the user's password or authenticator app. A signed-in user adds Facebook to their methods instead (`/auth/providers/facebook/start?link=1`), also an account without an address or with one Facebook doesn't vouch for: the account signs them in by its id, and the address is only noted. See [Several sign-in methods](sign-in-methods.md). The operator's sign-up check (`user.signing_up`, `method: "facebook"`) runs before a new user is created and fails closed.

## The second step, switching it off, sessions

As for every provider: with a policy of `optional` or `required`, the sign-in goes on with a second factor (`amr: ["facebook", "otp"]`; Facebook alone gives `["facebook"]`). While an admin has the method off, the routes send the browser back with `madauth_error=method_disabled`; without the provider in the store they answer 404. The client secret is encrypted by the key service in the store.

## Not covered yet

- Giving the authorization back: madAuth keeps no Facebook token, so deleting an account doesn't remove the app's permissions; the user removes the app in Facebook's settings. Facebook asks apps for a data deletion URL; madAuth's account deletion is what it points to.
- Facebook's OpenID Connect code flow with PKCE, once Meta no longer marks it as in testing.
