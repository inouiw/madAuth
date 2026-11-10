# LinkedIn sign-in security

How madAuth protects LinkedIn sign-in, for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules (`packages/server/src/social.test.ts`) mention this file, so update it when you change them.

LinkedIn sign-in is the preset `linkedin` of the [OpenID Connect providers](server.md#openid-connect-provider-setup): "Sign In with LinkedIn using OpenID Connect", with the issuer `https://www.linkedin.com/oauth` ([setup](server.md#linkedin-setup)). madAuth is a confidential client of a LinkedIn app. The method is as strong as the user's LinkedIn account; LinkedIn doesn't verify identities, so an account says nothing more than its address. Where that is not enough, the [sign-in policy](server.md#sign-in-methods) adds a second factor.

## The redirect and the callback

`GET /auth/providers/linkedin/start` keeps a random `state` and the page to return to (`return_to`, an origin in `ALLOWED_ORIGINS`) in a cookie signed with the server's key, valid for ten minutes and sent back only on `/auth/providers/linkedin` with `SameSite=Lax`. The callback accepts a code only with that cookie and the same `state`; a callback without it, with another `state`, or that LinkedIn answers with an error sends the user back with `madauth_error` (`verification_failed`, or `cancelled` when they declined), and nothing is stored. LinkedIn matches the redirect URI against the app's, so a code never reaches another server.

Code: [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `startOAuth` and `takeOAuthState` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts).

## Where LinkedIn departs from the generic flow

The preset fixes these, and an admin can't change them:

- **No PKCE.** LinkedIn has PKCE for native apps only, at an endpoint of its own; its web flow refuses a verifier. The code is protected by the `state`, the redirect URI LinkedIn matches, and the client secret, which the exchange needs.
- **The secret in the form** (`client_secret_post`), the only way LinkedIn documents; its discovery document names none.
- **No `nonce` in the ID token.** LinkedIn doesn't return it, so a token without one holds; a token with one must still carry the sign-in's. The ID token comes straight from LinkedIn's token endpoint over TLS, in exchange for the code and the secret, so it can't be one replayed from another sign-in.
- **The issuer** is `https://www.linkedin.com/oauth`, as LinkedIn's discovery document and ID tokens name it (older documentation says `https://www.linkedin.com`).

Otherwise the ID token is checked as any OpenID Connect provider's: signed with one of LinkedIn's published keys, by the issuer, for the client, unexpired, with a `sub`. The account is `oidc:linkedin:<sub>`; LinkedIn's `sub` is pairwise, so a new LinkedIn app gives every user another one.

Code: `PRESET_RULES.linkedin` in [`oidc-presets.ts`](../packages/server/src/oidc-presets.ts), `rulesOf` in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `verifyIdToken` and `exchangeCode` in [`oidc.ts`](../packages/server/src/oidc.ts).

## Only an address LinkedIn vouches for

The address counts as verified when LinkedIn says `email_verified: true`, which LinkedIn may leave out. Anyone can make a LinkedIn account with an address they don't own, so the admin API refuses `trustEmail: true` (`invalid_provider`).

Code: `addressOf` in [`oidc.ts`](../packages/server/src/oidc.ts), the `trustEmail` check in `parseProviderFields` in [`providers.ts`](../packages/server/src/providers.ts).

## An address LinkedIn doesn't vouch for, or none

An address LinkedIn doesn't vouch for is confirmed by e-mail once, at the first sign-in, before it signs anyone up: the confirmation e-mail goes to it, the browser comes back with `#madauth_next=email-confirmation`, and the account signs in by itself only once the link or the code was used. An account without an address types one, which its confirmation e-mail proves (`#madauth_next=email-address`, then `POST /auth/providers/linkedin/address`, which answers the same for every address), as described in [Microsoft security](microsoft-security.md#an-account-without-an-address). An address that signs in another way is refused (`other_method`) before anything is sent. A server whose webhook sends no e-mails refuses both (`email_unverified`), unless the account is a returning one.

Code: `resolveProviderUser` and `resolveUnconfirmedProviderUser` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts), the `/callback` and `/address` routes in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts).

## A method signs in only users who have it

A LinkedIn sign-in never joins a user who signs in another way: whoever controls the LinkedIn account must not get past the user's password or authenticator app. A signed-in user adds LinkedIn to their methods instead (`/auth/providers/linkedin/start?link=1`), also an account without an address or with one LinkedIn doesn't vouch for: the account signs them in by its id, and the address is only noted. See [Several sign-in methods](sign-in-methods.md). The operator's sign-up check (`user.signing_up`, `method: "linkedin"`) runs before a new user is created and fails closed.

## The second step, switching it off, sessions

As for every provider: with a policy of `optional` or `required`, the sign-in goes on with a second factor (`amr: ["linkedin", "otp"]`; LinkedIn alone gives `["linkedin"]`). While an admin has the method off, the routes send the browser back with `madauth_error=method_disabled`; without the provider in the store they answer 404. The client secret is encrypted by the key service in the store.

## Not covered yet

- Giving the authorization back: madAuth keeps no LinkedIn token; the user removes the app in LinkedIn's settings.
