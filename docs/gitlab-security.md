# GitLab sign-in security

How madAuth protects GitLab sign-in, for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules (`packages/server/src/social.test.ts`) mention this file, so update it when you change them.

GitLab sign-in is the preset `gitlab` of the [OpenID Connect providers](server.md#openid-connect-provider-setup), on gitlab.com or a self-hosted GitLab ([setup](server.md#gitlab-setup)); its id is `gitlab` unless the admin gives another (a second instance). madAuth is a confidential client of a GitLab application. The method is as strong as the user's GitLab account; where that is not enough, the [sign-in policy](server.md#sign-in-methods) adds a second factor.

## The redirect and the callback

`GET /auth/providers/gitlab/start` keeps a random `state`, a PKCE verifier and the page to return to (`return_to`, an origin in `ALLOWED_ORIGINS`) in a cookie signed with the server's key, valid for ten minutes and sent back only on `/auth/providers/gitlab` with `SameSite=Lax`. The callback accepts a code only with that cookie and the same `state`; a callback without it, with another `state`, or that GitLab answers with an error sends the user back with `madauth_error` (`verification_failed`, or `cancelled` when they declined), and nothing is stored. GitLab's flow is the generic one, unchanged: the issuer's discovery document (gitlab.com's, or the instance's), PKCE (`S256`) and a `nonce`; the code is exchanged with the PKCE verifier and the client secret. GitLab matches the redirect URI against the application's, so a code never reaches another server.

Code: [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `startOAuth` and `takeOAuthState` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts).

## The ID token and the issuer

The ID token must be signed with one of the issuer's published keys, with an asymmetric algorithm, by the issuer, for the client, unexpired, with the sign-in's `nonce` and a `sub`, as for any [OpenID Connect provider](server.md#openid-connect-provider-setup). The id stays bound to its issuer for good (the setting `provider-issuers`): a GitLab at another issuer takes another id, since its user ids are different people. The account is `oidc:<id>:<sub>`.

Code: `PRESET_RULES.gitlab` in [`oidc-presets.ts`](../packages/server/src/oidc-presets.ts), `verifyIdToken` in [`oidc.ts`](../packages/server/src/oidc.ts).

## Only an address GitLab vouches for

The address counts as verified when GitLab's claims say `email_verified: true`. GitLab may leave the address out unless the user has a public one; then the user types it. On a self-hosted instance, GitLab's admins can give a user any address, so `email_verified` is as good as they are; `trustEmail: true` trusts every address, for an instance whose admins check them. For gitlab.com the admin API refuses `trustEmail: true` (`invalid_provider`), with the preset or without: anyone can make an account there with an address they don't own. A gitlab.com provider stored by 0.7.5 with it reads as `false`.

Code: `addressOf` in [`oidc.ts`](../packages/server/src/oidc.ts), the `trustEmail` check in `parseProviderFields` in [`providers.ts`](../packages/server/src/providers.ts).

## An address GitLab doesn't vouch for, or none

An address GitLab doesn't vouch for is confirmed by e-mail once, at the first sign-in, before it signs anyone up: the confirmation e-mail goes to it, the browser comes back with `#madauth_next=email-confirmation`, and the account signs in by itself only once the link or the code was used. An account without an address types one, which its confirmation e-mail proves (`#madauth_next=email-address`, then `POST /auth/providers/gitlab/address`, which answers the same for every address), as described in [Microsoft security](microsoft-security.md#an-account-without-an-address). An address that signs in another way is refused (`other_method`) before anything is sent. A server whose webhook sends no e-mails refuses both (`email_unverified`), unless the account is a returning one.

Code: `resolveProviderUser` and `resolveUnconfirmedProviderUser` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts), the `/callback` and `/address` routes in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts).

## A method signs in only users who have it

A GitLab sign-in never joins a user who signs in another way: whoever controls the GitLab account must not get past the user's password or authenticator app. A signed-in user adds GitLab to their methods instead (`/auth/providers/gitlab/start?link=1`), also an account without an address or with one GitLab doesn't vouch for: the account signs them in by its id, and the address is only noted. See [Several sign-in methods](sign-in-methods.md). The operator's sign-up check (`user.signing_up`, `method: "gitlab"`) runs before a new user is created and fails closed.

## The second step, switching it off, sessions

As for every provider: with a policy of `optional` or `required`, the sign-in goes on with a second factor (`amr: ["gitlab", "otp"]`; GitLab alone gives `["gitlab"]`). While an admin has the method off, the routes send the browser back with `madauth_error=method_disabled`; without the provider in the store they answer 404. The client secret is encrypted by the key service in the store.

## Not covered yet

- Giving the authorization back: madAuth keeps no GitLab token, so deleting an account doesn't revoke the application's grant; the user removes it under GitLab's **Applications**.
