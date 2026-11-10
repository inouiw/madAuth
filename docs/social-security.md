# Social provider security

How madAuth protects sign-in with GitLab, LinkedIn, Slack, Facebook and X, for app developers and for whoever runs the server. GitLab, LinkedIn and Slack are presets of the [OpenID Connect providers](server.md#openid-connect-provider-setup); Facebook and X speak OAuth 2.0 without OpenID Connect. Each section links to the code that implements it. The tests that check these rules (`packages/server/src/social.test.ts`) mention this file, so update it when you change them.

Each provider's method is as strong as the user's account there; where that is not enough, the [sign-in policy](server.md#sign-in-methods) adds a second factor.

## What all five share

- **The redirect and the callback** are the OpenID Connect providers' routes, `/auth/providers/<id>/start` and `/callback`: a random `state`, the PKCE verifier and the page to return to (an origin in `ALLOWED_ORIGINS`) wait in a cookie signed with the server's key, valid for ten minutes and sent back only to `/auth/providers/<id>` with `SameSite=Lax`. The callback accepts a code only with that cookie and the same `state`. madAuth is a confidential client of every one of them: the code is exchanged with the client secret, which the key service encrypts in the store, so a code that leaks is of no use to anyone else.
- **Only an address the provider vouches for signs in at once.** Any other address is confirmed by e-mail once, at the first sign-in, before it signs anyone up; an account without an address types one, which its confirmation e-mail proves. An address that signs in another way is refused (`other_method`) before anything is sent. A server whose webhook sends no e-mails refuses such an account (`email_unverified`). The rules are the [OpenID Connect providers'](server.md#openid-connect-provider-setup); see [Microsoft security](microsoft-security.md#an-account-without-an-address) for the address step.
- **The account is the provider's id for the user, not the address**, so a user whose address changes at the provider keeps their account. A sign-in never joins a user who signs in another way; a signed-in user adds the provider to their methods with its button's `purpose: 'link'` instead. See [Several sign-in methods](sign-in-methods.md).
- **The operator's sign-up check** (`user.signing_up`, with the provider's id as `method`) runs before a new user is created and fails closed. While an admin has the method off, the routes send the browser back with `madauth_error=method_disabled`; without the provider in the store they answer 404.

Code: [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `startOAuth`, `takeOAuthState`, `resolveProviderUser` and `resolveUnconfirmedProviderUser` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts).

## GitLab

The generic OpenID Connect flow, unchanged: the issuer's discovery document (gitlab.com's, or a self-hosted instance's), PKCE (`S256`), a `nonce` the ID token must carry, and an ID token signed with one of the issuer's published keys, for the client, unexpired. The address counts as verified when GitLab's claims say `email_verified: true`. On a self-hosted instance, GitLab's admins can give a user any address, so `email_verified` is as good as they are; `trustEmail: true` trusts every address, for an instance whose admins check them. The id stays bound to its issuer for good, as every OpenID Connect provider's: a GitLab at another issuer takes another id, since its user ids (`sub`) are different people.

Code: `PRESET_RULES.gitlab` in [`oidc-presets.ts`](../packages/server/src/oidc-presets.ts), `verifyIdToken` and `addressOf` in [`oidc.ts`](../packages/server/src/oidc.ts).

## LinkedIn

The generic flow with LinkedIn's departures, which the preset fixes and an admin can't change:

- **No PKCE.** LinkedIn has PKCE for native apps only, at an endpoint of its own; its web flow refuses a verifier. The code is protected by the `state`, the redirect URI LinkedIn matches against the app's, and the client secret, which the exchange needs.
- **The secret in the form** (`client_secret_post`), the only way LinkedIn documents; its discovery document names none.
- **No `nonce` in the ID token.** LinkedIn doesn't return it, so a token without one holds; a token with one must still carry the sign-in's. The ID token comes straight from LinkedIn's token endpoint over TLS, in exchange for the code and the secret, so it can't be one replayed from another sign-in.
- The issuer is `https://www.linkedin.com/oauth`, as LinkedIn's discovery document and ID tokens name it (older documentation says `https://www.linkedin.com`).

The address counts as verified when LinkedIn says `email_verified: true`, which LinkedIn may leave out; then it is confirmed by e-mail. LinkedIn doesn't verify identities: a LinkedIn account says nothing more than its address.

Code: `PRESET_RULES.linkedin` in [`oidc-presets.ts`](../packages/server/src/oidc-presets.ts), `rulesOf` in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `verifyIdToken` and `exchangeCode` in [`oidc.ts`](../packages/server/src/oidc.ts).

## Slack

The generic flow without PKCE: Slack's PKCE is an app setting that turns the app into a public client for good, and madAuth is a confidential one. The code is protected by the `state`, the redirect URL Slack matches, and the client secret; the ID token must carry the sign-in's `nonce`. The address counts as verified when Slack says `email_verified: true`. Slack doesn't document what `email_verified` means, and a workspace's admins manage its members' accounts (on Enterprise Grid, also through SCIM), so a verified address is only as good as the workspace that vouches for it. An address madAuth's user already signs in with another way is never joined, whatever Slack says (see above); what remains is a new sign-up with an address its owner never used here. Use Slack where its workspaces are your users' own, e.g. an app for your workspace.

Code: `PRESET_RULES.slack` in [`oidc-presets.ts`](../packages/server/src/oidc-presets.ts).

## Facebook

Facebook Login's manual redirect flow: the login dialog with the `state` and the permissions `email` and `public_profile`, and the code exchanged with the App Secret. Facebook's OpenID Connect code flow with PKCE is still marked "in testing" by Meta, so madAuth doesn't use it; the code is protected by the `state`, the redirect URI Facebook matches against the app's, and the App Secret. The account comes from the Graph API (`GET /me`, version `v26.0`), with the access token in the header and `appsecret_proof` (the token's HMAC-SHA256 with the App Secret), so the app's **Require App Secret** setting can be on.

**The address is never counted as verified.** Facebook's documentation only says `email` is the profile's primary address when it has a valid one, not that it is confirmed, so it is confirmed by e-mail once, at the first sign-in. An account without one (made with a phone number, or the user didn't grant `email`) types an address. The account is Facebook's app-scoped user id (`facebook:<id>`).

Code: [`facebook.ts`](../packages/server/src/facebook.ts), `socialAccountOf` in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `facebookAccountKey` in [`users.ts`](../packages/server/src/users.ts).

## X

X's OAuth 2.0 authorization-code flow with PKCE (`S256`) and the `state`, and the code exchanged with the client secret as HTTP Basic. The account comes from the X API v2 (`GET /2/users/me`). X has no OpenID Connect, so there is no ID token to check: the account is what X's API answers for the access token madAuth got from X's token endpoint itself.

**The address counts as verified when X sends it**, as `confirmed_email` (the scope `users.email`): the address X confirmed. Without it, the user types one, which its confirmation e-mail proves. The account is X's numeric user id (`x:<id>`), which stays when the user changes their @username.

Code: [`x.ts`](../packages/server/src/x.ts), `socialAccountOf` in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `xAccountKey` in [`users.ts`](../packages/server/src/users.ts).

## Not covered yet

- **Giving the authorization back.** madAuth keeps no token of these providers, so deleting an account doesn't revoke its grant there (GitHub's and Apple's are revoked): the user removes the app at the provider. Facebook asks apps for a data deletion URL; madAuth's account deletion is what it points to.
- Allowing only some Slack workspaces (the ID token's `https://slack.com/team_id`).
- Facebook's OpenID Connect code flow with PKCE, once Meta no longer marks it as in testing.
- Discord, Twitch and the other OAuth 2.0 providers.
