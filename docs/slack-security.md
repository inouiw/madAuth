# Slack sign-in security

How madAuth protects Slack sign-in, for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules (`packages/server/src/social.test.ts`) mention this file, so update it when you change them.

Slack sign-in is the preset `slack` of the [OpenID Connect providers](server.md#openid-connect-provider-setup): "Sign in with Slack", with the issuer `https://slack.com` ([setup](server.md#slack-setup)). madAuth is a confidential client of a Slack app. The method is as strong as the user's Slack account and the workspace it belongs to; where that is not enough, the [sign-in policy](server.md#sign-in-methods) adds a second factor.

## The redirect and the callback

`GET /auth/providers/slack/start` keeps a random `state` and the page to return to (`return_to`, an origin in `ALLOWED_ORIGINS`) in a cookie signed with the server's key, valid for ten minutes and sent back only on `/auth/providers/slack` with `SameSite=Lax`. The callback accepts a code only with that cookie and the same `state`; a callback without it, with another `state`, or that Slack answers with an error sends the user back with `madauth_error` (`verification_failed`, or `cancelled` when they declined), and nothing is stored. Slack matches the redirect URL against the app's, so a code never reaches another server.

Code: [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `startOAuth` and `takeOAuthState` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts).

## No PKCE, but the nonce

Slack's PKCE is an app setting that turns the app into a public client for good, and madAuth is a confidential one: the authorization request has no PKCE, and the code is protected by the `state`, the redirect URL Slack matches, and the client secret, which the exchange needs. The ID token must carry the sign-in's `nonce`, and is checked as any OpenID Connect provider's: signed with one of Slack's published keys, by the issuer, for the client, unexpired, with a `sub`. The account is `oidc:slack:<sub>`, one per workspace membership: the same person in two workspaces is two accounts.

Code: `PRESET_RULES.slack` in [`oidc-presets.ts`](../packages/server/src/oidc-presets.ts), `verifyIdToken` in [`oidc.ts`](../packages/server/src/oidc.ts).

## Only an address Slack vouches for

The address counts as verified when Slack says `email_verified: true`. Slack doesn't document what `email_verified` means, and a workspace's admins manage its members' accounts (on Enterprise Grid, also through SCIM), so a verified address is only as good as the workspace that vouches for it. An address that already signs in another way is never joined, whatever Slack says (see below); what remains is a new sign-up with an address its owner never used here. Use Slack where its workspaces are your users' own, e.g. an app for your workspace. The admin API refuses `trustEmail: true` (`invalid_provider`) for its issuer, with the preset or without; one stored by 0.7.5 reads as `false`.

Code: `addressOf` in [`oidc.ts`](../packages/server/src/oidc.ts), the `trustEmail` check in `parseProviderFields` in [`providers.ts`](../packages/server/src/providers.ts).

## An address Slack doesn't vouch for, or none

An address Slack doesn't vouch for is confirmed by e-mail once, at the first sign-in, before it signs anyone up: the confirmation e-mail goes to it, the browser comes back with `#madauth_next=email-confirmation`, and the account signs in by itself only once the link or the code was used. An account without an address types one, which its confirmation e-mail proves (`#madauth_next=email-address`, then `POST /auth/providers/slack/address`, which answers the same for every address), as described in [Microsoft security](microsoft-security.md#an-account-without-an-address). An address that signs in another way is refused (`other_method`) before anything is sent. A server whose webhook sends no e-mails refuses both (`email_unverified`), unless the account is a returning one.

Code: `resolveProviderUser` and `resolveUnconfirmedProviderUser` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts), the `/callback` and `/address` routes in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts).

## A method signs in only users who have it

A Slack sign-in never joins a user who signs in another way: whoever controls the Slack account must not get past the user's password or authenticator app. A signed-in user adds Slack to their methods instead (`/auth/providers/slack/start?link=1`), also an account without an address or with one Slack doesn't vouch for: the account signs them in by its id, and the address is only noted. See [Several sign-in methods](sign-in-methods.md). The operator's sign-up check (`user.signing_up`, `method: "slack"`) runs before a new user is created and fails closed.

## The second step, switching it off, sessions

As for every provider: with a policy of `optional` or `required`, the sign-in goes on with a second factor (`amr: ["slack", "otp"]`; Slack alone gives `["slack"]`). While an admin has the method off, the routes send the browser back with `madauth_error=method_disabled`; without the provider in the store they answer 404. The client secret is encrypted by the key service in the store.

## Not covered yet

- Allowing only some workspaces (the ID token's `https://slack.com/team_id`).
- Giving the authorization back: madAuth keeps no Slack token.
