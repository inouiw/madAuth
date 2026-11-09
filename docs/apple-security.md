# Sign in with Apple security

How madAuth protects Sign in with Apple, for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules mention this file, so update it when you change them.

Sign in with Apple is the method `apple`: Apple IDs, on the web through the [OpenID Connect providers'](server.md#openid-connect-provider-setup) redirect flow, and in iOS and macOS apps through the identity token the app gets from Apple's own sheet. What is Apple's own: the client secret is a JWT madAuth signs with the developer account's key, Apple answers the callback with a POST, the user's name comes once and beside the token, an address may be a relay address Apple made for the user, and the authorization is given back to Apple when the account goes.

## The redirect and the callback

As for every OpenID Connect provider: `GET /auth/providers/apple/start` keeps a random `state`, a `nonce` and the page to return to (an origin in `ALLOWED_ORIGINS`) in a cookie signed with the server's key, valid for ten minutes and sent back only on `/auth/providers/apple` with `SameSite=Lax`. Apple has no PKCE, so none is sent; the code is bound to the sign-in by the `state`, the ID token by the `nonce`, and only madAuth can exchange the code: the exchange needs the client secret.

Apple demands `response_mode=form_post` when the name or the address is asked for, and answers with a **POST from its own site**. A cross-site POST brings no `SameSite=Lax` cookie, so the state cookie isn't there. madAuth's POST callback therefore checks and stores nothing: it keeps the name Apple sent (see below) in a cookie of its own and answers `303` to the GET callback with the code and the state in the query, where the browser sends the state cookie as it does for every other provider, and the same checks run. The POST is exempt from the rule that a POST to `/auth/*` needs an app's `Origin`, since it is Apple's. The alternative, a `SameSite=None` state cookie, would weaken the cookie for one provider; the extra hop puts the code into a URL once, as it is for every provider that answers with a GET.

The endpoints are Apple's documented ones under `https://appleid.apple.com/auth/`, not read from a discovery document: they never change.

Code: `APPLE_ENDPOINTS` in [`packages/server/src/apple.ts`](../packages/server/src/apple.ts), the `/start` and the two `/callback` routes in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `startOAuth` and `takeOAuthState` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts).

## The client secret: a key, never a shared secret

Apple has no fixed client secret: the client authenticates with a JWT signed with a key of the developer account (ES256), for the Team ID (`iss`), the client (`sub`) and Apple (`aud`), valid up to six months. madAuth keeps the key (the `.p8` file's text) as the provider's secret, encrypted by the [key service](server.md#key-service) like every client secret, and signs a secret that lives five minutes for each call to Apple: nothing long-lived to leak, and nothing to renew every six months. An admin sets the key with the Team ID and the Key ID; a key that isn't an EC P-256 key is refused when it is set, and the admin API never answers the key, only that one is set.

Code: `appleClientSecret` and `importAppleKey` in [`apple.ts`](../packages/server/src/apple.ts), `checkAppleKey` in [`app.ts`](../packages/server/src/app.ts).

## The ID token

The ID token must be signed with one of Apple's published keys (`https://appleid.apple.com/auth/keys`), by `https://appleid.apple.com`, for the Services ID (the web flow) or one of the provider's App IDs (a native app, see below), unexpired, with the sign-in's `nonce` and a `sub`. A token for several audiences is refused: Apple issues its tokens for one. A token that doesn't hold sends the user back with `madauth_error=verification_failed`, and nothing is stored.

Code: `verifyAppleIdToken` in [`apple.ts`](../packages/server/src/apple.ts).

## The account: Apple's `sub`

A returning account is known by Apple's `sub`, `apple:<sub>`, not by its address, which the user may change or hide. The `sub` is the same for every App ID and Services ID of one developer team, so the user who signed up on the web is the same user in the iOS app, and the other way round. (An app transferred to another team gets other `sub`s: Apple's `transfer_sub` for that migration is not handled.)

Code: `appleAccountKey` in [`users.ts`](../packages/server/src/users.ts).

## The address: verified, also a relay address

Apple marks every address it sends as verified (`email_verified`, as `true` or `"true"`). A user may hide theirs: Apple then sends a **relay address** of Hide My Email (`…@privaterelay.appleid.com`, `is_private_email`), which forwards to the user. madAuth takes it as the user's address like any verified one, as Auth0, Clerk, Supabase and Better Auth do: it is the only address Apple gives, and Apple's review refuses apps that then demand the real one. Mail to it arrives only when your sending domain and addresses are registered with Apple (see [Apple setup](server.md#apple-setup)), so register them. Someone who signed up with a password under their real address and hides it at Apple becomes a second user: they add Apple to their methods while signed in instead (`?link=1`), as with every provider.

An address Apple doesn't mark verified (Apple doesn't send such today) is confirmed by e-mail once before it signs anyone up, and an account without an address (a managed Apple ID of a school or company may have none) has the user type one, both as for any [OpenID Connect provider](server.md#openid-connect-provider-setup). As with every provider, an Apple sign-in never joins a user who signs in another way (`other_method`): whoever controls the Apple ID must not get past the user's password or authenticator app.

Code: `appleProfile` in [`apple.ts`](../packages/server/src/apple.ts), `resolveProviderUser` and `resolveUnconfirmedProviderUser` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts).

## The name: once, and no proof

Apple sends the user's name only at the first authorization, beside the token: in the web flow as the POST's `user` field (JSON), in a native app as the credential's `fullName`. The user may have edited it on Apple's page, and it isn't signed: madAuth takes it as the display name of a new user, as it takes Google's `name`, and nothing else depends on it. In the web flow the name waits in a cookie signed with the server's key (`madauth_provider_name`, HttpOnly, five minutes, sent only to `/auth/providers/apple`) between the POST and the GET, so that the URL doesn't carry it. A returning user keeps the name they have; the token never has one.

Code: `appleUserName` in [`apple.ts`](../packages/server/src/apple.ts), the POST `/callback` route in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts).

## Native apps: the identity token

An iOS or macOS app shows Apple's own sheet (`ASAuthorizationAppleIDProvider`) and gets an identity token for its own App ID (the bundle identifier), not for the Services ID. The admin lists the App IDs on the provider (`bundleIds`); a token for any other audience is refused. The app first gets a nonce from madAuth (`POST /auth/providers/apple/nonce`, kept in a `SameSite=Strict` cookie for five minutes, or `POST /auth/oidc/nonce` for the [token exchange](server.md#native-apps), kept for the application and used once) and passes it to Apple's request as it is, so the token was asked for by this app just now; then it hands the token to `POST /auth/providers/apple/verify` (or the token exchange), which checks it as the web flow's. The sign-in otherwise behaves as `google/verify`: the user is resolved the same way, the sign-up check runs, and a policy that asks for a second factor sends the app to a browser.

Code: [`routes/apple.ts`](../packages/server/src/routes/apple.ts), `exchange` in [`routes/oidc-endpoints.ts`](../packages/server/src/routes/oidc-endpoints.ts).

## Giving the authorization back

Apple's [App Store Review Guideline 5.1.1 (v)](https://developer.apple.com/app-store/review/guidelines/#data-collection-and-storage) asks apps that let users delete their account to revoke the user's Sign in with Apple tokens as well. The code exchange answers a refresh token; madAuth keeps it on the account, encrypted by the key service (`secret`, as GitHub's access token is), with the client it was issued to, and renews it at every sign-in. When the user removes Apple from their methods, deletes their account, or an admin deletes the user or resets their sign-in, madAuth posts the token to `https://appleid.apple.com/auth/revoke` as that client: Apple then no longer lists the app under the user's Sign in with Apple apps, and a relay address stops forwarding. Best effort: the deletion goes ahead whatever Apple answers, and a failure is logged.

A native app gets the refresh token too, by passing Apple's `authorizationCode` with the identity token (`Madauth.apple.signIn({ credential, authorizationCode })`, or `authorization_code` in the token exchange): madAuth exchanges it as the token's App ID. Without the code the sign-in works, but the account has nothing to give back.

Code: `revokeAppleGrant` and `encryptAppleGrant` in [`routes/apple.ts`](../packages/server/src/routes/apple.ts), `exchangeAppleCode` and `revokeAppleToken` in [`apple.ts`](../packages/server/src/apple.ts), `revokeProviderGrant` in [`app.ts`](../packages/server/src/app.ts).

## Not covered

- **Apple's server-to-server notifications** (consent revoked, account deleted at Apple, e-mail forwarding switched off or on) are not received: a user who revokes the app at Apple keeps their madAuth account until they delete it, and a relay address that stopped forwarding stays their address.
- **`transfer_sub`** when an app moves to another developer team: the accounts would have to be migrated by hand.
- **Apple's JS for web pages** (`AppleID.auth`, a popup) is not used: the web flow is the redirect. An identity token from it is accepted by `apple/verify` when it was issued for the Services ID.
