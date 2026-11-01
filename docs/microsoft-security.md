# Microsoft sign-in security

How madAuth protects Microsoft sign-in, for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules mention this file, so update it when you change them.

Microsoft sign-in is the method `microsoft`: personal Microsoft accounts (Outlook, Xbox) and work or school accounts of Microsoft Entra ID. It is the [OpenID Connect providers'](server.md#openid-connect-provider-setup) redirect flow, with what is Microsoft's own: its endpoints, an issuer per tenant, an account that is the tenant and the object id, and an address that counts as verified only when Microsoft says its domain's owner verified it. madAuth is a confidential client of an app registration in Entra ([setup](server.md#microsoft-setup)). The method is as strong as the user's Microsoft account; where that is not enough, the [sign-in policy](server.md#sign-in-methods) adds a second factor.

## The redirect and the callback

As for every OpenID Connect provider: `GET /auth/providers/microsoft/start` keeps a random `state`, a `nonce`, a PKCE verifier and the page to return to (an origin in `ALLOWED_ORIGINS`) in a cookie signed with the server's key, valid for ten minutes and sent back only on `/auth/providers/microsoft` with `SameSite=Lax`. The callback accepts a code only with that cookie and the same `state`, and exchanges it with the PKCE verifier and the client secret, which goes in the form (`client_secret_post`). Microsoft matches the redirect URI against the app registration's, so a code never reaches another server.

The endpoints are Microsoft's documented ones under `https://login.microsoftonline.com/<tenant>/`, not read from a discovery document: for `common`, `organizations` and `consumers` Microsoft's document names its issuer as a template (`…/{tenantid}/v2.0`), which the generic check refuses, and the endpoints don't change.

Code: `microsoftEndpoints` in [`packages/server/src/microsoft.ts`](../packages/server/src/microsoft.ts), [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts), `startOAuth` and `takeOAuthState` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts).

## The ID token and the tenant

The ID token must be signed with one of the tenant's published keys (`…/<tenant>/discovery/v2.0/keys`), for the app's client ID, unexpired, with the sign-in's `nonce`, as for any [OpenID Connect provider](server.md#openid-connect-provider-setup). Its issuer must be the one of the tenant the account is in, `https://login.microsoftonline.com/<tid>/v2.0`, with the token's own `tid`: a token that names one tenant and comes from another is refused. Which tenants may sign in is the provider's `tenant`, which the operator sets, with no default:

| `tenant` | Who signs in | The token's `tid` |
| --- | --- | --- |
| `common` | Work, school and personal accounts | any |
| `organizations` | Work and school accounts | any but the personal accounts' (`9188040d-6c67-4c5b-b112-36a304b66dad`) |
| `consumers` | Personal accounts | the personal accounts' only |
| a tenant id (a GUID) | One organization's accounts | that one only |

A token that doesn't hold sends the user back with `madauth_error=verification_failed`, and nothing is stored.

Code: `verifyMicrosoftIdToken` in [`microsoft.ts`](../packages/server/src/microsoft.ts), `verifyIdToken` in [`oidc.ts`](../packages/server/src/oidc.ts).

## The account: tenant and object id

A returning account is known by its tenant and its object id (`oid`), `microsoft:<tid>:<oid>`, not by its address, which can change, and not by `sub`, which Microsoft makes different for each app registration: registering the app anew, or changing the provider's `tenant`, keeps every account. The same person in two tenants (a guest account, say) is two accounts, as Microsoft has it.

Code: `microsoftAccountKey` in [`users.ts`](../packages/server/src/users.ts).

## Only an address Microsoft vouches for

In Entra, a tenant's admin can give a user any address, also one of another organization's domain: a sign-in that took the `email` claim as proven would let them sign in as anyone (the "nOAuth" weakness). Microsoft has no `email_verified`. madAuth counts the address as verified only when the token says `xms_edov: true` ("email domain owner verified"), an optional claim of madAuth's app registration that its operator switches on ([setup](server.md#microsoft-setup)); Microsoft counts the addresses of personal accounts as domain-verified.

Any other address is confirmed by e-mail once, at the first sign-in, before it signs anyone up, as for an [OpenID Connect provider](server.md#openid-connect-provider-setup) that doesn't vouch for it: the confirmation e-mail goes to it, the browser comes back with `#madauth_next=email-confirmation`, and the account signs in by itself only once the link or the code was used. An address that signs in another way is refused (`other_method`) before anything is sent. Without `xms_edov` in the app registration, every Microsoft user confirms their address this way once.

Code: `microsoftProfile` in [`microsoft.ts`](../packages/server/src/microsoft.ts), `resolveProviderUser` and `resolveUnconfirmedProviderUser` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts).

## An account without an address

Microsoft's token can come without an address: a personal account made with a phone number, a work user without a `mail` attribute, a work address whose domain the organization never verified (since June 2023, Microsoft leaves those out of the tokens of new multi-tenant apps). Then the user types one, as Microsoft itself recommends, and the confirmation e-mail proves it; the same holds for every OpenID Connect provider.

- The callback signs in a returning account at once: its user is known. Otherwise it keeps the account in a cookie signed with the server's key (`madauth_pending_account`, HttpOnly, `SameSite=Strict`, sent only to `/auth/providers/<id>`, ten minutes) and sends the browser back with `#madauth_next=email-address&madauth_method=microsoft`. The URL carries no address.
- `GET /auth/providers/microsoft/address` answers what the dialog offers in the field: the token's `preferred_username` when it looks like an address, else nothing. It is only a suggestion.
- `POST /auth/providers/microsoft/address` with the address answers the same for every address (202), as a password sign-up does: a new or unfinished sign-up gets the account and the confirmation e-mail; the owner of an address that signs in another way gets `email.send_already_registered`, and nothing is linked to them. The code then goes to `/auth/email/verify` with the address.
- A server whose webhook sends no e-mails refuses such an account (`email_unverified`), unless it is a returning one.

Code: the `/callback` and `/address` routes in [`routes/oidc.ts`](../packages/server/src/routes/oidc.ts).

## A method signs in only users who have it

As with Google and GitHub, a Microsoft sign-in never joins a user who signs in another way: whoever controls the Microsoft account must not get past the user's password or authenticator app. A signed-in user adds Microsoft to their methods instead (`/auth/providers/microsoft/start?link=1`), also an account without an address or with one Microsoft doesn't vouch for: the account signs them in by its tenant and object id, and the address is only noted. See [Several sign-in methods](sign-in-methods.md).

The operator's sign-up check (`user.signing_up`, `method: "microsoft"`) runs before a new user is created and fails closed.

## The second step, switching it off, sessions

As for every provider: with a policy of `optional` or `required`, the sign-in goes on with a second factor (`amr: ["microsoft", "otp"]`; Microsoft alone gives `["microsoft"]`). While an admin has the method off, the routes send the browser back with `madauth_error=method_disabled`; without a Microsoft [provider](server.md#providers) in the store they answer 404. The client secret is encrypted by the key service in the store.

## Not covered yet

- Sovereign clouds (`login.microsoftonline.us`, `login.chinacloudapi.cn`) and Entra External ID (`ciamlogin.com`): the endpoints are the global cloud's.
- An allowlist of tenants: `organizations` admits every organization; one tenant id admits only that one.
- Certificate credentials (`private_key_jwt`) instead of the client secret, whose lifetime Entra limits to two years: an admin sets a new one with `updateProvider('microsoft', { clientSecret })` before it expires.
