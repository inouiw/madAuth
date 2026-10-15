# API keys

How a user gives a program access to an API in their name, for app developers and for whoever runs the server. A script, a CI job or an integration sends one of the user's API keys, and acts as the user, limited to the key's scopes: on your app's API, or on madAuth's own [admin API](server.md#http-api). Each section links to the code that implements it. The tests that check these rules mention this file, so update it when you change them.

Code: [`packages/server/src/api-keys.ts`](../packages/server/src/api-keys.ts), [`routes/api-keys.ts`](../packages/server/src/routes/api-keys.ts).

## A key belongs to a user

A signed-in user makes keys, as on GitHub: `Madauth.apiKeys.create()`, or the dialog of `Madauth.showManageApiKeysDialog()`. A key acts as its user: it has no rights of its own, only scopes that narrow down what the user may do.

- **Shown once.** madAuth answers the new key once (`madauth_` and 43 random characters, 256 bits) and keeps only its SHA-256. A lost key is revoked and replaced. The prefix makes a leaked key easy to recognise, e.g. for secret scanning.
- **Only within ten minutes of signing in**, like adding a sign-in method (`401 reauth_required` otherwise): a key is a way in that outlives the session, so a session someone took over must not be able to make one. See [Several sign-in methods](sign-in-methods.md#only-within-ten-minutes-of-signing-in).
- **A name, at least one scope, and optionally an expiry.** The name (1 to 64 characters) says what the key is for. Without `expiresAt` the key works until it is revoked.
- **At most 20 keys per user** (`409 too_many_api_keys`).
- **A key is no session.** It never signs in, never renews a session, and the routes for the signed-in user (making keys, changing methods) don't take it.

## Scopes

A scope says which calls a key allows. madAuth's own are fixed; your app lists its own at `API_KEY_SCOPES_URL`. `GET /auth/api-keys/scopes` lists both, each with its description, the role a user needs for it and the calls it allows, and `Madauth.apiKeys.scopes()` adds whether the signed-in user may give a key each one.

madAuth's scopes, one per admin task, need the role `admin`:

| Scope | Allows |
| --- | --- |
| `madauth:claims:read` | `POST /auth/admin/claims/get` |
| `madauth:claims:write` | `POST /auth/admin/claims/set` |
| `madauth:settings:read` | `POST /auth/admin/settings/get` |
| `madauth:settings:write` | `POST /auth/admin/settings/set` |
| `madauth:sign-in:reset` | `POST /auth/admin/sign-in/reset` |

**A key never does more than its user may.** A user gives a key only scopes whose role they hold (`403 scope_not_allowed`), and every use checks again with the user's roles of now: a scope whose role the user lost, or that your app no longer lists, stops counting, and comes back with the role. So a key doesn't keep a power its user lost.

### Your app's scopes

`API_KEY_SCOPES_URL` is a URL of your app (https, or http on the local machine) that answers your API's scopes as JSON:

```json
{
  "scopes": [
    { "name": "orders:read", "description": "Read your orders", "endpoints": ["GET /api/orders"] },
    { "name": "orders:refund", "description": "Refund orders", "role": "staff", "endpoints": ["POST /api/orders/{id}/refund"] }
  ]
}
```

- `name`: lower-case words (letters, digits, `-`, `_`) separated by `:`, at most 64 characters, unique, never starting with `madauth:`.
- `description`: up to 200 characters, shown when a user chooses the scopes of a key.
- `role` (optional): the role in the user's [claims](server.md#claims) a user needs for the scope. Without it, every user may give a key the scope; your backend still decides what the user may do.
- `endpoints` (optional): the calls the scope allows, for people to read.

madAuth reads the list when it first needs it and again every five minutes. When the list can't be read, the last one read stays, and madAuth tries again after a minute and logs why. Until a list was read, keys have madAuth's scopes only: making a key with one of your app's answers `503 temporarily_unavailable`, and checking a key leaves your app's scopes out. A list that isn't well-formed counts as not read.

The demo lists two example scopes in [`demo/public/api-scopes.json`](../demo/public/api-scopes.json).

## Using a key

A program sends the key as `Authorization: Bearer madauth_…`. Such a request needs no `Origin`: no web page makes a browser send that header to madAuth, since madAuth's CORS doesn't allow it, so it can't be forged from another site, and a program has no user's cookies.

### In your backend

`createApiKeyVerifier` asks madAuth whom a key acts for (`POST /auth/api-keys/verify`), and reuses the answer for a minute (`cacheSeconds`), so a revoked key stops working there within that time. It keeps the keys' hashes, never the keys. Check the scope your route needs:

```ts
import { createApiKeyVerifier } from '@madauth/server/verify';

const verifyApiKey = createApiKeyVerifier({ issuer: 'https://auth.example.com' });

const caller = await verifyApiKey(request); // or the key itself
if (!caller) return new Response('Unauthorized', { status: 401 });
if (!caller.apiKey.scopes.includes('orders:read')) return new Response('Forbidden', { status: 403 });
console.log(caller.user.id, caller.user.claims, caller.apiKey.name);
```

`apiKey.scopes` are the scopes that count now (see above). When madAuth doesn't answer, the verifier resolves to null and logs it: the request is refused rather than let through. Other languages call `POST <issuer>/auth/api-keys/verify` with the key in the `Authorization` header: `200 { user, apiKey: { id, name, scopes } }`, or `401 invalid_api_key`.

A route that takes both sessions and keys checks `createSessionVerifier` first and the key after; a session is not limited by scopes, a key is.

### On madAuth's admin API

An admin's key with the right scope calls the admin API like the admin's session does:

```bash
curl -X POST https://auth.example.com/auth/admin/claims/get \
  -H "Authorization: Bearer madauth_…" -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com"}'
```

- The key's user must have the role `admin` now (`403 forbidden`), and the key the route's scope (`403 insufficient_scope`). An unknown, revoked or expired key is `401 invalid_api_key`.
- The rules of the admin API hold as for the user's session, e.g. no admin takes the role `admin` from themselves.
- The webhook's `by` is the user's address, and `byApiKey { id, name }` names the key.
- **A key never manages keys**: listing and revoking a user's keys (`POST /auth/admin/api-keys/list` and `revoke`) take an admin's session, so a leaked key can't revoke the others or see which there are.

## Revoking a key

- **Its user** revokes it with `Madauth.apiKeys.revoke(id)` (`POST /auth/api-keys/revoke`), or in the dialog. That takes a session, not a recent sign-in: it only takes access away.
- **An admin** revokes a user's key, e.g. one that leaked: `Madauth.admin.listApiKeys(email)` and `revokeApiKey(email, id)`.
- **[Resetting a user's sign-in](server.md#resetting-a-users-sign-in)** and **deleting a user** remove all their keys: whoever took the account over may have made some.
- A **password reset** keeps them, as it keeps passkeys: the user reviews their keys and revokes what they don't know.

A revoked key stops working at madAuth at once, and in your backend once the verifier's answer is a minute old.

## What the webhook is told

`user.api_key_created` (`user`, `apiKey { id, name, scopes, createdAt, expiresAt, lastUsedAt }`) and `user.api_key_revoked` (`user`, `apiKey { id, name }`, and `by` when an admin revoked it). Never the key itself.

## Not covered yet

- Keys for machines that act for no user (service accounts), and the OAuth client credentials grant, which needs madAuth as an [OpenID Connect provider](https://github.com/inouiw/madAuth/issues/53).
- Limiting a key to certain IP addresses, or rate limits per key.
- Registering the `madauth_` prefix with GitHub secret scanning.
- Showing which calls a key made (an audit log): `lastUsedAt` says when it was last used, to the hour.
