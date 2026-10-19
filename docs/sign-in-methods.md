# Several sign-in methods

How a user gets more than one way to sign in, and loses one, for app developers and for whoever runs the server. Each section links to the code that implements it. The tests that check these rules mention this file, so update it when you change them. Which methods the server offers, and which of them sign in on their own, is the [sign-in policy](server.md#sign-in-methods).

## Signing up with one, adding more

A user signs up with one method: a password, Google, GitHub, an OpenID Connect provider, the e-mail link, the authenticator app, or a passkey (the app and a passkey alone confirm the address by e-mail first, see [Signing up with a passkey](passkey-security.md#signing-up-with-a-passkey)). While signed in, they can add more: a passkey, a password, the e-mail link, Google, GitHub, an OpenID Connect provider, the app. Each of them then signs the user in, as long as the admin allows the method as a sign-in method (`allowAsSignInMethod`). A user with a password and a passkey can sign in with either; one with Google and the app (allowed on its own) with either.

A method is only ever added while signed in, never by signing in:

- A sign-in with a method the user doesn't have, for their address, is refused as before: `403 other_method` names how the address signs in (`methods`), and an e-mail link or a password sign-up for it gets `email.send_already_registered`. Whoever controls a Google, GitHub or OpenID Connect account with the user's address must not get past their password, their passkeys or their app. See [GitHub sign-in security](github-security.md#a-method-signs-in-only-users-who-have-it).
- The one takeover that remains is of a sign-up nobody finished, as before: nobody has proven it.

So adding a method needs both: the signed-in user, and the method itself (the provider's sign-in, the passkey's ceremony, the new password, the inbox the user's address already proved).

Code: `linkProviderAccount` in [`routes/oauth.ts`](../packages/server/src/routes/oauth.ts), `/auth/password/add`, `/auth/email-link/add`, `/auth/passkey/register/*`.

## Only within two minutes of signing in

A sensitive change made with a session is refused with `401 reauth_required` more than two minutes after the user signed in: the session's `auth_time`, which renewals keep. The time is the one of the token the user was read from (the session token, or the renewal token that renewed it), so another user's token in the same request can't make the sign-in look recent. A session someone took over (a stolen cookie, an unlocked computer) must not let them add a way in that outlives it, nor take one away. The user signs in again, a full sign-in with their second factor if their policy asks for one (madAuth's dialog asks them to, and goes back to the change after), and the change follows.

What it covers:
- adding a sign-in method (a password, the e-mail link, a passkey, Google, GitHub, an OpenID Connect provider) and removing one;
- setting up the authenticator app or a phone, replacing or removing them, and new recovery codes (these take a code from the app or the phone as well);
- making an API key, and deleting the account;
- the admin API's changes: claims, settings, providers, a user's sign-in reset.

A change of several steps checks it when it starts, and its own state finishes it: the setup of the app or a phone (its setup cookie), a passkey's ceremony, a provider's redirect. Replacing or removing the phone starts with the code to the current number (`Madauth.sms.send()`), which the setup or the removal then takes. Two minutes rather than one, since after a sign-in with an SMS code the next SMS can only go a minute later.

Exempt: an API key with the scope for the admin API (a key has no sign-in; making one takes the recent sign-in), the [setup token](server.md#first-setup), and what only takes access away: revoking an API key, an admin revoking a user's key, signing out.

Code: `recentUser` in [`routes/helpers.ts`](../packages/server/src/routes/helpers.ts), `auth_time` in [`tokens.ts`](../packages/server/src/tokens.ts).

## Google, GitHub and OpenID Connect providers

A signed-in user adds Google, GitHub or an OpenID Connect provider through the provider's own sign-in: the button with `purpose: 'link'` (the dialog's "Connect …"). With One Tap / FedCM, the browser gets an ID token and `POST /auth/providers/google/link` adds it; with the redirect flows, `/start?link=1` remembers the user in the flow's state, the callback checks that the same user is still signed in at that browser, adds the account and returns with `#madauth_linked=google`. The provider's account may have another address than the user: it signs in by its own id (`sub`, GitHub's user id), and its address is noted on the account (`email` in `GET /auth/methods`). An account that signs in another user stays theirs (`409 account_taken`).

Removing GitHub takes its authorization back at GitHub, with the token kept from its last sign-in, as deleting the account does. Removing Google leaves the app among the user's connected apps at Google.

## Removing a method

`POST /auth/methods/remove` (`Madauth.methods.remove(id)`) removes a password, Google, GitHub, an OpenID Connect provider, the e-mail link or a passkey. The authenticator app takes a code from it (`Madauth.authenticator.remove`), and the phone one sent to it.

- **Not the last way in.** A method can't go when the user would have no method left that the admin allows as a sign-in method (`403 only_method`): nobody could sign in as them, and a sign-up for their address could take the user over. A method switched off by the admin doesn't count, nor one the server is not configured for (e.g. GitHub without its OAuth App). A user who can't sign in now anyway (every method of theirs is switched off) is not locked out by the removal.
- **Not the last second factor a policy requires.** See [Passkey security](passkey-security.md#removing-a-passkey).

The account a user signed up with is no different: it can go once another method signs them in. Two removals at once can't both take the last ways in: a removal that finds the user without a way in afterwards puts its account back and answers `only_method`.

## Losing every way in

A user who lost every way in, or a second factor they can't sign in without, can't change their methods: that takes a sign-in. An admin [resets their sign-in](server.md#resetting-a-users-sign-in) instead: all their methods and second factors go, their sessions end, and the address counts as unconfirmed. The user then signs up again like anyone whose sign-up nobody finished, with any method that is on, and keeps their id, claims and roles. Whoever proves the address next gets the account, so the admin checks who is asking first.

Code: `resetSignIn` in [`users.ts`](../packages/server/src/users.ts), `/auth/admin/sign-in/reset` in [`app.ts`](../packages/server/src/app.ts).

## What the webhook is told

`user.method_added` and `user.method_removed`, with the `method` (and for a passkey its `id` and `name`, for a provider the provider's `email`). Setting up or removing the app or a phone stays `user.second_factor_enabled` and `user.second_factor_disabled`. A reset is one `user.sign_in_reset`, with the admin as `by`, not a removal per method.

## Not covered yet

- Adding a method by signing in with it: an address that has a password never gets Google by a Google sign-in, also when Google verified the address.
- Changing a password while signed in: "Forgot password?" sets a new one.
- Revoking Google's grant when Google is removed.
