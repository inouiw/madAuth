# Upgrading

## To 0.4

0.4 adds the authenticator app (TOTP), as a second factor for Google and password and as a method of its own, and a sign-in policy. What changes for you:

- **The settings list what is on.** The `methods` setting is the list of the primary methods that are on (`google`, `password`, `totp`), each with its policy for the authenticator app (`none`, `optional`, `required`); a method that is not listed is off. A value stored by 0.3 is ignored with a warning in the log: run `set-methods` again after upgrading, e.g. `set-methods google password`. `Madauth.admin.setSettings` replaces the list instead of merging into it, and the answer says `configured` instead of `available`, with `secondFactor` for Google and password and a `totp` entry. Until the methods are set, a server runs Google and/or password without a second factor, and the authenticator app on its own is off until listed.
- **Schema version 5.** `account.lastUsedStep` and the new model `recoveryCode`. SQLite upgrades itself and DynamoDB needs nothing; for your own SQL tables run `npx @madauth/server schema --dialect <yours> --from 4` and apply it before you deploy. See [Schema versions](server.md#schema-versions).
- **E-mail confirmation moved.** `POST /auth/password/verify-email` is now `POST /auth/email/verify`, and `send-verification` is `POST /auth/email/send-verification`: the confirmation is the same for a sign-up with a password and one with the app. The web library's methods keep their names; only direct HTTP users adjust.
- **Google no longer joins a user who signs in another way.** A Google sign-in with the address of a password user used to link the Google account to them; now it answers `403 other_method`, since whoever controls the Google account must not get past the password (and the app). Users who already have both accounts keep both. A sign-up nobody finished is still taken over.
- **Sign-ins may end in a second step.** With a policy that asks for the app, `password.signIn`, `verifyEmail`, `confirmReset` and Google end with `totp_required` or `totp_setup_required` instead of a user: the dialog handles it; a custom screen calls `Madauth.totp.verify` or the setup pair (see [Building your own login screen](custom-ui.md#authenticator-app-madauthtotp)). The redirect flow may return with `#madauth_next=…`.
- **`deleteAccount` takes a code** once the user has the app (`Madauth.deleteAccount({ code })`; `code_required` without one).
- **`amr` is exposed:** on `user.amr` in the web library and in `createSessionVerifier`'s result, e.g. `['pwd', 'otp']`. Webhook `user` objects don't carry it.
- **New webhook types** `totp.enabled`, `totp.disabled` and `totp.recovery_code_used` (opt in with `WEBHOOK_EVENTS`); `user.signed_in` can carry `method: "totp"` and `secondFactor`; `signup.before` and `user.created` can carry `method: "totp"`.
- **New:** `TOTP_ISSUER` (optional), `GET /auth/config` with `totp` and `email` fields and `secondFactor` on Google and password, `POST /auth/admin/totp/remove` and `remove-totp` on the command line, `init --totp` for a server where people sign up with the app alone.
- **Keep `MADAUTH_SIGNING_KEY`:** the secrets of the authenticator apps are encrypted with a key derived from it. A new key makes every enrolled app stop working until it is set up again.

## To 0.3.0-beta.2

- **"Forgot password?" only resets passwords.** A user without a password (who signs in with Google) no longer gets a reset e-mail that adds one. Instead madAuth sends the new type `email.no_password`, which tells them how they sign in. Add it to `WEBHOOK_EVENTS` and update your receiver first: the aws-ses-mailer and the dev-receiver of [madAuth-webhooks](https://github.com/inouiw/madAuth-webhooks) handle it from their next version, while an older mailer answers an empty 2xx to a type it doesn't know, so the server would count the e-mail as sent. Without the type in the list, such a user gets no e-mail, and the answer comes faster than for an address with a password (see [Password security](password-security.md#no-account-enumeration)).
- **`email.already_registered` carries `methods`**, how the user signs in (e.g. `["google"]`), so the e-mail can say so instead of pointing a Google user to "Forgot password?".
- **`Madauth.initialize` resolves with `leftOut`**, the methods whose providers the server doesn't offer, on success and on failure. Code that compares the result as a whole, like `toEqual({ isSuccess: true })`, has to expect `leftOut` as well.

## To 0.3

0.3 stores every user, whichever way they sign in, and replaces roles with claims. What changes for you:

- **`DATABASE_URL` is required**, also for Google-only servers (`sqlite:<path>` or `dynamodb:<table>`, or your own store adapter). E-mail & password sign-in is on when the webhook sends the e-mails (`email.verify` and `email.reset` in `WEBHOOK_EVENTS`), no longer whenever a database is set. A server with a database and no webhook is a Google-only server now.
- **Google users get a new id.** A Google user used to be `google:<sub>`; now every user is `usr_…`, the same whichever way they sign in. Data your backend keyed by the old id belongs to the new one: on the first sign-in after the upgrade, the `user.created` event (with `method: "google"`) carries the new id and the address. Sessions issued before the upgrade end when their session token expires.
- **Roles are a claim.** `user.roles` is gone; the session token and `user` carry `claims`, and roles are `claims.roles`. The `role` table is dropped (schema version 4) and roles are not migrated: set them again with `npx @madauth/server set-roles <email> admin`, after that user has signed in once. `Madauth.admin.setRoles` / `getRoles` became `setClaims` / `getClaims`, and the HTTP routes `/auth/admin/roles/*` became `/auth/admin/claims/*`.
- **Webhook events were renamed:** `password.reset` → `email.password_reset`, `roles.changed` → `user.claims_changed` (its data is `userId`, `email`, `claims`, `by`). `signup.before` and `user.created` are sent for Google sign-ups too, with a `method`. `user.deleted` has no `passwordUserId` any more: the deleted user is `user.id`.
- **Custom store adapters:** run `npx @madauth/server schema --dialect <yours> --from 3` and apply the SQL before you deploy. See [Schema versions](server.md#schema-versions).

See [Claims](server.md#claims) and [Sign-in methods](server.md#sign-in-methods) for what is new.
