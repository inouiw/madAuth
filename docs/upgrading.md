# Upgrading

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
