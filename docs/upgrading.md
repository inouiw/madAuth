# Upgrading

## To 0.3

0.3 stores every user, whichever way they sign in, and replaces roles with claims. What changes for you:

- **`DATABASE_URL` is required**, also for Google-only servers (`sqlite:<path>` or `dynamodb:<table>`, or your own store adapter). E-mail & password sign-in is on when the webhook sends the e-mails (`email.verify` and `email.reset` in `WEBHOOK_EVENTS`), no longer whenever a database is set. A server with a database and no webhook is a Google-only server now.
- **Google users get a new id.** A Google user used to be `google:<sub>`; now every user is `usr_…`, the same whichever way they sign in. Data your backend keyed by the old id belongs to the new one: on the first sign-in after the upgrade, the `user.created` event (with `method: "google"`) carries the new id and the address. Sessions issued before the upgrade end when their session token expires.
- **Roles are a claim.** `user.roles` is gone; the session token and `user` carry `claims`, and roles are `claims.roles`. The `role` table is dropped (schema version 4) and roles are not migrated: set them again with `npx @madauth/server set-roles <email> admin`, after that user has signed in once. `Madauth.admin.setRoles` / `getRoles` became `setClaims` / `getClaims`, and the HTTP routes `/auth/admin/roles/*` became `/auth/admin/claims/*`.
- **Webhook events were renamed:** `password.reset` → `email.password_reset`, `roles.changed` → `user.claims_changed` (its data is `userId`, `email`, `claims`, `by`). `signup.before` and `user.created` are sent for Google sign-ups too, with a `method`. `user.deleted` has no `passwordUserId` any more: the deleted user is `user.id`.
- **Custom store adapters:** run `npx @madauth/server schema --dialect <yours> --from 3` and apply the SQL before you deploy. See [Schema versions](server.md#schema-versions).

See [Claims](server.md#claims) and [Sign-in methods](server.md#sign-in-methods) for what is new.
