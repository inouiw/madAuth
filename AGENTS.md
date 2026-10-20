# AGENTS.md

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues on `inouiw/madAuth`, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default labels are used as-is: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Communication

- Keep responses concise and technical — avoid filler, hedging, and restating what the user already knows.
- When a change can reasonably be implemented in more than one way, ask the user which approach they prefer before writing code.
- Ask clarifying questions whenever requirements, scope, or expected behavior are ambiguous — don't guess silently.

## Repository structure

```
madAuth/
├── packages/server/  # @madauth/server — the sign-in service and its CLI
├── packages/web/     # @madauth/web — the browser client and UI components
├── demo/             # Demo app, served at madauth.com/demo
├── site/             # madauth.com landing page
├── deploy/aws/       # User-facing AWS CDK template for running the server
├── scripts/          # The release script (npm run release <version>, see docs/releasing.md) and npm run size, the bundle size measurement (see docs/development.md)
└── docs/             # User-facing documentation
```

The webhook receivers (the dev receiver that prints e-mails and SMS codes, and the AWS SES mailer) live in the companion repo `inouiw/madAuth-webhooks`.

## Workflow

- **When asked to implement a GitHub issue, always create a separate branch first** (e.g. `issue-<number>-short-description`) and do the work there — never commit the implementation directly to `main`.
- **Avoid stacking when possible — base every PR on `main`. Only genuinely dependent changes need stacking.** (Stacked PRs combined with squash merges force rebases and force-pushes of the child branches; for a dependent sequence, prefer merging each PR before starting the next one on fresh `main`.)
- **Every completed change — not just GitHub issues — ends with a pull request that is then reviewed.** However small the change, once it is done: publish the branch and open a PR (`git push -u` the branch, then `gh pr create`), then run the code review as described below. Reference the issue it implements in the PR description, if any.
- **Make GitHub close the issue automatically when the PR merges:** include a closing keyword followed by the issue number — `Fixes #<issue>`, `Closes #<issue>`, or `Resolves #<issue>` — in **both** the PR description and the commit message. Plain references like "issue #10" or "see #10" do **not** auto-close.
- **Check for merge conflicts with `main` and fix them without being asked.** Before opening a PR, and again whenever you return to an already-open one, run `git fetch origin` and check the branch merges cleanly (`gh pr view <PR#> --json mergeable`, or attempt `git merge origin/main`). On a conflict, resolve it yourself by merging `origin/main` into the branch — adopt the conventions `main` introduced in the meantime, don't just splice the textual halves together. Re-run the affected workspaces' checks after the merge, then push it.
- **Then review the pull request as a real GitHub code review**, not just a summary comment. Run `/code-review --comment`, which posts each finding as an **inline review comment anchored to the exact file and line** on the PR. Do not post findings only as a plain `gh pr comment` timeline comment. Address any findings before considering the work done.
  - **Keep review feedback concise:** one sentence per finding — state the problem and its impact, no preamble. Only report real issues; no "looks good" filler comments.
  - **Control the depth with the effort level — always at least `medium`.** Default to `/code-review medium --comment`. Use `high` (up to `max`) only when broad coverage matters more than noise. Do not use `low` — it misses too much for reviews that gate merging.
- **A task that needs a browser or a terminal is still yours to finish: use the user's browser and terminal and do as much of it as you can yourself.** For a step only the user can do — signing in to Azure, say, or any other credential prompt — ask them to do that one step, then carry on independently with the rest.
- **After implementing a change, run the stack locally and check that it works without errors.** Exercise the changed flows in the browser — watch the server log and the browser console, don't just check that the processes start.
  - `.claude/launch.json` has the configs `server` (port 8787), `demo` (3000), `site` (3001) and `webhooks` (8790: the dev receiver from a checkout of `inouiw/madAuth-webhooks` next to this repo, which prints each e-mail and SMS with its link and code).
  - A worktree has no `packages/server/.env` (it is git-ignored): create it from `.env.example`, with a key from `npm run -s cli -w packages/server -- generate-key` and a secret from `generate-webhook-secret`. The dev receiver needs the same `WEBHOOK_SECRET` in its own `.env`, or every hand-over fails with 401.
  - The dev receiver only prints links and codes for the webhook types it knows. When you add a webhook type, list it in `WEBHOOK_EVENTS` (your `.env` and `.env.example`) — madAuth only sends the listed types — and update the receivers in `madAuth-webhooks` too, or test with a receiver that logs every body.
  - **Google and GitHub sign-in are tested through the user's Chrome browser (the claude-in-chrome tools)**: they need the provider's own pages, which the preview browser does not open, and the user enters their Google or GitHub credentials themselves — never enter credentials on the user's behalf.
  - **Stop the dev servers when you are done testing**, so the ports are free for the next agent session.
  - **If a port is already in use, do not kill the occupying process on your own** — it may belong to another still-running agent session. Ask the user first.
- **Check for missing AWS permissions.** Locally, code runs with your own AWS credentials, which are broader than the deployed roles — a call that works locally can still fail with `AccessDenied` when deployed. For every new or changed AWS call, verify that the corresponding IAM statement exists in the CDK stack (`deploy/aws`, or the site's stack in `site/infra`).

### Coding guidelines

- Prefer immutable variables and pure functions.
- Prefer a result type with a success and an error case over exceptions.
- Avoid try-catch blocks for branching. Prefer to check whether something exists over handling exceptions.

### Testing

Before considering a task done, run what CI runs at the repo root: `npm run typecheck`, `npm test`, `npm run build` and `npm run size -- --check` (the bundle sizes the READMEs and the landing page name; see `docs/development.md`). `deploy/aws` and `site/infra` are separate npm projects outside the workspaces: after changing one, run `npm ci && npm run typecheck && npm run build` and `npx cdk synth` in it, and in `deploy/aws` also `npm test` (see `.github/workflows/infra.yml` for the context values).

### Documentation

`docs/`, the READMEs, and `CONTEXT.md` (once it exists) describe the behavior users and agents rely on. Update them **in the same commit** as the code change, and never leave them describing behavior that no longer exists. Do not amend commits; create a new commit instead.

Releases and the madauth.com deploy (on `v*` tags) are described in `docs/releasing.md`.
