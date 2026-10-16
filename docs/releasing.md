# Releasing

A release publishes `@madauth/web` and `@madauth/server` to npm, the server image to `ghcr.io/inouiw/madauth-server`, and the server bundles for Node, AWS Lambda and Azure Functions to a GitHub release. The [release workflow](../.github/workflows/release.yml) does all of it when a version tag is pushed.

## Publishing a release

Both packages share one version. On `main`, up to date with GitHub, run the release script with the new version:

```bash
npm run release 0.6.0
```

It checks first and changes nothing until every check passes:

- you are on `main`, the working tree is clean, and `main` is the same as `origin/main`;
- the version is a version, newer than the current one, and its tag doesn't exist yet;
- CI passed for the commit, which the script reads with the [GitHub CLI](https://cli.github.com) (`gh`, logged in with `gh auth login`). The release workflow runs the tests again, but the deploy of madauth.com starts at the same time without them.

Then it asks, and on `y` sets both packages to the version (`npm version … -w packages/web -w packages/server --no-git-tag-version`, which updates `package-lock.json` too), commits `Release <version>`, tags `v<version>` and pushes `main` and the tag together (`git push --atomic`). If a step fails, e.g. the push because `main` moved meanwhile, it undoes the commit and the tag, and nothing is pushed. `npm run release 0.6.0 --dry-run` runs the checks only. The script is [`scripts/release.sh`](../scripts/release.sh).

A version with a suffix, e.g. `0.6.0-beta.1`, is a prerelease: npm publishes it under the `next` tag, so `npm install` keeps installing the last stable version, and the image doesn't move `latest`.

The workflow stops before publishing anything if the tag doesn't match both package versions, or if the type check or the tests fail.

## One-time setup

npm publishes with [trusted publishing](https://docs.npmjs.com/trusted-publishers): the workflow proves who it is with GitHub's OIDC token, so there is no npm token to store or rotate, and every version it publishes gets a provenance statement.

1. **First publish by hand.** A trusted publisher can only be added to a package that exists. Log in, then publish the first version from your machine:

   ```bash
   npm login
   ```

   ```bash
   npm ci && npm run build -w packages/server -w packages/web
   ```

   ```bash
   npm publish -w packages/server -w packages/web
   ```

   Then push the tag for that version (e.g. `v0.1.0`). The workflow skips the npm packages that are already published and still pushes the image and creates the GitHub release.

2. **Add the trusted publisher.** On npmjs.com, for each of `@madauth/web` and `@madauth/server`: *Settings → Trusted publishing → GitHub Actions*, with organization or user `inouiw`, repository `madAuth`, workflow filename `release.yml` and environment `npm`.

3. **Lock down token publishing.** On the same settings page, choose *Require two-factor authentication and disallow tokens*. Trusted publishing keeps working.

4. **Make the image public.** The first release creates the `madauth-server` package on GitHub as private. Under *Your profile → Packages → madauth-server → Package settings*, change its visibility to public.

The `npm` environment in GitHub (*Settings → Environments*) is created by the first run. Add required reviewers there if releases should wait for approval. The image and the GitHub release are published after npm, so they wait too.
