# Releasing

A madAuth release publishes `@madauth/web` and `@madauth/server` to npm, the server image to `ghcr.io/inouiw/madauth-server`, and the server bundles for Node, AWS Lambda and Azure Functions to a GitHub release. The [release workflow](../.github/workflows/release.yml) does all of it when a version tag `v<version>` is pushed. `@madauth/google-identity` has a version of its own and is released on its own, with a `google-identity-v<version>` tag, see [below](#releasing-madauthgoogle-identity).

## Publishing a release

`@madauth/web` and `@madauth/server` share one version. On `main`, up to date with GitHub, run the release script with the new version:

```bash
npm run release 0.6.0
```

It checks first and changes nothing until every check passes:

- you are on `main`, the working tree is clean, and `main` is the same as `origin/main`;
- the version is a version, newer than the current one, and its tag doesn't exist yet;
- `@madauth/web`'s dependency range on `@madauth/google-identity` takes the version in `packages/google-identity` (npm links the workspace copy only while it does, and the published `@madauth/web` installs what the range says);
- CI passed for the commit, which the script reads with the [GitHub CLI](https://cli.github.com) (`gh`, logged in with `gh auth login`). The release workflow runs the tests again, but the deploy of madauth.com starts at the same time without them.

Then it asks, and on `y` sets both packages to the version (`npm version … -w packages/web -w packages/server --no-git-tag-version`, which updates `package-lock.json` too), commits `Release <version>`, tags `v<version>` and pushes `main` and the tag together (`git push --atomic`). If a step fails, e.g. the push because `main` moved meanwhile, it undoes the commit and the tag, and nothing is pushed. `npm run release 0.6.0 --dry-run` runs the checks only. The script is [`scripts/release.sh`](../scripts/release.sh).

A version with a suffix, e.g. `0.6.0-beta.1`, is a prerelease: npm publishes it under the `next` tag, so `npm install` keeps installing the last stable version, and the image doesn't move `latest`.

The workflow stops before publishing anything if the tag doesn't match both package versions, or if the type check or the tests fail.

## Releasing @madauth/google-identity

`@madauth/google-identity` is a library of its own, shared with other projects, so it follows [semantic versioning](https://semver.org) on its own: a madAuth release doesn't move it, and a change to it doesn't need a madAuth release. The same script releases it, with the package name first:

```bash
npm run release google-identity 0.2.0
```

The checks are the same (minus the dependency range), the commit is `Release @madauth/google-identity 0.2.0`, the tag `google-identity-v0.2.0`, and the workflow publishes that package alone: no image, no GitHub release, no deploy of madauth.com.

`@madauth/web` depends on it with a caret range (`^0.1.0`). A patch of the module reaches madAuth users through `npm update` without a madAuth release. A new minor below 1.0, or a new major, is outside the range: widen the range in `packages/web/package.json` in the same change that needs the new version, and the next madAuth release carries it (the release script checks that the range takes the workspace version). Release the module before the madAuth release that depends on its new version, so that the published `@madauth/web` can install it.

## One-time setup

npm publishes with [trusted publishing](https://docs.npmjs.com/trusted-publishers): the workflow proves who it is with GitHub's OIDC token, so there is no npm token to store or rotate, and every version it publishes gets a provenance statement.

1. **First publish by hand.** A trusted publisher can only be added to a package that exists. Log in, then publish the first version from your machine:

   ```bash
   npm login
   ```

   ```bash
   npm ci && npm run build -w packages/google-identity -w packages/server -w packages/web
   ```

   ```bash
   npm publish -w packages/google-identity -w packages/server -w packages/web
   ```

   Then push the tag for that version (e.g. `v0.1.0`). The workflow skips the npm packages that are already published and still pushes the image and creates the GitHub release.

   The same goes for a package added later (`@madauth/google-identity`, first published by hand at 0.1.0): publish it by hand once at its current version (`npm run build -w packages/google-identity && npm publish -w packages/google-identity`), then add its trusted publisher as below. Until then, the release workflow's publish of that package fails for want of a trusted publisher.

2. **Add the trusted publisher.** On npmjs.com, for each of `@madauth/google-identity`, `@madauth/web` and `@madauth/server`: *Settings → Trusted publishing → GitHub Actions*, with organization or user `inouiw`, repository `madAuth`, workflow filename `release.yml` and environment `npm`.

3. **Lock down token publishing.** On the same settings page, choose *Require two-factor authentication and disallow tokens*. Trusted publishing keeps working.

4. **Make the image public.** The first release creates the `madauth-server` package on GitHub as private. Under *Your profile → Packages → madauth-server → Package settings*, change its visibility to public.

The `npm` environment in GitHub (*Settings → Environments*) is created by the first run. Add required reviewers there if releases should wait for approval. The image and the GitHub release are published after npm, so they wait too.
