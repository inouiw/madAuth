#!/usr/bin/env bash
# Releases @madauth/web and @madauth/server: sets both to the version, commits "Release <version>" on main, tags
# it v<version> and pushes both. The tag starts the release workflow (npm, the server image, the GitHub release)
# and the deploy of madauth.com. See docs/releasing.md.
#
#   npm run release 0.6.0-beta.1               a version with a suffix is a prerelease (npm's tag `next`)
#   npm run release 0.6.0 --dry-run            only the checks: changes nothing
set -euo pipefail

usage() {
  echo "Usage: npm run release <version> [--dry-run], e.g. npm run release 0.6.0-beta.1" >&2
  exit 2
}
fail() {
  echo "release: $*" >&2
  exit 1
}

version=""
# npm keeps a --dry-run before its own `--` for itself, and tells it to the script this way.
dry_run=$([ "${npm_config_dry_run:-}" = true ] && echo true || echo false)
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=true ;;
    -*) usage ;;
    *) [ -z "$version" ] || usage; version="${arg#v}" ;;
  esac
done
[ -n "$version" ] || usage
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] ||
  fail "\"$version\" is no version: use e.g. 0.6.0, or 0.6.0-beta.1 for a prerelease."
tag="v$version"

cd "$(git rev-parse --show-toplevel)"

# --- Checks: nothing changes until all of them pass. ---

[ "$(git symbolic-ref --quiet --short HEAD || true)" = main ] || fail "Releases are made from main: run git checkout main first."
[ -z "$(git status --porcelain)" ] || fail "The working tree has changes: commit or stash them first."
git fetch --quiet origin main --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] ||
  fail "main is not the same as origin/main: run git pull (or push your commits through a pull request) first."
! git rev-parse --quiet --verify "refs/tags/$tag" >/dev/null || fail "The tag $tag exists already."

current=$(node -p "require('./packages/server/package.json').version")
[ "$(node -p "require('./packages/web/package.json').version")" = "$current" ] ||
  fail "packages/web and packages/server have different versions: set them to the same one first."
# Semantic versioning's order, prereleases included: 0.6.0-beta.1 < 0.6.0-beta.2 < 0.6.0.
newer=$(node -e '
  const parse = (v) => { const [core, pre] = v.split(/-(.*)/s); return { core: core.split(".").map(Number), pre: pre ? pre.split(".") : [] }; };
  const part = (a, b) => { const na = /^\d+$/.test(a), nb = /^\d+$/.test(b); return na && nb ? Number(a) - Number(b) : na ? -1 : nb ? 1 : a < b ? -1 : a > b ? 1 : 0; };
  const compare = (x, y) => {
    for (let i = 0; i < 3; i++) if (x.core[i] !== y.core[i]) return x.core[i] - y.core[i];
    if (!x.pre.length || !y.pre.length) return y.pre.length - x.pre.length;
    for (let i = 0; i < Math.min(x.pre.length, y.pre.length); i++) { const d = part(x.pre[i], y.pre[i]); if (d) return d; }
    return x.pre.length - y.pre.length;
  };
  console.log(compare(parse(process.argv[1]), parse(process.argv[2])) > 0);
' "$version" "$current")
[ "$newer" = true ] || fail "$version is not newer than the current version $current."

# The release workflow runs the tests again, but the deploy of madauth.com starts at the same time without them.
sha=$(git rev-parse HEAD)
ci=$(gh run list --commit "$sha" --workflow ci.yml --json status,conclusion --jq '.[0] | "\(.status) \(.conclusion)"' 2>/dev/null || true)
case "$ci" in
  "completed success") ;;
  "") echo "release: could not read the CI run of ${sha:0:7} (is gh installed and logged in?): check it on GitHub before you go on." >&2 ;;
  *) fail "CI of ${sha:0:7} is \"$ci\": wait until it has passed." ;;
esac

if [[ "$version" == *-* ]]; then kind="a prerelease: npm's tag next, the image's latest stays"; else kind="a stable release: npm's tag latest"; fi
echo "Release $version ($kind), from $current, at ${sha:0:7}: sets both packages, commits, tags $tag and pushes main and the tag."
if $dry_run; then
  echo "Dry run: every check passed, nothing was changed."
  exit 0
fi
read -r -p "Publish $version? [y/N] " answer || answer=""
[[ "$answer" =~ ^[yY]$ ]] || fail "Cancelled: nothing was changed."

# --- The release. ---

npm version "$version" -w packages/web -w packages/server --no-git-tag-version --loglevel=error >/dev/null
git commit --quiet --all --message "Release $version"
git tag "$tag"
# Both or neither: a tag without its commit on main, or the other way round, would be a release half made.
if ! git push --atomic --quiet origin main "$tag"; then
  git tag --delete "$tag" >/dev/null
  git reset --quiet --hard HEAD~1
  fail "The push was refused, so the release commit and the tag were undone here. Run git pull, then try again."
fi

origin=$(git remote get-url origin | sed -E 's#^git@github\.com:#https://github.com/#; s#\.git$##')
echo "Pushed $tag. The release and the deploy run at $origin/actions"
if [[ "$version" == *-* ]]; then echo "Once published: npm install @madauth/web@next @madauth/server@next"; fi
