#!/usr/bin/env bash
# Releases madAuth (@madauth/web and @madauth/server, which share one version) or @madauth/google-identity
# (its own version): sets the version, commits "Release <version>" (or "Release @madauth/google-identity <version>")
# on main, tags it and pushes both. The tag starts the release workflow (npm, and for madAuth the server image,
# the GitHub release and the deploy of madauth.com). See docs/releasing.md.
#
#   npm run release 0.6.0-beta.1                   madAuth; a version with a suffix is a prerelease (npm's tag `next`)
#   npm run release google-identity 0.2.0          @madauth/google-identity, tag google-identity-v0.2.0
#   npm run release 0.6.0 --dry-run                only the checks: changes nothing
set -euo pipefail

usage() {
  echo "Usage: npm run release [google-identity] <version> [--dry-run], e.g. npm run release 0.6.0-beta.1" >&2
  exit 2
}
fail() {
  echo "release: $*" >&2
  exit 1
}

version=""
package=madauth
# npm keeps a --dry-run before its own `--` for itself, and tells it to the script this way.
dry_run=$([ "${npm_config_dry_run:-}" = true ] && echo true || echo false)
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=true ;;
    -*) usage ;;
    google-identity) [ "$package" = madauth ] && [ -z "$version" ] || usage; package=google-identity ;;
    *) [ -z "$version" ] || usage; version="${arg#v}" ;;
  esac
done
[ -n "$version" ] || usage
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] ||
  fail "\"$version\" is no version: use e.g. 0.6.0, or 0.6.0-beta.1 for a prerelease."

# What the two kinds of release set, tag and say.
if [ "$package" = google-identity ]; then
  workspaces=(packages/google-identity)
  tag="google-identity-v$version"
  what="@madauth/google-identity"
  message="Release @madauth/google-identity $version"
else
  workspaces=(packages/web packages/server)
  tag="v$version"
  what="@madauth/web and @madauth/server"
  message="Release $version"
fi

cd "$(git rev-parse --show-toplevel)"

# --- Checks: nothing changes until all of them pass. ---

[ "$(git symbolic-ref --quiet --short HEAD || true)" = main ] || fail "Releases are made from main: run git checkout main first."
[ -z "$(git status --porcelain)" ] || fail "The working tree has changes: commit or stash them first."
git fetch --quiet origin main --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] ||
  fail "main is not the same as origin/main: run git pull (or push your commits through a pull request) first."
! git rev-parse --quiet --verify "refs/tags/$tag" >/dev/null || fail "The tag $tag exists already."

current=$(node -p "require('./${workspaces[0]}/package.json').version")
for pkg in "${workspaces[@]}"; do
  [ "$(node -p "require('./$pkg/package.json').version")" = "$current" ] ||
    fail "${workspaces[0]} and $pkg have different versions: set them to the same one first."
done
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

# @madauth/web must be able to use the @madauth/google-identity that is released with it (npm links the workspace
# copy only while it satisfies the range, and the published @madauth/web installs what the range says).
if [ "$package" = madauth ]; then
  satisfied=$(node -e '
    const range = require("./packages/web/package.json").dependencies["@madauth/google-identity"];
    const v = require("./packages/google-identity/package.json").version;
    // A caret range on the same major (and the same minor below 1.0), from the range'"'"'s version upwards.
    const [rv, vv] = [range.replace(/^\^/, ""), v].map((s) => s.split(/[-.]/).slice(0, 3).map(Number));
    const sameLine = rv[0] === vv[0] && (rv[0] > 0 || rv[1] === vv[1]);
    const notBelow = vv[0] > rv[0] || (vv[0] === rv[0] && (vv[1] > rv[1] || (vv[1] === rv[1] && vv[2] >= rv[2])));
    console.log(range.startsWith("^") && sameLine && notBelow);
  ')
  [ "$satisfied" = true ] ||
    fail "packages/web's dependency on @madauth/google-identity ($(node -p "require('./packages/web/package.json').dependencies['@madauth/google-identity']")) does not take packages/google-identity's version $(node -p "require('./packages/google-identity/package.json').version"): set it to a caret range that does (release @madauth/google-identity first if it is new)."
fi

# The release workflow runs the tests again, but the deploy of madauth.com starts at the same time without them.
sha=$(git rev-parse HEAD)
ci=$(gh run list --commit "$sha" --workflow ci.yml --json status,conclusion --jq '.[0] | "\(.status) \(.conclusion)"' 2>/dev/null || true)
case "$ci" in
  "completed success") ;;
  "") fail "Could not read the CI run of ${sha:0:7}: install the GitHub CLI (gh) and run gh auth login." ;;
  "null null") fail "CI has not run for ${sha:0:7} yet: wait until it has passed." ;;
  *) fail "CI of ${sha:0:7} is \"$ci\": wait until it has passed." ;;
esac

if [[ "$version" == *-* ]]; then kind="a prerelease: npm's tag next"; else kind="a stable release: npm's tag latest"; fi
if [ "$package" = madauth ] && [[ "$version" == *-* ]]; then kind="$kind, the image's latest stays"; fi
echo "Release $what $version ($kind), from $current, at ${sha:0:7}: sets the version, commits, tags $tag and pushes main and the tag."
if $dry_run; then
  echo "Dry run: every check passed, nothing was changed."
  exit 0
fi
read -r -p "Publish $what $version? [y/N] " answer || answer=""
[[ "$answer" =~ ^[yY]$ ]] || fail "Cancelled: nothing was changed."

# --- The release. ---

# What a failed step leaves is undone: the tree was clean and at $sha before.
undo() {
  git tag --delete "$tag" >/dev/null 2>&1 || true
  git reset --quiet --hard "$sha"
  fail "$1 The release commit and the tag were undone here; nothing was pushed."
}
args=()
for pkg in "${workspaces[@]}"; do args+=(-w "$pkg"); done
npm version "$version" "${args[@]}" --no-git-tag-version --loglevel=error >/dev/null || undo "npm version failed."
git commit --quiet --all --message "$message" || undo "The commit failed."
git tag "$tag" || undo "The tag failed."
# Both or neither: a tag without its commit on main, or the other way round, would be a release half made.
git push --atomic --quiet origin main "$tag" || undo "The push was refused: run git pull, then try again."

echo "Pushed $tag. The release runs at $(gh repo view --json url --jq .url)/actions"
if [[ "$version" == *-* ]]; then
  if [ "$package" = google-identity ]; then echo "Once published: npm install @madauth/google-identity@next"; else echo "Once published: npm install @madauth/web@next @madauth/server@next"; fi
fi
