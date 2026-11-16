#!/usr/bin/env bash
#
# Deploys the community libraries to repo.jsentinel.eu/{releases,snapshots}.
# Maven Central is published through scripts/clean-bundle-for-central.sh.
#
# Until 00.83.00 this script ran "package deploy:deploy" without the signing
# profile: a release reached the registry without .asc files, sources, Javadoc
# or SBOM, from whatever the working tree held, while the same version on Maven
# Central was signed. The registry is the first source the enterprise edition
# and its customers resolve from, so a release is now published there under the
# same conditions as on Central (security analysis 2026-11-10, SA42):
#
#   * A release version is deployed only from a clean working tree whose HEAD
#     is the commit of the signed tag v<version>, with the profiles
#     _release_prepare (sources, Javadoc, SBOM, no snapshot dependencies) and
#     _release_sign-artifacts, signed with the pinned release key (see
#     scripts/lib/release-common.sh).
#   * After the upload the log is checked: every uploaded file needs an
#     uploaded .asc, and no test jar may have left the machine. Then POM, jar
#     and SBOM of every module are fetched back from the registry and their
#     signatures verified against the pinned key. The script fails otherwise;
#     the version is then on the registry and has to be removed there by hand,
#     because releases are not overwritten.
#   * A snapshot version is deployed unsigned and from any tree; the commit and
#     the state of the tree are printed. Snapshots are development builds and
#     carry no promise of origin.
#   * Demo modules are excluded, and with them the npm frontend build. Test
#     jars are not deployed (-Dmaven.test.skip=true): they hold test fixtures
#     and key stores for tests. The gate runs the tests, not the deploy.
#
# The goal deploy:deploy is named explicitly: with com.svenruppert:dependencies
# as the parent the plain deploy phase uploads nothing and still reports
# BUILD SUCCESS. One reactor pass covers the parent, the BOM and the libraries;
# a second pass would make the registry answer 409 for a release.
#
# Usage:
#   scripts/deploy-jsentinel.sh [--dry-run] [-- <maven arguments>]
#   scripts/deploy-jsentinel.sh --verify-published [<version>]
#   scripts/deploy-jsentinel.sh --check-log <maven log>
#
#   --dry-run           Performs every check and the complete build with
#                       "verify", but neither signs nor uploads. Lists per
#                       module what would be signed and uploaded, and where to.
#                       Failed checks are reported and the run goes on.
#   --verify-published  Uploads nothing. Fetches POM, jar and SBOM of every
#                       module of <version> (default: the version in pom.xml)
#                       together with their .asc from the registry and verifies
#                       the signatures against the pinned release key.
#                       JCUSTOS_VERIFY_BASE_URL selects another repository,
#                       for example https://repo.maven.apache.org/maven2.
#   --check-log         Uploads nothing. Repeats the check of a deploy log:
#                       every uploaded file needs an uploaded .asc, and no test
#                       artefact may have been uploaded.
#
# Exit codes: 0 deployed and verified (or dry run without findings), 1 a check,
# the build or the verification failed, 64 usage.
set -euo pipefail

# shellcheck source=scripts/lib/release-common.sh
. "$(cd "$(dirname "$0")" && pwd)/lib/release-common.sh"

usage() {
  sed -n '/^# Usage:/,/^# Exit codes/p' "$0" | sed 's/^# \{0,1\}//'
}

MODE=deploy
REQUESTED_VERSION=""
CHECK_LOG=""
MAVEN_EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
  --dry-run) JC_DRY_RUN=true ;;
  --verify-published) MODE=verify ;;
  --check-log)
    MODE=check-log
    CHECK_LOG="${2:-}"
    [ -f "$CHECK_LOG" ] || {
      usage >&2
      exit 64
    }
    shift
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  --)
    shift
    MAVEN_EXTRA=("$@")
    break
    ;;
  -*)
    usage >&2
    exit 64
    ;;
  *) REQUESTED_VERSION="$1" ;;
  esac
  shift
done

jc_require_tools git python3 shasum java
VERSION=$(jc_reactor version)
MODULES="$JC_PARENT_ARTIFACT
$(jc_reactor libraries)"

# Reads a Maven log and fails for every uploaded file without an uploaded
# signature, and for every uploaded test jar. Checksums and repository metadata
# are written by the deploy plugin and carry no signature of their own.
check_uploads() {
  local log="$1" uploaded url missing=0 files=0
  uploaded=$(sed -n 's/^.*Uploaded to jsentinel-[a-z-]*: \([^ ]*\).*$/\1/p' "$log" | sort -u)
  if [ -z "$uploaded" ]; then
    jc_fail "the log shows no upload to the registry"
    return 0
  fi
  for url in $uploaded; do
    case "$url" in
    *.asc | *.md5 | *.sha1 | *.sha256 | *.sha512 | */maven-metadata.xml) continue ;;
    *-tests.jar | *-test-sources.jar)
      jc_fail "a test artefact was uploaded: $url"
      continue
      ;;
    esac
    files=$((files + 1))
    if ! printf '%s\n' "$uploaded" | grep -qxF "$url.asc"; then
      missing=$((missing + 1))
      jc_fail "uploaded without signature: $url"
    fi
  done
  if [ "$missing" -eq 0 ]; then
    jc_pass "$files uploaded files, each with an uploaded .asc"
  fi
  return 0
}

# Fetches the published files of one version and checks their signatures.
verify_published() {
  local version="$1" base="${JCUSTOS_VERIFY_BASE_URL:-$JC_RELEASES_URL}" directory module name url suffixes missing=0 checked=0 unverified=0
  jc_require_tools curl gpg
  directory=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$directory'" EXIT
  jc_say "Verifying $JC_GROUP_ID $version on $base"
  jc_check_trust_anchor
  for module in $MODULES; do
    suffixes=".pom .jar -cyclonedx.json"
    [ "$module" = "$JC_PARENT_ARTIFACT" ] && suffixes=".pom -cyclonedx.json"
    [ "$module" = "$JC_BOM_ARTIFACT" ] && suffixes=".pom"
    for suffix in $suffixes; do
      name="$module-$version$suffix"
      url="$base/$JC_GROUP_PATH/$module/$version/$name"
      checked=$((checked + 1))
      if ! curl -fsS -m 60 -o "$directory/$name" "$url" 2>/dev/null; then
        missing=$((missing + 1))
        jc_fail "not published: $url"
        continue
      fi
      if ! curl -fsS -m 60 -o "$directory/$name.asc" "$url.asc" 2>/dev/null; then
        missing=$((missing + 1))
        jc_fail "no signature: $url.asc"
        continue
      fi
      if ! jc_signature_is_pinned "$directory/$name.asc" "$directory/$name"; then
        unverified=$((unverified + 1))
        [ -z "$JCUSTOS_RELEASE_KEY_FINGERPRINT" ] || jc_fail "signature does not verify against the pinned key: $name"
      fi
    done
  done
  jc_say ""
  jc_say "$checked files checked: $missing missing or unsigned, $unverified not verified against the pinned key."
}

# Both read-only modes report every finding instead of stopping at the first.
if [ "$MODE" = verify ]; then
  JC_DRY_RUN=true
  verify_published "${REQUESTED_VERSION:-$VERSION}"
  [ "$JC_CHECK_FAILURES" -eq 0 ] || exit 1
  exit 0
fi
if [ "$MODE" = check-log ]; then
  JC_DRY_RUN=true
  check_uploads "$CHECK_LOG"
  [ "$JC_CHECK_FAILURES" -eq 0 ] || exit 1
  exit 0
fi
[ -z "$REQUESTED_VERSION" ] || {
  usage >&2
  exit 64
}

case "$VERSION" in
*-SNAPSHOT) RELEASE=false REPOSITORY_ID=jsentinel-snapshots TARGET_URL=$JC_SNAPSHOTS_URL ;;
*) RELEASE=true REPOSITORY_ID=jsentinel-releases TARGET_URL=$JC_RELEASES_URL ;;
esac
LOG="${TMPDIR:-/tmp}/jcustos-community-deploy.log"

if [ "$JC_DRY_RUN" = true ]; then
  jc_say "DRY RUN: nothing is signed or uploaded."
fi
jc_say "Deploying $JC_GROUP_ID $VERSION to $TARGET_URL"
jc_say "Commit: $(jc_head_commit)$(jc_tree_is_clean || printf ' (working tree has local changes)')"

MAVEN=(./mvnw -B -V -Dmaven.test.skip=true -pl "$(jc_demo_exclusions)")
if [ "$RELEASE" = true ]; then
  jc_say "Preconditions for a release"
  jc_check_clean_tree
  jc_check_head_is_tag "v$VERSION"
  jc_check_trust_anchor
  jc_check_tag_signature "v$VERSION"
  jc_check_no_open_decisions
  if [ "$JC_DRY_RUN" = true ]; then
    MAVEN+=(-P "_release_prepare,_java" clean verify)
  else
    jc_require_tools gpg
    MAVEN+=(-P "_release_prepare,_release_sign-artifacts,_java,?gpg" "-Dgpg.keyname=$JCUSTOS_RELEASE_KEY_FINGERPRINT" clean verify deploy:deploy)
  fi
elif [ "$JC_DRY_RUN" = true ]; then
  MAVEN+=(clean verify)
else
  MAVEN+=(clean verify deploy:deploy)
fi
MAVEN+=(${MAVEN_EXTRA[@]+"${MAVEN_EXTRA[@]}"})

jc_say "Build: ${MAVEN[*]}"
jc_say "Log:   $LOG"
BUILD_STARTED=$(date +%s)
if (cd "$JC_REPO_ROOT" && "${MAVEN[@]}") >"$LOG" 2>&1; then
  jc_pass "Maven finished in $(($(date +%s) - BUILD_STARTED)) s"
else
  grep -E '^\[ERROR\]' "$LOG" | head -20 || true
  JC_DRY_RUN=false
  jc_fail "Maven failed; see $LOG. Check the registry for a partial upload before the next attempt."
fi

if [ "$JC_DRY_RUN" = true ]; then
  jc_say ""
  jc_say "Would upload to $TARGET_URL/$JC_GROUP_PATH/"
  FILE_COUNT=0
  MODULE_COUNT=0
  for module in $MODULES; do
    MODULE_COUNT=$((MODULE_COUNT + 1))
    files=$(jc_planned_files "$JC_REPO_ROOT" "$module" "$VERSION")
    [ "$RELEASE" = false ] || jc_check_module_files "$module" "$VERSION" "$files"
    for name in $files; do
      FILE_COUNT=$((FILE_COUNT + 1))
      if [ "$RELEASE" = true ]; then
        printf '  would sign and upload  %s\n' "$module/$VERSION/$name (+ .asc)"
      else
        printf '  would upload unsigned  %s\n' "$module/$VERSION/$name"
      fi
    done
  done
  jc_say ""
  jc_say "Dry run finished: $MODULE_COUNT modules, $FILE_COUNT files, $JC_CHECK_FAILURES check(s) failed."
  [ "$JC_CHECK_FAILURES" -eq 0 ] || exit 1
  exit 0
fi

if [ "$RELEASE" = true ]; then
  JC_DRY_RUN=true
  check_uploads "$LOG"
  [ "$JC_CHECK_FAILURES" -eq 0 ] && verify_published "$VERSION"
  if [ "$JC_CHECK_FAILURES" -ne 0 ]; then
    jc_die "$VERSION is on the registry, but not as a signed release ($JC_CHECK_FAILURES finding(s) above). Remove the version there before the next attempt."
  fi
  jc_say "Deployed, and what the registry serves verified against $JCUSTOS_RELEASE_KEY_FINGERPRINT."
  jc_say "Repeat the check at any time with: scripts/deploy-jsentinel.sh --verify-published $VERSION"
else
  jc_say "Deployed $(grep -c "Uploaded to $REPOSITORY_ID" "$LOG" || true) files (snapshot, unsigned)."
fi
