#!/usr/bin/env bash
#
# Builds the bundle for the Central Portal from a clean checkout of the release
# tag.
#
# Until 00.83.00 this script collected whatever lay under
# ~/.m2/repository/eu/jsentinel/<module>/<version>: the output of some earlier
# "mvnw install", from any commit, from a tree with local changes, with or
# without signatures. Maven Central is immutable, so the bundle is now tied to
# the commit it claims to be (security analysis 2026-11-10, SA42):
#
#   1. Preconditions: release version, clean working tree, HEAD is the commit
#      of tag v<version>, the tag is signed with the pinned release key (see
#      scripts/lib/release-common.sh), the Maven wrapper pins its download, and
#      SECURITY.md has no decision left open.
#   2. The tag is exported with "git archive" into an empty directory and built
#      there into a dedicated, empty local repository
#      (target/release-<version>/local-repository), with strict checksums for
#      everything Maven downloads. Only the library modules are built: the demos
#      and their npm frontend build are not part of a release.
#   3. The artefacts are taken from that repository and from nowhere else. Per
#      module the script requires POM, jar, sources, Javadoc (not empty) and the
#      CycloneDX SBOM, and for every file a signature that verifies against the
#      pinned key.
#   4. Checksums are written, read back and compared; the zip is tested; a
#      manifest next to the bundle records tag, commit, tool versions and the
#      SHA-256 of every file.
#
# Why a bundle at all: central-publishing-maven-plugin under Maven 4.0.0-rc-5
# produces a zip that holds the POMs only (it depends on the Maven 2
# compatibility layer); Central rejects it. Maven 4's installer names the
# consumer POM <artifactId>-<version>.pom and keeps the build POM under the
# classifier "build", which is left out here, as are test jars and test sources.
#
# Usage:
#   scripts/clean-bundle-for-central.sh [--dry-run] [--skip-tests] [<version>] [-- <maven arguments>]
#
#   --dry-run     Performs every check and the complete build, but neither
#                 signs nor installs nor writes a bundle. It builds with
#                 "verify", lists what would be signed and bundled and prints
#                 the manifest. Failed checks are reported and the run goes on;
#                 if the tree is not at a clean release tag, the working tree is
#                 built instead so that the rest can still be inspected.
#   --skip-tests  Builds without running the tests. For re-bundling a commit
#                 that scripts/gate.sh has passed; the default runs them.
#   <version>     Optional; must equal the version in pom.xml.
#
# Exit codes: 0 bundle written (or dry run without findings), 1 a check or the
# build failed, 64 usage.
set -euo pipefail

# shellcheck source=scripts/lib/release-common.sh
. "$(cd "$(dirname "$0")" && pwd)/lib/release-common.sh"

usage() {
  sed -n '/^# Usage:/,/^# Exit codes/p' "$0" | sed 's/^# \{0,1\}//'
}

SKIP_TESTS=false
REQUESTED_VERSION=""
MAVEN_EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
  --dry-run) JC_DRY_RUN=true ;;
  --skip-tests) SKIP_TESTS=true ;;
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

jc_require_tools git python3 shasum tar zip unzip java
[ "$JC_DRY_RUN" = true ] || jc_require_tools gpg

VERSION=$(jc_reactor version)
TAG="v$VERSION"
WORK="$JC_REPO_ROOT/target/release-$VERSION"
SOURCE="$WORK/source"
LOCAL_REPOSITORY="$WORK/local-repository"
STAGING="$WORK/staging"
BUILD_LOG="$WORK/build.log"
OUTPUT="$JC_REPO_ROOT/target/central-publishing"
BUNDLE="$OUTPUT/central-bundle.zip"
MANIFEST="$OUTPUT/central-bundle.manifest.txt"
[ "$JC_DRY_RUN" = true ] && MANIFEST="$WORK/central-bundle.manifest.dry-run.txt"

if [ "$JC_DRY_RUN" = true ]; then
  jc_say "DRY RUN: nothing is signed, installed or bundled."
fi

# --- 1. preconditions -------------------------------------------------------
jc_say "Preconditions for $JC_GROUP_ID $VERSION"
if [ -n "$REQUESTED_VERSION" ] && [ "$REQUESTED_VERSION" != "$VERSION" ]; then
  jc_fail "requested version $REQUESTED_VERSION, but pom.xml is at $VERSION"
fi
jc_check_release_version "$VERSION"
if jc_reactor check-bom >/dev/null 2>&1; then
  jc_pass "jCustos-bom matches the reactor"
else
  jc_fail "jCustos-bom does not match the reactor (scripts/lib/reactor.py check-bom)"
fi
jc_check_clean_tree
jc_check_head_is_tag "$TAG"
jc_check_trust_anchor
jc_check_tag_signature "$TAG"
jc_check_no_open_decisions
WRAPPER_SUM=$(sed -n 's/^distributionSha256Sum=//p' "$JC_REPO_ROOT/.mvn/wrapper/maven-wrapper.properties" | tr -d '[:space:]')
if [ -n "$WRAPPER_SUM" ]; then
  jc_pass "Maven wrapper pins its distribution (sha256 $WRAPPER_SUM)"
else
  jc_fail "the Maven wrapper has no distributionSha256Sum"
fi

BOUND_TO_TAG=false
if jc_tree_is_clean && [ "$(jc_git rev-parse -q --verify "refs/tags/$TAG^{commit}" 2>/dev/null || true)" = "$(jc_head_commit)" ]; then
  BOUND_TO_TAG=true
fi

# --- 2. clean export and build ---------------------------------------------
rm -rf "$WORK"
mkdir -p "$SOURCE" "$LOCAL_REPOSITORY" "$STAGING"

if [ "$BOUND_TO_TAG" = true ]; then
  SOURCE_DESCRIPTION="git archive of tag $TAG"
  jc_git archive --format=tar "$TAG" | tar -x -C "$SOURCE"
else
  # Reached in a dry run only: a real run has stopped at the checks above.
  SOURCE_DESCRIPTION="WORKING TREE at $(jc_head_commit), not a clean checkout of tag $TAG (not releasable)"
  (cd "$JC_REPO_ROOT" && git ls-files -co --exclude-standard -z) |
    python3 -c '
import os, shutil, sys
source, target = sys.argv[1:3]
for name in sys.stdin.buffer.read().split(b"\0"):
    name = name.decode()
    path = os.path.join(source, name)
    if name and os.path.isfile(path):
        destination = os.path.join(target, name)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        shutil.copy2(path, destination)
' "$JC_REPO_ROOT" "$SOURCE"
fi
jc_say ""
jc_say "Source:           $SOURCE_DESCRIPTION"
jc_say "Build directory:  $SOURCE"
jc_say "Local repository: $LOCAL_REPOSITORY (empty)"

MAVEN=(./mvnw -B -V -C "-Dmaven.repo.local=$LOCAL_REPOSITORY" -pl "$(jc_demo_exclusions)")
[ "$SKIP_TESTS" = true ] && MAVEN+=(-DskipTests)
if [ "$JC_DRY_RUN" = true ]; then
  MAVEN+=(-P "_release_prepare,_java" clean verify)
else
  MAVEN+=(-P "_release_prepare,_release_sign-artifacts,_java,?gpg" "-Dgpg.keyname=$JCUSTOS_RELEASE_KEY_FINGERPRINT" clean install)
fi
MAVEN+=(${MAVEN_EXTRA[@]+"${MAVEN_EXTRA[@]}"})

jc_say "Build:            ${MAVEN[*]}"
jc_say "Build log:        $BUILD_LOG"
BUILD_STARTED=$(date +%s)
if (cd "$SOURCE" && "${MAVEN[@]}") >"$BUILD_LOG" 2>&1; then
  jc_pass "build succeeded in $(($(date +%s) - BUILD_STARTED)) s"
else
  grep -E '^\[ERROR\]' "$BUILD_LOG" | head -20 || true
  jc_fail "the build failed; see $BUILD_LOG"
  jc_say ""
  jc_say "Dry run stopped after the build: $JC_CHECK_FAILURES check(s) failed."
  exit 1
fi
if grep -q "requires online mode" "$BUILD_LOG"; then
  jc_fail "Maven ran offline and skipped the SBOM; a release build has to run online"
fi

# --- 3. collect, verify, checksum ------------------------------------------
jc_say ""
jc_say "Artefacts"
MODULES="$JC_PARENT_ARTIFACT
$(jc_reactor libraries)"
MODULE_COUNT=0
FILE_COUNT=0
LISTING="$WORK/files.txt"
: >"$LISTING"

for module in $MODULES; do
  MODULE_COUNT=$((MODULE_COUNT + 1))
  destination="$STAGING/$JC_GROUP_PATH/$module/$VERSION"
  mkdir -p "$destination"

  if [ "$JC_DRY_RUN" = true ]; then
    files=$(jc_planned_files "$SOURCE" "$module" "$VERSION")
    for name in $files; do
      cp "$(jc_planned_path "$SOURCE" "$module" "$VERSION" "$name")" "$destination/$name"
    done
  else
    repository_directory="$LOCAL_REPOSITORY/$JC_GROUP_PATH/$module/$VERSION"
    [ -d "$repository_directory" ] || jc_die "$module: $repository_directory does not exist; the build did not install the module"
    files=""
    for path in "$repository_directory"/*; do
      name=$(basename "$path")
      if jc_is_published_file "$name"; then
        files="$files$name
"
        cp "$path" "$destination/$name"
        if [ -f "$path.asc" ]; then
          cp "$path.asc" "$destination/$name.asc"
        else
          jc_fail "$module: $name has no signature"
        fi
      fi
    done
  fi

  jc_check_module_files "$module" "$VERSION" "$files"
  jc_check_javadoc_size "$module" "$destination/$module-$VERSION-javadoc.jar"
  jc_check_sbom_file "$module" "$VERSION" "$destination/$module-$VERSION-cyclonedx.json"

  for name in $files; do
    file="$destination/$name"
    FILE_COUNT=$((FILE_COUNT + 1))
    if [ "$JC_DRY_RUN" = true ]; then
      printf '  would sign and bundle  %-70s %9s bytes\n' "$module/$VERSION/$name" "$(jc_file_size "$file")"
    else
      if ! jc_signature_is_pinned "$file.asc" "$file"; then
        jc_fail "$module: the signature of $name does not verify against the pinned release key"
      fi
      jc_write_checksums "$file.asc"
    fi
    jc_write_checksums "$file"
    jc_verify_checksums "$file" || jc_fail "$module: checksum of $name does not match after staging"
    printf '%s  %s\n' "$(jc_sha256 "$file")" "$JC_GROUP_PATH/$module/$VERSION/$name" >>"$LISTING"
    if [ -f "$file.asc" ]; then
      printf '%s  %s\n' "$(jc_sha256 "$file.asc")" "$JC_GROUP_PATH/$module/$VERSION/$name.asc" >>"$LISTING"
    fi
  done
  [ "$JC_DRY_RUN" = true ] || jc_say "  staged $module ($(printf '%s\n' "$files" | grep -c .) files, signatures verified)"
done

# --- 4. bundle and manifest --------------------------------------------------
mkdir -p "$OUTPUT"
BUNDLE_SUM="not written (dry run)"
if [ "$JC_DRY_RUN" != true ]; then
  rm -f "$BUNDLE"
  (cd "$STAGING" && zip -qr "$BUNDLE" .)
  unzip -tq "$BUNDLE" >/dev/null || jc_die "the bundle does not pass unzip -t"
  staged=$(find "$STAGING" -type f | wc -l | tr -d ' ')
  zipped=$(unzip -Z1 "$BUNDLE" | grep -vc '/$')
  [ "$staged" = "$zipped" ] || jc_die "the bundle holds $zipped files, the staging directory $staged"
  BUNDLE_SUM=$(jc_sha256 "$BUNDLE")
fi

{
  if [ "$JC_DRY_RUN" = true ]; then
    printf 'DRY RUN - this manifest describes no bundle\n'
  fi
  printf 'jCustos community edition - Central bundle manifest\n'
  printf 'version:            %s\n' "$VERSION"
  printf 'tag:                %s\n' "$TAG"
  printf 'tag object:         %s\n' "$(jc_git rev-parse -q --verify "refs/tags/$TAG" 2>/dev/null || printf 'none')"
  printf 'commit:             %s\n' "$(jc_head_commit)"
  printf 'source:             %s\n' "$SOURCE_DESCRIPTION"
  printf 'release key:        %s\n' "${JCUSTOS_RELEASE_KEY_FINGERPRINT:-not configured}"
  printf 'output timestamp:   %s\n' "$(jc_reactor timestamp)"
  printf 'built (UTC):        %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'java:               %s\n' "$(java -version 2>&1 | head -1)"
  printf 'maven:              %s\n' "$(grep -m1 -E '^Apache Maven ' "$BUILD_LOG" || (cd "$SOURCE" && ./mvnw -v 2>/dev/null | grep -m1 -E '^Apache Maven '))"
  printf 'maven distribution: sha256 %s\n' "${WRAPPER_SUM:-not pinned}"
  printf 'tests:              %s\n' "$([ "$SKIP_TESTS" = true ] && printf 'skipped' || printf 'run')"
  printf 'modules:            %s\n' "$MODULE_COUNT"
  printf 'files:              %s (plus signatures and four checksum files each)\n' "$FILE_COUNT"
  printf 'bundle sha256:      %s\n' "$BUNDLE_SUM"
  printf '\nsha256  path\n'
  cat "$LISTING"
} >"$MANIFEST"

jc_say ""
if [ "$JC_DRY_RUN" = true ]; then
  sed -n '1,/^sha256  path$/p' "$MANIFEST"
  jc_say "(file list: $MANIFEST)"
  jc_say ""
  jc_say "Dry run finished: $MODULE_COUNT modules, $FILE_COUNT files would be signed and bundled, $JC_CHECK_FAILURES check(s) failed."
  [ "$JC_CHECK_FAILURES" -eq 0 ] || exit 1
  exit 0
fi

ls -lh "$BUNDLE"
cat <<EOF

Bundle ready:  $BUNDLE
Manifest:      $MANIFEST
Staged $FILE_COUNT files of $MODULE_COUNT modules from tag $TAG ($(jc_head_commit)),
every signature verified against $JCUSTOS_RELEASE_KEY_FINGERPRINT.

Keep the manifest with the release; it is the record of what was uploaded.

Next steps:
  1. Open https://central.sonatype.com/publishing
  2. Click 'Publish Component' / 'Upload a bundle'
  3. Upload the bundle above
  4. Wait for validation, then publish

  Alternative (curl, user-managed deployment):
    curl --request POST \\
      --user "\$CENTRAL_USER:\$CENTRAL_PASSWORD" \\
      --form bundle=@$BUNDLE \\
      'https://central.sonatype.com/api/v1/publisher/upload?name=jCustos-V${VERSION}&publishingType=USER_MANAGED'
EOF
