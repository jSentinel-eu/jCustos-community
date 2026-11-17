# shellcheck shell=bash
#
# Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
#
# Licensed under the EUPL, Version 1.2 or - as soon they will be
# approved by the European Commission - subsequent versions of the
# EUPL (the "Licence"); You may not use this work except in
# compliance with the Licence. You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Shared by deploy-jsentinel.sh, clean-bundle-for-central.sh,
# build-relocation-bundle.sh and gate.sh. Sourced, never executed.
# Written for bash 3.2 (the bash of macOS): no mapfile, no associative arrays.

JC_REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
JC_GROUP_ID="eu.jsentinel"
JC_GROUP_PATH="eu/jsentinel"
JC_PARENT_ARTIFACT="jCustos-community-parent"
JC_BOM_ARTIFACT="jCustos-bom"
JC_RELEASES_URL="https://repo.jsentinel.eu/releases"
JC_SNAPSHOTS_URL="https://repo.jsentinel.eu/snapshots"

# ---------------------------------------------------------------------------
# Trust anchor for release signatures (security analysis 2026-11-10, SA42).
#
# The OpenPGP fingerprint of the key that signs jCustos releases: 40 hex
# digits, no spaces. The scripts sign with exactly this key (-Dgpg.keyname,
# gpg --local-user), refuse a release tag that is not signed with it, and
# refuse to bundle or to accept an upload whose signatures come from another
# key. Consumers compare against the same value; it is published in
# docs/security/release-verification.md and SECURITY.md.
#
# The key that signed 00.81.10 to 00.83.00 on Maven Central, pinned for
# 00.84.00 (decision SA42-D1, 2026-11-17); a dedicated release key follows in
# 00.85.00 and replaces this value then.
JC_DEFAULT_RELEASE_KEY_FINGERPRINT="4CCCE751C38AD66AB1DC94D044A7EECD37010CF3"
# ---------------------------------------------------------------------------
JCUSTOS_RELEASE_KEY_FINGERPRINT="${JCUSTOS_RELEASE_KEY_FINGERPRINT:-$JC_DEFAULT_RELEASE_KEY_FINGERPRINT}"
JCUSTOS_RELEASE_KEY_FINGERPRINT=$(printf '%s' "$JCUSTOS_RELEASE_KEY_FINGERPRINT" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')

# In a dry run a failed check is recorded and the run goes on, so that one
# pass shows everything that stands between the working copy and a release.
# In a real run the first failed check ends the script.
JC_DRY_RUN=false
JC_CHECK_FAILURES=0

jc_say() { printf '%s\n' "$*"; }
jc_warn() { printf 'WARNING: %s\n' "$*" >&2; }
jc_die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}
jc_pass() { printf '  [ok]   %s\n' "$*"; }
jc_fail() {
  printf '  [FAIL] %s\n' "$*"
  JC_CHECK_FAILURES=$((JC_CHECK_FAILURES + 1))
  if [ "$JC_DRY_RUN" != true ]; then
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
  fi
}

jc_reactor() { python3 "$JC_REPO_ROOT/scripts/lib/reactor.py" "$@"; }

jc_require_tools() {
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || jc_die "required tool not found: $tool"
  done
}

# Maven -pl argument that removes the demo modules from the reactor. Selecting
# the libraries by name does not work for the root project: Maven 4 expands an
# aggregator to all of its modules, demos included.
jc_demo_exclusions() {
  jc_reactor demos | sed 's/^/!/' | paste -sd, -
}

jc_sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

jc_file_size() { stat -f%z "$1" 2>/dev/null || stat -c%s "$1"; }

jc_write_checksums() {
  local file="$1"
  if command -v md5sum >/dev/null 2>&1; then
    md5sum "$file" | awk '{print $1}' >"$file.md5"
  else
    md5 -q "$file" >"$file.md5"
  fi
  shasum -a 1 "$file" | awk '{print $1}' >"$file.sha1"
  shasum -a 256 "$file" | awk '{print $1}' >"$file.sha256"
  shasum -a 512 "$file" | awk '{print $1}' >"$file.sha512"
}

# Reads the checksum files back and compares them with the file as it lies in
# the staging directory now. Returns 1 on the first mismatch.
jc_verify_checksums() {
  local file="$1" algorithm expected actual
  for algorithm in 1 256 512; do
    [ -f "$file.sha$algorithm" ] || return 1
    expected=$(cat "$file.sha$algorithm")
    actual=$(shasum -a "$algorithm" "$file" | awk '{print $1}')
    [ "$expected" = "$actual" ] || return 1
  done
  [ -f "$file.md5" ] || return 1
  return 0
}

# --- git state --------------------------------------------------------------

jc_git() { git -C "$JC_REPO_ROOT" "$@"; }

jc_head_commit() { jc_git rev-parse HEAD; }

jc_tree_is_clean() {
  [ -z "$(jc_git status --porcelain --untracked-files=normal)" ]
}

jc_check_release_version() {
  local version="$1"
  case "$version" in
  *-SNAPSHOT) jc_fail "version $version is a snapshot; a release needs a release version in every POM" ;;
  '') jc_fail "the root POM has no version" ;;
  *) jc_pass "version $version is a release version" ;;
  esac
}

jc_check_clean_tree() {
  if jc_tree_is_clean; then
    jc_pass "working tree is clean (no modified, staged or untracked files)"
  else
    jc_fail "working tree is not clean: $(jc_git status --porcelain --untracked-files=normal | wc -l | tr -d ' ') path(s) differ from HEAD"
  fi
}

jc_check_head_is_tag() {
  local tag="$1" tag_commit head
  head=$(jc_head_commit)
  tag_commit=$(jc_git rev-parse -q --verify "refs/tags/$tag^{commit}" 2>/dev/null || true)
  if [ -z "$tag_commit" ]; then
    jc_fail "tag $tag does not exist"
  elif [ "$tag_commit" != "$head" ]; then
    jc_fail "HEAD ($head) is not the commit of tag $tag ($tag_commit)"
  else
    jc_pass "HEAD is the commit of tag $tag ($head)"
  fi
}

jc_check_trust_anchor() {
  case "$JCUSTOS_RELEASE_KEY_FINGERPRINT" in
  '')
    jc_fail "no trust anchor: the fingerprint of the release signing key is not configured (scripts/lib/release-common.sh or JCUSTOS_RELEASE_KEY_FINGERPRINT)"
    ;;
  *[!0-9A-F]*)
    jc_fail "the configured release key fingerprint contains characters that are not hex digits"
    ;;
  *)
    if [ "${#JCUSTOS_RELEASE_KEY_FINGERPRINT}" -eq 40 ] || [ "${#JCUSTOS_RELEASE_KEY_FINGERPRINT}" -eq 64 ]; then
      jc_pass "release signing key pinned: $JCUSTOS_RELEASE_KEY_FINGERPRINT"
    else
      jc_fail "the configured release key fingerprint has ${#JCUSTOS_RELEASE_KEY_FINGERPRINT} digits; expected 40 (or 64 for a v5 key)"
    fi
    ;;
  esac
}

# Prints the fingerprints gpg reports for a good signature: the key that made
# it and, last, its primary key. Prints nothing when the signature is bad, the
# key is unknown, expired or revoked, or the status output is missing: GnuPG
# emits VALIDSIG for every cryptographically valid signature, but GOODSIG only
# when the key is neither expired nor revoked (EXPKEYSIG, REVKEYSIG otherwise).
jc_validsig_fingerprints() {
  awk '
    $1 == "[GNUPG:]" && $2 == "GOODSIG" { good = 1 }
    $1 == "[GNUPG:]" && $2 == "VALIDSIG" { signer = $3; primary = $NF }
    END { if (good && signer != "") { print signer; print primary } }
  '
}

jc_fingerprint_matches() {
  local fingerprints="$1"
  [ -n "$JCUSTOS_RELEASE_KEY_FINGERPRINT" ] || return 1
  printf '%s\n' "$fingerprints" | grep -qx "$JCUSTOS_RELEASE_KEY_FINGERPRINT"
}

# 0 when <signature> is a good signature over <file> made with the pinned key.
jc_signature_is_pinned() {
  local signature="$1" file="$2" fingerprints
  fingerprints=$(gpg --batch --status-fd 1 --verify "$signature" "$file" 2>/dev/null | jc_validsig_fingerprints || true)
  jc_fingerprint_matches "$fingerprints"
}

jc_check_tag_signature() {
  local tag="$1" fingerprints
  if [ "$(jc_git cat-file -t "refs/tags/$tag" 2>/dev/null || true)" != "tag" ]; then
    jc_fail "tag $tag is not an annotated tag, so it cannot carry a signature"
    return 0
  fi
  fingerprints=$(jc_git verify-tag --raw "$tag" 2>&1 | jc_validsig_fingerprints || true)
  if [ -z "$fingerprints" ]; then
    jc_fail "tag $tag carries no valid signature (create release tags with git tag -s)"
  elif jc_fingerprint_matches "$fingerprints"; then
    jc_pass "tag $tag is signed with the pinned release key"
  else
    jc_fail "tag $tag is signed, but not with the pinned release key (signed by $(printf '%s' "$fingerprints" | tail -1))"
  fi
}

# Places in the published policy documents that still wait for a decision of
# the maintainer, as "file:line: text". The marker is spelt out in the legend of
# SECURITY.md as well; the legend is followed by an ellipsis and does not count.
jc_open_decisions() {
  (cd "$JC_REPO_ROOT" && grep -n -E '<<TO BE DECIDED BY THE MAINTAINER: [A-Za-z]' \
    SECURITY.md docs/security/release-verification.md 2>/dev/null) || true
}

jc_check_no_open_decisions() {
  local open
  open=$(jc_open_decisions | wc -l | tr -d ' ')
  if [ "$open" = 0 ]; then
    jc_pass "SECURITY.md and the release verification page have no open decision"
  else
    jc_fail "$open decision(s) of the maintainer are still open in SECURITY.md / docs/security/release-verification.md (<<TO BE DECIDED BY THE MAINTAINER: ...>>)"
  fi
}

# --- what is published --------------------------------------------------------

# 0 for a file of a module's repository directory that belongs in a release:
# the consumer POM, the jar with sources and Javadoc, and the SBOM. Maven 4's
# build POM, the test jar and the test sources stay behind.
jc_is_published_file() {
  case "$1" in
  *-build.pom | *-tests.jar | *-test-sources.jar) return 1 ;;
  *.pom | *.jar | *-cyclonedx.json | *-cyclonedx.xml) return 0 ;;
  *) return 1 ;;
  esac
}

# Lists, one name per line, what a module would publish, read from the
# project-local repository Maven 4 fills below the root target directory during
# package or verify. Used by the dry runs, which neither install nor deploy.
# There the consumer POM carries the classifier "consumer" and the plain .pom is
# the build POM; in a real repository the names are <a>-<v>.pom and
# <a>-<v>-build.pom. The BOM has no parent and is not copied there: its POM is
# published as it stands.
jc_planned_files() {
  local source_root="$1" module="$2" version="$3" directory name
  if [ "$module" = "$JC_BOM_ARTIFACT" ]; then
    [ -f "$source_root/$module/pom.xml" ] && printf '%s\n' "$module-$version.pom"
    return 0
  fi
  directory="$source_root/target/project-local-repo/$JC_GROUP_ID/$module/$version"
  [ -d "$directory" ] || return 0
  for name in "$directory"/*; do
    name=$(basename "$name")
    case "$name" in
    "$module-$version-consumer.pom") printf '%s\n' "$module-$version.pom" ;;
    "$module-$version.pom") ;;
    *) if jc_is_published_file "$name"; then printf '%s\n' "$name"; fi ;;
    esac
  done
}

# Path of a planned file inside the source tree of a dry run.
jc_planned_path() {
  local source_root="$1" module="$2" version="$3" name="$4"
  if [ "$module" = "$JC_BOM_ARTIFACT" ]; then
    printf '%s\n' "$source_root/$module/pom.xml"
    return 0
  fi
  case "$name" in
  "$module-$version.pom") name="$module-$version-consumer.pom" ;;
  esac
  printf '%s\n' "$source_root/target/project-local-repo/$JC_GROUP_ID/$module/$version/$name"
}

# The acceptance checks every release artefact set has to pass, whatever the
# directory layout it is read from. $1 module, $2 version, $3 newline-separated
# list of file names. Jar modules need sources, Javadoc and an SBOM; the parent
# carries the aggregate SBOM; the BOM is a POM and nothing else.
jc_check_module_files() {
  local module="$1" version="$2" files="$3" base="$1-$2" required
  if ! printf '%s\n' "$files" | grep -qx "$base.pom"; then
    jc_fail "$module: no POM ($base.pom)"
  fi
  if printf '%s\n' "$files" | grep -qx "$base.jar"; then
    for required in "$base-sources.jar" "$base-javadoc.jar" "$base-cyclonedx.json" "$base-cyclonedx.xml"; do
      printf '%s\n' "$files" | grep -qx "$required" || jc_fail "$module: $required is missing"
    done
  elif [ "$module" = "$JC_PARENT_ARTIFACT" ]; then
    for required in "$base-cyclonedx.json" "$base-cyclonedx.xml"; do
      printf '%s\n' "$files" | grep -qx "$required" || jc_fail "$module: aggregate SBOM $required is missing"
    done
  elif [ "$module" != "$JC_BOM_ARTIFACT" ]; then
    jc_fail "$module: no jar ($base.jar)"
  fi
  return 0
}

# Minimum size of a -javadoc.jar. An empty one (manifest only) has about 300
# bytes, the smallest real one about 111 KB. 00.74.10 shipped empty Javadoc
# jars to Maven Central because the javadoc tool had aborted and failOnError is
# false; Central is immutable, so this is checked before anything is uploaded.
JC_JAVADOC_MIN_BYTES=51200

jc_check_javadoc_size() {
  local module="$1" file="$2" size
  [ -f "$file" ] || return 0
  size=$(jc_file_size "$file")
  if [ "$size" -lt "$JC_JAVADOC_MIN_BYTES" ]; then
    jc_fail "$module: $(basename "$file") has only $size bytes (below $JC_JAVADOC_MIN_BYTES), almost certainly empty"
  fi
  return 0
}

# 0 when the file is a CycloneDX document that names the expected component.
jc_check_sbom_file() {
  local module="$1" version="$2" file="$3"
  [ -f "$file" ] || return 0
  if ! python3 - "$file" "$module" "$version" <<'PY'; then
import json, sys
path, module, version = sys.argv[1:4]
try:
    with open(path, encoding="utf-8") as handle:
        bom = json.load(handle)
    component = bom["metadata"]["component"]
    ok = (bom.get("bomFormat") == "CycloneDX"
          and component.get("name") == module
          and component.get("version") == version)
except (OSError, ValueError, KeyError):
    ok = False
sys.exit(0 if ok else 1)
PY
    jc_fail "$module: $(basename "$file") is not a CycloneDX SBOM for $module $version"
  fi
  return 0
}
