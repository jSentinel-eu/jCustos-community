#!/usr/bin/env bash
#
# Builds the ONE-TIME relocation bundle for the V00.81.10 jCustos rebrand
# (gate decision 4): 47 pom-only artifacts under the OLD coordinates
# com.svenruppert.jsentinel:jSentinel-*:<version> whose
# <distributionManagement><relocation> points to the new GAV
# eu.jsentinel:jCustos-*:<version>. Maven resolves the relocation from the
# POM before fetching any jar, so pom packaging satisfies both Maven and
# Central validation (no jar/sources/javadoc needed).
#
# Usage:
#   ./scripts/build-relocation-bundle.sh [--dry-run] 00.81.10
#
# Produces target/central-publishing/relocation-bundle.zip — upload it to
# Central as a second deployment AFTER the main jCustos bundle validated.
#
# The POMs are generated here, so nothing is read from ~/.m2 and there is no
# build to bind to a commit. What this script shares with the release scripts
# is the question of which key signs (security analysis 2026-11-10, SA42): it
# signs with the pinned release key of scripts/lib/release-common.sh and
# verifies every signature against it, instead of using whatever key gpg
# considers the default. --dry-run generates the POMs and their checksums and
# lists what would be signed, without signing and without writing a bundle.
set -euo pipefail

# shellcheck source=scripts/lib/release-common.sh
. "$(cd "$(dirname "$0")" && pwd)/lib/release-common.sh"

if [ "${1:-}" = "--dry-run" ]; then
    JC_DRY_RUN=true
    shift
fi
REPO_ROOT="$JC_REPO_ROOT"
VERSION="${1:?usage: build-relocation-bundle.sh [--dry-run] <version>}"
jc_check_trust_anchor
OLD_GROUP="com.svenruppert.jsentinel"
OLD_GROUP_PATH="com/svenruppert/jsentinel"
NEW_GROUP="eu.jsentinel"

# old artifactId -> derived new artifactId (jSentinel- -> jCustos-)
OLD_MODULES=(
    "jSentinel-parent" "jSentinel-core" "jSentinel-test" "jSentinel-vaadin"
    "jSentinel-rest" "jSentinel-standalone" "jSentinel-processor"
    "jSentinel-persistence-testkit" "jSentinel-persistence-eclipsestore"
    "jSentinel-crypto-bc" "jSentinel-credentials-hibp" "jSentinel-dx"
    "jSentinel-dx-vaadin" "jSentinel-dx-rest" "jSentinel-dx-standalone"
    "jSentinel-autoservice-annotations" "jSentinel-autoservice-processor"
    "jSentinel-vaadin-starter" "jSentinel-propagation"
    "jSentinel-propagation-processor" "jSentinel-propagation-oidc"
    "jSentinel-events" "jSentinel-events-rest" "jSentinel-events-testkit"
    "jSentinel-events-persistence-eclipsestore" "jSentinel-monitoring"
    "jSentinel-events-webhook" "jSentinel-events-opentelemetry"
    "jSentinel-events-siem" "jSentinel-audit-integrity"
    "jSentinel-audit-integrity-testkit"
    "jSentinel-audit-integrity-persistence-eclipsestore" "jSentinel-jwt"
    "jSentinel-oauth2" "jSentinel-oauth2-vaadin" "jSentinel-oauth2-rest"
    "jSentinel-identity-oidc" "jSentinel-identity-oidc-vaadin"
    "jSentinel-identity-oidc-rest" "jSentinel-test-oidc"
    "jSentinel-identity-vendor-keycloak" "jSentinel-identity-vendor-entra"
    "jSentinel-identity-vendor-auth0" "jSentinel-identity-vendor-okta"
    "jSentinel-identity-vendor-google" "jSentinel-identity-vendor-github"
    "jSentinel-dpop"
)

STAGING="$REPO_ROOT/target/relocation-staging"
BUNDLE_DIR="$REPO_ROOT/target/central-publishing"
BUNDLE="$BUNDLE_DIR/relocation-bundle.zip"
rm -rf "$STAGING"
mkdir -p "$STAGING" "$BUNDLE_DIR"

checksums() {
    local file="$1"
    if command -v md5sum >/dev/null 2>&1; then
        md5sum "$file" | awk '{print $1}' > "$file.md5"
    else
        md5 -q "$file" > "$file.md5"
    fi
    shasum -a 1   "$file" | awk '{print $1}' > "$file.sha1"
    shasum -a 256 "$file" | awk '{print $1}' > "$file.sha256"
    shasum -a 512 "$file" | awk '{print $1}' > "$file.sha512"
}

total=0
for old in "${OLD_MODULES[@]}"; do
    new="${old/jSentinel-/jCustos-}"
    dst="$STAGING/$OLD_GROUP_PATH/$old/$VERSION"
    mkdir -p "$dst"
    pom="$dst/$old-$VERSION.pom"
    cat > "$pom" <<POM
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>$OLD_GROUP</groupId>
  <artifactId>$old</artifactId>
  <version>$VERSION</version>
  <packaging>pom</packaging>
  <name>$old (relocated)</name>
  <description>jSentinel was rebranded to jCustos in V00.81.10. This artifact moved to $NEW_GROUP:$new. Update your dependency coordinates; packages moved from com.svenruppert.jsentinel to eu.jsentinel.jcustos.</description>
  <url>https://jsentinel.eu</url>
  <licenses>
    <license>
      <name>European Union Public License 1.2</name>
      <url>https://joinup.ec.europa.eu/software/page/eupl</url>
    </license>
  </licenses>
  <developers>
    <developer>
      <name>Sven Ruppert</name>
      <email>sven.ruppert@gmail.com</email>
    </developer>
  </developers>
  <scm>
    <url>https://github.com/jSentinel-eu/jCustos-community</url>
  </scm>
  <distributionManagement>
    <relocation>
      <groupId>$NEW_GROUP</groupId>
      <artifactId>$new</artifactId>
      <version>$VERSION</version>
      <message>jSentinel was rebranded to jCustos (V00.81.10): use $NEW_GROUP:$new. Packages moved to eu.jsentinel.jcustos; see the jcustos-migration guide.</message>
    </relocation>
  </distributionManagement>
</project>
POM
    checksums "$pom"
    total=$((total+1))
    if [ "$JC_DRY_RUN" = true ]; then
        echo "  would sign and bundle  $OLD_GROUP_PATH/$old/$VERSION/$old-$VERSION.pom"
        continue
    fi
    gpg --batch --yes --armor --local-user "$JCUSTOS_RELEASE_KEY_FINGERPRINT" --detach-sign "$pom"
    jc_signature_is_pinned "$pom.asc" "$pom" \
        || jc_die "the signature of $old-$VERSION.pom does not verify against the pinned release key"
    checksums "$pom.asc"
done

if [ "$JC_DRY_RUN" = true ]; then
    echo "Dry run finished: $total relocation POMs generated under $STAGING, nothing signed, no bundle written, $JC_CHECK_FAILURES check(s) failed."
    [ "$JC_CHECK_FAILURES" -eq 0 ] || exit 1
    exit 0
fi

( cd "$STAGING" && zip -q -r "$BUNDLE" com )
echo "Relocation bundle ready: $BUNDLE ($total relocation POMs, signed with $JCUSTOS_RELEASE_KEY_FINGERPRINT and checksummed)."
