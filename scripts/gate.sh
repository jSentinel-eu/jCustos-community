#!/usr/bin/env bash
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
# The verification gate of the community edition: one command that runs what a
# commit has to pass before it is released (security analysis 2026-11-10,
# SA44). It needs no credentials and changes nothing outside target
# directories and its own log directory. .forgejo/workflows/verify.yml runs the
# same script; until that workflow is a required check, this script, run by the
# maintainer, is the binding gate.
#
# Stages, in this order; all of them run even if an earlier one fails:
#
#   preflight        shell and Python syntax of scripts/, the Maven wrapper pins
#                    its download, SECURITY.md has its sections, no tracked file
#                    is covered by .gitignore. Reports WARN while decisions
#                    of the maintainer are still open in the published
#                    documents (contact address, release key and so on)
#   definitions      the rules consolidated in 00.84.00 (ER31) have one
#                    definition each in the library sources: the https and
#                    loopback rule, the dev flag, the JOSE segment counter and
#                    the JSON reader (scripts/single-definitions.py)
#   bom              jCustos-bom has the reactor's version and output timestamp
#                    and manages exactly the publishable modules (the BOM has no
#                    parent, so Maven itself does not tie it to the reactor)
#   build            clean reactor build with all tests (mvnw clean verify)
#   enforcer         the rules against vulnerable Jackson versions, foreign
#                    repositories, unversioned plugins and mocking frameworks
#                    ran in every module that inherits them
#   sources          the build left every tracked file as it was (nine modules
#                    still run license:update-file-header, which rewrites
#                    sources instead of checking them)
#   frontend         informative: whether a demo ran npm, and whether a lockfile
#                    is committed for it (the demos are not released; the
#                    release scripts leave them out)
#   sbom             a CycloneDX SBOM per library module and the aggregate
#   advisories       every third-party component of those SBOMs against OSV
#   licence-headers  informative: Java sources without the EUPL header
#   reproducibility  optional, slow: two builds in two directories give the
#                    same jars
#
# Usage:
#   scripts/gate.sh [--offline] [--with-reproducibility]
#
#   --offline               Maven runs with -o and nothing asks the network.
#                           The CycloneDX plugin and the OSV scan need it, so
#                           sbom and advisories are reported as NOT RUN and
#                           the gate ends with exit code 2: usable while
#                           developing, not as a release gate.
#   --with-reproducibility  Adds the reproducibility stage.
#
#   JCUSTOS_GATE_DIR        Directory for the logs (default: a new temporary
#                           directory, printed at the start).
#
# Exit codes:
#   0   every required stage passed
#   1   at least one stage failed
#   2   no stage failed, but a required stage did not run (incomplete)
#   64  usage
set -uo pipefail

# shellcheck source=scripts/lib/release-common.sh
. "$(cd "$(dirname "$0")" && pwd)/lib/release-common.sh"

OFFLINE=false
REPRODUCIBILITY=false
while [ $# -gt 0 ]; do
  case "$1" in
  --offline) OFFLINE=true ;;
  --with-reproducibility) REPRODUCIBILITY=true ;;
  -h | --help)
    sed -n '/^# Usage:/,/^#   64  usage/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    sed -n '/^# Usage:/,/^#   64  usage/p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 64
    ;;
  esac
  shift
done

jc_require_tools git python3 shasum java
cd "$JC_REPO_ROOT" || exit 1

GATE_DIR="${JCUSTOS_GATE_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/jcustos-gate.XXXXXX")}"
mkdir -p "$GATE_DIR"
GATE_STARTED=$(date +%s)
VERSION=$(jc_reactor version)
LIBRARIES=$(jc_reactor libraries)
EXCEPTIONS="$JC_REPO_ROOT/scripts/osv-exceptions.txt"
SECURITY_SECTIONS="Reporting a vulnerability
What to include
What to expect
Coordinated disclosure
Scope
Supported versions
Verifying a release"

STAGE_NAMES=()
STAGE_RESULTS=()
STAGE_SECONDS=()
STAGE_DETAILS=()
STAGE_STARTED=0
DETAIL=""

begin() {
  STAGE_STARTED=$(date +%s)
  DETAIL=""
  printf '\n=== %s ===\n' "$1"
}
# record <name> <PASS|FAIL|NOT RUN|WARN|SKIPPED> <detail>
record() {
  STAGE_NAMES+=("$1")
  STAGE_RESULTS+=("$2")
  STAGE_SECONDS+=("$(($(date +%s) - STAGE_STARTED))")
  STAGE_DETAILS+=("$3")
  printf -- '--- %s: %s (%s)\n' "$1" "$2" "$3"
}

jc_say "jCustos community gate: version $VERSION, commit $(jc_head_commit)$(jc_tree_is_clean || printf ' with local changes')"
jc_say "Mode: $([ "$OFFLINE" = true ] && printf 'offline' || printf 'online'), logs in $GATE_DIR"

# --- preflight ---------------------------------------------------------------
begin preflight
problems=0
for script in scripts/*.sh scripts/lib/*.sh; do
  if ! bash -n "$script" 2>"$GATE_DIR/syntax.log"; then
    problems=$((problems + 1))
    jc_say "syntax error in $script:"
    cat "$GATE_DIR/syntax.log"
  fi
done
for script in scripts/*.py scripts/lib/*.py; do
  if ! python3 -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1])' "$script" 2>"$GATE_DIR/syntax.log"; then
    problems=$((problems + 1))
    jc_say "syntax error in $script:"
    cat "$GATE_DIR/syntax.log"
  fi
done
if [ "$(grep -c -E '^distributionSha256Sum=[0-9a-f]{64}$' .mvn/wrapper/maven-wrapper.properties)" != 1 ]; then
  problems=$((problems + 1))
  jc_say ".mvn/wrapper/maven-wrapper.properties: distributionSha256Sum is missing or malformed"
fi
if [ -f SECURITY.md ]; then
  while IFS= read -r section; do
    if ! grep -q -E "^#+ $section\$" SECURITY.md; then
      problems=$((problems + 1))
      jc_say "SECURITY.md: section '$section' is missing"
    fi
  done <<EOF
$SECURITY_SECTIONS
EOF
  open_decisions=$(jc_open_decisions | wc -l | tr -d ' ')
else
  problems=$((problems + 1))
  open_decisions=0
  jc_say "SECURITY.md is missing"
fi
ignored_but_tracked=$(git ls-files -ci --exclude-standard | wc -l | tr -d ' ')
if [ "$ignored_but_tracked" != 0 ]; then
  problems=$((problems + 1))
  jc_say "$ignored_but_tracked tracked file(s) are covered by .gitignore:"
  git ls-files -ci --exclude-standard | head -20
fi
DETAIL="scripts parse, wrapper checksum set, SECURITY.md complete in structure"
if [ "$problems" != 0 ]; then
  record preflight FAIL "$problems problem(s), see above"
elif [ "$open_decisions" != 0 ]; then
  # Not a defect of the commit, so the gate does not fail on it; the release
  # scripts do, because a release must not publish a policy with blanks.
  jc_open_decisions
  record preflight WARN "$DETAIL; $open_decisions maintainer decision(s) still open, which blocks a release"
else
  record preflight PASS "$DETAIL"
fi

# --- definitions -------------------------------------------------------------
begin definitions
# ER31 (JS-SEC-098, CWE-1041): a second copy of a security rule drifts from the first; every
# hardening has to find all of them. Source search only, no build needed.
python3 scripts/single-definitions.py | tee "$GATE_DIR/definitions.log"
if [ "${PIPESTATUS[0]}" = 0 ]; then
  record definitions PASS "$(tail -1 "$GATE_DIR/definitions.log")"
else
  record definitions FAIL "$(tail -1 "$GATE_DIR/definitions.log"); see above"
fi

# --- bom -----------------------------------------------------------------------
begin bom
if DETAIL=$(jc_reactor check-bom); then
  record bom PASS "$DETAIL"
else
  printf '%s\n' "$DETAIL"
  record bom FAIL "jCustos-bom does not match the reactor"
fi

# --- build -------------------------------------------------------------------
begin build
git status --porcelain --untracked-files=all >"$GATE_DIR/tree-before.txt"
git diff HEAD | shasum -a 256 >>"$GATE_DIR/tree-before.txt"
MAVEN=(./mvnw -B -V -fae)
if [ "$OFFLINE" = true ]; then
  MAVEN+=(-o)
else
  MAVEN+=(-Psbom)
fi
MAVEN+=(clean verify)
jc_say "${MAVEN[*]}   (log: $GATE_DIR/build.log)"
"${MAVEN[@]}" >"$GATE_DIR/build.log" 2>&1
BUILD_STATUS=$?
TESTS=$(python3 - <<'PY'
import glob
import xml.etree.ElementTree as ET
totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
modules = set()
for report in glob.glob("*/target/surefire-reports/TEST-*.xml"):
    root = ET.parse(report).getroot()
    modules.add(report.split("/", 1)[0])
    for key in totals:
        totals[key] += int(root.get(key, 0))
print(f"{totals['tests']} tests in {len(modules)} modules, {totals['failures']} failures, "
      f"{totals['errors']} errors, {totals['skipped']} skipped")
PY
)
if [ "$BUILD_STATUS" = 0 ]; then
  record build PASS "$TESTS"
else
  grep -E '^\[ERROR\]' "$GATE_DIR/build.log" | head -30
  record build FAIL "mvnw ended with $BUILD_STATUS; $TESTS"
fi

# --- enforcer ----------------------------------------------------------------
begin enforcer
# Every project of the reactor inherits the rules except the BOM, which has no
# parent: the root project plus all modules but one.
expected=$(($(printf '%s\n%s\n' "$LIBRARIES" "$(jc_reactor demos)" | grep -c .)))
problems=0
DETAIL=""
for rule in ban-vulnerable-jackson enforce-repository-hygiene ban-mocking-frameworks; do
  ran=$(grep -c -E "^\[INFO\] --- enforcer:[^ ]+:enforce \($rule\) @ " "$GATE_DIR/build.log")
  DETAIL="$DETAIL$rule $ran, "
  [ "$ran" -ge "$expected" ] || problems=$((problems + 1))
done
DETAIL="${DETAIL}expected $expected each"
if [ "$problems" = 0 ] && [ "$BUILD_STATUS" = 0 ]; then
  record enforcer PASS "$DETAIL"
elif [ "$problems" = 0 ]; then
  record enforcer FAIL "$DETAIL; the build failed, so a rule may be the reason"
else
  record enforcer FAIL "$DETAIL"
fi

# --- sources -------------------------------------------------------------------
begin sources
git status --porcelain --untracked-files=all >"$GATE_DIR/tree-after.txt"
git diff HEAD | shasum -a 256 >>"$GATE_DIR/tree-after.txt"
if cmp -s "$GATE_DIR/tree-before.txt" "$GATE_DIR/tree-after.txt"; then
  record sources PASS "the build changed no tracked file and left no untracked one"
else
  diff "$GATE_DIR/tree-before.txt" "$GATE_DIR/tree-after.txt" | head -20
  record sources FAIL "the build modified the working tree (git status before and after differ)"
fi

# --- frontend (informative) ------------------------------------------------------
begin frontend
# A Vaadin demo builds its own production bundle when src/main/bundles holds no
# current one, which is the case in every fresh checkout: npm install and Vite
# run then. Without a committed package-lock.json the transitive npm packages
# are whatever the registry serves that day.
frontend_builds=$(grep -c -E '^\[INFO\] --- vaadin:[^ ]+:build-frontend ' "$GATE_DIR/build.log")
npm_runs=$(grep -c -E 'Running `npm (install|ci)`' "$GATE_DIR/build.log")
lockfiles=$(git ls-files '*package-lock.json' | wc -l | tr -d ' ')
if [ "$npm_runs" = 0 ]; then
  record frontend PASS "$frontend_builds Vaadin frontend builds, none ran npm (production bundles under src/main/bundles were current)"
elif [ "$lockfiles" = 0 ]; then
  record frontend WARN "$npm_runs of $frontend_builds Vaadin frontend builds ran npm without a committed package-lock.json; informative, the demos are not released"
else
  record frontend PASS "$npm_runs of $frontend_builds Vaadin frontend builds ran npm; $lockfiles lockfile(s) are committed"
fi

# --- sbom ----------------------------------------------------------------------
begin sbom
SBOMS=()
if [ "$OFFLINE" = true ]; then
  record sbom "NOT RUN" "offline: the CycloneDX plugin requires online mode"
else
  problems=0
  for module in $LIBRARIES; do
    [ "$module" = "$JC_BOM_ARTIFACT" ] && continue
    sbom="$module/target/CycloneDX-SBom.json"
    if [ ! -f "$sbom" ] || [ ! -f "$module/target/CycloneDX-SBom.xml" ]; then
      problems=$((problems + 1))
      jc_say "missing: $sbom (or its .xml)"
      continue
    fi
    SBOMS+=("$sbom")
  done
  if ! python3 - "$VERSION" target/CycloneDX-SBom.json ${SBOMS[@]+"${SBOMS[@]}"} <<'PY'; then
import json
import sys
version, aggregate_path, module_paths = sys.argv[1], sys.argv[2], sys.argv[3:]
problems = []

def load(path):
    try:
        with open(path, encoding="utf-8") as handle:
            bom = json.load(handle)
    except (OSError, ValueError) as error:
        problems.append(f"{path}: {error}")
        return None
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
        problems.append(f"{path}: not a CycloneDX 1.6 document")
    return bom

modules = []
for path in module_paths:
    bom = load(path)
    if bom is None:
        continue
    component = bom.get("metadata", {}).get("component", {})
    module = path.split("/", 1)[0]
    modules.append(module)
    if component.get("name") != module or component.get("version") != version:
        problems.append(f"{path}: describes {component.get('name')} {component.get('version')}, "
                        f"expected {module} {version}")
aggregate = load(aggregate_path)
if aggregate is not None:
    listed = {c.get("name") for c in aggregate.get("components", [])
              if c.get("group") == "eu.jsentinel"}
    missing = sorted(set(modules) - listed)
    if missing:
        problems.append(f"{aggregate_path}: aggregate does not list {', '.join(missing)}")
for problem in problems:
    print(problem)
sys.exit(1 if problems else 0)
PY
    problems=$((problems + 1))
  fi
  if [ "$problems" = 0 ]; then
    record sbom PASS "${#SBOMS[@]} module SBOMs (CycloneDX 1.6, json and xml) and the aggregate in target/"
  else
    record sbom FAIL "$problems problem(s), see above"
  fi
fi

# --- advisories ----------------------------------------------------------------
begin advisories
if [ "$OFFLINE" = true ]; then
  record advisories "NOT RUN" "offline: the OSV database was not asked"
elif [ "${#SBOMS[@]}" = 0 ]; then
  record advisories "NOT RUN" "no SBOM to scan"
else
  python3 scripts/osv-scan.py --exceptions "$EXCEPTIONS" "${SBOMS[@]}" | tee "$GATE_DIR/osv.log"
  case "${PIPESTATUS[0]}" in
  0) record advisories PASS "$(tail -1 "$GATE_DIR/osv.log")" ;;
  1) record advisories FAIL "$(tail -1 "$GATE_DIR/osv.log")" ;;
  *) record advisories "NOT RUN" "$(tail -1 "$GATE_DIR/osv.log")" ;;
  esac
fi

# --- licence headers (informative) ---------------------------------------------
begin licence-headers
without=$(git ls-files -z '*.java' | xargs -0 grep -L 'Licensed under the EUPL' | wc -l | tr -d ' ')
total=$(git ls-files '*.java' | wc -l | tr -d ' ')
if [ "$without" = 0 ]; then
  record licence-headers PASS "all $total tracked Java files carry the EUPL header"
else
  record licence-headers WARN "$without of $total tracked Java files carry no EUPL header; informative, the build has no header check"
fi

# --- reproducibility (optional) --------------------------------------------------
begin reproducibility
if [ "$REPRODUCIBILITY" != true ]; then
  record reproducibility SKIPPED "not requested (--with-reproducibility)"
else
  REPRO="$GATE_DIR/reproducibility"
  rm -rf "$REPRO"
  status=0
  for copy in first second; do
    mkdir -p "$REPRO/$copy"
    git ls-files -co --exclude-standard -z | python3 -c '
import os, shutil, sys
target = sys.argv[1]
for name in sys.stdin.buffer.read().split(b"\0"):
    name = name.decode()
    if name and os.path.isfile(name):
        destination = os.path.join(target, name)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        shutil.copy2(name, destination)
' "$REPRO/$copy"
    REBUILD=(./mvnw -B -DskipTests -pl "$(jc_demo_exclusions)")
    if [ "$OFFLINE" = true ]; then
      REBUILD+=(-o)
    else
      REBUILD+=(-Psbom)
    fi
    REBUILD+=(clean package)
    jc_say "build $copy: ${REBUILD[*]}   (log: $REPRO/$copy.log)"
    (cd "$REPRO/$copy" && "${REBUILD[@]}") >"$REPRO/$copy.log" 2>&1 || status=1
  done
  for copy in first second; do
    (cd "$REPRO/$copy" && find . -path '*/target/*' \( -name '*.jar' -o -name 'CycloneDX-SBom.*' \) -not -path '*/project-local-repo/*' -type f -exec shasum -a 256 {} + | sort -k 2) >"$REPRO/$copy.sha256"
  done
  compared=$(wc -l <"$REPRO/first.sha256" | tr -d ' ')
  if [ "$status" != 0 ]; then
    record reproducibility FAIL "a rebuild failed, see $REPRO/first.log and second.log"
  elif [ "$compared" = 0 ]; then
    record reproducibility FAIL "the rebuilds produced no artefact to compare"
  elif cmp -s "$REPRO/first.sha256" "$REPRO/second.sha256"; then
    record reproducibility PASS "$compared artefacts (jars$([ "$OFFLINE" = true ] || printf ' and SBOMs')) byte-identical in two builds from different directories"
  else
    diff "$REPRO/first.sha256" "$REPRO/second.sha256" | head -40
    record reproducibility FAIL "$(diff "$REPRO/first.sha256" "$REPRO/second.sha256" | grep -c '^<') of $compared artefacts differ between two builds"
  fi
fi

# --- summary -------------------------------------------------------------------
failed=0
incomplete=0
printf '\n=== summary: jCustos community %s, commit %s ===\n' "$VERSION" "$(jc_head_commit)"
printf '%-16s %-8s %6s  %s\n' stage result time detail
index=0
while [ "$index" -lt "${#STAGE_NAMES[@]}" ]; do
  printf '%-16s %-8s %5ss  %s\n' "${STAGE_NAMES[$index]}" "${STAGE_RESULTS[$index]}" "${STAGE_SECONDS[$index]}" "${STAGE_DETAILS[$index]}"
  case "${STAGE_RESULTS[$index]}" in
  FAIL) failed=$((failed + 1)) ;;
  "NOT RUN") incomplete=$((incomplete + 1)) ;;
  esac
  index=$((index + 1))
done
printf 'total %ss, logs in %s\n' "$(($(date +%s) - GATE_STARTED))" "$GATE_DIR"

if [ "$failed" != 0 ]; then
  printf 'GATE FAILED: %s stage(s) failed.\n' "$failed"
  exit 1
fi
if [ "$incomplete" != 0 ]; then
  printf 'GATE INCOMPLETE: nothing failed, but %s required stage(s) did not run. Not a release gate result.\n' "$incomplete"
  exit 2
fi
printf 'GATE PASSED.\n'
exit 0
