#!/usr/bin/env python3
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
"""
Checks the components of CycloneDX SBOMs against the OSV database (osv.dev).

Usage:
  osv-scan.py [--exceptions <file>] <CycloneDX json> [<CycloneDX json> ...]

Every Maven component of the given SBOMs is sent to the OSV batch API as a
package URL with its version. Components of the project itself (group
eu.jsentinel) are left out: they are what is being built. The request carries
package coordinates only, no credentials and no source code.

Result:
  0  scanned, no advisory (or only advisories with a valid exception)
  1  at least one advisory without a valid exception
  2  NOT RUN: no component to scan, unreadable input, or OSV not reachable.
     A scan that could not ask is not a scan that found nothing, so this is
     never reported as success.

Exceptions: one per line, "<advisory id> <YYYY-MM-DD> <reason>". The id may be
the OSV id or one of its aliases (GHSA-..., CVE-...). An exception is ignored
from the day after its date; the advisory fails the scan again until someone
has looked at it. Lines starting with # are comments.

Python 3 standard library only.
"""
import datetime
import json
import os
import sys
import urllib.error
import urllib.request

# JCUSTOS_OSV_API points the scan at another OSV instance (a mirror, or an
# unreachable address to see how the gate reports a scan that cannot run).
OSV_API = os.environ.get("JCUSTOS_OSV_API", "https://api.osv.dev").rstrip("/")
OSV_BATCH = OSV_API + "/v1/querybatch"
OSV_QUERY = OSV_API + "/v1/query"
OSV_VULN = OSV_API + "/v1/vulns/"
OWN_GROUP = "eu.jsentinel"
BATCH_SIZE = 500
TIMEOUT_SECONDS = 60

EXIT_CLEAN, EXIT_FOUND, EXIT_NOT_RUN = 0, 1, 2


class NotRun(Exception):
    """The scan could not be carried out."""


def post(url, payload):
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        raise NotRun(f"OSV request to {url} failed: {error}") from error


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:
            return json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def read_components(paths):
    """purl without qualifiers -> sorted list of SBOM subjects that contain it."""
    components = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                bom = json.load(handle)
        except (OSError, ValueError) as error:
            raise NotRun(f"cannot read {path}: {error}") from error
        if bom.get("bomFormat") != "CycloneDX":
            raise NotRun(f"{path} is not a CycloneDX document")
        subject = bom.get("metadata", {}).get("component", {}).get("name", path)
        for component in bom.get("components", []):
            purl = component.get("purl", "")
            if not purl.startswith("pkg:maven/"):
                continue
            if component.get("group") == OWN_GROUP:
                continue
            components.setdefault(purl.split("?", 1)[0], set()).add(subject)
    return {purl: sorted(subjects) for purl, subjects in components.items()}


def query(purls):
    """purl -> list of advisory ids."""
    found = {}
    for start in range(0, len(purls), BATCH_SIZE):
        chunk = purls[start:start + BATCH_SIZE]
        answer = post(OSV_BATCH, {"queries": [{"package": {"purl": p}} for p in chunk]})
        results = answer.get("results")
        if not isinstance(results, list) or len(results) != len(chunk):
            raise NotRun("OSV answered with an unexpected number of results")
        for purl, result in zip(chunk, results):
            ids = [v["id"] for v in result.get("vulns", [])]
            token = result.get("next_page_token")
            while token:
                page = post(OSV_QUERY, {"package": {"purl": purl}, "page_token": token})
                ids.extend(v["id"] for v in page.get("vulns", []))
                token = page.get("next_page_token")
            if ids:
                found[purl] = sorted(set(ids))
    return found


def read_exceptions(path):
    exceptions = {}
    if not path:
        return exceptions
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as error:
        raise NotRun(f"cannot read the exceptions file {path}: {error}") from error
    for number, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        try:
            if len(parts) < 3:
                raise ValueError("expected '<id> <YYYY-MM-DD> <reason>'")
            expires = datetime.date.fromisoformat(parts[1])
        except ValueError as error:
            raise NotRun(f"{path}:{number}: {error}") from error
        exceptions[parts[0]] = (expires, parts[2])
    return exceptions


def describe(advisory_id):
    """(aliases, severity, summary, fixed versions) - best effort."""
    detail = get(OSV_VULN + advisory_id)
    if not detail:
        return [], "unknown", "(details not available)", []
    severity = (detail.get("database_specific") or {}).get("severity") or "unknown"
    fixed = sorted({
        event["fixed"]
        for affected in detail.get("affected", [])
        for version_range in affected.get("ranges", [])
        for event in version_range.get("events", [])
        if "fixed" in event})
    return detail.get("aliases", []), severity, detail.get("summary", ""), fixed


def main(arguments):
    exceptions_path = None
    if arguments[:1] == ["--exceptions"]:
        if len(arguments) < 2:
            print(__doc__.strip(), file=sys.stderr)
            return EXIT_NOT_RUN
        exceptions_path, arguments = arguments[1], arguments[2:]
    if not arguments or arguments[0].startswith("-"):
        print(__doc__.strip(), file=sys.stderr)
        return EXIT_NOT_RUN

    try:
        components = read_components(arguments)
        if not components:
            raise NotRun("the SBOMs list no third-party Maven component; nothing was scanned")
        exceptions = read_exceptions(exceptions_path)
        found = query(sorted(components))
    except NotRun as reason:
        print(f"OSV scan NOT RUN: {reason}")
        return EXIT_NOT_RUN

    today = datetime.date.today()
    blocking = 0
    accepted = 0
    used_exceptions = set()
    for purl in sorted(found):
        print(f"{purl}")
        print(f"    in: {', '.join(components[purl])}")
        for advisory_id in found[purl]:
            aliases, severity, summary, fixed = describe(advisory_id)
            names = [advisory_id] + aliases
            exception = next((exceptions[n] + (n,) for n in names if n in exceptions), None)
            status = "FAIL"
            note = ""
            if exception:
                expires, reason, key = exception
                used_exceptions.add(key)
                if expires >= today:
                    status = "accepted"
                    note = f" [exception until {expires}: {reason}]"
                else:
                    note = f" [exception expired on {expires}]"
            if status == "FAIL":
                blocking += 1
            else:
                accepted += 1
            print(f"    {status:8} {advisory_id} ({', '.join(aliases) or 'no alias'}) "
                  f"severity {severity}, fixed in {', '.join(fixed) or 'no fixed version listed'}{note}")
            if summary:
                print(f"             {summary}")

    for key in sorted(set(exceptions) - used_exceptions):
        print(f"note: exception {key} matches no advisory any more; remove it")

    print(f"OSV scan: {len(components)} third-party components from {len(arguments)} SBOM(s), "
          f"{len(found)} with advisories, {blocking} advisory(ies) blocking, {accepted} accepted by exception.")
    return EXIT_FOUND if blocking else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
