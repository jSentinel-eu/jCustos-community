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
Facts about the community reactor, read from the POMs with an XML parser.

The release scripts used to cut the version and the module list out of pom.xml
with grep and sed ("the second <version> element"). That breaks silently as
soon as the file is rearranged, so every script asks this helper instead.

Usage (from any directory):
  reactor.py version        project version of the root POM
  reactor.py libraries      publishable modules, one per line (root POM order)
  reactor.py demos          demo modules, one per line
  reactor.py timestamp      project.build.outputTimestamp of the root POM
  reactor.py check-bom      compare jCustos-bom/pom.xml with the reactor

A module is publishable when its directory name does not start with "demo".
The root project (jCustos-community-parent) is published as well, but it is
not a module and therefore not in the list.

Exit codes: 0 success, 1 check-bom found a difference, 2 usage or parse error.
Python 3 standard library only.
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"m": "http://maven.apache.org/POM/4.0.0"}
ROOT = Path(__file__).resolve().parents[2]
BOM_MODULE = "jCustos-bom"
GROUP_ID = "eu.jsentinel"
DEMO_PREFIX = "demo"


def _die(message):
    print(f"reactor.py: {message}", file=sys.stderr)
    sys.exit(2)


def parse(path):
    try:
        return ET.parse(path).getroot()
    except (OSError, ET.ParseError) as error:
        _die(f"cannot read {path}: {error}")


def text(node, xpath):
    found = node.find(xpath, NS)
    return found.text.strip() if found is not None and found.text else None


def root_pom():
    return parse(ROOT / "pom.xml")


def version(pom):
    value = text(pom, "m:version")
    if not value:
        _die("the root POM has no <version>")
    return value


def modules(pom):
    return [m.text.strip() for m in pom.findall("m:modules/m:module", NS)]


def libraries(pom):
    return [m for m in modules(pom) if not m.startswith(DEMO_PREFIX)]


def demos(pom):
    return [m for m in modules(pom) if m.startswith(DEMO_PREFIX)]


def timestamp(pom):
    return text(pom, "m:properties/m:project.build.outputTimestamp")


def check_bom(pom):
    """The BOM has no parent, so nothing in Maven ties it to the reactor."""
    bom = parse(ROOT / BOM_MODULE / "pom.xml")
    problems = []

    if bom.find("m:parent", NS) is not None:
        problems.append("the BOM declares a <parent>; it must stand alone")

    reactor_version = version(pom)
    bom_version = text(bom, "m:version")
    if bom_version != reactor_version:
        problems.append(
            f"version: BOM {bom_version!r}, reactor {reactor_version!r}")

    reactor_timestamp = timestamp(pom)
    bom_timestamp = text(bom, "m:properties/m:project.build.outputTimestamp")
    if not reactor_timestamp:
        problems.append("the root POM sets no project.build.outputTimestamp")
    if bom_timestamp != reactor_timestamp:
        problems.append(
            "project.build.outputTimestamp: "
            f"BOM {bom_timestamp!r}, reactor {reactor_timestamp!r}")

    if bom.find("m:dependencies", NS) is not None:
        problems.append("the BOM declares <dependencies> outside its management section")

    managed = []
    for dependency in bom.findall(
            "m:dependencyManagement/m:dependencies/m:dependency", NS):
        group = text(dependency, "m:groupId")
        artifact = text(dependency, "m:artifactId")
        entry_version = text(dependency, "m:version")
        if group != GROUP_ID:
            problems.append(f"foreign entry {group}:{artifact}")
        if entry_version not in ("${project.version}", reactor_version):
            problems.append(
                f"{artifact}: version {entry_version!r} does not follow the BOM version")
        for forbidden in ("scope", "type", "classifier", "optional", "exclusions"):
            if dependency.find(f"m:{forbidden}", NS) is not None:
                problems.append(f"{artifact}: <{forbidden}> does not belong in the BOM")
        managed.append(artifact)

    duplicates = sorted({a for a in managed if managed.count(a) > 1})
    if duplicates:
        problems.append("listed more than once: " + ", ".join(duplicates))

    expected = [m for m in libraries(pom) if m != BOM_MODULE]
    for module in expected:
        declared = text(parse(ROOT / module / "pom.xml"), "m:artifactId")
        if declared != module:
            problems.append(
                f"module directory {module} declares artifactId {declared!r}")
    missing = sorted(set(expected) - set(managed))
    surplus = sorted(set(managed) - set(expected))
    if missing:
        problems.append("publishable modules missing in the BOM: " + ", ".join(missing))
    if surplus:
        problems.append("BOM entries without a publishable module: " + ", ".join(surplus))
    if BOM_MODULE not in modules(pom):
        problems.append(f"{BOM_MODULE} is not a module of the reactor")

    if problems:
        print(f"jCustos-bom does not match the reactor ({len(problems)} difference(s)):")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"jCustos-bom matches the reactor: version {reactor_version}, "
          f"{len(managed)} managed modules, outputTimestamp {reactor_timestamp}")
    return 0


def main(arguments):
    if len(arguments) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    command = arguments[0]
    pom = root_pom()
    if command == "version":
        print(version(pom))
    elif command == "libraries":
        print("\n".join(libraries(pom)))
    elif command == "demos":
        print("\n".join(demos(pom)))
    elif command == "timestamp":
        print(timestamp(pom) or "")
    elif command == "check-bom":
        return check_bom(pom)
    else:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
