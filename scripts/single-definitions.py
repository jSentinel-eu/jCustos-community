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
Checks that the rules consolidated in 00.84.00 (ER31, JS-SEC-098, CWE-1041)
keep exactly one definition in the main sources of the library modules
(jCustos-*/src/main/java; the demos and all test sources are not searched).

Usage:
  single-definitions.py [--root <directory>]

Up to 00.83.00 the https rule existed six times with two different rules, the
JSON reading three times and the JOSE segment counter three times; every
hardening had to be applied to each copy, and one copy was always missed. The
checks:

  https rule        a method named requireHttps*/validateHttps* is declared
                    once, in EndpointSecurity
  loopback rule     a method named isLoopback* is declared once, in
                    EndpointSecurity
  dev flag          the string "jcustos.dev" occurs once in code, in
                    EndpointSecurity (comments do not count)
  segment counter   a method named countSegments is declared once, in
                    JoseLimits
  JSON reader       one class compares characters with '{' or '[' (the mark of
                    a JSON reader; a writer only appends them): BoundedJson.
                    The event wire codec (CanonicalJson, WireJson) is the
                    documented exception until ER59 (V00.85.00) decides it.
  scheme check      a URI scheme is compared - getScheme() as the receiver or
                    the argument of equals/equalsIgnoreCase/startsWith/
                    contentEquals, or one of the literals "http", "https",
                    "http://", "https://" (any case) compared that way or as a
                    switch label - in EndpointSecurity only. An inline
                    "https".equalsIgnoreCase(uri.getScheme()) is a second https
                    rule that a method-name search cannot see (RF28: the DX
                    JWKS check let "https:///jwks" pass). Tolerated, with the
                    number of comparisons each may contain, are the places
                    whose rule is not the transport rule: the RFC 8252
                    redirect-URI check of the DX bootstrap (loopback http
                    without the dev flag), the target normalisation of
                    PostLogoutRedirectValidator and the htu normalisation of
                    DpopHttpUri (default ports per scheme).

Comments and the content of string literals are removed before the search, so
documentation that names a method does not count as a definition. Two kinds of
literal survive: "jcustos.dev" for the dev-flag rule and the scheme literals
above for the scheme check.

Result:
  0  every rule has exactly its one definition
  1  a rule has a second definition, or its one definition is missing
  64 usage

Python 3 standard library only.
"""
import pathlib
import re
import sys

EXIT_PASS, EXIT_FAIL, EXIT_USAGE = 0, 1, 64

CORE = "jCustos-core/src/main/java/eu/jsentinel/jcustos/"
ENDPOINT_SECURITY = CORE + "net/EndpointSecurity.java"
JOSE_LIMITS = CORE + "jwt/api/JoseLimits.java"
BOUNDED_JSON = CORE + "util/json/BoundedJson.java"
EVENT_CODEC = (
    "jCustos-events/src/main/java/eu/jsentinel/jcustos/events/codec/CanonicalJson.java",
    "jCustos-events/src/main/java/eu/jsentinel/jcustos/events/wire/WireJson.java",
)
# Scheme comparisons outside EndpointSecurity that follow a rule of their own, and how many
# comparisons each may contain; one more is reported like a stray file.
SCHEME_CHECK_EXCEPTIONS = {
    # RFC 8252 sections 7.3 and 8.3: isHttpsOrLoopback, the redirect-URI check (2)
    "jCustos-dx/src/main/java/eu/jsentinel/jcustos/dx/internal/AbstractJCustosBootstrap.java": 2,
    # which URIs are web targets, and their default ports, for the allowlist comparison (4)
    CORE + "oidc/api/PostLogoutRedirectValidator.java": 4,
    # RFC 9449 section 4.3: the default port of the htu claim per scheme (2)
    "jCustos-dpop/src/main/java/eu/jsentinel/jcustos/dpop/DpopHttpUri.java": 2,
}
# A literal that names an http(s) scheme; strip() keeps it for the scheme check.
SCHEME_LITERAL = re.compile(r'"(?i:https?(?:://)?)"')
_COMPARE = r"\.\s*(?:equals|equalsIgnoreCase|startsWith|contentEquals)\s*\("
_GET_SCHEME = r"getScheme\s*\(\s*\)"
_SCHEME_TEXT = r'"(?i:https?(?:://)?)"'
SCHEME_CHECK = re.compile(
    # uri.getScheme().equals(...), also after .toLowerCase(...)
    _GET_SCHEME + r"\s*(?:\.\s*to(?:Lower|Upper)Case\s*\([^()]*\)\s*)?" + _COMPARE
    # X.equals(uri.getScheme()) and Objects.equals(uri.getScheme(), X)
    + r"|" + _COMPARE + r"\s*[\w.()]*?" + _GET_SCHEME
    # "https".equals(x), x.startsWith("https://"), case "https" ->
    + r"|" + _SCHEME_TEXT + r"\s*" + _COMPARE
    + r"|" + _COMPARE + r"\s*" + _SCHEME_TEXT
    + r"|\bcase\s+" + _SCHEME_TEXT)


def declaration(name_pattern):
    """A method declaration: a type, the name, a parameter list and the opening brace."""
    return re.compile(
        r"[\w<>\[\]?,]+\s+(" + name_pattern + r")\s*\("
        r"(?:[^;{}()]|\([^()]*\))*\)\s*(?:throws\s+[\w.,\s]+)?\{")


# (label, pattern, the files allowed to match - the first one is required -, whether that file
# may match once only, explanation, the most matches a tolerated file may have - a file that is
# not named there may match any number of times)
RULES = (
    ("https rule", declaration(r"(?:requireHttps|validateHttps)\w*"), (ENDPOINT_SECURITY,), True,
     "declare no https check of your own; call EndpointSecurity.requireHttps(uri, errorCode)", {}),
    ("loopback rule", declaration(r"isLoopback\w*"), (ENDPOINT_SECURITY,), True,
     "recognise loopback hosts with EndpointSecurity.isLoopbackHost(host)", {}),
    ("dev flag", re.compile(r'"jcustos\.dev"'), (ENDPOINT_SECURITY,), True,
     "read the flag through EndpointSecurity.devModeEnabled()", {}),
    ("segment counter", declaration(r"countSegments"), (JOSE_LIMITS,), True,
     "count JOSE segments with JoseLimits.countSegments(compact)", {}),
    ("JSON reader", re.compile(r"(?<!append\()'[{\[]'"), (BOUNDED_JSON,) + EVENT_CODEC, False,
     "read JSON with eu.jsentinel.jcustos.util.json.BoundedJson", {}),
    ("scheme check", SCHEME_CHECK, (ENDPOINT_SECURITY,) + tuple(SCHEME_CHECK_EXCEPTIONS), False,
     "compare no scheme yourself; call EndpointSecurity.requireHttps(uri, errorCode) or "
     "EndpointSecurity.isHttpsEndpoint(uri)", SCHEME_CHECK_EXCEPTIONS),
)
# The definition every rule needs; the event codec is tolerated, not required.
REQUIRED = {label: allowed[0] for label, _, allowed, *_ in RULES}


def strip(source):
    """The code of a Java source without comments; string literals keep their quotes only,
    except a literal that is exactly "jcustos.dev", which the dev-flag rule looks for, and a
    scheme literal ("http", "https", "http://", "https://"), which the scheme check reads."""
    out = []
    i, n = 0, len(source)
    while i < n:
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = n if end < 0 else end
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif source.startswith('"""', i):
            end = source.find('"""', i + 3)
            out.append('""')
            i = n if end < 0 else end + 3
        elif source[i] in "\"'":
            quote, j = source[i], i + 1
            while j < n and source[j] != quote and source[j] != "\n":
                j += 2 if source[j] == "\\" else 1
            literal = source[i:j + 1]
            # Character literals stay (the JSON rule reads them); strings are emptied.
            kept = quote == "'" or literal == '"jcustos.dev"' or SCHEME_LITERAL.fullmatch(literal)
            out.append(literal if kept else '""')
            i = j + 1
        else:
            out.append(source[i])
            i += 1
    return "".join(out)


def main(argv):
    root = pathlib.Path(".")
    args = list(argv)
    while args:
        arg = args.pop(0)
        if arg == "--root" and args:
            root = pathlib.Path(args.pop(0))
        else:
            print(__doc__.split("Usage:")[1].split("\n\n")[0], file=sys.stderr)
            return EXIT_USAGE
    sources = sorted(root.glob("jCustos-*/src/main/java/**/*.java"))
    if not sources:
        print(f"no library sources under {root.resolve()}", file=sys.stderr)
        return EXIT_FAIL

    found = {label: [] for label, *_ in RULES}
    for path in sources:
        relative = path.relative_to(root).as_posix()
        code = strip(path.read_text(encoding="utf-8"))
        for label, pattern, *_ in RULES:
            hits = len(pattern.findall(code))
            if hits:
                found[label].append((relative, hits))

    problems = 0
    for label, _, allowed, once, hint, limits in RULES:
        strays = [(file, hits) for file, hits in found[label] if file not in allowed]
        hits_in_home = sum(hits for file, hits in found[label] if file == REQUIRED[label])
        problem_count = problems
        if hits_in_home == 0:
            problems += 1
            print(f"{label}: the definition in {REQUIRED[label]} is missing")
        elif once and hits_in_home > 1:
            problems += 1
            print(f"{label}: {REQUIRED[label]} defines it {hits_in_home} times - keep one")
        for file, hits in strays:
            problems += 1
            print(f"{label}: second definition in {file} ({hits}x) - {hint}")
        for file, hits in found[label]:
            if file in limits and hits > limits[file]:
                problems += 1
                print(f"{label}: {file} matches {hits}x, its own rule accounts for "
                      f"{limits[file]} - {hint}")
        if problems == problem_count:
            print(f"{label}: one definition, {REQUIRED[label]}")
    print(f"{len(sources)} library source files searched, {problems} problem(s)")
    return EXIT_FAIL if problems else EXIT_PASS


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
