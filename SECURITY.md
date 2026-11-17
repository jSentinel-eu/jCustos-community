# Security policy

jCustos is a security framework. A vulnerability in it is a vulnerability in
every application that relies on it for authentication, authorisation or
session handling, so reports are treated with priority and handled in private
until a fix is available.

This policy covers the community edition in this repository.

## Reporting a vulnerability

Do **not** open a public issue, pull request or discussion for a suspected
vulnerability, neither on git.jsentinel.eu nor on the GitHub mirror, and do not
describe it in a public channel. Everything posted there is visible to
everyone at once, including to people who would use it.

Report it in private:

- by e-mail to `sven@jsentinel.eu`, with a subject that starts with
  `[jCustos security]`. Encrypted reports are welcome: use the release signing
  key named under [Verifying a release](#verifying-a-release), which carries an
  encryption subkey;
- or through private vulnerability reporting on the GitHub mirror
  (`https://github.com/jSentinel-eu/jCustos-community`, tab *Security*,
  *Report a vulnerability*).

If you are unsure whether what you found is a vulnerability, report it this
way all the same. A report that turns out to be harmless costs little; a
vulnerability discussed in public cannot be taken back.

## What to include

A report can be acted on quickly when it contains:

- the affected module and version (for example `eu.jsentinel:jCustos-vaadin`
  `00.83.00`), and the edition if you use the enterprise edition as well;
- the integration it concerns (Vaadin Flow, REST, standalone) and the relevant
  configuration, reduced to what is needed to show the problem;
- what an attacker has to control and what they gain: which check is bypassed,
  which data is exposed, which state is changed;
- steps to reproduce it, ideally a small test or a minimal project. A proof of
  concept is welcome, a working exploit against third parties is not needed;
- the JDK and, where it matters, the servlet container and Vaadin version;
- whether the issue is already known to others or has a disclosure date;
- how you would like to be credited, or that you prefer not to be named.

Please use synthetic data only. Do not send credentials, tokens, personal data
or production logs; if a log is needed, remove such content first.

## What to expect

The maintainer aims at:

- an acknowledgement within three working days;
- a first assessment within ten working days;
- a fix within 30 days for a critical and within 60 days for a high severity,
  and with the next regular release for medium and low severity (severity as
  assessed in step 2 below, with CVSS as guidance);
- an update at least every 14 days until the fix is released.

The handling follows these steps:

1. The report is acknowledged and you are told who handles it.
2. It is reproduced and assessed (affected modules and versions, preconditions,
   severity). You are told the result, also when the report is not regarded as
   a vulnerability, with the reasons.
3. A fix is developed in private together with a regression test that fails
   without it. Where possible you are offered the fix for review before it is
   released.
4. A release is published for the supported versions. The release notes
   describe the change and name the identifier of the finding.
5. You are credited in the release notes unless you asked not to be.

## Coordinated disclosure

Please give the project the time to publish a fix before you disclose the
issue, and tell us about the date you have in mind. In return the project
works on the report without undue delay and keeps you informed.

Research that follows this policy is regarded as done in good faith: testing
against your own installations, with your own accounts and synthetic data,
without degrading services of others and without accessing data that is not
yours.

- The project asks reporters not to disclose a vulnerability earlier than 90
  days after the report, or earlier than the release of the fix if that comes
  first. The deadline is shortened when the vulnerability is already being
  exploited, and it can be extended by agreement when a fix needs longer.

If a vulnerability is being exploited already, say so in the report; the steps
above are then shortened, and an advisory with a mitigation may be published
before the fix.

## Scope

In scope:

- the library and testkit modules of the community edition published under the
  group `eu.jsentinel` (the modules listed in `jCustos-bom`), in a supported
  version;
- the build and release process of this repository, as far as it affects what
  consumers receive: the published POMs and BOM, signatures, checksums and
  SBOMs, the release scripts under `scripts/`.

Out of scope:

- the demo modules (`demo-*`). They are reference applications with fixed test
  accounts and are not published; a weakness that shows a mistake in the
  library behind them is in scope, the demo configuration itself is not;
- vulnerabilities in third-party dependencies without a jCustos-specific way to
  reach them. Please report those to the dependency; do tell us when jCustos
  pins or forces a vulnerable version;
- findings that require an application to use jCustos against its
  documentation (for example disabling a check that is on by default), unless
  the documentation is what is wrong;
- the enterprise edition, which lives in a repository of its own. Reports
  that concern both editions can be sent through the channel above.

## Supported versions

Security fixes are released for the versions marked as supported. Other
versions receive no fixes; the remedy is to move to a supported one.

| Version | Status |
|---|---|
| 00.84.x | supported |
| 00.83.x | critical fixes only, until three months after the release of 00.84.00 |
| all other versions | not supported |

The versions published on Maven Central:

- `eu.jsentinel:jCustos-*` — 00.81.10, 00.81.20, 00.82.00, 00.83.00.
- Nine modules moved to the enterprise edition after 00.81.10 and exist in the
  community coordinates in that version only: `jCustos-monitoring`,
  `jCustos-events-rest`, `jCustos-events-webhook`, `jCustos-events-siem`,
  `jCustos-events-opentelemetry`, `jCustos-events-persistence-eclipsestore`,
  `jCustos-audit-integrity`, `jCustos-audit-integrity-testkit` and
  `jCustos-audit-integrity-persistence-eclipsestore`. They remain available
  under the EUPL but are end of life and receive no fixes; their successors
  are part of the enterprise edition.
- `com.svenruppert.jsentinel:jSentinel-*` — the coordinates before the rename,
  00.73.00 to 00.81.00, plus relocation POMs at 00.81.10 that point to
  `eu.jsentinel:jCustos-*:00.81.10`.
- `com.svenruppert:security-for-flow-*` — the coordinates before 00.73.00
  (`security-for-flow-parent`: 00.50.00, 00.51.00, 00.60.00, 00.70.00,
  00.72.00).

## Verifying a release

Releases on Maven Central are signed and carry checksums. From 00.84.00 on
the release process signs the copies on `repo.jsentinel.eu` in the same way
and publishes a CycloneDX SBOM with every module. Up to 00.83.00 the deploy
script for `repo.jsentinel.eu` did not sign (for `jCustos-core` 00.83.00 the
`.asc` files are absent there); verify those versions against Maven Central.
[docs/security/release-verification.md](docs/security/release-verification.md)
describes how to check signature, checksum and SBOM.

Fingerprint of the release signing key:

- `4CCC E751 C38A D66A B1DC  94D0 44A7 EECD 3701 0CF3` (RSA 2048, user ID
  `Sven Ruppert <sven.ruppert@gmail.com>`), published in addition to this file
  in [docs/security/release-verification.md](docs/security/release-verification.md)
  and on the key servers `keys.openpgp.org` and `keyserver.ubuntu.com`.
- A dedicated release key is planned for 00.85.00. It will be certified by
  this key and announced here before it signs a release.

A release whose signature does not verify against that key did not come from
this project. Please report it through the channel above.
