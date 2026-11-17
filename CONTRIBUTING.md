# Contributing to jCustos

## Before your first pull request: sign the CLA

jCustos is open core. The Community Edition in this repository is free software
under the EUPL 1.2; a separate Enterprise Edition funds the work. That model
only holds if the project may license contributions under both — so every
contribution needs the [Contributor Licence Agreement](CLA.md).

The grant is **non-exclusive**: you keep all rights in your own work. In return
the project commits to keeping your contribution permanently available under a
free licence. Obvious fixes (typos, formatting, a handful of lines without
creative choice) need no signature.

To sign, add this line to your pull request:

> I have read the jCustos CLA v1.0 and agree to it. Name, e-mail, date.

Contributing on behalf of an employer? Use `CLA-CORPORATE.md`.

## Where the code lives, and how your pull request gets in

Development happens on **https://git.jsentinel.eu/jSentinel/jCustos-community**.
The GitHub repository is a **mirror of it** — so pull requests are welcome
there, but they are not merged with the button.

What happens instead: the maintainer picks your commits up, applies them on the
development side, and the mirror carries them back to GitHub. Your pull request
is then closed with a pointer to the commit that carries your work. Authorship
is preserved — the commit stays yours.

Two consequences worth knowing:

- Your branch may show as "closed" rather than "merged" even though the change
  shipped. Check the referenced commit, not the badge.
- Because the mirror overwrites GitHub branches, do not expect a maintainer to
  push fixups onto your branch there. Review feedback comes as comments; push
  the follow-up yourself.

If you would rather work where the code is developed, an account on
git.jsentinel.eu works too — pull requests there follow the ordinary flow.

## Working on the code

```bash
./mvnw clean install          # full reactor, 52 modules
./mvnw test -pl jCustos-core  # a single module
```

Two conventions worth knowing before you start:

- **No mocking frameworks.** Tests run against real implementations; the build
  enforces this and fails on Mockito, EasyMock or PowerMock. Where a real
  implementation is awkward, the fixtures in `jCustos-test` usually help.
- **The edition boundary is a test.** `CommunityDoesNotReferenceEnterpriseTest`
  fails if community code references the enterprise edition. Nothing here may
  depend on it.

Source, comments, log and exception messages are American English. User-facing
strings follow the project's i18n resources.

## Reporting security issues

Please do not open a public issue for a vulnerability. [SECURITY.md](SECURITY.md)
describes how to report one in private, what to include and what happens next.
