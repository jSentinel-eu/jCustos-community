# jCustos V00.84.10 — releases come from repo.jsentinel.eu first

**Theme:** the companion release to the enterprise authorisation server for MCP services. The community
edition gains the refresh-token family contract that server relies on, and every jCustos release now reaches
`repo.jsentinel.eu` on the day it is made, with Maven Central following once a month.

Community and enterprise are released together as 00.84.10.

## Where releases are published

From 00.84.10 every release of jCustos is published to `https://repo.jsentinel.eu/releases` on the day it is
made and reaches Maven Central with the next monthly deploy. Sonatype limits how many files an organisation may
publish to Central per calendar month; one jCustos release alone comes close to that limit. The artefacts on
both hosts are the same files, built from the same signed tag and signed with the same release key.
`docs/security/release-verification.md` gains "Resolving from `repo.jsentinel.eu`": the order for Maven and
Gradle, the resolver's groupId filter that restricts the registry to the jCustos groups, and the signature
check the enterprise release now applies to the community artefacts it resolves; the edition matrix, the
migration note and `SECURITY.md` follow. **Consumers:** put `repo.jsentinel.eu/releases` before Central to get a
release on the day it is made; builds that resolve from Central only receive it with the next monthly deploy.

## The refresh-token family store tells a replayed token from a made-up one (exit review R9, CWE-841)

`RefreshTokenFamilyStore.detectReuse` and `consumeAndRotate` revoke a family on any hash that is not its current
one, so they cannot distinguish an earlier token that was rotated away (reuse, a theft signal) from a secret
nobody ever issued. Where a family id is visible to others, that let anyone who knew it end the family. The
store contract gains a side-effect-free `classify(familyId, presentedHash)` returning `PresentedHash.CURRENT`,
`PREVIOUSLY_ISSUED`, `UNKNOWN` or `UNDETERMINED`; a store that overrides it remembers at least
`ISSUED_HASH_HISTORY` (16) issued hashes per family, the current one included, in its own storage, so the
history survives a restart. `InMemoryRefreshTokenFamilyStore` implements it with a bounded ring of 64-bit
fingerprints per family. `jCustos-persistence-testkit` ships the new `RefreshTokenFamilyStoreContract`,
including a restart test driven by an overridable `reopen` hook. **Consumers:** nothing to change — `classify` is
an experimental default method answering `UNDETERMINED`, `detectReuse` and `consumeAndRotate` keep their
semantics and `RefreshTokenRotator` behaves exactly as before. Authors of a persistent family store should
override `classify`, keep the history next to the current hash, run the new contract and override `reopen`.

## The release scripts no longer report false findings

`scripts/deploy-jsentinel.sh` checked every uploaded file with `printf "$list" | grep -qxF` under
`set -o pipefail`. When `grep -q` stopped at its first match, `printf`, still writing the 68 kB list, died of
`SIGPIPE`, and the pipeline counted as failed: the deploy of 00.84.00 reported 37 files "uploaded without
signature", although the log shows an uploaded `.asc` for every file and every signature on the registry
verifies against the release key. The checks, and the same pattern in `scripts/lib/release-common.sh`, now read
from a here-string. **Consumers:** release managers only.

## Tests

The community reactor runs 5759 tests in 51 modules, 39 of them skipped (seven are the history tests of the
family-store contract, skipped for a store without history); the enterprise reactor runs 687 tests in 11
modules. None fails. Counted as `<testcase>` elements of the Surefire reports.

## Upgrading

Raise the jCustos modules to 00.84.10. Nothing in your configuration or stored data needs to change.
