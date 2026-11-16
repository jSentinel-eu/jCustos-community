# SBOM and Cryptographic Supply-Chain Provenance

Status: draft — V00.71.00, revised V00.84.00 (security analysis 2026-11-10)
CWE: CWE-937 (Use of Components with Known Vulnerabilities)

> Until 00.83.00 this page described an SBOM that the build did not produce:
> no release up to that version carries one, neither on Maven Central nor on
> `repo.jsentinel.eu`. The reasons and the present state are below. How a
> consumer verifies signature, checksum and SBOM of a release is described in
> [`../../release-verification.md`](../../release-verification.md).

## What is generated

The community parent POM configures `org.cyclonedx:cyclonedx-maven-plugin`
2.9.3 with one execution (`build-sbom`, goal `makeAggregateBom`, CycloneDX
1.6). When it runs, every module gets

- `target/CycloneDX-SBom.json`
- `target/CycloneDX-SBom.xml`

and the root project gets the aggregate over the modules of the reactor under
the same names. Each file is attached to the build with the classifier
`cyclonedx`, so a release publishes it as
`<artifactId>-<version>-cyclonedx.json` / `.xml` next to the jar, with a
signature.

It does **not** run in an ordinary build. It runs

- in the release build (profile `_release_prepare`), and
- on request: `./mvnw -Psbom package`.

```bash
./mvnw -Psbom clean package       # online; SBOM under every module
ls jCustos-core/target/CycloneDX-SBom.*
```

Two properties of the plugin matter here, because each of them made the SBOM
disappear without an error before 00.84.00:

- Every goal of the plugin requires online mode. In an offline build (`-o`)
  Maven skips it and prints `Goal 'makeAggregateBom' requires online mode for
  execution but Maven is currently offline, skipping`.
- With `skipNotDeployed` (default `true`) the plugin skips a module whose
  model shows no deploy or publish execution. Under Maven 4 with the
  `central-publishing-maven-plugin` extension no module shows one, and every
  module was skipped with `Skipping CycloneDX goal, because module skips
  deploy`. The parent POM sets `skipNotDeployed` to `false`.

Because a skipped plugin is only a line in the log, the release scripts and
`scripts/gate.sh` check that the files exist and describe the right module.

## What the SBOM covers

The CycloneDX SBOM lists every Maven coordinate on the **compile**,
**provided** and **runtime** classpath of the module; test scope is left out.
For the credential pipeline that includes:

| Module                             | Cryptographic third-party deps         |
|------------------------------------|----------------------------------------|
| `jCustos-core`                     | none — JDK-only                        |
| `jCustos-crypto-bc`                | `org.bouncycastle:bcprov-jdk18on:1.86` |
| `jCustos-credentials-hibp`         | none — JDK-only (`HttpClient`)         |
| `jCustos-persistence-eclipsestore` | none crypto-relevant                   |

The SBOM does **not** describe the cryptographic content of the JDK
itself — the JDK is not a Maven coordinate. JDK trust is documented
separately in `jdk-distribution-trust.md`.

With `project.build.outputTimestamp` set in the POMs the plugin writes a
reproducible document: no build timestamp, and a serial number derived from
the content.

## Verification expectations

Deployments that require supply-chain assurance should run, per
release:

1. **SBOM archival.** Store both `*-cyclonedx.json` and `*-cyclonedx.xml`
   alongside the release binaries. They become evidence in CVE
   response, see `../playbooks/provider-compromise.md`.
2. **SBOM diff between releases.** `cyclonedx diff old.json new.json`
   (or any compatible tool) — every new component is a fresh
   supply-chain decision.
3. **CVE scan.** Feed each SBOM through an OSV / Grype / Dependency
   Track instance. The framework does not bundle a scanner at run time; the
   project's own gate (`scripts/gate.sh`) sends the third-party components of
   every module SBOM to the OSV database and fails on an advisory that has no
   dated exception in `scripts/osv-exceptions.txt`.
4. **Signature verification of third-party deps.** Maven Central
   signatures (`*.asc`) are part of the Maven Central deploy
   contract. Every dependency of the community edition is resolved from Maven
   Central, including `com.svenruppert:proxybuilder` and
   `proxybuilder-annotations` (00.11.01, published there; earlier versions of
   this page said proxybuilder was not on Central). The build declares no
   other repository, and an enforcer rule rejects any repository other than
   Maven Central and the project's own `repo.jsentinel.eu`.

## What is **not** in scope

- The framework does **not** publish a transparency-log entry.
- The framework does **not** sign its own jars with Sigstore (yet).
- The framework does **not** generate provenance attestations
  (SLSA / in-toto).

These are deliberate gaps tracked in `gaps.md`.

## Provenance for the cryptographic path

Each released library jar carries:

- PGP signature (`*.asc`) — produced by the release build and verified
  against the pinned release key: by `scripts/clean-bundle-for-central.sh`
  before the bundle for Maven Central is written, by
  `scripts/deploy-jsentinel.sh` on the files it fetches back from
  `repo.jsentinel.eu` after the upload.
  The fingerprint of that key is published in `SECURITY.md` and in
  [`../../release-verification.md`](../../release-verification.md); earlier
  versions of this page named `gpg.svenruppert.com`, a host that does not
  exist.
- Maven Central metadata — checksums, GAV, timestamps.
- A release manifest (`central-bundle.manifest.txt`) written by
  `scripts/clean-bundle-for-central.sh`: tag, commit, JDK and Maven version
  and the SHA-256 of every published file.

Consumers verify with:

```bash
gpg --verify jCustos-core-00.84.00.jar.asc jCustos-core-00.84.00.jar
echo "$(cat jCustos-core-00.84.00.jar.sha512)  jCustos-core-00.84.00.jar" | shasum -a 512 -c
```

and compare the fingerprint gpg prints with the published one.

Releases up to 00.83.00 on `repo.jsentinel.eu` were uploaded without
signatures; verify those versions against Maven Central.

## Maintenance

When a new module is added to the reactor (parent `pom.xml`
`<modules>` list), this document's coverage table is updated and the module is
added to `jCustos-bom`; `scripts/gate.sh` fails while the BOM and the reactor
differ. The SBOM is regenerated by every release build and by the gate — an
ordinary or offline build does not produce it.
