# SBOM and Cryptographic Supply-Chain Provenance

Status: draft — V00.71.00
CWE: CWE-937 (Use of Components with Known Vulnerabilities)

## What is generated

The parent POM applies `org.cyclonedx:cyclonedx-maven-plugin` to every
module. Build artefacts:

- `target/CycloneDX-SBom.json`
- `target/CycloneDX-SBom.xml`

These are produced as part of the standard `package` lifecycle for
each module:

```bash
./mvnw clean package          # SBOM regenerated under every module
ls jSentinel-core/target/CycloneDX-SBom.*
```

## What the SBOM covers

The CycloneDX SBOM lists every Maven coordinate on the **compile** and
**runtime** classpath of the module. For the credential pipeline that
includes:

| Module                          | Cryptographic third-party deps     |
|---------------------------------|------------------------------------|
| `jSentinel-core`                 | none — JDK-only                    |
| `jSentinel-crypto-bc`            | `org.bouncycastle:bcprov-jdk18on:1.86` |
| `jSentinel-credentials-hibp`     | none — JDK-only (`HttpClient`)     |
| `jSentinel-persistence-eclipsestore` | none crypto-relevant            |

The SBOM does **not** describe the cryptographic content of the JDK
itself — the JDK is not a Maven coordinate. JDK trust is documented
separately in `jdk-distribution-trust.md`.

## Verification expectations

Deployments that require supply-chain assurance should run, per
release:

1. **SBOM archival.** Store both `*.json` and `*.xml` artefacts
   alongside the release binaries. They become evidence in CVE
   response, see `../playbooks/provider-compromise.md`.
2. **SBOM diff between releases.** `cyclonedx diff old.json new.json`
   (or any compatible tool) — every new component is a fresh
   supply-chain decision.
3. **CVE scan.** Feed each SBOM through an OSV / Grype / Dependency
   Track instance. The framework itself does not bundle a scanner.
4. **Signature verification of third-party deps.** Maven Central
   signatures (`*.asc`) are part of the Maven Central deploy
   contract. Operators that consume locally-installed dependencies
   (e.g. `com.svenruppert:proxybuilder` until it lands on Central)
   must verify those signatures themselves.

## What is **not** in scope

- The framework does **not** publish a transparency-log entry.
- The framework does **not** sign its own jars with Sigstore (yet).
- The framework does **not** generate provenance attestations
  (SLSA / in-toto).

These are deliberate gaps tracked in `gaps.md`.

## Provenance for the cryptographic path

Each released library jar carries:

- PGP signature (`*.asc`) — produced by the release pipeline,
  verifiable against `gpg.svenruppert.com` keys.
- Maven Central metadata — checksums, GAV, timestamps.

Consumers verify with:

```bash
gpg --verify jSentinel-core-00.71.00.jar.asc jSentinel-core-00.71.00.jar
sha512sum -c jSentinel-core-00.71.00.jar.sha512
```

## Maintenance

When a new module is added to the reactor (parent `pom.xml`
`<modules>` list), this document's coverage table is updated. The
SBOM itself is regenerated automatically by the build — no manual
step is required.
