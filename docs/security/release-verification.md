# Verifying a jCustos release

Status: V00.84.00 (security analysis 2026-11-10, SA42 – SA44)

This page is for anyone who consumes jCustos and wants to know that the
artefact in their build is the one the project released: which key signed it,
whether the file is intact, what it contains, and how the release was built.
The second half describes the release procedure itself, because a signature is
only worth as much as the process behind it.

## What a release consists of

Per module (`eu.jsentinel:<artifactId>:<version>`):

| File | Content |
|---|---|
| `<a>-<v>.pom` | consumer POM |
| `<a>-<v>.jar` | classes |
| `<a>-<v>-sources.jar` | sources |
| `<a>-<v>-javadoc.jar` | API documentation |
| `<a>-<v>-cyclonedx.json`, `<a>-<v>-cyclonedx.xml` | CycloneDX 1.6 SBOM of the module (from 00.84.00) |
| `<file>.asc` | detached OpenPGP signature, one per file above |
| `<file>.md5`, `.sha1`, `.sha256`, `.sha512` | checksums on Maven Central; `repo.jsentinel.eu` holds the types Maven's deploy uploads (for `jCustos-core` 00.83.00 `.sha256` and `.sha512` are absent there) |

The parent POM `jCustos-community-parent` carries the aggregate SBOM of all
library modules under the same classifier. `jCustos-bom` is a POM only.

Test jars and test sources are not published. Demo modules are not published.

Where:

- Maven Central — `https://repo.maven.apache.org/maven2/eu/jsentinel/`
- `https://repo.jsentinel.eu/releases/eu/jsentinel/` — the project's own
  registry, same artefact set from 00.84.00 on. Up to 00.83.00 the deploy
  script uploaded there without signing and without the release profile, so
  signatures, sources and Javadoc are missing (checked for `jCustos-core`
  00.83.00); verify those versions against Maven Central.

## The release signing key

Every file of a release is signed with one key. Its fingerprint is the trust
anchor: a signature proves nothing unless it is compared with a fingerprint
obtained from a place the attacker does not control.

- Fingerprint: `4CCC E751 C38A D66A B1DC  94D0 44A7 EECD 3701 0CF3`
  (without spaces `4CCCE751C38AD66AB1DC94D044A7EECD37010CF3`), RSA 2048,
  created 2013-08-08, user ID `Sven Ruppert <sven.ruppert@gmail.com>`.
- Published at: this page and `SECURITY.md` in the repository, and the key
  servers `keys.openpgp.org` and `keyserver.ubuntu.com`:

  ```bash
  gpg --keyserver hkps://keys.openpgp.org --recv-keys 4CCCE751C38AD66AB1DC94D044A7EECD37010CF3
  ```

This key signed the releases 00.81.10 to 00.83.00 on Maven Central and signs
00.84.00. A dedicated release key, Ed25519 and held on a hardware token, is
planned for 00.85.00. It will be certified by this key and announced here and
in `SECURITY.md` before it signs a release; this key stays valid, so earlier
releases can still be verified.

The same value is configured in `scripts/lib/release-common.sh`
(`JC_DEFAULT_RELEASE_KEY_FINGERPRINT`); the release scripts sign with that key
and refuse artefacts and tags signed with another one.

Earlier versions of the documentation pointed to `gpg.svenruppert.com` for the
key. That host does not exist; do not rely on it.

## Verifying a signature

Fetch the artefact and its signature, import the release key once, and compare
the fingerprint gpg reports with the one above.

```bash
BASE=https://repo.maven.apache.org/maven2/eu/jsentinel/jCustos-core/00.84.00
curl -fsSO $BASE/jCustos-core-00.84.00.jar
curl -fsSO $BASE/jCustos-core-00.84.00.jar.asc

gpg --verify jCustos-core-00.84.00.jar.asc jCustos-core-00.84.00.jar
```

The output has to say `Good signature`, and the line `Primary key fingerprint`
(or `using … key`) has to show the release key's fingerprint. `Good signature`
from any other key means the file was signed by someone else. A warning that
the key is not certified with a trusted signature only says that you have not
marked the key as trusted in your own keyring; the fingerprint comparison is
what counts.

For a whole build, Maven can do the comparison for every dependency. One way
is the plugin `org.simplify4u.plugins:pgpverify-maven-plugin` with a key map
that pins `eu.jsentinel:*` to the fingerprint above.

## Verifying a checksum

A checksum shows that a download is complete and unchanged in transit. It does
not show where the file comes from: whoever can replace the file on a server
can replace the checksum next to it. Use it together with the signature, not
instead of it.

```bash
curl -fsSO $BASE/jCustos-core-00.84.00.jar.sha512
echo "$(cat jCustos-core-00.84.00.jar.sha512)  jCustos-core-00.84.00.jar" | shasum -a 512 -c
```

Maven compares the checksums of everything it downloads. By default a mismatch
is a warning; `mvn --strict-checksums` (`-C`) makes it an error, and the
release build of jCustos runs with it.

Maven Central and `repo.jsentinel.eu` are filled by two separate builds of the
same tag. The build is reproducible, so a version is expected to have the same
bytes in both places; compare the SHA-256 if in doubt. The signature files
differ between the two because they are made in separate runs; both verify
against the same key.

## Using the SBOM

The SBOM of a module lists every Maven component on its compile, provided and
runtime class path with version and hashes, in CycloneDX 1.6.

```bash
curl -fsSO $BASE/jCustos-core-00.84.00-cyclonedx.json
curl -fsSO $BASE/jCustos-core-00.84.00-cyclonedx.json.asc
gpg --verify jCustos-core-00.84.00-cyclonedx.json.asc jCustos-core-00.84.00-cyclonedx.json
```

Verify its signature like that of the jar, then feed it to the tool of your
choice (OSV-Scanner, Grype, Dependency-Track, `cyclonedx diff` between two
releases). What it does not describe:

- the JDK and the servlet container, which are not Maven components;
- test-scoped dependencies;
- what your own build resolves. Your dependency management can move a
  transitive version, so the SBOM of your application is the authority for
  your deployment; the jCustos SBOM tells you what jCustos was built and
  tested with.

The SBOM is generated by `cyclonedx-maven-plugin` 2.9.3 in the release build
(profile `_release_prepare`) and on request (`./mvnw -Psbom package`). It is
not part of an ordinary build: every goal of the plugin needs online mode, and
Maven skips it in an offline build with no more than a warning. The scripts
below therefore check that the files exist instead of trusting the build to
have produced them.

## Rebuilding a release

The build is reproducible: `project.build.outputTimestamp` is fixed in the
POMs (up to 00.83.00 Maven 4 supplied its default), so the same commit built
with the same JDK gives the same jars, byte for byte. This was checked for
00.83.00: `jCustos-core`, `jCustos-jwt` and `jCustos-rest`, rebuilt from the
tag `v00.83.00`, have the SHA-1 that Maven Central publishes for them. To
recompute a published jar:

```bash
git clone https://github.com/jSentinel-eu/jCustos-community.git
cd jCustos-community
git checkout v00.84.00
git tag -v v00.84.00                   # signed with the release key
./mvnw -DskipTests -pl jCustos-core -am package
shasum -a 256 jCustos-core/target/jCustos-core-00.84.00.jar
```

Compare with the SHA-256 of the published jar. Use the JDK release the jar was
built with (`Build-Jdk-Spec` in its `META-INF/MANIFEST.MF` names the feature
release, the release manifest the exact build); a different compiler may emit
different class files. The Maven version is fixed by the wrapper, whose
download is pinned by `distributionSha256Sum` in
`.mvn/wrapper/maven-wrapper.properties`.

Release tags from 00.84.00 on are signed with the release key. Tags up to
`v00.83.00` are annotated, most of them unsigned.

## How a release is made

Three scripts. The two that publish have a `--dry-run` that performs every
check and the whole build without signing, installing or uploading anything.

1. `scripts/gate.sh` — the verification gate. Clean reactor build with all
   tests, the enforcer rules, the BOM against the reactor, SBOM generation, an
   advisory scan of every third-party component against OSV, and optionally
   two builds compared byte for byte. It needs no credentials and changes
   nothing outside build directories. Exit code 0 means passed, 1 failed,
   2 incomplete (a required stage could not run, for example offline). The
   commit to be tagged has to pass it with 0; the two scripts below do not run
   it themselves.
2. `scripts/clean-bundle-for-central.sh` — the bundle for Maven Central. It
   refuses to run unless the version is a release version, the working tree is
   clean, `HEAD` is the commit of the tag `v<version>` and that tag is signed
   with the release key. It then exports the tag with `git archive` into an
   empty directory and builds it into an empty local repository with strict
   checksums, takes the artefacts from that repository only, verifies every
   signature against the release key, writes and re-reads the checksums and
   records tag, commit, tool versions and the SHA-256 of every file in
   `target/central-publishing/central-bundle.manifest.txt`.
3. `scripts/deploy-jsentinel.sh` — the upload to `repo.jsentinel.eu`, under
   the same preconditions and with the same profiles and key. After the upload
   it fails if any uploaded file lacks an uploaded signature or a test jar was
   uploaded, and it fetches POM, jar and SBOM of every module back and
   verifies their signatures against the release key.
   `scripts/deploy-jsentinel.sh --verify-published <version>` repeats that
   check at any time; with `JCUSTOS_VERIFY_BASE_URL` it checks another
   repository, for example Maven Central.

Only the library modules are built in steps 2 and 3. The demo applications run
an npm build without a lockfile; that build stays out of the process that
holds the signing key.

Not part of the process yet, and stated here so that nobody assumes it:

- no entry in a transparency log, no Sigstore signature;
- no SLSA or in-toto provenance attestation;
- the gate runs on the maintainer's machine. `.forgejo/workflows/verify.yml`
  runs the same script on push and pull request, but it is not a required
  check yet.
