# PKCS#11 / HSM as Pepper Key Source

Status: current — V00.84.00
CWE: CWE-320 (Key Management Errors), CWE-522 (Insufficiently
Protected Credentials)

## Why this matters

A pepper is a server-side secret mixed into every stored password hash
(HMAC-SHA-256 over the KDF output, see `PepperApplicator`). Whoever
holds the password database but not the pepper cannot test guesses
offline. The pepper therefore has to live somewhere else than the
database and its backups — see `../playbooks/pepper-compromise.md`.

## The SPI as it is

`PepperService` (jCustos-core) has two methods:

- `activeKeyId()` — the key id new hashes are peppered with;
- `resolve(keyId)` — the key bytes for a key id, as a copy.

The HMAC itself is computed **inside the JVM** by `PepperApplicator`.
Every implementation therefore hands key bytes to the JVM; none of
them keeps the key on a token while hashing.

## Key sources shipped since 00.84.00

| Source | Use | Notes |
|---|---|---|
| `KeyStorePepperService.fromPkcs12(path, password)` | a PKCS12 file | Secret-key entries, key id = alias (compared exactly; PKCS12 stores aliases in lower case). The file must belong to the process user, carry no group or other permissions and must not be a symbolic link. |
| `KeyStorePepperService.fromKeyStore(keyStore, entryPassword)` | a key store the application loaded, e.g. a PKCS#11 token through `SunPKCS11` | The key must be **extractable** (`CKA_SENSITIVE=false`, `CKA_EXTRACTABLE=true`); a key that never leaves the token is refused at `load()` with "not extractable". |
| `FilePepperService.fromDirectory(dir)` | one Base64 file per key id, e.g. `/run/secrets` | Same file checks as the PKCS12 source, plus the key-directory rules below. Kubernetes secret volumes (symbolic links, root-owned, group-readable) are refused; see "Key files in containers". |
| `InMemoryPepperService` | tests, or keys the application obtained itself | Heap only. |

All sources load only the key ids that are named (one active, any
number retired), refuse keys shorter than 32 bytes, fail closed at
`load()` and never put key material, file content or a password into a
message, a log line or `toString()`.

## Key files in containers

`FilePepperService` checks, before it reads anything:

- **each key file:** not a symbolic link, owned by the process user, no
  permissions for group or others (0400 or 0600), exactly one hard link;
- **the key directory:** not a symbolic link, owned by the process user
  or by root, not writable by group or others unless its sticky bit is
  set. The directories above it are not checked.

Any violation stops `load()`; the application does not start without
its pepper.

**Docker Swarm.** Declare the secret with the process `uid` and
`mode: 0400`; `/run/secrets` belongs to root and is not writable by
others, so `FilePepperService.fromDirectory(Path.of("/run/secrets"))`
accepts it.

**Kubernetes.** The entries of a secret volume are symbolic links into
`..data/`, owned by root and, with `fsGroup`, readable by the group. They
are refused, and an `emptyDir` itself (mode 0777 without sticky bit) is
refused as key directory as well. Copy the key in an init container
that runs as the application's user into an owner-only sub-directory of
an in-memory `emptyDir`:

```yaml
spec:
  securityContext:
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001            # lets the init container read the secret
  volumes:
    - name: pepper-secret
      secret:
        secretName: jcustos-pepper
        defaultMode: 0440
    - name: pepper
      emptyDir:
        medium: Memory        # the key never reaches the node's disk
  initContainers:
    - name: copy-pepper
      image: busybox:1.36
      command: ["sh", "-c", "umask 077 && rm -rf /pepper/keys && mkdir /pepper/keys && cp /secret/pepper-2026 /pepper/keys/ && chmod 0400 /pepper/keys/pepper-2026"]
      volumeMounts:
        - { name: pepper-secret, mountPath: /secret, readOnly: true }
        - { name: pepper, mountPath: /pepper }
  containers:
    - name: app
      volumeMounts:
        - { name: pepper, mountPath: /pepper, readOnly: true }
```

The application then loads
`FilePepperService.fromDirectory(Path.of("/pepper/keys")).activeKeyId("pepper-2026").load()`.
`/pepper/keys` belongs to the process user and carries mode 0700, the key
file mode 0400 with one link; `cp` follows the secret's symbolic link and
writes a plain file. Do not mount the secret volume into the application
container. The recipe follows from the documented layout of secret volumes
and from the checks above; a test reproduces the directory layout, but it
has not been run on a cluster. A PKCS12 file from a secret volume is
refused for the same reasons; copy it the same way and use
`KeyStorePepperService.fromPkcs12(...)`.

## PKCS#11 with an extractable key

```java
Provider p11 = Security.getProvider("SunPKCS11")
    .configure("name=corp-hsm\nlibrary=/usr/lib/softhsm/libsofthsm2.so\nslot=0");
KeyStore token = KeyStore.getInstance("PKCS11", p11);
token.load(null, pin);
PepperService pepper = KeyStorePepperService.fromKeyStore(token, null)
    .activeAlias("pepper-2026")
    .load();
```

This protects the key at rest (it is stored on the token, not in a file
next to the application) but not in use: the bytes are read once at
start and held in memory, as with every other source.

## What 00.84.00 does **not** offer

- HMAC on the token (`CKM_SHA256_HMAC` with a non-extractable key). It
  needs a different SPI — the service would compute the tag instead of
  handing out the key — and is a candidate for a later release.
- Vendor-specific HSM adapters; a vendor JCA provider is wired the same
  way as `SunPKCS11` above.
- Key generation. Generate the key with the token's tools or, for
  PKCS12, with
  `keytool -genseckey -storetype PKCS12 -keystore pepper.p12 -alias pepper-2026 -keyalg HmacSHA256 -keysize 256`.
- FIPS-mode bridging — see `fips-profile.md`.

## Rotation

Load the new key as active and the old one as retired
(`.activeAlias("pepper-2027").retiredAlias("pepper-2026")`) and restart.
Hashes peppered with the old key keep verifying; `needsRehash` reports
`RehashReason.PEPPER_KEY_ROTATED`, and they are re-encoded under the new
key at the next successful login. Retire a key only after the
population has been rehashed or reset.

## What the framework guarantees

- Key bytes are never logged, persisted by the framework, included in
  `toString()` or accepted as input to `AuditEvent` types.
- An unknown key id in a stored envelope is answered like a wrong
  password, after a dummy KDF run at real cost.
