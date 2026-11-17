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
| `FilePepperService.fromDirectory(dir)` | one Base64 file per key id, e.g. `/run/secrets` | Same file checks as the PKCS12 source. Kubernetes secret volumes (symbolic links, root-owned, group-readable) are refused; copy the key into an owner-only file at start or use PKCS12. |
| `InMemoryPepperService` | tests, or keys the application obtained itself | Heap only. |

All sources load only the key ids that are named (one active, any
number retired), refuse keys shorter than 32 bytes, fail closed at
`load()` and never put key material, file content or a password into a
message, a log line or `toString()`.

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
