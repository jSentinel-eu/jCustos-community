# Java Serialization Policy

Status: draft — V00.74.10
CWE: CWE-502 (Deserialization of Untrusted Data), CWE-915
(Improperly Controlled Modification of Dynamically-Determined Object
Attributes), CWE-913 (Improper Control of Dynamically-Managed Code
Resources)

## Position statement

`jSentinel` (jSentinel) **does not use Java serialization as
an active data path**. No code in the framework calls
`ObjectOutputStream`, `ObjectInputStream`, `writeObject`,
`readObject`, `readObjectNoData`, `readResolve`, `writeReplace` or
the `Externalizable` lifecycle methods. The classes that do declare
`implements Serializable` carry the marker for one of two strictly
limited reasons — Vaadin lifecycle integration and Java's mandatory
`Throwable` heritage — and no untrusted byte stream is ever fed
through Java deserialization at any point.

This is a deliberate design choice. Java serialization is the most
fertile single source of remote code execution vulnerabilities in the
JVM ecosystem (`commons-collections`, `spring-core`, `groovy`,
`hibernate`, the Apache T3 chain, the various Shiro and JBoss
gadgets). Avoiding it as an active data path eliminates an entire
class of CVE risk without further engineering effort.

This document is the explicit, auditable statement of that policy,
the current state survey that proves it, and the operator checklist
that keeps it true.

## What "Java serialization" means here

Three distinct concepts are easy to conflate; this document
distinguishes them strictly:

1. **The JDK `java.io.Serializable` mechanism.** Marker interface +
   `ObjectInputStream.readObject()` byte-stream protocol. This is the
   one with the CVE history. The framework does **not** use it as a
   data path.
2. **The Vaadin Flow `Serializable` requirement.** Vaadin Flow
   binds session-scoped state to the servlet session and historically
   supported servlet container session replication through Java
   serialization. Vaadin therefore demands that any object reachable
   from a `VaadinSession` attribute implement `Serializable`. This is
   a *contract requirement at the API boundary*, not an active code
   path inside jSentinel.
3. **Generic "object serialization"** — meaning any conversion of an
   object graph to a byte sequence and back. The framework uses
   exactly two such conversions, and both are JOSE/JSON-based or
   Eclipse-Store-based; neither involves `ObjectInputStream`.

The phrase "Java serialization" throughout this document means
specifically **(1)** unless qualified otherwise.

## Threat model — what we sidestep

The CVE classes the policy explicitly avoids:

| Class | Example CVEs | How we sidestep |
|---|---|---|
| Gadget-chain RCE on untrusted `readObject` input | CVE-2015-4852 (commons-collections), CVE-2017-9805 (Struts2), CVE-2021-44832, the WebLogic T3 chain (CVE-2015-4852 / 2018-2628 / 2020-2883 / etc.) | No `ObjectInputStream` in the framework; consumers control whether their session container replicates state |
| Deserialization in HTTP body / RPC payload | Many vendor-specific endpoint vulns | jSentinel speaks JSON over HTTP for token-exchange (V00.74) and JOSE-Compact for JWT (V00.76); never `application/x-java-serialized-object` |
| Deserialization in cache / queue / broker | Various Redis-backed and JMS-backed exploits | The Eclipse-Store persistence module uses Eclipse's own binary codec, not Java serialization. The V00.75 EventBus envelopes are signed Canonical JSON or Eclipse Serializer — both forbid `Serializable` round-trips |
| Deserialization in distributed session replication | Tomcat / Wildfly / WebLogic session-replication CVEs | jSentinel does not orchestrate session replication. If a deployment uses container-level session replication, the gadget surface is the container's, not the framework's. Operators avoiding the risk should use sticky sessions or Vaadin's stateless mode |
| `readObject` side-effect attacks via `serialPersistentFields` | Various tool-chain vulnerabilities | No class in the framework declares `serialPersistentFields`, custom `writeObject` or custom `readObject` |
| Look-Ahead Deserialization bypass | Various filter-bypass CVEs | We don't deserialize, so a filter bypass has nothing to bypass |

## Current state — full survey

A complete grep across the V00.74.10 reactor (`./mvnw` reactor, 26
library modules + 6 demo modules) on every Java serialization marker:

```text
grep -rn 'implements Serializable | extends Serializable
        | java.io.Serializable | ObjectOutputStream | ObjectInputStream
        | serialVersionUID' --include='*.java'
```

### Library modules — six ceremonial occurrences

Re-checked for 00.84.00 over every library module (`jCustos-*/src/main`):
the four occurrences of V00.74.10 below, under their jCustos names, and two
added in 00.84.00, both in `jCustos-identity-oidc-vaadin`.

| File | Marker | Reason |
|---|---|---|
| `jSentinel-vaadin/.../AuthorizationListener.java` | `implements …, Serializable; private static final long serialVersionUID` | Listener is attached to the Vaadin session lifecycle. Vaadin's `VaadinServiceInitListener` chain demands `Serializable` because container session replication would otherwise crash. No `writeObject` / `readObject` override. |
| `jSentinel-vaadin/.../SessionLifetimeListener.java` | `implements …, Serializable; private static final long serialVersionUID` | Same Vaadin reason. Holds only an `Instant`-based timeout snapshot — no credentials, no tokens. |
| `jSentinel-dx/.../JSentinelBootstrapException.java` | `private static final long serialVersionUID` | Inherits from `RuntimeException → Exception → Throwable`. `Throwable` is mandatorily `Serializable` per JLS. The `serialVersionUID` is the canonical declaration that suppresses the compiler warning. No custom serialization behaviour. |
| `jSentinel-propagation-oidc/.../JSentinelPropagationException.java` | `private static final long serialVersionUID` | Same `Throwable` inheritance. Same canonical declaration. |
| `jCustos-identity-oidc-vaadin/.../VaadinSessionRegistryCleanup.java` (00.84.00) | `private static final long serialVersionUID` (via Vaadin's `SessionDestroyListener`) | Vaadin lifecycle listener, Shape 1. Its only field, the `SessionRegistry`, is `transient`. No `writeObject` / `readObject` override. |
| `jCustos-identity-oidc-vaadin/.../AbstractOidcLogoutView.java`, nested `PendingLogoutTokens` (00.84.00) | `implements Serializable; private static final long serialVersionUID` | `VaadinSession` attribute holding the unused single-use logout tokens of one session (JS-SEC-147), bounded in number. Vaadin requires the marker for session attributes. The tokens are session-bound proofs of intent, not credentials; a replicated session carries them like the rest of its state. No `writeObject` / `readObject` override. |

That is the complete list. The remaining sixteen library modules
(`jSentinel-core`, `-rest`, `-standalone`, `-test`, `-processor`,
`-persistence-eclipsestore`, `-persistence-testkit`, `-crypto-bc`,
`-credentials-hibp`, `-propagation`, `-propagation-processor`,
`-autoservice-annotations`, `-autoservice-processor`,
`-vaadin-starter`, `-dx-vaadin`, `-dx-rest`, `-dx-standalone`)
contain **zero** `Serializable`-related declarations.

### Demo modules — five `PersistentUserDirectory` instances

`PersistentUserDirectory` ships in five demo modules
(`demo-jsentinel-vaadin-persistence`, `-vaadin-hardening`,
`-rest-persistence`, `-rest-hardening`,
`-standalone-persistence`). Each declares two `Serializable` records
(`StoredUser`, `UserState`).

These are **demo patterns**, not framework code. They show
consumers how to build a Vaadin-session-compatible store. The
records carry the marker because:

- Vaadin requires it for objects reachable from `VaadinSession`.
- The Eclipse-Store binary codec serializes any reachable object —
  Eclipse Store does **not** use Java serialization, but it
  happily traverses `Serializable` objects too. Operators who
  want to avoid the marker entirely can write equivalent records
  without it and use Eclipse Store's `PersistenceTypeDescription`
  mechanism instead.

### Classes that intentionally do **not** implement `Serializable`

The framework's deliberately-non-`Serializable` types include:

- `JSentinelSubject` — identity record, must not flow across a
  serialization boundary the framework does not control.
- `SecuritySubject` — its V00.70 predecessor, same rationale.
- `TokenCredential` and every sealed subtype (`BearerToken`,
  `OidcAccessToken`, `RefreshToken`, `ApiKey`) — raw token material
  must never enter a serialized payload by accident. `toString()`
  masks the raw value precisely so a stray log line cannot leak it;
  `Serializable` would defeat that mask via a broken consumer.
- `Policy`, `PolicyDecision`, `AccessContext`, `RoleName`,
  `PermissionName` — first-class authorization values, kept
  serialization-agnostic so they can be re-modelled (e.g. as JSON,
  CBOR or Eclipse-Store records) without API breaks.
- `PasswordHash`, `PasswordHashPolicy`, `SecretValue`,
  `PepperReference` — credential-related; their `toString()` and
  `AutoCloseable` machinery is the security boundary, and a
  `Serializable` marker would invite operator code that bypasses it.
- `JSentinelRuntime`, `RegisteredJSentinelService`,
  `JSentinelBootstrapWarning`, `HealthStatus` (V00.74.10) — runtime
  diagnostics; their JSON serialization in V00.74.10 is opt-in via
  `runtime.toJson()`, never via the Java mechanism.

## The two legitimate Serializable shapes

### Shape 1 — Vaadin lifecycle listeners

Vaadin's session model requires `Serializable` on listeners attached
to the session lifecycle. Two framework listeners qualify:
`AuthorizationListener` and `SessionLifetimeListener`. Both are:

- **Effectively immutable** after construction: their fields are
  `final`, populated from `JSentinelServiceResolver` at construction
  time.
- **State-free at the listener level**: they delegate to resolver
  lookups for every request, so a replicated session never carries
  meaningful state in the listener itself.
- **`writeObject` / `readObject`-free**: no custom serialization
  hooks, no `serialPersistentFields`, no `readResolve` /
  `writeReplace`. If Vaadin's container does serialize them, the
  resulting bytes are just the field references.

A `serialVersionUID` is declared explicitly to fix the binary class
identity. The literal value is meaningful only when the same JVM
serializes and deserializes — for jSentinel's purposes the UID is a
suppression of the `MissingSerialVersionUID` compiler warning, not a
versioning commitment.

### Shape 2 — `Throwable` inheritance

`Throwable` implements `Serializable`. Any custom exception inherits
that. Java exception serialization is used by:

- Logging frameworks that print a stack trace.
- Thread-pool executors that propagate failure across worker
  boundaries.
- Some application servers' error-page handlers.

`JSentinelBootstrapException` and `JSentinelPropagationException`
declare `serialVersionUID = 1L` to suppress the compiler warning.
Neither overrides `writeObject` / `readObject`; neither carries any
sensitive payload (no tokens, no credentials, no pepper material).
A serialized stack trace contains class names, line numbers and the
exception message — and the exception message is, by framework
convention, free of secrets.

## Why Eclipse Store and Canonical JSON are the chosen alternatives

The framework needs to convert object graphs to bytes in two
contexts; both consciously avoid the Java mechanism:

### Persistence — `jSentinel-persistence-eclipsestore`

Eclipse Store uses its own binary codec (`PersistenceTypeHandler`,
`BinaryHandler*`). It does **not** call `ObjectInputStream`; it
reads its own length-prefixed records driven by a type-handler
registry the operator controls. A malicious payload cannot trigger
a gadget chain through Eclipse Store because the framework
deserializes only types it has explicitly registered.

References: Eclipse Store's `PersistenceTypeDescription` is the
operator-visible contract; the persistence layer documentation in
`docs/security/credentials/playbooks/rollback-boundaries.md` covers
the rollback semantics.

V00.74.20 closes the V00.74.10-documented gap that prevented
consumer-side persistence from coexisting with the framework stores
under one directory. `JSentinelStorageFactory.openAt(...)` returns a
`JSentinelStoragePair` with a linked-lifecycle framework storage and
an application-side `EmbeddedStorageManager`. Both use the
Eclipse-Store binary codec; the JDK `ObjectOutputStream` fallback
that some consumer code resorted to in V00.74.10 (when a parallel
`users.ser` file lived next to the framework storage) is now
obsolete — the pair's app half is a fully-typed Eclipse-Store
manager and the consumer wires user-directory roots through it via
`pair.app().setRoot(...)` / `storeRoot()` like any other Eclipse
Store consumer.

### Event Bus (V00.75) — signed Canonical JSON or Eclipse Serializer

`Konzept-V00.75.00.md` §"Payload-Serialisierung" makes the explicit
choice:

- **Canonical JSON** (RFC 8785-style determinism) for interoperable
  envelopes. Parsing is done by the framework's own JSON encoder
  (V00.74.10 `JsonEncoder`, internal) on the producer side and by
  Jackson / the consumer's parser of choice on the consumer side.
- **Eclipse Serializer** for Java-to-Java deployments that want a
  binary codec without the interop overhead.

Both codecs sign the envelope (Ed25519 default, ECDSA fallback). A
mismatched signature is rejected before any payload deserialization
takes place. Java's `Serializable` is not in the codec set.

### Token propagation (V00.74) — JSON over HTTPS

The V00.74 `TokenExchangeStrategy` and `ClientCredentialsStrategy`
talk to OAuth2 token endpoints. The request body is
`application/x-www-form-urlencoded`. The response body is
`application/json`. Parsing is done by jSentinel's own small JSON
reader, not by Jackson. No `ObjectInputStream`, no `application/x-java-
serialized-object` content type ever appears on the wire.

### JWT (V00.76, planned) — JOSE compact serialization

JWTs are parsed via Nimbus JOSE+JWT, which works on the
JOSE-compact format (`base64url(header).base64url(payload).base64url(signature)`).
No `ObjectInputStream`. The Nimbus library itself is non-Serializable
on its types.

## Anti-patterns the framework rejects

The following patterns are forbidden in framework code and will be
rejected at review:

1. **`implements Serializable` on a domain record** (subject, token,
   policy, claim, credential value) without an audited Vaadin or
   `Throwable` reason. Records are otherwise fine, but the marker
   itself is a contract claim the framework does not make.
2. **Custom `writeObject` / `readObject` / `readResolve` /
   `writeReplace` methods.** No class in the framework has these,
   and none should be added. They are the primary attack surface for
   gadget chains.
3. **`Externalizable` implementations.** Same rationale.
4. **Putting an `ObjectInputStream` / `ObjectOutputStream` on a
   classpath we control.** A code review that introduces either
   class triggers automatic rejection unless the change includes a
   documented justification, a `JsonReader`-equivalent alternative
   was explicitly considered and rejected, and a Look-Ahead-Deserialization
   filter is configured (`ObjectInputFilter`) with a closed type
   allow-list.
5. **`SerializationFilter` / `ObjectInputFilter` configuration in
   the library.** The framework does not configure filters because
   it does not deserialize. Operators whose container does should
   configure the filter at the container level.
6. **Storing credentials, tokens or pepper material in a
   `Serializable` record.** Even with the Vaadin reason satisfied, a
   credential value must not become part of a serializable byte
   stream the framework controls. `TokenCredential#toString()`
   masking exists precisely to prevent this leak.

## Operator and contributor checklist

When adding or reviewing framework code:

- [ ] New `implements Serializable` declarations require a
      one-paragraph rationale tied to a Vaadin lifecycle integration
      or a `Throwable` heritage. Anything else triggers review
      rejection.
- [ ] No `writeObject`, `readObject`, `readResolve`,
      `writeReplace`, `readObjectNoData`, `Externalizable` methods.
- [ ] No `ObjectInputStream` / `ObjectOutputStream` imports outside
      tests that explicitly exercise the absence of the mechanism.
- [ ] New records carrying credentials, tokens, pepper or
      authentication state are not `Serializable`.
- [ ] The CI grep recipe (below) reports the same four library hits
      it did at V00.74.10, plus the two reviewed 00.84.00 hits in
      `jCustos-identity-oidc-vaadin`. Any new hit triggers a
      documented review.

For operators deploying the framework:

- [ ] Container session replication is either disabled or scoped to
      Vaadin's serialization contract (the four listed Vaadin
      listeners are state-free, but consumer code may not be).
- [ ] Application server's RMI / JMX / IIOP / T3 stacks are either
      disabled or fronted by a `jdk.serialFilter` allow-list.
- [ ] No JNDI lookup is exposed to user-controlled input. (Tangential
      to serialization, but the Log4Shell pattern travels in the
      same neighbourhood.)
- [ ] `application/x-java-serialized-object` is rejected at the
      ingress / API gateway.
- [ ] Custom HTTP handlers do not accept Java-serialized request
      bodies. (REST adapters in jSentinel speak JSON only — but
      consumers may add their own handlers.)
- [ ] Deployment SBOM (`sbom-and-provenance.md`) records the
      transitive presence of any library that historically appeared
      in gadget chains (`commons-collections`, `commons-beanutils`,
      `commons-fileupload`, `groovy-runtime`, `xstream`).

## Verification recipe

A repeatable check that the policy holds:

```bash
# Total Java-serialization-related markers across the reactor:
grep -rn 'implements Serializable\|extends Serializable\|java\.io\.Serializable\|ObjectOutputStream\|ObjectInputStream\|writeObject\|readObject\|Externalizable\|serialVersionUID' \
  --include='*.java' \
  jSentinel-core jSentinel-vaadin jSentinel-rest jSentinel-standalone \
  jSentinel-test jSentinel-processor jSentinel-persistence-eclipsestore \
  jSentinel-persistence-testkit jSentinel-crypto-bc jSentinel-credentials-hibp \
  jSentinel-dx jSentinel-dx-vaadin jSentinel-dx-rest jSentinel-dx-standalone \
  jSentinel-autoservice-annotations jSentinel-autoservice-processor \
  jSentinel-vaadin-starter jSentinel-propagation jSentinel-propagation-processor \
  jSentinel-propagation-oidc
```

Expected output across the library modules: exactly four matches —
the two Vaadin listeners plus the two exception classes. Since
00.84.00 `jCustos-identity-oidc-vaadin` adds two reviewed classes
(`VaadinSessionRegistryCleanup`, `AbstractOidcLogoutView.PendingLogoutTokens`,
see the survey above). Anything more triggers a documented review.

An ArchUnit rule that codifies the policy is appropriate as
project-level test infrastructure (not yet shipped):

```java
@Test
void noSerializableExceptOnAllowList() {
  ArchRuleDefinition.classes()
      .that().resideInAPackage("com.svenruppert.jsentinel..")
      .and().areNotAssignableTo(Throwable.class)
      .and().doNotImplement(VaadinServiceInitListener.class)
      .and().doNotImplement(UIInitListener.class)
      .should().notImplement(Serializable.class)
      .check(reactor);
}
```

Consumers are encouraged to add this rule to their own CI when their
domain types carry credentials or tokens.

## What this framework guarantees

| Statement |
|-----------|
| No framework code calls `ObjectInputStream.readObject` or `ObjectOutputStream.writeObject`. |
| No framework class implements `Externalizable`. |
| No framework class declares `writeObject`, `readObject`, `readResolve`, `writeReplace` or `readObjectNoData`. |
| No framework class declares `serialPersistentFields`. |
| No framework persistence path uses Java serialization (Eclipse Store ships its own binary codec). |
| No framework HTTP path accepts or produces `application/x-java-serialized-object`. |
| `TokenCredential`, `JSentinelSubject`, `PasswordHash`, `SecretValue`, `PepperReference` are not `Serializable`. |
| Sensitive fields are masked by `toString()` and not exposed through any framework-controlled serialization mechanism. |

## What this framework does not claim

- It does **not** prevent the host application server from
  serializing framework objects via Vaadin's session-replication
  contract. Operators control that.
- It does **not** filter or wrap `ObjectInputStream` traffic that
  consumer code might initiate.
- It does **not** audit consumer code that adds `implements
  Serializable` to its own domain records.
- It does **not** validate that the JVM's `jdk.serialFilter`,
  `jdk.serialFilterFactory` or
  `jdk.includeInExceptions` are configured.
- It does **not** prevent a misconfigured RMI / JMX / IIOP / T3
  endpoint on the host JVM from exposing a gadget chain.
- It does **not** sandbox consumer-supplied `JSentinelEventListener`
  implementations against malicious behaviour. The Event Bus
  signature check (V00.75) is the operative defence; consumer
  listeners run with the host JVM's privileges.

## Outlook

- **V00.75 (Event Bus)** preserves the policy: signed Canonical JSON
  or Eclipse Serializer; never Java serialization. The Replay-Schutz
  and the per-producer sequence guarantees rely on signature
  verification, not on a deserialization-time filter.
- **V00.76 (jSentinel-jwt)** preserves the policy: JOSE compact
  format via Nimbus, no `ObjectInputStream`.
- **V00.77 (OAuth2 RP flows)** preserves the policy: form-encoded
  request bodies, JSON response bodies, no Java serialization on the
  wire or in the cache.
- **V00.78 (OIDC RP)** preserves the policy: Discovery and UserInfo
  responses are JSON; ID-Token payloads are signed JWT.
- **V00.79 (Federation hardening)** preserves the policy: DPoP
  proofs are signed JWT; mTLS, PAR, JAR are all JOSE/JSON paths.
  Vendor profile modules do not introduce Java serialization.
- **V00.80 (MFA / WebAuthn / Device Management)** preserves the
  policy: WebAuthn attestation parsing is CBOR-based and follows
  the WebAuthn spec; the device store uses Eclipse Store's binary
  codec.

The serialization policy is therefore expected to hold without
modification through V00.80. If a future release introduces an
active Java-serialization data path, this document must be
rewritten — not amended.

## Maintenance

This document is updated when:

- A new `Serializable` declaration is added to any framework
  library module.
- A new persistence module is introduced that requires a serialization
  codec choice.
- A new HTTP path is introduced that could accept or produce
  Java-serialized data.
- The Vaadin or JDK version bump changes the surrounding
  serialization contract.

The verification recipe in §"Verification recipe" is run before
every minor release; its output is recorded against the running
`RELEASE-NOTES-*.md` for that release.

## References

- CWE-502 — Deserialization of Untrusted Data
  (https://cwe.mitre.org/data/definitions/502.html)
- CWE-915 — Improperly Controlled Modification of
  Dynamically-Determined Object Attributes
  (https://cwe.mitre.org/data/definitions/915.html)
- JEP 290 — Filter Incoming Serialization Data
  (`jdk.serialFilter`, `ObjectInputFilter`)
- JEP 415 — Context-Specific Deserialization Filters
- Konzept-V00.75.00 §"Payload-Serialisierung"
- Konzept-V00.74.10 §3 — `JsonEncoder` invariants
- `docs/security/credentials/standards/fips-profile.md` —
  cryptographic provider posture
- `docs/security/credentials/standards/jdk-distribution-trust.md` —
  JCA primitive surface
