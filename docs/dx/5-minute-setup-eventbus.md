# 5-Minute Setup — jCustos Security Event Bus (V00.75)

Wire a signed, replay-protected Security Event Bus into a JDK app in five
minutes. Everything below uses only `jCustos-events` (the SPI core);
persistence and the REST/SSE bridge are opt-in add-ons at the end.

## 1. Dependency

```xml
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-events</artifactId>
  <version>00.75.00</version>
</dependency>
```

## 2. Wire the publisher + bus

```java
// Keys: in-memory Ed25519 for local setups (swap for JdkKeyStoreKeyManagement
// in production — same SPI). Since 00.84.00 a key signs only for the producer
// it is bound to: name the keystore alias after the producer id or declare it
// with withProducerBinding(...) (JS-SEC-101).
var keys = new InMemoryKeyManagement(new Ed25519SignatureAlgorithm(), KeyId.of("eventbus-1"));

// Who is allowed to publish what.
var producer = EventProducerId.of("my-service");
var policy = AllowListProducerPolicy.builder()
    .allow(producer, LoginSucceededEvent.TYPE)
    .allow(producer, SessionRevokedEvent.TYPE)
    .build();

// The publish pipeline: canonicalize -> hash -> sign -> replay-mark.
var publish = new PublishPipeline(
    keys, new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec(),
    PayloadHashAlgorithm.SHA_256, producer,
    new InMemorySequenceStore(), new InMemoryReplayStore(), policy,
    Duration.ofMinutes(5), Instant::now);

var bus = new DefaultJCustosEventBus(publish);
```

## 3. Subscribe + publish

```java
// sessionId() is a session reference ("sref-…", 00.84.00): match it
// against SessionRef.of(id) of the sessions you hold.
bus.subscribe(SessionRevokedEvent.class, e ->
    System.out.println("revoke UI session " + e.sessionId()));

var meta = EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"),
    Instant.now(), JCustosEventSeverity.INFO);
bus.publish(new LoginSucceededEvent(meta, "password"));
```

`publish` signs the event into a `SignedJCustosEventEnvelope` and dispatches
the typed event to local listeners. A failing listener is isolated by default
(`ISOLATE_AND_CONTINUE`) and reported as a `ListenerFailedEvent`.

## 4. Audit on the bus

Audit is a *consumer*, not hard-wired:

```java
JCustosAuditService audit = /* your audit service */;
new AuditEventBusListener(audit).subscribeTo(bus);
```

`LoginSucceeded` / `LoginFailed` / `PermissionDenied` events are mapped to the
core `AuditEvent` model; a throwing audit sink is isolated.

## 5. Verify an incoming envelope (consumer side)

A remote consumer (e.g. a Vaadin app) verifies envelopes it receives:

```java
var consume = new ConsumePipeline(
    keys /* the matching public keys */, SignatureAlgorithms.defaults(),
    new InMemoryReplayStore(), new InMemorySequenceStore(),
    new SequenceValidator(), SequenceViolationStrategy.REJECT, policy);

JCustosEventVerificationResult result = consume.verify(envelope, Instant.now());
if (result instanceof JCustosEventVerificationResult.Valid valid) {
  /* react on valid.payload() — the decoded, checked payload */
}
// else: InvalidSignature / UnknownKey / KeyRevoked / KeyExpired / Expired /
//       PayloadHashMismatch / ReplayDetected / SequenceViolation / ProducerNotAllowed /
//       KeyNotAuthorizedForProducer / PayloadMetadataMismatch
```

Since 00.84.00 the pipeline checks that the verifying key is bound to the
claimed producer (`KeyNotAuthorizedForProducer`, JS-SEC-101) and that the
payload describes the event the envelope announces (`PayloadMetadataMismatch`,
JS-SEC-107); read the event from `Valid.payload()` instead of decoding
`canonicalPayload` yourself. A fresh sequence scope accepts only the first
sequence (`SequenceValidator.DEFAULT_MAX_INITIAL_SEQUENCE`, JS-SEC-105): a
consumer that joins a running producer with an empty sequence store seeds the
scope with `updateSequence` or uses
`new SequenceValidator(maxInitialSequence, maxTolerableGap)`.

## 6. Opt-in: persistence + REST/SSE bridge

* **Persistent, restart-safe stores** — add `jCustos-events-persistence-eclipsestore`
  and swap the in-memory stores for `EclipseStoreEventStorage.openAt(dir)`'s
  `replayStore()` / `sequenceStore()` / `envelopeStore()` / `deadLetterStore()`.
* **REST/SSE bridge** — add `jCustos-events-rest`, register
  `SseStreamHttpHandler` at `GET /api/events/stream` (replay-from-cursor + live
  tail) and `EventPublishHttpHandler` at `POST /api/events` (permission-gated,
  runs the consume pipeline). The channel itself is secured by HTTPS / mTLS —
  the bridge does not encrypt it. Since 00.84.00 both handlers are built with
  a guard from `EventsRestGuard.of(resolver, permission)`, which runs the REST
  filter chain (JS-SEC-115): `SseStreamHttpHandler.builder(broadcaster, codec,
  guard).subscriptionScope(...)` delivers each subscriber only the tenants it
  may read (JS-SEC-102), and `EventPublishHttpHandler.builder(service,
  guard).producerBinding(...)` names the producers a caller may submit for —
  the deprecated constructors bind nobody, so every submission through them is
  refused (JS-SEC-101).

## 7. Feature flag

Emission from existing services is gated by `jcustos.events.bus.enabled`
(default off) via `FeatureFlaggedEventPublisher`, so legacy direct-audit
deployments are unaffected until you opt in.

---

All V00.75 types carry `@ExperimentalJCustosApi`; stable-API promotion is
staged for a later release after demo adoption.
