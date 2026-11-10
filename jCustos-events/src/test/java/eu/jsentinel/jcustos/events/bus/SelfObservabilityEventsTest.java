package eu.jsentinel.jcustos.events.bus;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.types.EnvelopeRejectedEvent;
import eu.jsentinel.jcustos.events.types.EventBusSelfObservabilityEvent;
import eu.jsentinel.jcustos.events.types.ReplayDetectedEvent;
import eu.jsentinel.jcustos.events.types.SequenceViolationEvent;
import eu.jsentinel.jcustos.events.types.SignatureInvalidEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Instant;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

@DisplayName("SelfObservabilityEvents")
class SelfObservabilityEventsTest {

  private static final Instant NOW = Instant.parse("2026-07-19T12:00:00Z");

  /** One real signed envelope through the real pipeline — no mocks. */
  private static final SignedJCustosEventEnvelope ENVELOPE =
      new BusFixtures().publishPipeline().toEnvelope(BusFixtures.event());

  @Test
  @DisplayName("Valid maps to no event at all")
  void validMapsToEmpty() {
    Optional<EventBusSelfObservabilityEvent> mapped = SelfObservabilityEvents.fromVerification(
        new JCustosEventVerificationResult.Valid(ENVELOPE), ENVELOPE, NOW);
    assertTrue(mapped.isEmpty());
  }

  @Test
  @DisplayName("the REASON_* constants are pinned literally")
  void reasonConstantsArePinned() {
    assertEquals("unknown-key", SelfObservabilityEvents.REASON_UNKNOWN_KEY);
    assertEquals("key-revoked", SelfObservabilityEvents.REASON_KEY_REVOKED);
    assertEquals("key-expired", SelfObservabilityEvents.REASON_KEY_EXPIRED);
    assertEquals("expired", SelfObservabilityEvents.REASON_EXPIRED);
    assertEquals("producer-not-allowed", SelfObservabilityEvents.REASON_PRODUCER_NOT_ALLOWED);
    assertEquals("key-not-authorized-for-producer",
        SelfObservabilityEvents.REASON_KEY_NOT_AUTHORIZED);
    assertEquals("payload-metadata-mismatch",
        SelfObservabilityEvents.REASON_PAYLOAD_METADATA_MISMATCH);
  }

  static Stream<Arguments> failureCases() {
    return Stream.of(
        arguments("InvalidSignature",
            new JCustosEventVerificationResult.InvalidSignature("signature does not verify"),
            SignatureInvalidEvent.class, JCustosEventSeverity.ERROR),
        arguments("PayloadHashMismatch",
            new JCustosEventVerificationResult.PayloadHashMismatch(ENVELOPE.envelopeId()),
            SignatureInvalidEvent.class, JCustosEventSeverity.ERROR),
        arguments("ReplayDetected",
            new JCustosEventVerificationResult.ReplayDetected(ENVELOPE.envelopeId()),
            ReplayDetectedEvent.class, JCustosEventSeverity.CRITICAL),
        arguments("SequenceViolation",
            new JCustosEventVerificationResult.SequenceViolation(ENVELOPE.tenantId(),
                ENVELOPE.producerId(), EventSequence.of(4), EventSequence.of(2)),
            SequenceViolationEvent.class, JCustosEventSeverity.ERROR),
        arguments("UnknownKey",
            new JCustosEventVerificationResult.UnknownKey(ENVELOPE.keyId()),
            EnvelopeRejectedEvent.class, JCustosEventSeverity.ERROR),
        arguments("KeyRevoked",
            new JCustosEventVerificationResult.KeyRevoked(ENVELOPE.keyId()),
            EnvelopeRejectedEvent.class, JCustosEventSeverity.ERROR),
        arguments("KeyExpired",
            new JCustosEventVerificationResult.KeyExpired(ENVELOPE.keyId()),
            EnvelopeRejectedEvent.class, JCustosEventSeverity.ERROR),
        arguments("Expired",
            new JCustosEventVerificationResult.Expired(ENVELOPE.expiresAt()),
            EnvelopeRejectedEvent.class, JCustosEventSeverity.ERROR),
        arguments("ProducerNotAllowed",
            new JCustosEventVerificationResult.ProducerNotAllowed(ENVELOPE.producerId(),
                ENVELOPE.eventType(), ENVELOPE.tenantId()),
            EnvelopeRejectedEvent.class, JCustosEventSeverity.ERROR),
        arguments("KeyNotAuthorizedForProducer",
            new JCustosEventVerificationResult.KeyNotAuthorizedForProducer(ENVELOPE.keyId(),
                ENVELOPE.producerId(), ENVELOPE.tenantId()),
            EnvelopeRejectedEvent.class, JCustosEventSeverity.ERROR),
        arguments("PayloadMetadataMismatch",
            new JCustosEventVerificationResult.PayloadMetadataMismatch(ENVELOPE.envelopeId(),
                ConsumePipeline.FIELD_EVENT_TYPE),
            EnvelopeRejectedEvent.class, JCustosEventSeverity.ERROR));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("failureCases")
  @DisplayName("every failure maps to exactly one event of the most specific type")
  void everyFailureMapsToExactlyOneEvent(String name,
      JCustosEventVerificationResult result,
      Class<? extends EventBusSelfObservabilityEvent> expectedType,
      JCustosEventSeverity expectedSeverity) {
    Optional<EventBusSelfObservabilityEvent> mapped =
        SelfObservabilityEvents.fromVerification(result, ENVELOPE, NOW);
    // Optional<EventBusSelfObservabilityEvent> IS the exactly-one contract:
    // a failure never yields zero events and can never yield two.
    assertTrue(mapped.isPresent(), name + " must map to an event");
    EventBusSelfObservabilityEvent event = mapped.get();
    assertInstanceOf(expectedType, event);
    assertEquals(expectedSeverity, event.severity());
    assertEquals(ENVELOPE.tenantId(), event.tenantId(), "tenant propagated from envelope");
    assertEquals(JCustosEvent.SYSTEM_SUBJECT, event.subjectId());
    assertEquals(NOW, event.occurredAt());
  }

  static Stream<Arguments> rejectionReasonCases() {
    return Stream.of(
        arguments("UnknownKey",
            new JCustosEventVerificationResult.UnknownKey(ENVELOPE.keyId()), "unknown-key"),
        arguments("KeyRevoked",
            new JCustosEventVerificationResult.KeyRevoked(ENVELOPE.keyId()), "key-revoked"),
        arguments("KeyExpired",
            new JCustosEventVerificationResult.KeyExpired(ENVELOPE.keyId()), "key-expired"),
        arguments("Expired",
            new JCustosEventVerificationResult.Expired(ENVELOPE.expiresAt()), "expired"),
        arguments("ProducerNotAllowed",
            new JCustosEventVerificationResult.ProducerNotAllowed(ENVELOPE.producerId(),
                ENVELOPE.eventType(), ENVELOPE.tenantId()), "producer-not-allowed"),
        arguments("KeyNotAuthorizedForProducer",
            new JCustosEventVerificationResult.KeyNotAuthorizedForProducer(ENVELOPE.keyId(),
                ENVELOPE.producerId(), ENVELOPE.tenantId()),
            "key-not-authorized-for-producer"),
        arguments("PayloadMetadataMismatch",
            new JCustosEventVerificationResult.PayloadMetadataMismatch(ENVELOPE.envelopeId(),
                ConsumePipeline.FIELD_TENANT_ID), "payload-metadata-mismatch"));
  }

  @ParameterizedTest(name = "{0} -> {2}")
  @MethodSource("rejectionReasonCases")
  @DisplayName("the rejection family carries the literal reason and the envelope id")
  void rejectionFamilyCarriesReasonAndEnvelopeId(String name,
      JCustosEventVerificationResult result, String expectedReason) {
    EnvelopeRejectedEvent event = (EnvelopeRejectedEvent) SelfObservabilityEvents
        .fromVerification(result, ENVELOPE, NOW).orElseThrow();
    assertEquals(expectedReason, event.reason());
    // JS-SEC-104: the id is a fact only once the envelope is authenticated.
    String id = ENVELOPE.envelopeId().value();
    assertEquals(result.envelopeAuthenticated() ? id : "unverified:" + id,
        event.rejectedEnvelopeId());
  }

  @Test
  @DisplayName("InvalidSignature and PayloadHashMismatch both carry the claimed envelope id, marked unverified")
  void signatureFamilyCarriesEnvelopeId() {
    SignatureInvalidEvent fromSignature = (SignatureInvalidEvent) SelfObservabilityEvents
        .fromVerification(new JCustosEventVerificationResult.InvalidSignature("bad"),
            ENVELOPE, NOW)
        .orElseThrow();
    assertEquals("unverified:" + ENVELOPE.envelopeId().value(), fromSignature.envelopeId());

    SignatureInvalidEvent fromHash = (SignatureInvalidEvent) SelfObservabilityEvents
        .fromVerification(
            new JCustosEventVerificationResult.PayloadHashMismatch(ENVELOPE.envelopeId()),
            ENVELOPE, NOW)
        .orElseThrow();
    assertEquals("unverified:" + ENVELOPE.envelopeId().value(), fromHash.envelopeId());
  }

  @Test
  @DisplayName("ReplayDetected carries the replayed envelope id")
  void replayCarriesEnvelopeId() {
    ReplayDetectedEvent event = (ReplayDetectedEvent) SelfObservabilityEvents
        .fromVerification(
            new JCustosEventVerificationResult.ReplayDetected(ENVELOPE.envelopeId()),
            ENVELOPE, NOW)
        .orElseThrow();
    assertEquals(ENVELOPE.envelopeId().value(), event.replayedEnvelopeId());
  }

  @Test
  @DisplayName("SequenceViolation maps producer, expected and actual")
  void sequenceViolationMapsComponents() {
    SequenceViolationEvent event = (SequenceViolationEvent) SelfObservabilityEvents
        .fromVerification(
            new JCustosEventVerificationResult.SequenceViolation(ENVELOPE.tenantId(),
                ENVELOPE.producerId(), EventSequence.of(4), EventSequence.of(2)),
            ENVELOPE, NOW)
        .orElseThrow();
    assertEquals(ENVELOPE.producerId().value(), event.producerId());
    assertEquals(4, event.expected());
    assertEquals(2, event.actual());
  }

  /** The junk of JS-SEC-104: nothing in it is authentic, least of all the tenant. */
  private static SignedJCustosEventEnvelope claiming(String tenant, String envelopeId) {
    return BusFixtures.rebuild(ENVELOPE)
        .tenantId(TenantId.of(tenant))
        .envelopeId(EventEnvelopeId.of(envelopeId))
        .keyId(KeyId.of("nope"))
        .build();
  }

  private interface FailureOf
      extends Function<SignedJCustosEventEnvelope, JCustosEventVerificationResult> {
  }

  static Stream<Arguments> unauthenticatedCases() {
    return Stream.of(
        arguments("InvalidSignature", (FailureOf) junk ->
            new JCustosEventVerificationResult.InvalidSignature("bad")),
        arguments("PayloadHashMismatch", (FailureOf) junk ->
            new JCustosEventVerificationResult.PayloadHashMismatch(junk.envelopeId())),
        arguments("UnknownKey", (FailureOf) junk ->
            new JCustosEventVerificationResult.UnknownKey(junk.keyId())),
        arguments("KeyRevoked", (FailureOf) junk ->
            new JCustosEventVerificationResult.KeyRevoked(junk.keyId())),
        arguments("KeyExpired", (FailureOf) junk ->
            new JCustosEventVerificationResult.KeyExpired(junk.keyId())),
        arguments("KeyNotAuthorizedForProducer", (FailureOf) junk ->
            new JCustosEventVerificationResult.KeyNotAuthorizedForProducer(junk.keyId(),
                junk.producerId(), junk.tenantId())));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("unauthenticatedCases")
  @DisplayName("JS-SEC-104: a rejection before authentication adopts neither tenant nor full envelope id")
  void unauthenticatedRejectionAdoptsNoEnvelopeField(String name, FailureOf failure) {
    String longId = "A".repeat(100_000);
    SignedJCustosEventEnvelope junk = claiming("victim-tenant", longId);
    JCustosEventVerificationResult result = failure.apply(junk);

    EventBusSelfObservabilityEvent event =
        SelfObservabilityEvents.fromVerification(result, junk, NOW).orElseThrow();

    assertFalse(result.envelopeAuthenticated(), name);
    assertEquals(TenantId.DEFAULT, event.tenantId(),
        name + ": the event must not be raised under the tenant the junk claims");
    assertTrue(SelfObservabilityEvents.isUnauthenticatedRejection(event), name);
    String reportedId = event instanceof SignatureInvalidEvent signature
        ? signature.envelopeId()
        : ((EnvelopeRejectedEvent) event).rejectedEnvelopeId();
    assertEquals("unverified:" + "A".repeat(64), reportedId,
        name + ": the claimed id is marked and clipped to 64 characters");
  }

  static Stream<Arguments> authenticatedCases() {
    SignedJCustosEventEnvelope tenantEnvelope = claiming("acme", "env-acme");
    return Stream.of(
        arguments("Expired",
            new JCustosEventVerificationResult.Expired(tenantEnvelope.expiresAt())),
        arguments("ReplayDetected",
            new JCustosEventVerificationResult.ReplayDetected(tenantEnvelope.envelopeId())),
        arguments("SequenceViolation",
            new JCustosEventVerificationResult.SequenceViolation(tenantEnvelope.tenantId(),
                tenantEnvelope.producerId(), EventSequence.of(4), EventSequence.of(2))),
        arguments("ProducerNotAllowed",
            new JCustosEventVerificationResult.ProducerNotAllowed(tenantEnvelope.producerId(),
                tenantEnvelope.eventType(), tenantEnvelope.tenantId())),
        arguments("PayloadMetadataMismatch",
            new JCustosEventVerificationResult.PayloadMetadataMismatch(
                tenantEnvelope.envelopeId(), ConsumePipeline.FIELD_SUBJECT_ID)));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("authenticatedCases")
  @DisplayName("JS-SEC-104: a rejection of an authenticated envelope keeps its tenant")
  void authenticatedRejectionKeepsTenant(String name, JCustosEventVerificationResult result) {
    SignedJCustosEventEnvelope tenantEnvelope = claiming("acme", "env-acme");

    EventBusSelfObservabilityEvent event =
        SelfObservabilityEvents.fromVerification(result, tenantEnvelope, NOW).orElseThrow();

    assertTrue(result.envelopeAuthenticated(), name);
    assertEquals(TenantId.of("acme"), event.tenantId(), name);
    assertFalse(SelfObservabilityEvents.isUnauthenticatedRejection(event), name);
  }

  @Test
  @DisplayName("JS-SEC-104: unverifiedId clips on code points and never splits a surrogate pair")
  void unverifiedIdClipsOnCodePoints() {
    String emoji = new String(Character.toChars(0x1F600));
    String clipped = SelfObservabilityEvents.unverifiedId(emoji.repeat(100));
    assertEquals("unverified:" + emoji.repeat(64), clipped);
    assertEquals("unverified:short", SelfObservabilityEvents.unverifiedId("short"));
  }
}
