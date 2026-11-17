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
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.events.replay.InMemoryReplayStore;
import eu.jsentinel.jcustos.events.sequence.InMemorySequenceStore;
import eu.jsentinel.jcustos.events.sequence.SequenceValidator;
import eu.jsentinel.jcustos.events.sequence.SequenceViolationStrategy;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithms;
import eu.jsentinel.jcustos.events.store.InMemoryDeadLetterStore;
import eu.jsentinel.jcustos.events.store.JCustosEventDeadLetter;
import eu.jsentinel.jcustos.events.store.RejectionReason;
import eu.jsentinel.jcustos.events.types.DeadLetteredEvent;
import eu.jsentinel.jcustos.events.types.EnvelopeRejectedEvent;
import eu.jsentinel.jcustos.events.types.EventBusSelfObservabilityEvent;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ER27 (CWE-770): the producer chooses {@code expiresAt}, the consumer
 * remembers an accepted envelope id until then. The consumer bounds the
 * acceptance window itself. Every envelope here is signed by a real
 * {@link PublishPipeline} with a real key — only the time to live and the
 * producer's clock differ. No mocks.
 */
@DisplayName("ConsumePipeline — maximum acceptance window (ER27)")
class AcceptanceWindowTest {

  private static final Instant T0 = BusFixtures.T0;
  private static final Duration HUNDRED_YEARS = Duration.ofDays(36_525);
  private static final TenantId ACME = TenantId.of("acme");

  private final BusFixtures fx = new BusFixtures();

  /** A producer holding the bound key, signing with {@code ttl} on a clock at {@code issuedAt}. */
  private SignedJCustosEventEnvelope signed(Duration ttl, Instant issuedAt, TenantId tenant) {
    PublishPipeline producer = new PublishPipeline(fx.keyManagement,
        new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec(),
        PayloadHashAlgorithm.SHA_256, BusFixtures.PRODUCER, new InMemorySequenceStore(),
        new InMemoryReplayStore(), fx.allowAll, ttl, () -> issuedAt);
    return producer.toEnvelope(new LoginSucceededEvent(
        EventMetadata.create(tenant, SubjectId.of("alice"), T0, JCustosEventSeverity.INFO),
        "password"));
  }

  private SignedJCustosEventEnvelope signed(Duration ttl, Instant issuedAt) {
    return signed(ttl, issuedAt, TenantId.DEFAULT);
  }

  private ConsumePipeline consumer(Duration maxAcceptanceWindow, InMemoryReplayStore replay,
      InMemorySequenceStore sequence) {
    return new ConsumePipeline(fx.keyManagement, SignatureAlgorithms.defaults(), replay,
        sequence, new SequenceValidator(), SequenceViolationStrategy.REJECT, fx.allowAll,
        List.of(new CanonicalJsonPayloadCodec()), maxAcceptanceWindow);
  }

  @Test
  @DisplayName("a correctly signed envelope valid for a hundred years is rejected; neither replay store nor sequence moves")
  void hundredYearWindowIsRejectedWithoutSideEffects() {
    SignedJCustosEventEnvelope pinned = signed(HUNDRED_YEARS, T0);

    JCustosEventVerificationResult result = fx.consumePipeline().verify(pinned, T0);

    JCustosEventVerificationResult.AcceptanceWindowExceeded rejected = assertInstanceOf(
        JCustosEventVerificationResult.AcceptanceWindowExceeded.class, result);
    assertEquals(pinned.envelopeId(), rejected.envelopeId());
    assertEquals(T0, rejected.issuedAt());
    assertEquals(T0.plus(HUNDRED_YEARS), rejected.expiresAt());
    assertEquals(ConsumePipeline.DEFAULT_MAX_ACCEPTANCE_WINDOW, rejected.maxAcceptanceWindow());
    assertTrue(result.envelopeAuthenticated(), "the signature verified under a bound key");
    assertFalse(fx.consumeReplay.hasSeen(pinned.envelopeId()),
        "the id must not occupy the replay store");
    assertEquals(0, fx.consumeReplay.size());
    assertTrue(fx.consumeSequence.lastSequence(TenantId.DEFAULT, BusFixtures.PRODUCER).isEmpty(),
        "the rejected envelope must not advance the producer's sequence");

    // Its sequence was not consumed: the producer's next envelope, signed
    // within the window, carries the same first sequence and is accepted.
    SignedJCustosEventEnvelope inWindow = signed(Duration.ofMinutes(5), T0);
    assertEquals(pinned.sequence(), inWindow.sequence());
    assertTrue(fx.consumePipeline().verify(inWindow, T0).isValid());
    assertTrue(fx.consumeReplay.hasSeen(inWindow.envelopeId()));
  }

  @Test
  @DisplayName("a window of exactly the maximum is accepted, one second more is rejected")
  void maximumIsInclusive() {
    Duration max = Duration.ofMinutes(10);

    InMemoryReplayStore replay = new InMemoryReplayStore();
    assertTrue(consumer(max, replay, new InMemorySequenceStore())
        .verify(signed(max, T0), T0).isValid());
    assertEquals(1, replay.size());

    InMemoryReplayStore tooLongReplay = new InMemoryReplayStore();
    assertInstanceOf(JCustosEventVerificationResult.AcceptanceWindowExceeded.class,
        consumer(max, tooLongReplay, new InMemorySequenceStore())
            .verify(signed(max.plusSeconds(1), T0), T0));
    assertEquals(0, tooLongReplay.size());
  }

  @Test
  @DisplayName("an issuedAt in the future keeps the declared window short but is rejected on the window left")
  void futureIssuedAtIsRejectedOnTheRemainingWindow() {
    SignedJCustosEventEnvelope futureDated =
        signed(Duration.ofMinutes(5), T0.plus(Duration.ofDays(365)));
    assertEquals(Duration.ofMinutes(5),
        Duration.between(futureDated.issuedAt(), futureDated.expiresAt()),
        "the declared window alone fits");

    assertInstanceOf(JCustosEventVerificationResult.AcceptanceWindowExceeded.class,
        fx.consumePipeline().verify(futureDated, T0));
    assertFalse(fx.consumeReplay.hasSeen(futureDated.envelopeId()));
  }

  @Test
  @DisplayName("a declared window beyond the maximum is rejected even when the window left would fit")
  void declaredWindowCountsOnLateDelivery() {
    SignedJCustosEventEnvelope twoHours = signed(Duration.ofHours(2), T0);
    Instant late = T0.plus(Duration.ofMinutes(90));
    assertTrue(Duration.between(late, twoHours.expiresAt())
        .compareTo(ConsumePipeline.DEFAULT_MAX_ACCEPTANCE_WINDOW) < 0,
        "the window left alone fits");

    assertInstanceOf(JCustosEventVerificationResult.AcceptanceWindowExceeded.class,
        fx.consumePipeline().verify(twoHours, late));
    assertFalse(fx.consumeReplay.hasSeen(twoHours.envelopeId()));
  }

  @Test
  @DisplayName("the bound stays total at the ends of the instant range")
  void boundIsTotalAtExtremeInstants() {
    SignedJCustosEventEnvelope untilTheEnd = signed(Duration.between(T0, Instant.MAX), T0);
    assertEquals(Instant.MAX, untilTheEnd.expiresAt());

    assertInstanceOf(JCustosEventVerificationResult.AcceptanceWindowExceeded.class,
        fx.consumePipeline().verify(untilTheEnd, T0));
    assertInstanceOf(JCustosEventVerificationResult.AcceptanceWindowExceeded.class,
        fx.consumePipeline().verify(signed(Duration.ofMinutes(5), T0), Instant.MIN));
    assertEquals(0, fx.consumeReplay.size());
  }

  @Test
  @DisplayName("an envelope past its expiry is reported as Expired, whatever its window")
  void expiryIsCheckedFirst() {
    SignedJCustosEventEnvelope old = signed(HUNDRED_YEARS, T0.minus(Duration.ofDays(73_050)));

    assertInstanceOf(JCustosEventVerificationResult.Expired.class,
        fx.consumePipeline().verify(old, T0));
  }

  @Test
  @DisplayName("the default is one hour, every constructor without a maximum uses it, and the maximum must be positive")
  void defaultAndConfiguredMaximum() {
    assertEquals(Duration.ofHours(1), ConsumePipeline.DEFAULT_MAX_ACCEPTANCE_WINDOW);
    assertEquals(ConsumePipeline.DEFAULT_MAX_ACCEPTANCE_WINDOW,
        fx.consumePipeline().maxAcceptanceWindow());
    assertEquals(ConsumePipeline.DEFAULT_MAX_ACCEPTANCE_WINDOW,
        new ConsumePipeline(fx.keyManagement, SignatureAlgorithms.defaults(), fx.consumeReplay,
            fx.consumeSequence, new SequenceValidator(), SequenceViolationStrategy.REJECT,
            fx.allowAll, List.of(new CanonicalJsonPayloadCodec())).maxAcceptanceWindow());
    assertEquals(Duration.ofDays(2), consumer(Duration.ofDays(2), fx.consumeReplay,
        fx.consumeSequence).maxAcceptanceWindow());

    // A consumer of producers with a longer time to live raises the maximum.
    assertTrue(consumer(Duration.ofDays(2), new InMemoryReplayStore(),
        new InMemorySequenceStore()).verify(signed(Duration.ofDays(1), T0), T0).isValid());

    assertThrows(IllegalArgumentException.class,
        () -> consumer(Duration.ZERO, fx.consumeReplay, fx.consumeSequence));
    assertThrows(IllegalArgumentException.class,
        () -> consumer(Duration.ofSeconds(-1), fx.consumeReplay, fx.consumeSequence));
    assertThrows(NullPointerException.class,
        () -> consumer(null, fx.consumeReplay, fx.consumeSequence));
  }

  @Test
  @DisplayName("the rejection is reported like an authenticated time-window failure: event, dead letter, no throttle")
  void rejectionTakesTheExistingFailurePath() {
    SignedJCustosEventEnvelope pinned = signed(HUNDRED_YEARS, T0, ACME);
    JCustosEventVerificationResult result = fx.consumePipeline().verify(pinned, T0);
    assertInstanceOf(JCustosEventVerificationResult.AcceptanceWindowExceeded.class, result);

    List<EventBusSelfObservabilityEvent> events = new ArrayList<>();
    InMemoryDeadLetterStore deadLetters = new InMemoryDeadLetterStore();
    // No budget at all for keyless junk: an authenticated rejection is still reported.
    ConsumeFailureHandler handler = new ConsumeFailureHandler(
        ConsumeFailurePolicy.operationalDefaults(), deadLetters, events::add, () -> T0,
        0, Duration.ofMinutes(1));

    assertEquals(ConsumeFailureAction.REJECT_AND_DEAD_LETTER, handler.handle(pinned, result));

    assertEquals(2, events.size(), "the rejection event plus the dead-letter event");
    EnvelopeRejectedEvent rejected = assertInstanceOf(EnvelopeRejectedEvent.class, events.get(0));
    assertEquals(SelfObservabilityEvents.REASON_ACCEPTANCE_WINDOW_EXCEEDED, rejected.reason());
    assertEquals(pinned.envelopeId().value(), rejected.rejectedEnvelopeId());
    assertEquals(ACME, rejected.tenantId(), "the envelope is authenticated, its tenant a fact");
    assertFalse(SelfObservabilityEvents.isUnauthenticatedRejection(rejected));
    assertInstanceOf(DeadLetteredEvent.class, events.get(1));
    assertEquals(0, handler.suppressedUnauthenticatedCount());

    List<JCustosEventDeadLetter> open = deadLetters.findOpen(10);
    assertEquals(1, open.size());
    assertEquals(RejectionReason.EXPIRED, open.get(0).reason());

    assertEquals(ConsumeFailureAction.REJECT, ConsumeFailurePolicy.strict().actionFor(result));
  }

  @Test
  @DisplayName("a publish pipeline with a negative time to live fails at wiring time")
  void negativeTtlIsRefused() {
    assertThrows(IllegalArgumentException.class, () -> new PublishPipeline(fx.keyManagement,
        new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec(),
        PayloadHashAlgorithm.SHA_256, BusFixtures.PRODUCER, new InMemorySequenceStore(),
        new InMemoryReplayStore(), fx.allowAll, Duration.ofSeconds(-1), () -> T0));
    assertDoesNotThrow(() -> signed(Duration.ZERO, T0));
  }
}
