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
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventCategory;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.PayloadCodecException;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.events.keys.JCustosEventSigningKeyProvider;
import eu.jsentinel.jcustos.events.sequence.SequenceValidator;
import eu.jsentinel.jcustos.events.sequence.SequenceViolationStrategy;
import eu.jsentinel.jcustos.events.signature.EcdsaP256SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.Ed25519SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithms;
import eu.jsentinel.jcustos.events.store.InMemoryEnvelopeStore;
import eu.jsentinel.jcustos.events.store.JCustosEventCursor;
import eu.jsentinel.jcustos.events.store.JCustosEventEnvelopeStore;
import eu.jsentinel.jcustos.events.store.StoredEnvelope;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-108: a failed publish must not leave a hole in the producer's
 * sequence, and a hole that does occur must be healable on the consumer.
 * Real pipelines and in-memory stores. No mocks — the failing signer is a
 * hand-written key provider that pairs an Ed25519 algorithm with an EC key.
 */
@DisplayName("Sequence gaps — avoided on publish, healable on consume (JS-SEC-108)")
class SequenceGapHealingTest {

  /** An application event the canonicaliser refuses: a List component (R016). */
  private record BrokenAppEvent(EventMetadata metadata, List<String> tags)
      implements JCustosEvent {
    static final EventType TYPE = EventType.of("LoginSucceeded");

    @Override
    public EventType eventType() {
      return TYPE;
    }

    @Override
    public JCustosEventCategory category() {
      return JCustosEventCategory.AUTHENTICATION;
    }
  }

  private final BusFixtures fx = new BusFixtures();

  private static BrokenAppEvent brokenEvent() {
    return new BrokenAppEvent(EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"),
        BusFixtures.T0, JCustosEventSeverity.INFO), List.of("a", "b"));
  }

  @Test
  @DisplayName("a publish that fails in canonicalisation consumes no sequence")
  void failedCanonicalisationConsumesNoSequence() {
    PublishPipeline publisher = fx.publishPipeline();
    ConsumePipeline consumer = fx.consumePipeline();

    SignedJCustosEventEnvelope first = publisher.toEnvelope(BusFixtures.event());
    assertThrows(PayloadCodecException.class, () -> publisher.toEnvelope(brokenEvent()));
    SignedJCustosEventEnvelope next = publisher.toEnvelope(BusFixtures.event());

    assertEquals(1L, first.sequence().value());
    assertEquals(2L, next.sequence().value(), "the failed publish must not burn sequence 2");
    assertTrue(consumer.verify(first, BusFixtures.T0).isValid());
    assertTrue(consumer.verify(next, BusFixtures.T0).isValid(),
        "a strict consumer keeps accepting the producer after its failed publish");
  }

  // Ed25519 as the declared algorithm, but an EC private key: signing fails
  // after the sequence had to be reserved (it is part of the signature base).
  private PublishPipeline publisherWithBrokenSigner() {
    SignatureAlgorithm ed25519 = new Ed25519SignatureAlgorithm();
    PrivateKey wrongKey = new EcdsaP256SignatureAlgorithm().generateKeyPair().getPrivate();
    JCustosEventSigningKeyProvider brokenSigner = new JCustosEventSigningKeyProvider() {
      @Override
      public KeyId currentKeyId() {
        return BusFixtures.KEY;
      }

      @Override
      public PrivateKey currentSigningKey() {
        return wrongKey;
      }

      @Override
      public SignatureAlgorithm currentAlgorithm() {
        return ed25519;
      }
    };
    return new PublishPipeline(brokenSigner,
        new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec(),
        PayloadHashAlgorithm.SHA_256, BusFixtures.PRODUCER, fx.publishSequence,
        fx.publishReplay, fx.allowAll, Duration.ofMinutes(5), () -> BusFixtures.T0);
  }

  @Test
  @DisplayName("a publish that fails while signing hands its reservation back")
  void failedSignatureReleasesTheReservation() {
    PublishPipeline failing = publisherWithBrokenSigner();
    PublishPipeline working = fx.publishPipeline();

    SignedJCustosEventEnvelope first = working.toEnvelope(BusFixtures.event());
    assertThrows(RuntimeException.class, () -> failing.toEnvelope(BusFixtures.event()));
    assertThrows(RuntimeException.class, () -> failing.toEnvelope(BusFixtures.event()));

    assertEquals(EventSequence.of(1L),
        fx.publishSequence.lastSequence(TenantId.DEFAULT, BusFixtures.PRODUCER).orElseThrow(),
        "both failed publishes handed their sequence back");
    SignedJCustosEventEnvelope next = working.toEnvelope(BusFixtures.event());
    assertEquals(1L, first.sequence().value());
    assertEquals(2L, next.sequence().value());
  }

  @Test
  @DisplayName("a first publish that fails while signing leaves the scope fresh")
  void failedFirstPublishLeavesScopeFresh() {
    assertThrows(RuntimeException.class,
        () -> publisherWithBrokenSigner().toEnvelope(BusFixtures.event()));

    assertTrue(fx.publishSequence.lastSequence(TenantId.DEFAULT, BusFixtures.PRODUCER).isEmpty());
    assertEquals(1L, fx.publishPipeline().toEnvelope(BusFixtures.event()).sequence().value());
  }

  /**
   * A real in-memory envelope store whose next append fails once, before it
   * stores anything — the outage of a persistent store, honouring the atomic
   * {@code append} contract.
   */
  private static final class FailingOnceEnvelopeStore implements JCustosEventEnvelopeStore {
    private final InMemoryEnvelopeStore delegate = new InMemoryEnvelopeStore();
    private final AtomicBoolean failNext = new AtomicBoolean();

    void failNextAppend() {
      failNext.set(true);
    }

    @Override
    public JCustosEventCursor append(SignedJCustosEventEnvelope envelope) {
      if (failNext.compareAndSet(true, false)) {
        throw new IllegalStateException("envelope store unavailable");
      }
      return delegate.append(envelope);
    }

    @Override
    public List<StoredEnvelope> findAfter(JCustosEventCursor cursor, int limit) {
      return delegate.findAfter(cursor, limit);
    }

    @Override
    public Optional<SignedJCustosEventEnvelope> findByEnvelopeId(
        EventEnvelopeId envelopeId) {
      return delegate.findByEnvelopeId(envelopeId);
    }

    @Override
    public long count() {
      return delegate.count();
    }
  }

  @Test
  @DisplayName("an envelope the store refuses hands its sequence back; a strict consumer keeps up")
  void failedStoreAppendReleasesTheReservation() {
    FailingOnceEnvelopeStore store = new FailingOnceEnvelopeStore();
    DefaultJCustosEventBus bus = new DefaultJCustosEventBus(fx.publishPipeline(), store,
        ListenerErrorStrategy.ISOLATE_AND_CONTINUE, Runnable::run, () -> BusFixtures.T0);
    ConsumePipeline strictConsumer = fx.consumePipeline();
    List<JCustosEventVerificationResult> verdicts = new ArrayList<>();
    List<SignedJCustosEventEnvelope> sent = new ArrayList<>();
    bus.subscribeEnvelope(envelope -> {
      sent.add(envelope);
      verdicts.add(strictConsumer.verify(envelope, BusFixtures.T0));
    });
    List<LoginSucceededEvent> dispatched = new ArrayList<>();
    bus.subscribe(LoginSucceededEvent.class, dispatched::add);

    bus.publish(BusFixtures.event());
    store.failNextAppend();
    IllegalStateException outage = assertThrows(IllegalStateException.class,
        () -> bus.publish(BusFixtures.event()));
    bus.publish(BusFixtures.event());

    assertEquals("envelope store unavailable", outage.getMessage(),
        "the append failure reaches the caller unchanged");
    assertEquals(2, sent.size(), "the refused envelope is neither stored nor sent");
    assertEquals(2, dispatched.size(), "nor dispatched to local listeners");
    assertEquals(2L, store.count());
    assertEquals(1L, sent.get(0).sequence().value());
    assertEquals(2L, sent.get(1).sequence().value(),
        "the next envelope reuses the sequence the refused one had reserved");
    assertTrue(verdicts.stream().allMatch(JCustosEventVerificationResult::isValid),
        "a strict consumer accepts the producer's next envelope: " + verdicts);
  }

  @Test
  @DisplayName("abandon refuses another producer's envelope and leaves a later reservation alone")
  void abandonIsBoundToItsProducerAndBestEffort() {
    PublishPipeline publisher = fx.publishPipeline();
    SignedJCustosEventEnvelope first = publisher.toEnvelope(BusFixtures.event());
    SignedJCustosEventEnvelope second = publisher.toEnvelope(BusFixtures.event());
    SignedJCustosEventEnvelope foreign = BusFixtures.rebuild(second)
        .producerId(EventProducerId.of("another-producer"))
        .build();

    assertThrows(IllegalArgumentException.class, () -> publisher.abandon(foreign));
    assertFalse(publisher.abandon(first),
        "a later reservation exists, so the earlier sequence stays a hole");
    assertTrue(publisher.abandon(second));
    assertEquals(EventSequence.of(1L),
        fx.publishSequence.lastSequence(TenantId.DEFAULT, BusFixtures.PRODUCER).orElseThrow());
  }

  @Test
  @DisplayName("strict default: n, then n+2 — the gap and everything behind it is rejected")
  void strictConsumerRejectsBehindAGap() {
    PublishPipeline publisher = fx.publishPipeline();
    SignedJCustosEventEnvelope n = publisher.toEnvelope(BusFixtures.event());
    publisher.toEnvelope(BusFixtures.event()); // n+1, lost in transit
    SignedJCustosEventEnvelope nPlus2 = publisher.toEnvelope(BusFixtures.event());
    SignedJCustosEventEnvelope nPlus3 = publisher.toEnvelope(BusFixtures.event());
    ConsumePipeline consumer = fx.consumePipeline();

    assertTrue(consumer.verify(n, BusFixtures.T0).isValid());
    assertInstanceOf(JCustosEventVerificationResult.SequenceViolation.class,
        consumer.verify(nPlus2, BusFixtures.T0));
    assertInstanceOf(JCustosEventVerificationResult.SequenceViolation.class,
        consumer.verify(nPlus3, BusFixtures.T0));
    assertEquals(0L, consumer.acceptedSequenceAnomalyCount());
  }

  @Test
  @DisplayName("configured tolerance: n, then n+2 is accepted and counted, n+3 follows in order")
  void tolerantConsumerContinuesAfterAGap() {
    PublishPipeline publisher = fx.publishPipeline();
    SignedJCustosEventEnvelope n = publisher.toEnvelope(BusFixtures.event());
    publisher.toEnvelope(BusFixtures.event()); // n+1, lost in transit
    SignedJCustosEventEnvelope nPlus2 = publisher.toEnvelope(BusFixtures.event());
    SignedJCustosEventEnvelope nPlus3 = publisher.toEnvelope(BusFixtures.event());
    ConsumePipeline consumer = new ConsumePipeline(fx.keyManagement,
        SignatureAlgorithms.defaults(), fx.consumeReplay, fx.consumeSequence,
        new SequenceValidator(SequenceValidator.DEFAULT_MAX_INITIAL_SEQUENCE, 1L),
        SequenceViolationStrategy.REJECT, fx.allowAll);

    assertTrue(consumer.verify(n, BusFixtures.T0).isValid());
    assertTrue(consumer.verify(nPlus2, BusFixtures.T0).isValid(),
        "one skipped sequence is within the tolerance");
    assertEquals(1L, consumer.acceptedSequenceAnomalyCount(), "the loss is counted");
    assertTrue(consumer.verify(nPlus3, BusFixtures.T0).isValid());
    assertEquals(1L, consumer.acceptedSequenceAnomalyCount(), "n+3 is in order again");
    assertEquals(nPlus3.sequence(),
        fx.consumeSequence.lastSequence(TenantId.DEFAULT, BusFixtures.PRODUCER).orElseThrow());
  }

  @Test
  @DisplayName("a gap wider than the tolerance is still a violation")
  void toleranceIsBounded() {
    PublishPipeline publisher = fx.publishPipeline();
    SignedJCustosEventEnvelope n = publisher.toEnvelope(BusFixtures.event());
    publisher.toEnvelope(BusFixtures.event());
    publisher.toEnvelope(BusFixtures.event());
    SignedJCustosEventEnvelope nPlus3 = publisher.toEnvelope(BusFixtures.event());
    ConsumePipeline consumer = new ConsumePipeline(fx.keyManagement,
        SignatureAlgorithms.defaults(), fx.consumeReplay, fx.consumeSequence,
        new SequenceValidator(SequenceValidator.DEFAULT_MAX_INITIAL_SEQUENCE, 1L),
        SequenceViolationStrategy.REJECT, fx.allowAll);

    assertTrue(consumer.verify(n, BusFixtures.T0).isValid());
    assertInstanceOf(JCustosEventVerificationResult.SequenceViolation.class,
        consumer.verify(nPlus3, BusFixtures.T0));
  }

  @Test
  @DisplayName("strict consumer: the operator re-synchronises the scope and n+3 is processed again")
  void operatorResynchronisesAStrictConsumer() {
    PublishPipeline publisher = fx.publishPipeline();
    SignedJCustosEventEnvelope n = publisher.toEnvelope(BusFixtures.event());
    publisher.toEnvelope(BusFixtures.event()); // n+1, lost in transit
    SignedJCustosEventEnvelope nPlus2 = publisher.toEnvelope(BusFixtures.event());
    SignedJCustosEventEnvelope nPlus3 = publisher.toEnvelope(BusFixtures.event());
    ConsumePipeline consumer = fx.consumePipeline();
    assertTrue(consumer.verify(n, BusFixtures.T0).isValid());
    assertInstanceOf(JCustosEventVerificationResult.SequenceViolation.class,
        consumer.verify(nPlus2, BusFixtures.T0));

    // The operator reviewed the loss and declares n+2 the last sequence dealt with.
    fx.consumeSequence.updateSequence(TenantId.DEFAULT, BusFixtures.PRODUCER, nPlus2.sequence());

    assertTrue(consumer.verify(nPlus3, BusFixtures.T0).isValid());
  }
}
