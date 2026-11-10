package eu.jsentinel.jcustos.events.store;

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
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelopeBuilder;
import eu.jsentinel.jcustos.events.bus.EventBusObservabilityPublisher;
import eu.jsentinel.jcustos.events.types.DeadLetteredEvent;
import eu.jsentinel.jcustos.events.types.EventBusSelfObservabilityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("DeadLetterRecorder")
class DeadLetterRecorderTest {

  private static final Instant NOW = Instant.parse("2026-07-19T12:00:00Z");

  /** Hand-written failure-injecting decorator around the real store. */
  private static final class ThrowingStore implements JCustosEventDeadLetterStore {

    private final InMemoryDeadLetterStore delegate = new InMemoryDeadLetterStore();

    @Override
    public void store(JCustosEventDeadLetter deadLetter) {
      throw new IllegalStateException("dead-letter store unavailable");
    }

    @Override
    public List<JCustosEventDeadLetter> findOpen(int limit) {
      return delegate.findOpen(limit);
    }

    @Override
    public void markResolved(DeadLetterId id) {
      delegate.markResolved(id);
    }
  }

  @Test
  @DisplayName("record stores the letter (findable via findOpen) and emits DeadLettered")
  void recordStoresAndEmits() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    List<EventBusSelfObservabilityEvent> emitted = new ArrayList<>();
    DeadLetterRecorder recorder = new DeadLetterRecorder(store, emitted::add, () -> NOW);
    SignedJCustosEventEnvelope envelope = StoreFixtures.envelope("env-dlr-1");

    JCustosEventDeadLetter letter = recorder.record(envelope, RejectionReason.EXPIRED);

    List<JCustosEventDeadLetter> open = store.findOpen(10);
    assertEquals(1, open.size());
    assertEquals(letter.id(), open.get(0).id());
    assertEquals(envelope, open.get(0).envelope());
    assertEquals(RejectionReason.EXPIRED, open.get(0).reason());
    assertEquals(NOW, open.get(0).recordedAt());

    assertEquals(1, emitted.size(), "exactly one DeadLettered event");
    DeadLetteredEvent event = assertInstanceOf(DeadLetteredEvent.class, emitted.get(0));
    assertEquals("env-dlr-1", event.envelopeId());
    assertEquals(RejectionReason.EXPIRED.name(), event.reason());
    assertEquals(envelope.tenantId(), event.tenantId(), "tenant propagated from envelope");
    assertEquals(JCustosEvent.SYSTEM_SUBJECT, event.subjectId());
    assertEquals(JCustosEventSeverity.ERROR, event.severity());
    assertEquals(NOW, event.occurredAt());
  }

  @Test
  @DisplayName("a store failure propagates and suppresses the DeadLettered event")
  void storeFailurePropagates() {
    AtomicInteger emissions = new AtomicInteger();
    DeadLetterRecorder recorder = new DeadLetterRecorder(new ThrowingStore(),
        event -> emissions.incrementAndGet(), () -> NOW);

    assertThrows(IllegalStateException.class,
        () -> recorder.record(StoreFixtures.envelope("env-dlr-2"), RejectionReason.EXPIRED));

    assertEquals(0, emissions.get(), "no DeadLettered event when the store write failed");
  }

  @Test
  @DisplayName("an observability failure never masks the successful store")
  void observabilityFailureDoesNotMaskStore() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    DeadLetterRecorder recorder = new DeadLetterRecorder(store,
        event -> {
          throw new IllegalStateException("observability sink down");
        }, () -> NOW);

    JCustosEventDeadLetter letter =
        recorder.record(StoreFixtures.envelope("env-dlr-3"), RejectionReason.REPLAY_DETECTED);

    assertNotNull(letter);
    assertEquals(1, store.findOpen(10).size(), "the letter was stored despite the sink failure");
  }

  @Test
  @DisplayName("the constructor rejects nulls")
  void constructorRejectsNulls() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    EventBusObservabilityPublisher publisher = EventBusObservabilityPublisher.discard();
    assertThrows(NullPointerException.class,
        () -> new DeadLetterRecorder(null, publisher, () -> NOW));
    assertThrows(NullPointerException.class,
        () -> new DeadLetterRecorder(store, null, () -> NOW));
    assertThrows(NullPointerException.class,
        () -> new DeadLetterRecorder(store, publisher, null));
  }

  private static SignedJCustosEventEnvelope claimingTenant(String envelopeId, String tenant) {
    SignedJCustosEventEnvelope base = StoreFixtures.envelope(envelopeId);
    return SignedJCustosEventEnvelopeBuilder.create()
        .envelopeId(base.envelopeId())
        .eventId(base.eventId())
        .eventType(base.eventType())
        .tenantId(TenantId.of(tenant))
        .subjectId(base.subjectId())
        .producerId(base.producerId())
        .occurredAt(base.occurredAt())
        .issuedAt(base.issuedAt())
        .expiresAt(base.expiresAt())
        .correlationId(base.correlationId())
        .sequence(base.sequence())
        .keyId(base.keyId())
        .signatureAlgorithm(base.signatureAlgorithm())
        .payloadContentType(base.payloadContentType())
        .payloadHashAlgorithm(base.payloadHashAlgorithm())
        .canonicalPayloadHash(base.canonicalPayloadHash())
        .canonicalPayload(base.canonicalPayload())
        .signature(base.signature())
        .build();
  }

  @Test
  @DisplayName("JS-SEC-104: the event about an unauthenticated dead letter adopts neither tenant nor full id")
  void unauthenticatedDeadLetterAdoptsNoEnvelopeField() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    List<EventBusSelfObservabilityEvent> emitted = new ArrayList<>();
    DeadLetterRecorder recorder = new DeadLetterRecorder(store, emitted::add, () -> NOW);
    SignedJCustosEventEnvelope junk = claimingTenant("J".repeat(5_000), "victim-tenant");

    recorder.record(junk, RejectionReason.INVALID_SIGNATURE, false);
    // the two-argument form derives "unauthenticated" from a cryptographic reason
    recorder.record(claimingTenant("K".repeat(5_000), "victim-tenant"),
        RejectionReason.UNKNOWN_KEY);

    assertEquals(2, emitted.size());
    for (EventBusSelfObservabilityEvent event : emitted) {
      DeadLetteredEvent deadLettered = assertInstanceOf(DeadLetteredEvent.class, event);
      assertEquals(TenantId.DEFAULT, deadLettered.tenantId(),
          "the event must not be raised under the tenant the junk claims");
      assertEquals("unverified:".length() + 64, deadLettered.envelopeId().length());
    }
    // the forensic record itself keeps the envelope exactly as it arrived
    assertEquals(junk, store.findOpen(10).get(0).envelope());
  }

  @Test
  @DisplayName("JS-SEC-104: an authenticated dead letter keeps its tenant in the event")
  void authenticatedDeadLetterKeepsTenant() {
    List<EventBusSelfObservabilityEvent> emitted = new ArrayList<>();
    DeadLetterRecorder recorder = new DeadLetterRecorder(new InMemoryDeadLetterStore(),
        emitted::add, () -> NOW);

    recorder.record(claimingTenant("env-acme", "acme"), RejectionReason.EXPIRED, true);

    DeadLetteredEvent event = assertInstanceOf(DeadLetteredEvent.class, emitted.get(0));
    assertEquals(TenantId.of("acme"), event.tenantId());
    assertEquals("env-acme", event.envelopeId());
  }

  @Test
  @DisplayName("JS-SEC-109: recording the same rejection again yields one record and one event")
  void repeatedRejectionIsRecordedOnce() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    List<EventBusSelfObservabilityEvent> emitted = new ArrayList<>();
    DeadLetterRecorder recorder = new DeadLetterRecorder(store, emitted::add, () -> NOW);
    SignedJCustosEventEnvelope envelope = StoreFixtures.envelope("env-replayed");

    JCustosEventDeadLetter first = recorder.record(envelope, RejectionReason.EXPIRED);
    for (int i = 0; i < 9_999; i++) {
      assertEquals(first.id(), recorder.record(envelope, RejectionReason.EXPIRED).id(),
          "a repeat returns the open record it duplicates");
    }

    assertEquals(1, store.findOpen(Integer.MAX_VALUE).size());
    assertEquals(10_000L, store.occurrences(first.id()));
    assertEquals(1, emitted.size(), "a repeat is not announced a second time");
  }

  @Test
  @DisplayName("JS-SEC-109: a store that only implements the three original methods still deduplicates")
  void defaultStoreOrMergeDeduplicates() {
    List<JCustosEventDeadLetter> backing = new ArrayList<>();
    JCustosEventDeadLetterStore legacy = new JCustosEventDeadLetterStore() {
      @Override
      public void store(JCustosEventDeadLetter deadLetter) {
        backing.add(deadLetter);
      }

      @Override
      public List<JCustosEventDeadLetter> findOpen(int limit) {
        return backing.subList(0, Math.min(limit, backing.size()));
      }

      @Override
      public void markResolved(DeadLetterId id) {
        backing.removeIf(record -> record.id().equals(id));
      }
    };
    DeadLetterRecorder recorder = new DeadLetterRecorder(legacy,
        EventBusObservabilityPublisher.discard(), () -> NOW);
    SignedJCustosEventEnvelope envelope = StoreFixtures.envelope("env-legacy");

    for (int i = 0; i < 50; i++) {
      recorder.record(envelope, RejectionReason.EXPIRED);
    }
    recorder.record(envelope, RejectionReason.SEQUENCE_VIOLATION);

    assertEquals(2, backing.size(), "one record per distinct (envelope, reason)");
  }
}
