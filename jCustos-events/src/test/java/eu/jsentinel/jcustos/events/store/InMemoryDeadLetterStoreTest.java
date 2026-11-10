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

import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelopeBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryDeadLetterStore")
class InMemoryDeadLetterStoreTest {

  private static final Instant AT = Instant.parse("2026-06-24T10:15:30Z");

  @Test
  @DisplayName("stored dead letters appear in findOpen, oldest first")
  void storeAndFindOpen() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    store.store(JCustosEventDeadLetter.of(
        StoreFixtures.envelope("a"), RejectionReason.INVALID_SIGNATURE, AT));
    store.store(JCustosEventDeadLetter.of(
        StoreFixtures.envelope("b"), RejectionReason.REPLAY_DETECTED, AT));

    List<JCustosEventDeadLetter> open = store.findOpen(10);
    assertEquals(2, open.size());
    assertEquals(RejectionReason.INVALID_SIGNATURE, open.get(0).reason());
    assertEquals(RejectionReason.REPLAY_DETECTED, open.get(1).reason());
  }

  @Test
  @DisplayName("markResolved removes a record from findOpen")
  void markResolved() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    JCustosEventDeadLetter dl = JCustosEventDeadLetter.of(
        StoreFixtures.envelope("a"), RejectionReason.SEQUENCE_VIOLATION, AT);
    store.store(dl);
    store.markResolved(dl.id());
    assertTrue(store.findOpen(10).isEmpty());
  }

  @Test
  @DisplayName("R07: markResolved drops the heavy record so resolved dead letters do not accumulate")
  void markResolvedDropsRecord() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    JCustosEventDeadLetter a = JCustosEventDeadLetter.of(
        StoreFixtures.envelope("a"), RejectionReason.SEQUENCE_VIOLATION, AT);
    JCustosEventDeadLetter b = JCustosEventDeadLetter.of(
        StoreFixtures.envelope("b"), RejectionReason.REPLAY_DETECTED, AT);
    store.store(a);
    store.store(b);
    assertEquals(2, store.retainedRecordCount());

    store.markResolved(a.id());

    // the record (and its embedded signed envelope) is gone, not parked in a
    // side set — only the still-open dead letter is retained
    assertEquals(1, store.retainedRecordCount(),
        "a resolved dead letter must not be retained");
    List<JCustosEventDeadLetter> open = store.findOpen(10);
    assertEquals(1, open.size());
    assertEquals(RejectionReason.REPLAY_DETECTED, open.get(0).reason());
  }

  @Test
  @DisplayName("findOpen honours the limit")
  void limit() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    for (int i = 0; i < 5; i++) {
      store.store(JCustosEventDeadLetter.of(
          StoreFixtures.envelope("e" + i), RejectionReason.EXPIRED, AT));
    }
    assertEquals(3, store.findOpen(3).size());
  }

  @Test
  @DisplayName("JS-SEC-109: an identical rejection is folded into the open record and counted")
  void identicalRejectionIsStoredOnce() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    JCustosEventDeadLetter first = JCustosEventDeadLetter.of(
        StoreFixtures.envelope("replayed"), RejectionReason.EXPIRED, AT);

    assertEquals(first.id(), store.storeOrMerge(first).id());
    for (int i = 0; i < 2_999; i++) {
      JCustosEventDeadLetter repeat = JCustosEventDeadLetter.of(
          StoreFixtures.envelope("replayed"), RejectionReason.EXPIRED, AT.plusSeconds(i));
      assertEquals(first.id(), store.storeOrMerge(repeat).id());
    }
    // the plain store() path deduplicates too
    store.store(JCustosEventDeadLetter.of(
        StoreFixtures.envelope("replayed"), RejectionReason.EXPIRED, AT));

    assertEquals(1, store.retainedRecordCount());
    assertEquals(3_001L, store.occurrences(first.id()));
    assertEquals(0L, store.evictedCount());
  }

  @Test
  @DisplayName("JS-SEC-109: a different reason or different content under the same envelope id is a record of its own")
  void differentContentIsNotFolded() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    store.storeOrMerge(JCustosEventDeadLetter.of(
        StoreFixtures.envelope("same-id"), RejectionReason.EXPIRED, AT));
    store.storeOrMerge(JCustosEventDeadLetter.of(
        StoreFixtures.envelope("same-id"), RejectionReason.SEQUENCE_VIOLATION, AT));
    // same envelope id, forged content: must not hide behind the genuine record
    SignedJCustosEventEnvelope genuine = StoreFixtures.envelope("same-id");
    SignedJCustosEventEnvelope forged = SignedJCustosEventEnvelopeBuilder.create()
        .envelopeId(genuine.envelopeId())
        .eventId(genuine.eventId())
        .eventType(genuine.eventType())
        .tenantId(genuine.tenantId())
        .subjectId(genuine.subjectId())
        .producerId(genuine.producerId())
        .occurredAt(genuine.occurredAt())
        .issuedAt(genuine.issuedAt())
        .expiresAt(genuine.expiresAt())
        .correlationId(genuine.correlationId())
        .sequence(genuine.sequence())
        .keyId(genuine.keyId())
        .signatureAlgorithm(genuine.signatureAlgorithm())
        .payloadContentType(genuine.payloadContentType())
        .payloadHashAlgorithm(genuine.payloadHashAlgorithm())
        .canonicalPayloadHash(genuine.canonicalPayloadHash())
        .canonicalPayload(new byte[]{'x'})
        .signature(genuine.signature())
        .build();
    store.storeOrMerge(JCustosEventDeadLetter.of(forged, RejectionReason.EXPIRED, AT));

    assertEquals(3, store.retainedRecordCount());
  }

  @Test
  @DisplayName("JS-SEC-109: a rejection that recurs after its record was resolved is stored again")
  void resolvedRejectionIsStoredAgain() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    JCustosEventDeadLetter first = JCustosEventDeadLetter.of(
        StoreFixtures.envelope("recurring"), RejectionReason.EXPIRED, AT);
    store.storeOrMerge(first);
    store.markResolved(first.id());
    assertEquals(0L, store.occurrences(first.id()));

    JCustosEventDeadLetter again = JCustosEventDeadLetter.of(
        StoreFixtures.envelope("recurring"), RejectionReason.EXPIRED, AT);
    assertEquals(again.id(), store.storeOrMerge(again).id());

    assertEquals(1, store.retainedRecordCount());
    assertEquals(1L, store.occurrences(again.id()));
  }

  @Test
  @DisplayName("JS-SEC-109: 200 000 distinct rejections stay within the capacity, oldest evicted first")
  void capacityBoundsOpenRecords() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    assertEquals(InMemoryDeadLetterStore.DEFAULT_CAPACITY, store.capacity());

    for (int i = 0; i < 200_000; i++) {
      store.store(JCustosEventDeadLetter.of(
          StoreFixtures.envelope("flood-" + i), RejectionReason.EXPIRED, AT));
    }

    int capacity = InMemoryDeadLetterStore.DEFAULT_CAPACITY;
    assertEquals(capacity, store.retainedRecordCount());
    assertEquals(200_000L - capacity, store.evictedCount());
    List<JCustosEventDeadLetter> open = store.findOpen(Integer.MAX_VALUE);
    assertEquals("flood-" + (200_000 - capacity), open.get(0).envelope().envelopeId().value(),
        "the oldest retained record is the first one that still fits");
    assertEquals("flood-199999", open.get(capacity - 1).envelope().envelopeId().value());
  }

  @Test
  @DisplayName("JS-SEC-109: the capacity is configurable and an evicted rejection can be stored anew")
  void capacityIsConfigurable() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore(2);
    JCustosEventDeadLetter a = JCustosEventDeadLetter.of(
        StoreFixtures.envelope("a"), RejectionReason.EXPIRED, AT);
    store.store(a);
    store.store(JCustosEventDeadLetter.of(
        StoreFixtures.envelope("b"), RejectionReason.EXPIRED, AT));
    store.store(JCustosEventDeadLetter.of(
        StoreFixtures.envelope("c"), RejectionReason.EXPIRED, AT));

    assertEquals(2, store.retainedRecordCount());
    assertEquals(1L, store.evictedCount());
    assertEquals(0L, store.occurrences(a.id()), "the evicted record is gone");
    // the evicted rejection is not remembered as a duplicate
    JCustosEventDeadLetter aAgain = JCustosEventDeadLetter.of(
        StoreFixtures.envelope("a"), RejectionReason.EXPIRED, AT);
    assertEquals(aAgain.id(), store.storeOrMerge(aAgain).id());
    assertThrows(IllegalArgumentException.class, () -> new InMemoryDeadLetterStore(0));
  }
}
