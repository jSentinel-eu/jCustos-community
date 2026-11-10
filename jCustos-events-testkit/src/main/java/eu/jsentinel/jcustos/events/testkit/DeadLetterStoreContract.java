package eu.jsentinel.jcustos.events.testkit;

/*-
 * #%L
 * jCustos Events — Contract testkit
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.store.JCustosEventDeadLetter;
import eu.jsentinel.jcustos.events.store.JCustosEventDeadLetterStore;
import eu.jsentinel.jcustos.events.store.RejectionReason;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reusable contract for {@link JCustosEventDeadLetterStore} implementations.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
@DisplayName("JCustosEventDeadLetterStore — contract")
public interface DeadLetterStoreContract {

  JCustosEventDeadLetterStore newDeadLetterStore();

  /**
   * Creates a store that retains at most {@code capacity} open records — the
   * hook for {@link #capacityBoundsOpenRecords()} (JS-SEC-109). The default
   * returns {@code null}, which skips that test; an implementation with a
   * configurable bound overrides it so the bound is actually verified.
   *
   * @param capacity the maximum number of open records
   * @return a bounded store, or {@code null} if the bound cannot be set here
   * @since 00.84.00
   */
  default JCustosEventDeadLetterStore newDeadLetterStore(int capacity) {
    return null;
  }

  @Test
  @DisplayName("stored dead letters appear in findOpen, oldest first")
  default void storeAndFindOpen() {
    JCustosEventDeadLetterStore store = newDeadLetterStore();
    store.store(JCustosEventDeadLetter.of(
        TestkitEnvelopes.envelope("a"), RejectionReason.INVALID_SIGNATURE, TestkitEnvelopes.AT));
    store.store(JCustosEventDeadLetter.of(
        TestkitEnvelopes.envelope("b"), RejectionReason.REPLAY_DETECTED, TestkitEnvelopes.AT));
    List<JCustosEventDeadLetter> open = store.findOpen(10);
    assertEquals(2, open.size());
    assertEquals(RejectionReason.INVALID_SIGNATURE, open.get(0).reason());
    assertEquals(RejectionReason.REPLAY_DETECTED, open.get(1).reason());
  }

  @Test
  @DisplayName("markResolved removes a record from findOpen")
  default void markResolved() {
    JCustosEventDeadLetterStore store = newDeadLetterStore();
    JCustosEventDeadLetter dl = JCustosEventDeadLetter.of(
        TestkitEnvelopes.envelope("a"), RejectionReason.SEQUENCE_VIOLATION, TestkitEnvelopes.AT);
    store.store(dl);
    store.markResolved(dl.id());
    assertTrue(store.findOpen(10).isEmpty());
  }

  @Test
  @DisplayName("findOpen honours the limit")
  default void limit() {
    JCustosEventDeadLetterStore store = newDeadLetterStore();
    for (int i = 0; i < 5; i++) {
      store.store(JCustosEventDeadLetter.of(
          TestkitEnvelopes.envelope("e" + i), RejectionReason.EXPIRED, TestkitEnvelopes.AT));
    }
    assertEquals(3, store.findOpen(3).size());
  }

  @Test
  @DisplayName("JS-SEC-109: storeOrMerge folds an identical open rejection into one record")
  default void storeOrMergeFoldsIdenticalRejection() {
    JCustosEventDeadLetterStore store = newDeadLetterStore();
    JCustosEventDeadLetter first = JCustosEventDeadLetter.of(
        TestkitEnvelopes.envelope("replayed"), RejectionReason.EXPIRED, TestkitEnvelopes.AT);

    assertEquals(first.id(), store.storeOrMerge(first).id(),
        "the first record is stored and returned as itself");
    for (int i = 1; i <= 25; i++) {
      JCustosEventDeadLetter repeat = JCustosEventDeadLetter.of(
          TestkitEnvelopes.envelope("replayed"), RejectionReason.EXPIRED,
          TestkitEnvelopes.AT.plusSeconds(i));
      assertEquals(first.id(), store.storeOrMerge(repeat).id(),
          "a repeat returns the open record it duplicates");
    }

    List<JCustosEventDeadLetter> open = store.findOpen(100);
    assertEquals(1, open.size(), "one replayed envelope retains one record");
    assertEquals(first.id(), open.get(0).id());
  }

  @Test
  @DisplayName("JS-SEC-109: storeOrMerge keeps a different reason or different content apart")
  default void storeOrMergeKeepsDifferentRejectionsApart() {
    JCustosEventDeadLetterStore store = newDeadLetterStore();
    store.storeOrMerge(JCustosEventDeadLetter.of(
        TestkitEnvelopes.envelope("same-id"), RejectionReason.EXPIRED, TestkitEnvelopes.AT));
    store.storeOrMerge(JCustosEventDeadLetter.of(
        TestkitEnvelopes.envelope("same-id"), RejectionReason.SEQUENCE_VIOLATION,
        TestkitEnvelopes.AT));
    // Same envelope id, other content: a forged envelope must not be able to
    // hide behind — or displace — the record of a genuine one.
    store.storeOrMerge(JCustosEventDeadLetter.of(
        TestkitEnvelopes.envelope("same-id", new byte[]{'f', 'o', 'r', 'g', 'e', 'd'}),
        RejectionReason.EXPIRED, TestkitEnvelopes.AT));

    assertEquals(3, store.findOpen(100).size());
  }

  @Test
  @DisplayName("JS-SEC-109: a rejection that recurs after it was resolved is stored again")
  default void storeOrMergeStoresAgainAfterResolve() {
    JCustosEventDeadLetterStore store = newDeadLetterStore();
    JCustosEventDeadLetter first = JCustosEventDeadLetter.of(
        TestkitEnvelopes.envelope("recurring"), RejectionReason.EXPIRED, TestkitEnvelopes.AT);
    store.storeOrMerge(first);
    store.markResolved(first.id());

    JCustosEventDeadLetter again = JCustosEventDeadLetter.of(
        TestkitEnvelopes.envelope("recurring"), RejectionReason.EXPIRED, TestkitEnvelopes.AT);
    assertEquals(again.id(), store.storeOrMerge(again).id());

    List<JCustosEventDeadLetter> open = store.findOpen(100);
    assertEquals(1, open.size());
    assertEquals(again.id(), open.get(0).id());
  }

  @Test
  @DisplayName("JS-SEC-109: open records are bounded; beyond the capacity the oldest is evicted")
  default void capacityBoundsOpenRecords() {
    JCustosEventDeadLetterStore store = newDeadLetterStore(3);
    Assumptions.assumeTrue(store != null,
        "override newDeadLetterStore(int) to verify the capacity bound of this store");
    for (int i = 0; i < 50; i++) {
      store.storeOrMerge(JCustosEventDeadLetter.of(
          TestkitEnvelopes.envelope("flood-" + i), RejectionReason.EXPIRED,
          TestkitEnvelopes.AT));
    }

    List<JCustosEventDeadLetter> open = store.findOpen(100);
    assertEquals(3, open.size(), "the store never holds more than its capacity");
    assertEquals("flood-47", open.get(0).envelope().envelopeId().value());
    assertEquals("flood-49", open.get(2).envelope().envelopeId().value());
  }
}
