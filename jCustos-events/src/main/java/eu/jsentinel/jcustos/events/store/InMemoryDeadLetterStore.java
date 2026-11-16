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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * In-memory {@link JCustosEventDeadLetterStore}. Insertion order is
 * preserved so {@link #findOpen(int)} returns oldest-first. All access is
 * synchronized.
 *
 * <p>R07 (V00.76.10): {@link #markResolved(DeadLetterId)} now removes the record
 * entirely rather than parking its id in a side set while keeping the heavy
 * record (each embeds a full signed envelope). The store therefore only retains
 * <em>open</em> dead letters and cannot grow without bound for a producer that
 * reliably trips a rejection reason.
 *
 * <p>JS-SEC-109 (CWE-770): R07 bounded the resolved records only. Open records
 * are bounded as well now, in two ways. An identical rejection — same envelope
 * content, same reason — is folded into the open record it repeats and counted
 * ({@link #occurrences(DeadLetterId)}) instead of stored again, so replaying
 * one captured envelope retains one record. And the store holds at most
 * {@link #capacity()} open records: storing beyond that evicts the oldest one,
 * counts it ({@link #evictedCount()}) and logs
 * {@code events/dead-letter-evicted}.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class InMemoryDeadLetterStore implements JCustosEventDeadLetterStore, HasLogger {

  /**
   * Default number of open dead letters retained. Every record embeds a whole
   * signed envelope, so the bound is chosen for an operator's review queue,
   * not for an archive.
   *
   * @since 00.84.00
   */
  public static final int DEFAULT_CAPACITY = 1_000;

  /**
   * The eviction WARN is emitted on the 1st eviction and every Nth thereafter,
   * so a flood cannot flood the log in turn.
   */
  static final long EVICTION_LOG_INTERVAL = 1_000L;

  // What makes two rejections "the same": the whole envelope (content
  // equality, payload and signature included) and the reason. Not the
  // envelope id alone — the sender chooses it.
  private record Rejection(SignedJCustosEventEnvelope envelope, RejectionReason reason) {
  }

  private final int capacity;
  private final Map<DeadLetterId, JCustosEventDeadLetter> records = new LinkedHashMap<>();
  private final Map<Rejection, DeadLetterId> openByRejection = new HashMap<>();
  private final Map<DeadLetterId, Long> occurrences = new HashMap<>();
  private long evicted;

  /** Creates a store retaining at most {@link #DEFAULT_CAPACITY} open records. */
  public InMemoryDeadLetterStore() {
    this(DEFAULT_CAPACITY);
  }

  /**
   * @param capacity the maximum number of open records retained; at least 1
   * @since 00.84.00
   */
  public InMemoryDeadLetterStore(int capacity) {
    if (capacity < 1) {
      throw new IllegalArgumentException("capacity must be >= 1, was " + capacity);
    }
    this.capacity = capacity;
  }

  /**
   * Same as {@link #storeOrMerge} without its result: a repeat of an open
   * rejection is folded into that record, and {@code deadLetter}'s own id is
   * then not stored — see {@link JCustosEventDeadLetterStore#store}.
   *
   * @param deadLetter the record
   */
  @Override
  public void store(JCustosEventDeadLetter deadLetter) {
    storeOrMerge(deadLetter);
  }

  @Override
  public synchronized JCustosEventDeadLetter storeOrMerge(JCustosEventDeadLetter deadLetter) {
    Objects.requireNonNull(deadLetter, "deadLetter");
    Rejection rejection = new Rejection(deadLetter.envelope(), deadLetter.reason());
    DeadLetterId existing = openByRejection.get(rejection);
    if (existing != null) {
      occurrences.merge(existing, 1L, Long::sum);
      return records.get(existing);
    }
    records.put(deadLetter.id(), deadLetter);
    openByRejection.put(rejection, deadLetter.id());
    occurrences.put(deadLetter.id(), 1L);
    evictBeyondCapacity();
    return deadLetter;
  }

  // Oldest first: the newest rejections are the ones an operator is about to
  // look at, and an attacker who can fill the store should not be able to
  // keep the current ones out.
  private void evictBeyondCapacity() {
    Iterator<JCustosEventDeadLetter> oldestFirst = records.values().iterator();
    while (records.size() > capacity && oldestFirst.hasNext()) {
      JCustosEventDeadLetter oldest = oldestFirst.next();
      oldestFirst.remove();
      forget(oldest);
      evicted++;
      if (evicted % EVICTION_LOG_INTERVAL == 1) {
        logger().warn("events/dead-letter-evicted: the dead-letter store holds its maximum"
                + " of {} open records — the oldest was evicted ({} evicted so far)."
                + " Resolve open dead letters or find out who is flooding the ingest path.",
            capacity, evicted);
      }
    }
  }

  private void forget(JCustosEventDeadLetter removed) {
    openByRejection.remove(new Rejection(removed.envelope(), removed.reason()), removed.id());
    occurrences.remove(removed.id());
  }

  @Override
  public synchronized List<JCustosEventDeadLetter> findOpen(int limit) {
    if (limit < 0) {
      throw new IllegalArgumentException("limit must be >= 0, was " + limit);
    }
    List<JCustosEventDeadLetter> open = new ArrayList<>();
    for (JCustosEventDeadLetter record : records.values()) {
      if (open.size() >= limit) {
        break;
      }
      open.add(record);
    }
    return open;
  }

  @Override
  public synchronized void markResolved(DeadLetterId id) {
    // R07: drop the record (and its embedded signed envelope) — a resolved dead
    // letter no longer needs retention, so resolved records cannot accumulate.
    JCustosEventDeadLetter removed = records.remove(Objects.requireNonNull(id, "id"));
    if (removed != null) {
      forget(removed);
    }
  }

  /**
   * @return the maximum number of open records retained
   * @since 00.84.00
   */
  public int capacity() {
    return capacity;
  }

  /**
   * @param id an open dead letter
   * @return how often the rejection it records was stored — {@code 1} for a
   *     rejection seen once, {@code 0} if no open record has this id
   * @since 00.84.00
   */
  public synchronized long occurrences(DeadLetterId id) {
    return occurrences.getOrDefault(Objects.requireNonNull(id, "id"), 0L);
  }

  /**
   * @return how many open records were evicted because the store was full,
   *     over this store's lifetime
   * @since 00.84.00
   */
  public synchronized long evictedCount() {
    return evicted;
  }

  /** Test seam (R07): the number of retained (open) dead-letter records. */
  synchronized int retainedRecordCount() {
    return records.size();
  }
}
