/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.reset;

import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public final class InMemoryResetTokenStore implements ResetTokenStore {

  /** Diagnostic namespace of the capacity-exceeded code (JS-SEC-074, CWE-770). */
  public static final String CAPACITY_NAMESPACE = "credential/reset-token-store";

  private final ConcurrentHashMap<String, ResetTokenRecord> records =
      new ConcurrentHashMap<>();
  /** username → selectors, so retiring siblings on every issue stays proportional to the user's tokens. */
  private final ConcurrentHashMap<String, Set<String>> byUsername = new ConcurrentHashMap<>();
  private final int maxEntries;
  private final Clock clock;
  /** Earliest expiry among stored records; lets a full store refuse in O(1) when nothing can be purged. */
  private final AtomicReference<Instant> earliestExpiry = new AtomicReference<>(Instant.MAX);
  /** Records no longer ISSUED (consumed or expired by status) — the other class a purge could free. */
  private final AtomicInteger deadByStatus = new AtomicInteger();

  /** Bounded to {@link CapacityBound#DEFAULT_MAX_ENTRIES} live records. */
  public InMemoryResetTokenStore() {
    this(CapacityBound.DEFAULT_MAX_ENTRIES, Clock.systemUTC());
  }

  /**
   * @param maxEntries upper bound on stored records; when reached, consumed and
   *                   expired records are purged and a further {@code save}
   *                   fails with {@code credential/reset-token-store-capacity-exceeded}
   *                   (JS-SEC-074, CWE-770: the unauthenticated forgot-password
   *                   path must not grow the heap without limit)
   * @param clock      time source for the purge
   */
  public InMemoryResetTokenStore(int maxEntries, Clock clock) {
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public void save(ResetTokenRecord record) {
    Objects.requireNonNull(record, "record");
    if (records.size() >= maxEntries && !records.containsKey(record.selector())) {
      Instant now = Instant.now(clock);
      if (deadByStatus.get() > 0 || !now.isBefore(earliestExpiry.get())) {
        purgeDead(now);
      }
      if (records.size() >= maxEntries) {
        throw new IllegalStateException(
            CapacityBound.capacityExceededCode(CAPACITY_NAMESPACE) + ": " + maxEntries);
      }
    }
    ResetTokenRecord prior = records.putIfAbsent(record.selector(), record);
    if (prior != null) {
      throw new IllegalStateException(
          "reset token already exists for selector");
    }
    byUsername.computeIfAbsent(record.username(), k -> ConcurrentHashMap.newKeySet())
        .add(record.selector());
    earliestExpiry.accumulateAndGet(record.expiresAt(), (a, b) -> a.isBefore(b) ? a : b);
    if (record.status() != ResetTokenStatus.ISSUED) {
      deadByStatus.incrementAndGet();
    }
  }

  @Override
  public Optional<ResetTokenRecord> findBySelector(String selector) {
    Objects.requireNonNull(selector, "selector");
    return Optional.ofNullable(records.get(selector));
  }

  @Override
  public List<ResetTokenRecord> findByUsername(String username) {
    Objects.requireNonNull(username, "username");
    Set<String> selectors = byUsername.get(username);
    if (selectors == null) {
      return List.of();
    }
    List<ResetTokenRecord> found = new ArrayList<>(selectors.size());
    for (String selector : selectors) {
      ResetTokenRecord record = records.get(selector);
      if (record != null) {
        found.add(record);
      }
    }
    return List.copyOf(found);
  }

  /** Drops consumed, expired-by-status and expired-by-time records. */
  private void purgeDead(Instant now) {
    Instant nextExpiry = Instant.MAX;
    for (ResetTokenRecord record : records.values()) {
      boolean dead = record.status() != ResetTokenStatus.ISSUED || record.isExpired(now);
      if (dead && records.remove(record.selector(), record)) {
        byUsername.computeIfPresent(record.username(), (k, selectors) -> {
          selectors.remove(record.selector());
          return selectors.isEmpty() ? null : selectors;
        });
        if (record.status() != ResetTokenStatus.ISSUED) {
          deadByStatus.decrementAndGet();
        }
      } else if (record.expiresAt().isBefore(nextExpiry)) {
        nextExpiry = record.expiresAt();
      }
    }
    earliestExpiry.set(nextExpiry);
  }

  @Override
  public ResetTokenUpdateResult markConsumedIfCurrent(
      String selector, ResetTokenStatus expectedStatus) {
    return transition(selector, expectedStatus, ResetTokenStatus.CONSUMED);
  }

  @Override
  public ResetTokenUpdateResult markExpiredIfCurrent(
      String selector, ResetTokenStatus expectedStatus) {
    return transition(selector, expectedStatus, ResetTokenStatus.EXPIRED);
  }

  private ResetTokenUpdateResult transition(
      String selector, ResetTokenStatus expected, ResetTokenStatus target) {
    Objects.requireNonNull(selector, "selector");
    Objects.requireNonNull(expected, "expected");
    Objects.requireNonNull(target, "target");
    ResetTokenRecord current = records.get(selector);
    if (current == null) {
      return ResetTokenUpdateResult.NotFound.INSTANCE;
    }
    if (current.status() != expected) {
      return ResetTokenUpdateResult.Stale.INSTANCE;
    }
    ResetTokenRecord next = current.withStatus(target);
    if (!records.replace(selector, current, next)) {
      return ResetTokenUpdateResult.Stale.INSTANCE;
    }
    if (expected == ResetTokenStatus.ISSUED && target != ResetTokenStatus.ISSUED) {
      deadByStatus.incrementAndGet();
    }
    return new ResetTokenUpdateResult.Updated(next);
  }

  /** Test helper: number of stored tokens. */
  public int size() {
    return records.size();
  }
}
