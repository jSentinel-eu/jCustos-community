/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.accountlifecycle;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link EmailVerificationTokenStore} backed by a
 * {@link ConcurrentHashMap} keyed on the token hash.
 */
@ExperimentalJCustosApi
public final class InMemoryEmailVerificationTokenStore
    implements EmailVerificationTokenStore {

  /** Diagnostic namespace of the capacity-exceeded code (JS-SEC-074, CWE-770). */
  public static final String CAPACITY_NAMESPACE = "accountlifecycle/email-verification-token-store";

  private final ConcurrentHashMap<String, EmailVerificationTokenRecord> tokens =
      new ConcurrentHashMap<>();
  /**
   * tenant + subject → token hashes. Keeps {@link #deleteBySubject} proportional
   * to the subject's own tokens: since the services retire siblings on every
   * request (JS-SEC-074), a full scan would turn the unauthenticated
   * forgot-password path into O(n) CPU per call.
   */
  private final ConcurrentHashMap<String, Set<String>> bySubject = new ConcurrentHashMap<>();
  private final int maxEntries;
  private final Clock clock;
  /** Earliest expiry among stored records; lets a full store refuse in O(1) when nothing can be purged. */
  private final AtomicReference<Instant> earliestExpiry = new AtomicReference<>(Instant.MAX);
  /** Consumed records still stored; the other class of entries a purge could free. */
  private final AtomicInteger consumedCount = new AtomicInteger();

  /** Bounded to {@link CapacityBound#DEFAULT_MAX_ENTRIES} live records. */
  public InMemoryEmailVerificationTokenStore() {
    this(CapacityBound.DEFAULT_MAX_ENTRIES, Clock.systemUTC());
  }

  /**
   * @param maxEntries upper bound on stored records; when reached, consumed and
   *                   expired records are purged and a further {@code save}
   *                   fails with {@code accountlifecycle/email-verification-token-store-capacity-exceeded}
   *                   (JS-SEC-074, CWE-770: the unauthenticated request path must
   *                   not grow the heap without limit)
   * @param clock      time source for the purge
   * @since 00.84.00
   */
  public InMemoryEmailVerificationTokenStore(int maxEntries, Clock clock) {
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
    this.clock = requireNonNull(clock, "clock must not be null");
  }

  @Override
  public Optional<EmailVerificationTokenRecord> findByHash(String tokenHash) {
    requireNonBlank(tokenHash, "tokenHash");
    return Optional.ofNullable(tokens.get(tokenHash));
  }

  @Override
  public void save(EmailVerificationTokenRecord record) {
    requireNonNull(record, "record must not be null");
    if (tokens.size() >= maxEntries && !tokens.containsKey(record.tokenHash())) {
      // Only scan when the scan can free something: a consumed record exists or
      // the earliest expiry has passed. Otherwise an attacker hammering the
      // unauthenticated request path would buy an O(n) scan per call.
      Instant now = clock.instant();
      if (consumedCount.get() > 0 || !now.isBefore(earliestExpiry.get())) {
        purgeDead(now);
      }
      if (tokens.size() >= maxEntries) {
        throw new IllegalStateException(
            CapacityBound.capacityExceededCode(CAPACITY_NAMESPACE) + ": " + maxEntries);
      }
    }
    EmailVerificationTokenRecord previous = tokens.put(record.tokenHash(), record);
    if (previous != null && !subjectKey(previous).equals(subjectKey(record))) {
      unindex(previous);
    }
    bySubject.computeIfAbsent(subjectKey(record), k -> ConcurrentHashMap.newKeySet())
        .add(record.tokenHash());
    earliestExpiry.accumulateAndGet(record.expiresAt(), (a, b) -> a.isBefore(b) ? a : b);
    if (record.isConsumed() && (previous == null || !previous.isConsumed())) {
      consumedCount.incrementAndGet();
    }
  }

  private static String subjectKey(EmailVerificationTokenRecord record) {
    return subjectKey(record.tenant(), record.subjectId());
  }

  private static String subjectKey(TenantId tenant, SubjectId subjectId) {
    return tenant.value() + '\u0000' + subjectId.value();
  }

  private void unindex(EmailVerificationTokenRecord record) {
    bySubject.computeIfPresent(subjectKey(record), (k, hashes) -> {
      hashes.remove(record.tokenHash());
      return hashes.isEmpty() ? null : hashes;
    });
  }

  /**
   * @return number of stored records, live or not
   * @since 00.84.00
   */
  public int size() {
    return tokens.size();
  }

  /** Drops consumed and expired records. */
  private void purgeDead(Instant now) {
    removeIf(record -> record.isConsumed() || record.isExpired(now));
  }

  @Override
  public boolean markConsumed(String tokenHash, Instant at) {
    requireNonBlank(tokenHash, "tokenHash");
    requireNonNull(at, "at must not be null");
    boolean[] consumedNow = {false};
    tokens.computeIfPresent(tokenHash, (k, prev) -> {
      if (prev.isConsumed()) {
        return prev;
      }
      consumedNow[0] = true;
      return prev.withConsumedAt(at);
    });
    if (consumedNow[0]) {
      consumedCount.incrementAndGet();
    }
    return consumedNow[0];
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    Set<String> hashes = bySubject.remove(subjectKey(tenant, subjectId));
    if (hashes == null) {
      return 0;
    }
    int removed = 0;
    for (String hash : hashes) {
      EmailVerificationTokenRecord gone = tokens.remove(hash);
      if (gone != null) {
        removed++;
        if (gone.isConsumed()) {
          consumedCount.decrementAndGet();
        }
      }
    }
    return removed;
  }

  @Override
  public int purgeExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    return removeIf(record -> record.isExpired(now));
  }

  private int removeIf(java.util.function.Predicate<EmailVerificationTokenRecord> condition) {
    int removed = 0;
    Instant nextExpiry = Instant.MAX;
    for (EmailVerificationTokenRecord record : tokens.values()) {
      if (condition.test(record) && tokens.remove(record.tokenHash(), record)) {
        unindex(record);
        removed++;
        if (record.isConsumed()) {
          consumedCount.decrementAndGet();
        }
      } else if (record.expiresAt().isBefore(nextExpiry)) {
        nextExpiry = record.expiresAt();
      }
    }
    earliestExpiry.set(nextExpiry);
    return removed;
  }

  private static void requireNonBlank(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
  }
}
