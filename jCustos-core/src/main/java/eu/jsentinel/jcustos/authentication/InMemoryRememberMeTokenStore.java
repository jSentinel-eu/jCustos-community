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
package eu.jsentinel.jcustos.authentication;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.function.Predicate;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link RememberMeTokenStore} backed by a
 * {@link ConcurrentHashMap} keyed on the token hash. Reads are lock-free;
 * every mutation runs under one lock, because a rotation touches the live
 * token, its trail and the successor, and a subject-wide revocation touches
 * many records (JS-SEC-129, CWE-367).
 *
 * <h2>Bounds (JS-SEC-125, CWE-770)</h2>
 * <p>Live tokens and the trail of rotated tokens are two tables of at most
 * {@code maxEntries} entries each - {@link CapacityBound#DEFAULT_MAX_ENTRIES}
 * unless the constructor says otherwise, the bound of the Eclipse-Store
 * store. Every rotation adds a trail entry that lives until the consumed
 * token would have expired; until 00.84.00 the trail had no bound, and one
 * stolen cookie exchanged in a loop grew the heap without limit. At the bound
 * expired entries go first; if none is expired the entry stored first is
 * dropped and a warning is logged - for the first eviction and then once per
 * {@value #EVICTIONS_PER_LOG_LINE}. A dropped live record means that its
 * holder has to log in again; a dropped trail means that a replay of that one
 * token is refused as unknown instead of being recognised as a replay.</p>
 *
 * <p>The "invalid before" marks of
 * {@link #deleteBySubject(TenantId, SubjectId, Instant)} are one entry per
 * subject that was ever revoked wholesale and are not bounded: a dropped mark
 * would let a token from an overtaken operation through.</p>
 */
@ExperimentalJCustosApi
public final class InMemoryRememberMeTokenStore implements RememberMeTokenStore, HasLogger {

  /** One eviction warning for the first eviction and for every further block of this many. */
  static final long EVICTIONS_PER_LOG_LINE = 1_000;

  private final int maxEntries;
  private final BoundedTable<RememberMeTokenRecord> tokens =
      new BoundedTable<>(RememberMeTokenRecord::expiresAt);
  /**
   * hash → trail of a token consumed by a rotation (JS-SEC-128). Entries live
   * until the consumed record's expiry and go with the subject's tokens.
   */
  private final BoundedTable<RotatedToken> rotated =
      new BoundedTable<>(trail -> trail.record().expiresAt());
  /** (tenant, subject) → instant before which the subject's tokens are invalid (JS-SEC-129). */
  private final ConcurrentHashMap<SubjectScope, Instant> invalidBefore = new ConcurrentHashMap<>();

  /** Key of the invalidation mark. */
  private record SubjectScope(TenantId tenant, SubjectId subjectId) {
  }

  /** Serialises every mutation; see the class comment. */
  private final ReentrantLock mutation = new ReentrantLock();

  /** Creates an empty store bounded at {@link CapacityBound#DEFAULT_MAX_ENTRIES} per table. */
  public InMemoryRememberMeTokenStore() {
    this(CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  /**
   * Creates an empty store with an explicit bound (JS-SEC-125, CWE-770).
   *
   * @param maxEntries upper bound on live tokens and, separately, on the trail
   *                   of rotated tokens; at least 1
   * @since 00.84.00
   */
  public InMemoryRememberMeTokenStore(int maxEntries) {
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
  }

  @Override
  public Optional<RememberMeTokenRecord> findByHash(String tokenHash) {
    requireNonBlank(tokenHash, "tokenHash");
    return Optional.ofNullable(tokens.get(tokenHash));
  }

  @Override
  public void save(RememberMeTokenRecord record) {
    requireNonNull(record, "record must not be null");
    mutation.lock();
    try {
      putLive(record, record.createdAt());
    } finally {
      mutation.unlock();
    }
  }

  @Override
  public boolean saveUnlessInvalidated(RememberMeTokenRecord record) {
    requireNonNull(record, "record must not be null");
    mutation.lock();
    try {
      if (isInvalidated(record)) {
        return false;
      }
      putLive(record, record.createdAt());
      return true;
    } finally {
      mutation.unlock();
    }
  }

  @Override
  public boolean deleteByHash(String tokenHash) {
    requireNonBlank(tokenHash, "tokenHash");
    mutation.lock();
    try {
      return tokens.remove(tokenHash) != null;
    } finally {
      mutation.unlock();
    }
  }

  @Override
  public boolean markRotated(String tokenHash, Instant at) {
    requireNonBlank(tokenHash, "tokenHash");
    requireNonNull(at, "at must not be null");
    // JS-SEC-128: retire and leave the trail in one step, so that of two
    // concurrent presentations exactly one obtains the successor.
    mutation.lock();
    try {
      RememberMeTokenRecord live = tokens.remove(tokenHash);
      if (live == null) {
        return false;
      }
      putTrail(tokenHash, new RotatedToken(live, at), at);
      return true;
    } finally {
      mutation.unlock();
    }
  }

  @Override
  public boolean rotate(String oldHash, RememberMeTokenRecord successor, Instant now) {
    requireNonBlank(oldHash, "oldHash");
    requireNonNull(successor, "successor must not be null");
    requireNonNull(now, "now must not be null");
    if (oldHash.equals(successor.tokenHash())) {
      throw new IllegalArgumentException("successor must not reuse the old hash");
    }
    // JS-SEC-129 (CWE-367, CWE-613): claim, trail and successor in one critical
    // section. A revocation either precedes the rotation - the old token is gone
    // or the successor is older than the mark - or follows it and removes the
    // successor; it can no longer land in between and be undone.
    mutation.lock();
    try {
      RememberMeTokenRecord live = tokens.get(oldHash);
      if (live == null || live.isExpired(now) || isInvalidated(successor)) {
        return false;
      }
      tokens.remove(oldHash);
      putTrail(oldHash, new RotatedToken(live, now), now);
      putLive(successor, now);
      return true;
    } finally {
      mutation.unlock();
    }
  }

  @Override
  public Optional<RotatedToken> findRotated(String tokenHash) {
    requireNonBlank(tokenHash, "tokenHash");
    return Optional.ofNullable(rotated.get(tokenHash));
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    mutation.lock();
    try {
      return removeSubject(tenant, subjectId);
    } finally {
      mutation.unlock();
    }
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId, Instant invalidBefore) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    requireNonNull(invalidBefore, "invalidBefore must not be null");
    // JS-SEC-129 (CWE-613): deletion and mark under the same lock as rotate and
    // saveUnlessInvalidated.
    mutation.lock();
    try {
      this.invalidBefore.merge(new SubjectScope(tenant, subjectId), invalidBefore,
          (known, candidate) -> candidate.isAfter(known) ? candidate : known);
      return removeSubject(tenant, subjectId);
    } finally {
      mutation.unlock();
    }
  }

  @Override
  public int purgeExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    mutation.lock();
    try {
      int removed = tokens.removeIf(record -> record.isExpired(now));
      rotated.removeIf(trail -> trail.record().isExpired(now));
      return removed;
    } finally {
      mutation.unlock();
    }
  }

  /** Package-visible for tests: number of trail entries held (JS-SEC-125 bound). */
  int trailCount() {
    mutation.lock();
    try {
      return rotated.size();
    } finally {
      mutation.unlock();
    }
  }

  /** Caller holds {@link #mutation}. */
  private int removeSubject(TenantId tenant, SubjectId subjectId) {
    int removed = tokens.removeIf(record ->
        record.tenant().equals(tenant) && record.subjectId().equals(subjectId));
    rotated.removeIf(trail ->
        trail.record().tenant().equals(tenant) && trail.record().subjectId().equals(subjectId));
    return removed;
  }

  /** Caller holds {@link #mutation}. */
  private boolean isInvalidated(RememberMeTokenRecord record) {
    Instant mark = invalidBefore.get(new SubjectScope(record.tenant(), record.subjectId()));
    return mark != null && record.createdAt().isBefore(mark);
  }

  /** Caller holds {@link #mutation}. Stores a live record, making room at the bound. */
  private void putLive(RememberMeTokenRecord record, Instant now) {
    if (tokens.makeRoomFor(record.tokenHash(), maxEntries, now)) {
      logger().warn("authentication/remember-me-store-capacity: the remember-me store is at its"
          + " bound of {} live tokens; the oldest token is dropped for every new one", maxEntries);
    }
    tokens.put(record.tokenHash(), record);
  }

  /** Caller holds {@link #mutation}. Stores a trail, making room at the bound. */
  private void putTrail(String hash, RotatedToken trail, Instant now) {
    if (rotated.makeRoomFor(hash, maxEntries, now)) {
      logger().warn("authentication/remember-me-trail-capacity: the trail of rotated remember-me"
          + " tokens is at its bound of {} entries; the oldest trail is dropped for every"
          + " rotation, a replay of that token is then refused without being recognised",
          maxEntries);
    }
    rotated.put(hash, trail);
  }

  private static void requireNonBlank(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
  }

  /**
   * A map with lock-free reads and an insertion order for eviction. Mutated
   * only under the store's lock.
   *
   * @param <V> value type
   */
  private static final class BoundedTable<V> {
    private final ConcurrentHashMap<String, V> values = new ConcurrentHashMap<>();
    /** Keys in insertion order; the head is evicted first. */
    private final LinkedHashSet<String> order = new LinkedHashSet<>();
    private final Function<V, Instant> expiryOf;
    /** No entry expires before this instant; {@code null} while that is not known. */
    private Instant noExpiryBefore;
    private long evictions;

    private BoundedTable(Function<V, Instant> expiryOf) {
      this.expiryOf = expiryOf;
    }

    private V get(String key) {
      return values.get(key);
    }

    private int size() {
      return values.size();
    }

    private void put(String key, V value) {
      Instant expiry = expiryOf.apply(value);
      if (noExpiryBefore != null && expiry.isBefore(noExpiryBefore)) {
        noExpiryBefore = expiry;
      }
      if (values.put(key, value) == null) {
        order.add(key);
      }
    }

    private V remove(String key) {
      V removed = values.remove(key);
      if (removed != null) {
        order.remove(key);
      }
      return removed;
    }

    private int removeIf(Predicate<V> filter) {
      int removed = 0;
      Iterator<String> keys = order.iterator();
      while (keys.hasNext()) {
        String key = keys.next();
        if (filter.test(values.get(key))) {
          keys.remove();
          values.remove(key);
          removed++;
        }
      }
      return removed;
    }

    /**
     * Makes room for {@code incoming}: nothing happens for a known key or below
     * the bound; otherwise expired entries go first and then, while the table
     * is still full, the entry stored first. The scan for expired entries is
     * skipped while the earliest expiry seen by the last scan lies ahead.
     *
     * @return {@code true} when a live entry was evicted and a warning is due -
     *     for the first eviction and then once per {@link #EVICTIONS_PER_LOG_LINE}
     */
    private boolean makeRoomFor(String incoming, int maxEntries, Instant now) {
      if (values.size() < maxEntries || values.containsKey(incoming)) {
        return false;
      }
      if (noExpiryBefore == null || !now.isBefore(noExpiryBefore)) {
        Instant[] earliest = {Instant.MAX};
        removeIf(value -> {
          Instant expiry = expiryOf.apply(value);
          if (!now.isBefore(expiry)) {
            return true;
          }
          if (expiry.isBefore(earliest[0])) {
            earliest[0] = expiry;
          }
          return false;
        });
        noExpiryBefore = earliest[0];
      }
      long before = evictions;
      while (values.size() >= maxEntries) {
        remove(order.iterator().next());
        evictions++;
      }
      return evictions > before
          && (before == 0 || before / EVICTIONS_PER_LOG_LINE != evictions / EVICTIONS_PER_LOG_LINE);
    }
  }
}
