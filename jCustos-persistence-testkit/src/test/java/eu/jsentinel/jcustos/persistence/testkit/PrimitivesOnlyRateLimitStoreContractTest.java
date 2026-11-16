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
package eu.jsentinel.jcustos.persistence.testkit;

import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import eu.jsentinel.jcustos.ratelimiting.RateLimitStore;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.LockSupport;

import static java.util.Objects.requireNonNull;

/**
 * Runs {@link RateLimitStoreContract} against a store that implements only
 * the four primitives and inherits {@link RateLimitStore#tryAdmit} from the
 * SPI default - the shape of a third-party store written before 00.84.00.
 *
 * <p>JS-SEC-118: the primitives are thread-safe one by one, and
 * {@code countSince} takes its time, so a default that merely called them in
 * sequence would let every parallel caller read the count before the first
 * one records. The contract's concurrency test passes because the default
 * serialises its callers on the store instance.</p>
 */
class PrimitivesOnlyRateLimitStoreContractTest implements RateLimitStoreContract {

  @Override
  public RateLimitStore newStore() {
    return new PrimitivesOnlyStore();
  }

  private static final class PrimitivesOnlyStore implements RateLimitStore {

    private final ConcurrentHashMap<RateLimitKey, List<Instant>> events = new ConcurrentHashMap<>();

    @Override
    public void recordEvent(RateLimitKey key, Instant at) {
      requireNonNull(key, "key must not be null");
      requireNonNull(at, "at must not be null");
      events.computeIfAbsent(key, k -> new CopyOnWriteArrayList<>()).add(at);
    }

    @Override
    public int countSince(RateLimitKey key, Instant since) {
      requireNonNull(key, "key must not be null");
      requireNonNull(since, "since must not be null");
      List<Instant> recorded = events.get(key);
      int count = 0;
      if (recorded != null) {
        for (Instant event : recorded) {
          if (!event.isBefore(since)) {
            count++;
          }
        }
      }
      // a store that asks a remote service: the answer takes a moment, which is
      // all a check-then-record race needs
      LockSupport.parkNanos(200_000L);
      return count;
    }

    @Override
    public void reset(RateLimitKey key) {
      requireNonNull(key, "key must not be null");
      events.remove(key);
    }

    @Override
    public int purgeOlderThan(Instant cutoff) {
      requireNonNull(cutoff, "cutoff must not be null");
      int[] purged = {0};
      events.forEach((key, recorded) -> {
        for (Instant event : recorded) {
          if (event.isBefore(cutoff) && recorded.remove(event)) {
            purged[0]++;
          }
        }
      });
      events.values().removeIf(List::isEmpty);
      return purged[0];
    }
  }
}
