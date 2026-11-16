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
package eu.jsentinel.jcustos.ratelimiting;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-118 (CWE-367): the default of {@link RateLimitStore#tryAdmit} for a
 * store that implements the four primitives only. The store below is
 * thread-safe method by method and answers {@code countSince} slowly - without
 * serialisation every parallel caller reads the count before the first one
 * records.
 */
@DisplayName("RateLimitStore.tryAdmit - the default for stores that do not override it")
class RateLimitStoreDefaultAdmissionTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final RateLimitKey KEY = new RateLimitKey(TenantId.DEFAULT, "login:alice");

  private static final class PrimitivesOnlyStore implements RateLimitStore {
    private final List<Instant> events = new CopyOnWriteArrayList<>();

    @Override
    public void recordEvent(RateLimitKey key, Instant at) {
      events.add(at);
    }

    @Override
    public int countSince(RateLimitKey key, Instant since) {
      int count = 0;
      for (Instant event : events) {
        if (!event.isBefore(since)) {
          count++;
        }
      }
      LockSupport.parkNanos(2_000_000L); // the window in which the other callers read as well
      return count;
    }

    @Override
    public void reset(RateLimitKey key) {
      events.clear();
    }

    @Override
    public int purgeOlderThan(Instant cutoff) {
      return 0;
    }
  }

  @Test
  @DisplayName("JS-SEC-118: 40 parallel callers against limit 5 - exactly 5 are admitted through the inherited default")
  void defaultAdmissionIsSerialisedPerStore() throws Exception {
    RateLimitStore store = new PrimitivesOnlyStore();
    int threads = 40;
    int limit = 5;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      CountDownLatch ready = new CountDownLatch(threads);
      CountDownLatch start = new CountDownLatch(1);
      List<Future<RateLimitStore.Admission>> outcomes = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        Callable<RateLimitStore.Admission> caller = () -> {
          ready.countDown();
          start.await();
          return store.tryAdmit(KEY, T0, T0.minusSeconds(60), limit);
        };
        outcomes.add(pool.submit(caller));
      }
      assertTrue(ready.await(10, TimeUnit.SECONDS));
      start.countDown();
      int admitted = 0;
      for (Future<RateLimitStore.Admission> outcome : outcomes) {
        RateLimitStore.Admission admission = outcome.get(30, TimeUnit.SECONDS);
        assertTrue(admission.eventsInWindow() <= limit, "a caller saw more events than the limit");
        if (admission.admitted()) {
          admitted++;
        }
      }
      assertEquals(limit, admitted);
      assertEquals(limit, store.countSince(KEY, T0));
    } finally {
      pool.shutdownNow();
    }
  }
}
