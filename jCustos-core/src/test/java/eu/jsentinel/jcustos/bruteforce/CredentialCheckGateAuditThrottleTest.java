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
package eu.jsentinel.jcustos.bruteforce;

import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.bruteforce.CredentialCheckGateTest.ConcurrentAudit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exit review RF11 (CWE-779): a flood of deferrals produces at most one {@link RateLimitExceeded}
 * a second per gate, and the next event carries the deferrals that were held back. Real gate,
 * real semaphore, real threads; time from a clock the test sets.
 */
@DisplayName("RF11 - the credential-check gate audits a flood of deferrals once a second, with the count")
class CredentialCheckGateAuditThrottleTest {

  private static final Instant T0 = Instant.parse("2026-11-19T10:00:00Z");

  /** Clock whose instant the test sets; safe to read from other threads. */
  static final class SettableClock extends Clock {
    private volatile Instant now;

    SettableClock(Instant now) {
      this.now = now;
    }

    void set(Instant at) {
      this.now = at;
    }

    @Override
    public Instant instant() {
      return now;
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }
  }

  /** A gate of one permit and no wait, whose permit the caller holds: every enter() defers. */
  private record SaturatedGate(CredentialCheckGate gate, CredentialCheckGate.Admission.Entered held) {

    static SaturatedGate of(Duration wait, Clock clock, ConcurrentAudit audit) {
      CredentialCheckGate gate = CredentialCheckGate.of(LoginAttemptLimits.defaults()
          .withMaxConcurrentCredentialChecks(1)
          .withGateWait(wait)
          .withGateRetryAfter(Duration.ofSeconds(2)), clock, audit);
      return new SaturatedGate(gate,
          assertInstanceOf(CredentialCheckGate.Admission.Entered.class, gate.enter()));
    }

    void defer(int times) {
      for (int i = 0; i < times; i++) {
        assertInstanceOf(CredentialCheckGate.Admission.Deferred.class, gate.enter());
      }
    }
  }

  @Test
  @DisplayName("the audit interval is one second")
  void intervalIsOneSecond() {
    assertEquals(Duration.ofSeconds(1), CredentialCheckGate.AUDIT_INTERVAL);
  }

  @Test
  @DisplayName("1 000 deferrals within one second: exactly one event, for the first deferral")
  void floodWithinOneIntervalPublishesOnce() {
    ConcurrentAudit audit = new ConcurrentAudit();
    SettableClock clock = new SettableClock(T0);
    SaturatedGate saturated = SaturatedGate.of(Duration.ZERO, clock, audit);

    saturated.defer(500);
    clock.set(T0.plusMillis(999));
    saturated.defer(500);

    List<RateLimitExceeded> events = audit.rateLimited();
    assertEquals(1, events.size(), "one event for 1 000 deferrals within one second");
    RateLimitExceeded first = events.getFirst();
    assertEquals(CredentialCheckGate.AUDIT_SCOPE, first.scope());
    assertEquals("", first.subjectId());
    assertEquals(1, first.limit(), "the permits");
    assertEquals(Duration.ofNanos(1), first.window(), "a zero gate wait, as before");
    assertEquals(1, first.eventsInWindow(), "the first deferral stands for itself");
    assertEquals(T0, first.timestamp());
    assertEquals(1_000, saturated.gate().deferredCount());
    assertEquals(999, saturated.gate().unauditedDeferrals(), "held back, not lost");
    saturated.held().close();
  }

  @Test
  @DisplayName("the first deferral one second after the last event carries the deferrals held back, itself included")
  void nextEventCarriesTheHeldBackCount() {
    ConcurrentAudit audit = new ConcurrentAudit();
    SettableClock clock = new SettableClock(T0);
    SaturatedGate saturated = SaturatedGate.of(Duration.ofMillis(5), clock, audit);

    saturated.defer(1_000);
    Instant second = T0.plus(CredentialCheckGate.AUDIT_INTERVAL);
    clock.set(second);
    saturated.defer(1);

    List<RateLimitExceeded> events = audit.rateLimited();
    assertEquals(2, events.size());
    RateLimitExceeded next = events.get(1);
    assertEquals(1_000, next.eventsInWindow(), "999 held back + the publishing deferral");
    assertEquals(second, next.timestamp());
    assertEquals(Duration.ofMillis(5), next.window(), "the gate wait, as before");
    assertEquals(0, saturated.gate().unauditedDeferrals());
    assertEquals(saturated.gate().deferredCount(),
        events.stream().mapToLong(RateLimitExceeded::eventsInWindow).sum(),
        "summed over the events: every deferral, once");

    // the next interval starts at the second event, not at the first
    clock.set(second.plusMillis(500));
    saturated.defer(3);
    assertEquals(2, audit.rateLimited().size());
    clock.set(second.plus(CredentialCheckGate.AUDIT_INTERVAL));
    saturated.defer(1);
    assertEquals(4, audit.rateLimited().get(2).eventsInWindow());
    saturated.held().close();
  }

  @Test
  @DisplayName("deferrals one second or more apart are each published with a count of one")
  void sparseDeferralsArePublishedEachTime() {
    ConcurrentAudit audit = new ConcurrentAudit();
    SettableClock clock = new SettableClock(T0);
    SaturatedGate saturated = SaturatedGate.of(Duration.ZERO, clock, audit);
    for (int i = 0; i < 5; i++) {
      clock.set(T0.plusSeconds(i));
      saturated.defer(1);
    }
    List<RateLimitExceeded> events = audit.rateLimited();
    assertEquals(5, events.size());
    events.forEach(event -> assertEquals(1, event.eventsInWindow()));
    saturated.held().close();
  }

  @Test
  @DisplayName("a clock that goes back behind the last event publishes at once - fail towards more audit")
  void clockGoingBackPublishes() {
    ConcurrentAudit audit = new ConcurrentAudit();
    SettableClock clock = new SettableClock(T0);
    SaturatedGate saturated = SaturatedGate.of(Duration.ZERO, clock, audit);
    saturated.defer(10);
    clock.set(T0.minusSeconds(3600));
    saturated.defer(1);
    List<RateLimitExceeded> events = audit.rateLimited();
    assertEquals(2, events.size());
    assertEquals(10, events.get(1).eventsInWindow());
    saturated.held().close();
  }

  @Test
  @DisplayName("16 threads defer 200 times each within one second: one event; the next one carries all 3 200")
  void concurrentDeferralsPublishOncePerInterval() throws Exception {
    ConcurrentAudit audit = new ConcurrentAudit();
    SettableClock clock = new SettableClock(T0);
    SaturatedGate saturated = SaturatedGate.of(Duration.ZERO, clock, audit);
    int threads = 16;
    int perThread = 200;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      CountDownLatch ready = new CountDownLatch(threads);
      CountDownLatch start = new CountDownLatch(1);
      List<Future<?>> outcomes = new ArrayList<>();
      for (int t = 0; t < threads; t++) {
        outcomes.add(pool.submit(() -> {
          ready.countDown();
          start.await();
          saturated.defer(perThread);
          return null;
        }));
      }
      assertTrue(ready.await(10, TimeUnit.SECONDS));
      start.countDown();
      for (Future<?> outcome : outcomes) {
        outcome.get(30, TimeUnit.SECONDS);
      }
    } finally {
      pool.shutdownNow();
    }
    int total = threads * perThread;
    List<RateLimitExceeded> events = audit.rateLimited();
    assertEquals(1, events.size(), "exactly one event within the interval");
    assertEquals(1, events.getFirst().eventsInWindow());
    assertEquals(total - 1, saturated.gate().unauditedDeferrals(),
        "every other deferral counted once");

    clock.set(T0.plus(CredentialCheckGate.AUDIT_INTERVAL));
    saturated.defer(1);
    events = audit.rateLimited();
    assertEquals(2, events.size());
    assertEquals(total, events.get(1).eventsInWindow(), "3 199 held back + the publishing one");
    assertEquals(total + 1, events.stream().mapToLong(RateLimitExceeded::eventsInWindow).sum());
    assertEquals(total + 1, saturated.gate().deferredCount());
    saturated.held().close();
  }
}
