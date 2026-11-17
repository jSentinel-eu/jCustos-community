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

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.util.SubjectKeyCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-063 (CWE-770): the credential-check gate. Real semaphores, real threads.
 */
@DisplayName("JS-SEC-063 - CredentialCheckGate bounds concurrent credential checks")
class CredentialCheckGateTest {

  private static final Instant T0 = Instant.parse("2026-11-17T10:00:00Z");
  private static final Clock CLOCK = Clock.fixed(T0, ZoneOffset.UTC);

  /** Thread-safe audit recorder. */
  static final class ConcurrentAudit implements JCustosAuditService {
    final Queue<AuditEvent> events = new ConcurrentLinkedQueue<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }

    List<RateLimitExceeded> rateLimited() {
      return events.stream().filter(RateLimitExceeded.class::isInstance)
          .map(RateLimitExceeded.class::cast).toList();
    }
  }

  private static CredentialCheckGate bounded(int permits, Duration wait, Duration retryAfter,
                                             JCustosAuditService audit) {
    return CredentialCheckGate.of(LoginAttemptLimits.defaults()
        .withMaxConcurrentCredentialChecks(permits)
        .withGateWait(wait)
        .withGateRetryAfter(retryAfter), CLOCK, audit);
  }

  @Test
  @DisplayName("defaults: every shipped policy hands out the unbounded gate, which admits everyone at once")
  void defaultsAreUnbounded() {
    List<LoginAttemptPolicy> policies = List.of(
        new InMemoryLoginAttemptPolicy(),
        new StoreBackedLoginAttemptPolicy(new InMemoryLoginAttemptStore()),
        NoopLoginAttemptPolicy.INSTANCE);
    for (LoginAttemptPolicy policy : policies) {
      CredentialCheckGate gate = policy.credentialCheckGate();
      assertSame(CredentialCheckGate.unbounded(), gate, policy.getClass().getSimpleName());
      assertFalse(gate.bounded());
      for (int i = 0; i < 1_000; i++) {
        assertInstanceOf(CredentialCheckGate.Admission.Entered.class, gate.enter());
      }
      assertEquals(0, gate.inUse());
      assertEquals(0, gate.deferredCount());
    }
  }

  @Test
  @DisplayName("a policy with maxConcurrentCredentialChecks returns one bounded gate, the same instance on every call")
  void policiesHandOutTheirGate() {
    LoginAttemptLimits limits = LoginAttemptLimits.defaults().withMaxConcurrentCredentialChecks(3);
    InMemoryLoginAttemptPolicy inMemory = new InMemoryLoginAttemptPolicy(limits, CLOCK, null);
    StoreBackedLoginAttemptPolicy storeBacked = new StoreBackedLoginAttemptPolicy(
        new InMemoryLoginAttemptStore(), limits, TenantId.DEFAULT, CLOCK,
        SubjectKeyCanonicalizer.defaults(), null);
    for (LoginAttemptPolicy policy : List.of(inMemory, storeBacked)) {
      CredentialCheckGate gate = policy.credentialCheckGate();
      assertTrue(gate.bounded());
      assertEquals(3, gate.maxConcurrent());
      assertSame(gate, policy.credentialCheckGate(), "the permits live in one instance");
    }
  }

  @Test
  @DisplayName("two permits: two enter, the third is deferred with the retry-after and audited as RateLimitExceeded")
  void thirdAttemptIsDeferred() {
    ConcurrentAudit audit = new ConcurrentAudit();
    CredentialCheckGate gate = bounded(2, Duration.ofMillis(20), Duration.ofSeconds(3), audit);

    CredentialCheckGate.Admission first = gate.enter();
    CredentialCheckGate.Admission second = gate.enter();
    assertInstanceOf(CredentialCheckGate.Admission.Entered.class, first);
    assertInstanceOf(CredentialCheckGate.Admission.Entered.class, second);
    assertEquals(2, gate.inUse());

    CredentialCheckGate.Admission.Deferred third = assertInstanceOf(
        CredentialCheckGate.Admission.Deferred.class, gate.enter());
    assertEquals(Duration.ofSeconds(3), third.retryAfter());
    assertEquals(1, gate.deferredCount());

    List<RateLimitExceeded> events = audit.rateLimited();
    assertEquals(1, events.size());
    RateLimitExceeded event = events.getFirst();
    assertEquals(CredentialCheckGate.AUDIT_SCOPE, event.scope());
    assertEquals("", event.subjectId(), "the gate names no account");
    assertEquals(2, event.limit());
    assertEquals(2, event.eventsInWindow());
    assertEquals(Duration.ofMillis(20), event.window());
    assertEquals(T0, event.timestamp());

    ((CredentialCheckGate.Admission.Entered) first).close();
    assertInstanceOf(CredentialCheckGate.Admission.Entered.class, gate.enter(),
        "a closed permit is free again");
  }

  @Test
  @DisplayName("closing a permit twice releases it once")
  void closeIsIdempotent() {
    CredentialCheckGate gate = bounded(1, Duration.ZERO, Duration.ofSeconds(1), new ConcurrentAudit());
    CredentialCheckGate.Admission.Entered permit =
        assertInstanceOf(CredentialCheckGate.Admission.Entered.class, gate.enter());
    permit.close();
    permit.close();
    assertEquals(0, gate.inUse());
    CredentialCheckGate.Admission.Entered again =
        assertInstanceOf(CredentialCheckGate.Admission.Entered.class, gate.enter());
    assertInstanceOf(CredentialCheckGate.Admission.Deferred.class, gate.enter(),
        "a double close must not have created a second permit");
    again.close();
  }

  @Test
  @DisplayName("a zero wait defers at once; the audit window is recorded as one nanosecond")
  void zeroWaitDefersImmediately() {
    ConcurrentAudit audit = new ConcurrentAudit();
    CredentialCheckGate gate = bounded(1, Duration.ZERO, Duration.ofSeconds(1), audit);
    CredentialCheckGate.Admission.Entered permit =
        assertInstanceOf(CredentialCheckGate.Admission.Entered.class, gate.enter());
    long started = System.nanoTime();
    assertInstanceOf(CredentialCheckGate.Admission.Deferred.class, gate.enter());
    assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(1));
    assertEquals(Duration.ofNanos(1), audit.rateLimited().getFirst().window());
    permit.close();
  }

  @Test
  @DisplayName("an interrupted wait defers - fail closed - and keeps the interrupt flag")
  void interruptedWaitDefers() throws InterruptedException {
    CredentialCheckGate gate = bounded(1, Duration.ofSeconds(5), Duration.ofSeconds(1),
        new ConcurrentAudit());
    CredentialCheckGate.Admission.Entered held =
        assertInstanceOf(CredentialCheckGate.Admission.Entered.class, gate.enter());
    AtomicReference<CredentialCheckGate.Admission> outcome = new AtomicReference<>();
    AtomicReference<Boolean> stillInterrupted = new AtomicReference<>();
    Thread waiter = new Thread(() -> {
      Thread.currentThread().interrupt();
      outcome.set(gate.enter());
      stillInterrupted.set(Thread.currentThread().isInterrupted());
    });
    waiter.start();
    waiter.join(TimeUnit.SECONDS.toMillis(4));
    assertFalse(waiter.isAlive(), "an interrupted thread must not wait for the full gate wait");
    assertInstanceOf(CredentialCheckGate.Admission.Deferred.class, outcome.get());
    assertTrue(stillInterrupted.get());
    held.close();
  }

  @Test
  @DisplayName("200 threads through a gate of 3: never more than 3 inside at once")
  void parallelEntriesNeverExceedThePermits() throws InterruptedException {
    int permits = 3;
    int threads = 200;
    CredentialCheckGate gate = bounded(permits, Duration.ofSeconds(5), Duration.ofSeconds(1),
        new ConcurrentAudit());
    AtomicInteger inside = new AtomicInteger();
    AtomicInteger maxInside = new AtomicInteger();
    AtomicInteger deferred = new AtomicInteger();
    CountDownLatch go = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(threads);
    for (int i = 0; i < threads; i++) {
      Thread thread = new Thread(() -> {
        try {
          go.await();
          switch (gate.enter()) {
            case CredentialCheckGate.Admission.Deferred ignored -> deferred.incrementAndGet();
            case CredentialCheckGate.Admission.Entered permit -> {
              try {
                int now = inside.incrementAndGet();
                maxInside.accumulateAndGet(now, Math::max);
                Thread.sleep(1);
                inside.decrementAndGet();
              } finally {
                permit.close();
              }
            }
          }
        } catch (InterruptedException interrupted) {
          Thread.currentThread().interrupt();
        } finally {
          done.countDown();
        }
      });
      thread.setDaemon(true);
      thread.start();
    }
    go.countDown();
    assertTrue(done.await(60, TimeUnit.SECONDS));
    assertTrue(maxInside.get() <= permits, maxInside.get() + " checks ran at once");
    assertEquals(0, gate.inUse(), "every permit was given back");
    assertEquals(0, deferred.get(), "with a five-second wait nobody had to be deferred");
  }

  @Test
  @DisplayName("a failing audit sink does not break the deferral")
  void failingAuditSinkDoesNotBreakTheDeferral() {
    JCustosAuditService failing = new JCustosAuditService() {
      @Override
      public void publish(AuditEvent event) {
        throw new IllegalStateException("sink down");
      }

      @Override
      public List<AuditEvent> query(AuditQuery query) {
        return List.of();
      }
    };
    CredentialCheckGate gate = bounded(1, Duration.ZERO, Duration.ofSeconds(2), failing);
    CredentialCheckGate.Admission.Entered permit =
        assertInstanceOf(CredentialCheckGate.Admission.Entered.class, gate.enter());
    assertEquals(Duration.ofSeconds(2), assertInstanceOf(
        CredentialCheckGate.Admission.Deferred.class, gate.enter()).retryAfter());
    permit.close();
  }

  @Test
  @DisplayName("Deferred requires a positive retry-after")
  void deferredValidates() {
    assertThrows(NullPointerException.class, () -> new CredentialCheckGate.Admission.Deferred(null));
    assertThrows(IllegalArgumentException.class,
        () -> new CredentialCheckGate.Admission.Deferred(Duration.ZERO));
    assertThrows(IllegalArgumentException.class,
        () -> new CredentialCheckGate.Admission.Deferred(Duration.ofSeconds(-1)));
  }
}
