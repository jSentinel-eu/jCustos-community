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
package eu.jsentinel.jcustos.standalone;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.bruteforce.CredentialCheckGate;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptConfiguration;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptLimits;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-063 (CWE-770): the login flow enters the credential-check gate of the registered
 * policy. A real, slow {@link AuthenticationService} held on a latch shows the bound; the policy
 * is the real {@link InMemoryLoginAttemptPolicy}.
 */
@DisplayName("StandaloneLoginFlow - the credential-check gate (JS-SEC-063)")
class StandaloneLoginFlowGateTest {

  private static final String PASSWORD = "Correct-Horse-Battery-1";
  private static final Duration RETRY_AFTER = Duration.ofSeconds(2);

  private final ConcurrentAudit audit = new ConcurrentAudit();

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setJCustosAuditService(audit);
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new MapSubjectStore());
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
  }

  private InMemoryLoginAttemptPolicy register(int maxConcurrent, Duration gateWait) {
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(LoginAttemptLimits.defaults()
        .withMaxConcurrentCredentialChecks(maxConcurrent)
        .withGateWait(gateWait)
        .withGateRetryAfter(RETRY_AFTER), Clock.systemUTC(), audit);
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    return policy;
  }

  @Test
  @DisplayName("two permits, two slow checks in progress: the third login is deferred, no LoginFailed, never more than two at once")
  void thirdLoginIsDeferredWhileTwoChecksRun() throws InterruptedException {
    InMemoryLoginAttemptPolicy policy = register(2, Duration.ofMillis(50));
    SlowAuthentication service = new SlowAuthentication(2);
    StandaloneLoginFlow<String, String> flow = new StandaloneLoginFlow<>(service, Clock.systemUTC());

    List<Thread> workers = new ArrayList<>();
    Queue<StandaloneLoginFlow.LoginResult<String>> results = new ConcurrentLinkedQueue<>();
    for (int i = 0; i < 2; i++) {
      String user = "user-" + i;
      Thread worker = new Thread(() -> results.add(flow.login(PASSWORD, user)));
      worker.setDaemon(true);
      worker.start();
      workers.add(worker);
    }
    assertTrue(service.entered.await(10, TimeUnit.SECONDS), "both checks must be running");

    CredentialCheckDeferredException deferred = assertThrows(CredentialCheckDeferredException.class,
        () -> flow.login(PASSWORD, "third"));
    assertEquals(RETRY_AFTER, deferred.retryAfter());
    assertInstanceOf(CredentialVerificationUnavailableException.class, deferred,
        "an existing catch of the superclass handles the deferral");
    assertEquals(2, service.evaluations.get(), "the deferred login was not evaluated");

    service.release.countDown();
    for (Thread worker : workers) {
      worker.join(TimeUnit.SECONDS.toMillis(10));
    }
    assertEquals(2, results.size());
    results.forEach(result -> assertInstanceOf(StandaloneLoginFlow.LoginResult.Success.class, result));
    assertEquals(2, service.maxInside.get(), "the bound is the configured one");
    assertEquals(0, policy.credentialCheckGate().inUse(), "every permit was given back");

    assertTrue(audit.of(LoginFailed.class).isEmpty(), "a deferral is no failed login");
    List<RateLimitExceeded> rateLimited = audit.of(RateLimitExceeded.class);
    assertEquals(1, rateLimited.size());
    assertEquals(CredentialCheckGate.AUDIT_SCOPE, rateLimited.getFirst().scope());
    assertEquals(2, rateLimited.getFirst().limit());
  }

  @Test
  @DisplayName("twelve parallel logins through two permits: all are evaluated, never more than two at once")
  void parallelLoginsRespectTheBound() throws InterruptedException {
    register(2, LoginAttemptLimits.MAX_GATE_WAIT);
    SlowAuthentication service = new SlowAuthentication(0);
    service.release.countDown();
    service.pause = Duration.ofMillis(20);
    StandaloneLoginFlow<String, String> flow = new StandaloneLoginFlow<>(service, Clock.systemUTC());

    int logins = 12;
    CountDownLatch go = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(logins);
    AtomicInteger successes = new AtomicInteger();
    for (int i = 0; i < logins; i++) {
      String user = "user-" + i;
      Thread worker = new Thread(() -> {
        try {
          go.await();
          if (flow.login(PASSWORD, user) instanceof StandaloneLoginFlow.LoginResult.Success<String>) {
            successes.incrementAndGet();
          }
        } catch (InterruptedException interrupted) {
          Thread.currentThread().interrupt();
        } finally {
          done.countDown();
        }
      });
      worker.setDaemon(true);
      worker.start();
    }
    go.countDown();
    assertTrue(done.await(60, TimeUnit.SECONDS));
    assertEquals(logins, successes.get());
    assertTrue(service.maxInside.get() <= 2, service.maxInside.get() + " checks ran at once");
  }

  @Test
  @DisplayName("a deferral gives the reservation back: more deferrals than the threshold, then the correct password logs in")
  void deferralReleasesTheReservation() {
    InMemoryLoginAttemptPolicy policy = register(1, Duration.ZERO);
    SlowAuthentication service = new SlowAuthentication(0);
    service.release.countDown();
    StandaloneLoginFlow<String, String> flow = new StandaloneLoginFlow<>(service, Clock.systemUTC());
    int threshold = LoginAttemptConfiguration.defaults().failureThreshold();

    CredentialCheckGate.Admission.Entered held = assertInstanceOf(
        CredentialCheckGate.Admission.Entered.class, policy.credentialCheckGate().enter());
    for (int i = 0; i < threshold + 3; i++) {
      assertThrows(CredentialCheckDeferredException.class, () -> flow.login(PASSWORD, "alice"),
          "attempt " + (i + 1) + " must be deferred, not refused by left-over reservations");
    }
    assertEquals(LoginAttemptDecision.allowed(),
        policy.peek(LoginAttemptContext.now("alice", null, null)));
    held.close();

    assertInstanceOf(StandaloneLoginFlow.LoginResult.Success.class, flow.login(PASSWORD, "alice"));
    assertEquals(1, service.evaluations.get());
    assertTrue(audit.of(LoginFailed.class).isEmpty());
    // RF11 (CWE-779): the gate audits at most one deferral a second and carries the count
    List<RateLimitExceeded> deferrals = audit.of(RateLimitExceeded.class);
    assertFalse(deferrals.isEmpty(), "the first deferral is audited at once");
    assertEquals(1, deferrals.getFirst().eventsInWindow());
    assertTrue(deferrals.stream().mapToInt(RateLimitExceeded::eventsInWindow).sum()
        <= threshold + 3, "the count never exceeds the deferrals");
    assertEquals(threshold + 3, policy.credentialCheckGate().deferredCount());
  }

  @Test
  @DisplayName("the permit is given back when the check throws")
  void permitIsReleasedWhenTheCheckThrows() {
    InMemoryLoginAttemptPolicy policy = register(1, Duration.ZERO);
    SlowAuthentication service = new SlowAuthentication(0);
    service.release.countDown();
    StandaloneLoginFlow<String, String> flow = new StandaloneLoginFlow<>(service, Clock.systemUTC());

    service.failure = new IllegalStateException("directory down");
    assertInstanceOf(StandaloneLoginFlow.LoginResult.Rejected.class, flow.login(PASSWORD, "alice"));
    assertEquals(0, policy.credentialCheckGate().inUse());

    service.failure = new CredentialVerificationUnavailableException();
    assertThrows(CredentialVerificationUnavailableException.class, () -> flow.login(PASSWORD, "bob"));
    assertEquals(0, policy.credentialCheckGate().inUse());

    service.failure = null;
    assertInstanceOf(StandaloneLoginFlow.LoginResult.Success.class, flow.login(PASSWORD, "carol"),
        "the single permit is free again");
  }

  @Test
  @DisplayName("the exception requires a positive retry-after")
  void exceptionValidates() {
    assertThrows(NullPointerException.class, () -> new CredentialCheckDeferredException(null));
    assertThrows(IllegalArgumentException.class,
        () -> new CredentialCheckDeferredException(Duration.ZERO));
  }

  // ── fixtures ──

  /** Checks a password slowly: every call waits for {@link #release}, then for {@link #pause}. */
  private static final class SlowAuthentication implements AuthenticationService<String, String> {
    final CountDownLatch entered;
    final CountDownLatch release = new CountDownLatch(1);
    final AtomicInteger evaluations = new AtomicInteger();
    final AtomicInteger inside = new AtomicInteger();
    final AtomicInteger maxInside = new AtomicInteger();
    volatile Duration pause = Duration.ZERO;
    volatile RuntimeException failure;

    SlowAuthentication(int expectedEntries) {
      this.entered = new CountDownLatch(expectedEntries);
    }

    @Override
    public boolean checkCredentials(String password) {
      evaluations.incrementAndGet();
      maxInside.accumulateAndGet(inside.incrementAndGet(), Math::max);
      try {
        entered.countDown();
        if (!release.await(10, TimeUnit.SECONDS)) {
          throw new IllegalStateException("the test never released the check");
        }
        if (!pause.isZero()) {
          Thread.sleep(pause.toMillis());
        }
        RuntimeException next = failure;
        if (next != null) {
          throw next;
        }
        return PASSWORD.equals(password);
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
        throw new IllegalStateException("interrupted", interrupted);
      } finally {
        inside.decrementAndGet();
      }
    }

    @Override
    public String loadSubject(String password) {
      return "alice";
    }

    @Override
    public Class<String> subjectType() {
      return String.class;
    }
  }

  private static final class ConcurrentAudit implements JCustosAuditService {
    private final Queue<AuditEvent> events = new ConcurrentLinkedQueue<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.copyOf(events);
    }

    <T extends AuditEvent> List<T> of(Class<T> type) {
      return events.stream().filter(type::isInstance).map(type::cast).toList();
    }
  }

  /** Process-wide subject store so that the worker threads of one test see the same subject. */
  private static final class MapSubjectStore implements SubjectStore {
    private final Map<Class<?>, Object> subjects = new ConcurrentHashMap<>();

    @Override
    public <T> Optional<T> currentSubject(Class<T> subjectType) {
      return Optional.ofNullable(subjectType.cast(subjects.get(subjectType)));
    }

    @Override
    public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
      subjects.put(subjectType, subject);
    }

    @Override
    public <T> void deleteCurrentSubject(Class<T> subjectType) {
      subjects.remove(subjectType);
    }
  }
}
