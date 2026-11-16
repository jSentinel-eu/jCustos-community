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
import eu.jsentinel.jcustos.audit.BruteForceLimitReached;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptStore;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptConfiguration;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.NoopLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.StoreBackedLoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationResult;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import eu.jsentinel.jcustos.credential.password.PasswordHashingService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.password.limiter.KdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.limiter.KdfResourceBudget;
import eu.jsentinel.jcustos.credential.password.limiter.SemaphoreKdfExecutionLimiter;
import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;
import eu.jsentinel.jcustos.credential.store.CredentialRecord;
import eu.jsentinel.jcustos.credential.store.CredentialStatus;
import eu.jsentinel.jcustos.credential.store.InMemoryCredentialStore;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
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
 * The login flow against the real building blocks: {@link InMemoryLoginAttemptPolicy}, the
 * password-hashing pipeline with a real {@link SemaphoreKdfExecutionLimiter}, the
 * {@link InMemoryCredentialStore}. Covers JS-SEC-123 (atomic lockout), JS-SEC-124 (throttling
 * default) and JS-SEC-126 ("could not verify" is not "wrong").
 */
@DisplayName("StandaloneLoginFlow - hardening (JS-SEC-123, JS-SEC-124, JS-SEC-126)")
class StandaloneLoginFlowHardeningTest {

  private static final int THRESHOLD = LoginAttemptConfiguration.defaults().failureThreshold();

  private final RecordingAuditSink audit = new RecordingAuditSink();

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

  private static Optional<String> boundSubject() {
    return SubjectStores.subjectStore().currentSubject(String.class);
  }

  // ── one LoginFailed per rejected login (JS-SEC-123 follow-up) ───────

  @Test
  @DisplayName("every shipped policy: a rejected login leaves exactly one LoginFailed, with user name and reason")
  void oneLoginFailedPerRejectedLogin() {
    List<LoginAttemptPolicy> policies = List.of(
        new InMemoryLoginAttemptPolicy(),
        new StoreBackedLoginAttemptPolicy(new InMemoryLoginAttemptStore()),
        NoopLoginAttemptPolicy.INSTANCE);
    for (LoginAttemptPolicy policy : policies) {
      audit.clear();
      JCustosServiceResolver.setLoginAttemptPolicy(policy);
      StandaloneLoginFlow<String, String> flow =
          new StandaloneLoginFlow<>(new AcceptsOnly("Correct-Horse-1", true), Clock.systemUTC());

      assertInstanceOf(StandaloneLoginFlow.LoginResult.Rejected.class, flow.login("wrong", "alice"));

      String name = policy.getClass().getSimpleName();
      assertEquals(1, audit.all(LoginFailed.class).size(), name + ": " + audit.events());
      LoginFailed event = audit.single(LoginFailed.class);
      assertEquals("alice", event.username(), name);
      assertEquals(LoginAttemptPolicy.REASON_CREDENTIALS_REJECTED, event.reason(), name);
    }
  }

  @Test
  @DisplayName("every shipped policy: accepted credentials without a subject leave one LoginFailed with that reason")
  void oneLoginFailedWithTheFlowsReason() {
    List<LoginAttemptPolicy> policies = List.of(
        new InMemoryLoginAttemptPolicy(),
        new StoreBackedLoginAttemptPolicy(new InMemoryLoginAttemptStore()),
        NoopLoginAttemptPolicy.INSTANCE);
    for (LoginAttemptPolicy policy : policies) {
      audit.clear();
      JCustosServiceResolver.setLoginAttemptPolicy(policy);
      StandaloneLoginFlow<String, String> flow =
          new StandaloneLoginFlow<>(new AcceptsOnly("Correct-Horse-1", false), Clock.systemUTC());

      assertInstanceOf(StandaloneLoginFlow.LoginResult.Rejected.class,
          flow.login("Correct-Horse-1", "alice"));

      String name = policy.getClass().getSimpleName();
      assertEquals(1, audit.all(LoginFailed.class).size(), name + ": " + audit.events());
      assertEquals(StandaloneLoginFlow.REASON_NO_SUBJECT, audit.single(LoginFailed.class).reason(), name);
    }
  }

  /** Accepts one password; {@code withSubject == false} loads no subject for it. */
  private record AcceptsOnly(String password, boolean withSubject)
      implements AuthenticationService<String, String> {
    @Override
    public boolean checkCredentials(String credentials) {
      return password.equals(credentials);
    }

    @Override
    public String loadSubject(String credentials) {
      return withSubject ? "alice" : null;
    }

    @Override
    public Class<String> subjectType() {
      return String.class;
    }
  }

  // ── JS-SEC-126 ─────────────────────────────────────────────────────
  // ── JS-SEC-126 ─────────────────────────────────────────────────────

  @Test
  @DisplayName("JS-SEC-126: five logins shed by the KDF limiter are no failures - no lockout, no LoginFailed, the sixth succeeds")
  void shedVerificationIsNeitherSuccessNorFailure() {
    SemaphoreKdfExecutionLimiter limiter = new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(50)));
    PasswordAuthentication auth = new PasswordAuthentication(limiter);
    auth.register("victim", "Correct-Horse-1");
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy();
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    StandaloneLoginFlow<Login, String> flow = new StandaloneLoginFlow<>(auth, Clock.systemUTC());

    // an anonymous flood keeps the only KDF permit busy while the victim logs in correctly
    try (KdfExecutionLimiter.Lease flood = limiter.acquire().orElseThrow()) {
      for (int i = 0; i < THRESHOLD; i++) {
        assertThrows(CredentialVerificationUnavailableException.class,
            () -> flow.login(new Login("victim", "Correct-Horse-1"), "victim"),
            "a shed verification is the third outcome, not Rejected");
      }
    }

    assertTrue(audit.all(LoginFailed.class).isEmpty(),
        "a correct password that could not be checked must not be audited as a failed login");
    assertTrue(audit.all(BruteForceLimitReached.class).isEmpty());
    assertFalse(boundSubject().isPresent());
    assertEquals(LoginAttemptDecision.allowed(),
        policy.peek(LoginAttemptContext.now("victim", null, null)),
        "five shed attempts must not lock the account");
    LoginAttemptContext probe = LoginAttemptContext.now("victim", null, null);
    assertEquals(LoginAttemptDecision.allowed(), policy.beforeAttempt(probe),
        "... and must not have used up the attempts in flight either");
    policy.abandonAttempt(probe);

    // the flood is over: the same login now succeeds
    assertInstanceOf(StandaloneLoginFlow.LoginResult.Success.class,
        flow.login(new Login("victim", "Correct-Horse-1"), "victim"));
    assertEquals(1, audit.all(LoginSucceeded.class).size());
  }

  @Test
  @DisplayName("JS-SEC-126: with the permit available a wrong password is still a counted failure")
  void evaluatedMismatchStillCounts() {
    PasswordAuthentication auth = new PasswordAuthentication(new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(1, Duration.ofMillis(50))));
    auth.register("victim", "Correct-Horse-1");
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy();
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    StandaloneLoginFlow<Login, String> flow = new StandaloneLoginFlow<>(auth, Clock.systemUTC());

    for (int i = 0; i < THRESHOLD; i++) {
      assertInstanceOf(StandaloneLoginFlow.LoginResult.Rejected.class,
          flow.login(new Login("victim", "wrong-" + i), "victim"));
    }
    assertEquals(THRESHOLD, audit.all(LoginFailed.class).size(),
        "exactly one LoginFailed per rejected login - the policy's, not a second one of the flow");
    assertInstanceOf(StandaloneLoginFlow.LoginResult.LockedOut.class,
        flow.login(new Login("victim", "Correct-Horse-1"), "victim"));
  }

  @Test
  @DisplayName("XR09-6: any other exception from the AuthenticationService is a failed attempt - the key locks after the threshold")
  void otherExceptionCountsAsAFailedAttempt() {
    AtomicInteger checks = new AtomicInteger();
    AuthenticationService<Login, String> broken = new PasswordAuthentication(
        new SemaphoreKdfExecutionLimiter(new KdfResourceBudget(1, Duration.ofMillis(50)))) {
      @Override
      public boolean checkCredentials(Login credentials) {
        checks.incrementAndGet();
        throw new IllegalStateException("cannot parse " + credentials.password());
      }
    };
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy();
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    StandaloneLoginFlow<Login, String> flow = new StandaloneLoginFlow<>(broken, Clock.systemUTC());

    for (int i = 0; i < THRESHOLD; i++) {
      assertInstanceOf(StandaloneLoginFlow.LoginResult.Rejected.class,
          flow.login(new Login("victim", "crafted-" + i), "victim"),
          "the caller sees what wrong credentials show");
    }
    assertInstanceOf(StandaloneLoginFlow.LoginResult.LockedOut.class,
        flow.login(new Login("victim", "crafted-again"), "victim"),
        "a check that can be made to throw must not buy unlimited guesses");
    assertEquals(THRESHOLD, checks.get(), "the locked attempt does not reach the service");
    assertEquals(THRESHOLD, audit.all(LoginFailed.class).size());
    assertTrue(audit.all(LoginFailed.class).stream()
        .allMatch(event -> StandaloneLoginFlow.REASON_CHECK_FAILED.equals(event.reason())));
  }

  @Test
  @DisplayName("JS-SEC-123 / JS-SEC-126: CredentialVerificationUnavailableException releases the reservation and counts nothing")
  void unavailableReleasesTheReservation() {
    AuthenticationService<Login, String> shed = new PasswordAuthentication(
        new SemaphoreKdfExecutionLimiter(new KdfResourceBudget(1, Duration.ofMillis(50)))) {
      @Override
      public boolean checkCredentials(Login credentials) {
        throw new CredentialVerificationUnavailableException();
      }
    };
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy();
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    StandaloneLoginFlow<Login, String> flow = new StandaloneLoginFlow<>(shed, Clock.systemUTC());

    for (int i = 0; i < THRESHOLD * 4; i++) {
      assertThrows(CredentialVerificationUnavailableException.class,
          () -> flow.login(new Login("victim", "whatever"), "victim"),
          "attempt " + i + " must still reach the service - no reservation may be left behind");
    }
    assertTrue(audit.all(LoginFailed.class).isEmpty());
  }

  // ── JS-SEC-123 ─────────────────────────────────────────────────────

  @Test
  @DisplayName("JS-SEC-123: 50 parallel wrong logins at threshold 5 - at most 5 reach the credential check")
  void parallelLoginsCannotExceedTheThreshold() throws InterruptedException {
    int threads = 50;
    CountDownLatch insideCheck = new CountDownLatch(THRESHOLD);
    CountDownLatch releaseChecks = new CountDownLatch(1);
    AtomicInteger evaluated = new AtomicInteger();
    AuthenticationService<Login, String> slow = new AuthenticationService<>() {
      @Override
      public boolean checkCredentials(Login credentials) {
        evaluated.incrementAndGet();
        insideCheck.countDown();
        try {
          releaseChecks.await(10, TimeUnit.SECONDS);   // the KDF is running
        } catch (InterruptedException interrupted) {
          Thread.currentThread().interrupt();
        }
        return false;
      }

      @Override
      public String loadSubject(Login credentials) {
        return credentials.username();
      }

      @Override
      public Class<String> subjectType() {
        return String.class;
      }
    };
    JCustosServiceResolver.setLoginAttemptPolicy(new InMemoryLoginAttemptPolicy());
    JCustosServiceResolver.setJCustosAuditService(new ConcurrentAudit());   // 50 writers
    StandaloneLoginFlow<Login, String> flow = new StandaloneLoginFlow<>(slow, Clock.systemUTC());

    CountDownLatch go = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(threads);
    AtomicInteger lockedOut = new AtomicInteger();
    AtomicInteger rejected = new AtomicInteger();
    for (int i = 0; i < threads; i++) {
      int guess = i;
      Thread thread = new Thread(() -> {
        try {
          go.await();
          StandaloneLoginFlow.LoginResult<String> result =
              flow.login(new Login("victim", "guess-" + guess), "victim");
          if (result instanceof StandaloneLoginFlow.LoginResult.LockedOut<String>) {
            lockedOut.incrementAndGet();
          } else if (result instanceof StandaloneLoginFlow.LoginResult.Rejected<String>) {
            rejected.incrementAndGet();
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
    assertTrue(insideCheck.await(10, TimeUnit.SECONDS), "the threshold itself must get through");
    // every other thread has been turned away at the gate while these five are still checking
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (lockedOut.get() < threads - THRESHOLD && System.nanoTime() < deadline) {
      Thread.onSpinWait();
    }
    releaseChecks.countDown();
    assertTrue(done.await(20, TimeUnit.SECONDS));

    assertEquals(THRESHOLD, evaluated.get(),
        "guesses evaluated in one burst must be bounded by the threshold, not by the thread count");
    assertEquals(THRESHOLD, rejected.get());
    assertEquals(threads - THRESHOLD, lockedOut.get());
  }

  @Test
  @DisplayName("JS-SEC-123: a correct password whose key was locked while it was being checked is denied; no subject is bound")
  void successAfterLockoutIsDenied() {
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy();
    JCustosServiceResolver.setLoginAttemptPolicy(policy);
    // while this (correct) attempt is being verified, five failures for the account are reported
    AuthenticationService<Login, String> racing = new PasswordAuthentication(
        new SemaphoreKdfExecutionLimiter(new KdfResourceBudget(1, Duration.ofMillis(50)))) {
      @Override
      public boolean checkCredentials(Login credentials) {
        for (int i = 0; i < THRESHOLD; i++) {
          policy.recordFailure(LoginAttemptContext.now("victim", "10.0.0." + i, null));
        }
        return true;
      }
    };
    StandaloneLoginFlow<Login, String> flow = new StandaloneLoginFlow<>(racing, Clock.systemUTC());

    StandaloneLoginFlow.LoginResult<String> result =
        flow.login(new Login("victim", "Correct-Horse-1"), "victim");

    assertInstanceOf(StandaloneLoginFlow.LoginResult.LockedOut.class, result,
        "the lockout wins over the correct password");
    assertFalse(boundSubject().isPresent(), "no session for a denied login");
    assertTrue(audit.all(LoginSucceeded.class).isEmpty());
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.peek(LoginAttemptContext.now("victim", null, null)),
        "and the lockout is still in force afterwards");
  }

  // ── JS-SEC-124 ─────────────────────────────────────────────────────

  @Test
  @DisplayName("JS-SEC-124: without any registered policy the flow locks out after five wrong passwords")
  void throttlesWithoutARegisteredPolicy() {
    PasswordAuthentication auth = new PasswordAuthentication(new SemaphoreKdfExecutionLimiter(
        new KdfResourceBudget(4, Duration.ofMillis(250))));
    auth.register("victim", "Correct-Horse-1");
    StandaloneLoginFlow<Login, String> flow = new StandaloneLoginFlow<>(auth, Clock.systemUTC());
    assertTrue(JCustosServiceResolver.findLoginAttemptPolicy().isEmpty(), "nothing is registered");

    for (int i = 0; i < THRESHOLD; i++) {
      assertInstanceOf(StandaloneLoginFlow.LoginResult.Rejected.class,
          flow.login(new Login("victim", "wrong-" + i), "victim"));
    }
    int evaluatedSoFar = auth.evaluations.get();

    assertInstanceOf(StandaloneLoginFlow.LoginResult.LockedOut.class,
        flow.login(new Login("victim", "Correct-Horse-1"), "victim"),
        "the sixth attempt is refused although nobody configured a policy");
    assertEquals(evaluatedSoFar, auth.evaluations.get(), "and it is not evaluated");
    assertEquals(1, audit.all(BruteForceLimitReached.class).size());
  }

  // ── fixtures: real implementations ────────────────────────────────

  private record Login(String username, String password) {
  }

  /** An {@link AuthenticationService} on the real hashing pipeline and credential store. */
  private static class PasswordAuthentication implements AuthenticationService<Login, String> {
    final AtomicInteger evaluations = new AtomicInteger();
    private final InMemoryCredentialStore credentials = new InMemoryCredentialStore();
    private final PasswordHashingService hashing;

    PasswordAuthentication(KdfExecutionLimiter limiter) {
      this.hashing = PasswordHashingServices.defaults(fastPolicy(), limiter);
    }

    void register(String username, String password) {
      credentials.register(CredentialRecord.initial(username,
          hashing.hash(password.toCharArray()).encodedHash(), CredentialStatus.ACTIVE, Instant.now()));
    }

    @Override
    public boolean checkCredentials(Login login) {
      evaluations.incrementAndGet();
      Optional<CredentialRecord> record = credentials.findByUsername(login.username());
      CredentialVerificationResult result = record.isPresent()
          ? hashing.verify(login.password().toCharArray(), record.get().encodedHash())
          : hashing.verifyAgainstNothing(login.password().toCharArray());
      // the boolean contract has no room for "could not verify" - the third outcome is thrown
      CredentialVerificationUnavailableException.throwIfUnavailable(result);
      return result instanceof CredentialVerificationResult.Verified;
    }

    @Override
    public String loadSubject(Login login) {
      return login.username();
    }

    @Override
    public Class<String> subjectType() {
      return String.class;
    }

    private static PasswordHashPolicy fastPolicy() {
      Map<String, String> defaults = new LinkedHashMap<>();
      defaults.put(Pbkdf2ParameterNames.ITERATIONS, "1000");
      defaults.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
      Map<String, String> min = new LinkedHashMap<>(defaults);
      min.put(Pbkdf2ParameterNames.SALT_LENGTH, "16");
      Map<String, String> max = new LinkedHashMap<>();
      max.put(Pbkdf2ParameterNames.ITERATIONS, "2000");
      max.put(Pbkdf2ParameterNames.KEY_LENGTH, "64");
      max.put(Pbkdf2ParameterNames.SALT_LENGTH, "64");
      return DefaultPasswordHashPolicy.builder()
          .policyVersion(1)
          .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
          .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
          .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
          .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
          .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
          .build();
    }
  }

  /** Audit sink that takes events from many threads; {@link RecordingAuditSink} is single-threaded. */
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
  }

  /** Process-wide subject store so that threads of one test see the same subject. */
  private static final class MapSubjectStore
      implements eu.jsentinel.jcustos.authorization.api.SubjectStore {
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
