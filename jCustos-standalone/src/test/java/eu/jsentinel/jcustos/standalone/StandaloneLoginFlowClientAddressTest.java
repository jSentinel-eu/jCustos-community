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

import eu.jsentinel.jcustos.audit.BruteForceLimitReached;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptLimits;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-062 (CWE-307): {@link StandaloneLoginFlow#login(Object, String, String)} hands the client
 * address to the policy, so the address counter works for a standalone server that knows its
 * peer. The policy is the real {@link InMemoryLoginAttemptPolicy}; the authentication service is
 * a hand-written fake that accepts one password. Synthetic data only.
 */
@DisplayName("StandaloneLoginFlow - the client address reaches the address counter (JS-SEC-062)")
class StandaloneLoginFlowClientAddressTest {

  private static final String PASSWORD = "Correct-Horse-Battery-1";
  private static final String SPRAYER = "203.0.113.50";
  private static final String ELSEWHERE = "198.51.100.7";
  /** Three failures from one address within an hour lock it for 30 min. */
  private static final LoginAttemptLimits.AddressLimit ADDRESS = new LoginAttemptLimits.AddressLimit(
      3, Duration.ofHours(1), Duration.ofMinutes(30), Duration.ofHours(2));

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final StandaloneLoginFlow<Credentials, String> flow =
      new StandaloneLoginFlow<>(new OnePasswordAuthentication(), Clock.systemUTC());

  @BeforeEach
  void setUp() {
    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setLoginAttemptPolicy(new InMemoryLoginAttemptPolicy(
        LoginAttemptLimits.defaults().withAddressLimit(ADDRESS), Clock.systemUTC(), audit));
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new MapSubjectStore());
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
    SubjectStores.reset();
  }

  @Test
  @DisplayName("failures from one address across several user names lock the address - also for the right password")
  void sprayFromOneAddressLocksIt() {
    for (int i = 0; i < ADDRESS.failureThreshold(); i++) {
      String user = "user-" + i;
      assertInstanceOf(StandaloneLoginFlow.LoginResult.Rejected.class,
          flow.login(new Credentials(user, "guess-" + i), user, SPRAYER), user);
    }

    StandaloneLoginFlow.LoginResult.LockedOut<String> locked = assertInstanceOf(
        StandaloneLoginFlow.LoginResult.LockedOut.class,
        flow.login(new Credentials("alice", PASSWORD), "alice", SPRAYER),
        "the sprayed address is locked, whichever account it tries next");
    Duration remaining = locked.decision().remaining();
    assertTrue(remaining.compareTo(ADDRESS.initialLockout()) <= 0
            && remaining.compareTo(ADDRESS.initialLockout().minusMinutes(1)) > 0,
        "for the address lockout: " + remaining);

    assertInstanceOf(StandaloneLoginFlow.LoginResult.Success.class,
        flow.login(new Credentials("alice", PASSWORD), "alice", ELSEWHERE),
        "alice herself is not locked - she logs in from another address");
    assertEquals(ELSEWHERE, audit.single(LoginSucceeded.class).clientAddress(),
        "the success names the address");

    assertEquals(ADDRESS.failureThreshold(), audit.all(LoginFailed.class).size());
    audit.all(LoginFailed.class).forEach(failed -> assertEquals(SPRAYER, failed.clientAddress()));
    BruteForceLimitReached limitReached = audit.single(BruteForceLimitReached.class);
    assertEquals("", limitReached.username(), "the lockout belongs to the address");
    assertEquals(SPRAYER, limitReached.clientAddress());
  }

  @Test
  @DisplayName("login(credentials, username) passes no address: the same spray locks nothing, as before")
  void twoArgumentLoginCountsNoAddress() {
    int attempts = 3 * ADDRESS.failureThreshold();
    for (int i = 0; i < attempts; i++) {
      String user = "user-" + i;
      assertInstanceOf(StandaloneLoginFlow.LoginResult.Rejected.class,
          flow.login(new Credentials(user, "guess-" + i), user), user + " is evaluated");
    }
    assertInstanceOf(StandaloneLoginFlow.LoginResult.Success.class,
        flow.login(new Credentials("alice", PASSWORD), "alice"));
    assertNull(audit.single(LoginSucceeded.class).clientAddress());
    assertEquals(attempts, audit.all(LoginFailed.class).size());
    audit.all(LoginFailed.class).forEach(failed -> assertNull(failed.clientAddress()));
    assertTrue(audit.all(BruteForceLimitReached.class).isEmpty(), audit.events().toString());
  }

  @Test
  @DisplayName("a blank or null address counts on no address, like the two-argument method")
  void blankAddressIsNoAddress() {
    for (int i = 0; i < 2 * ADDRESS.failureThreshold(); i++) {
      String user = "user-" + i;
      assertInstanceOf(StandaloneLoginFlow.LoginResult.Rejected.class,
          flow.login(new Credentials(user, "guess"), user, i % 2 == 0 ? null : "  "), user);
    }
    assertTrue(audit.all(BruteForceLimitReached.class).isEmpty(), audit.events().toString());
  }

  /** User name and password; never logged. */
  private record Credentials(String username, String password) {
  }

  /** Accepts {@link #PASSWORD} for every user name. */
  private static final class OnePasswordAuthentication
      implements AuthenticationService<Credentials, String> {

    @Override
    public boolean checkCredentials(Credentials credentials) {
      return PASSWORD.equals(credentials.password());
    }

    @Override
    public String loadSubject(Credentials credentials) {
      return credentials.username();
    }

    @Override
    public Class<String> subjectType() {
      return String.class;
    }
  }

  private static final class MapSubjectStore implements SubjectStore {
    private final Map<Class<?>, Object> subjects = new HashMap<>();

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
