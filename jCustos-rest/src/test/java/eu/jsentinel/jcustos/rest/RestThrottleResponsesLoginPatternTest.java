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
package eu.jsentinel.jcustos.rest;

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.audit.NoopJCustosAuditService;
import eu.jsentinel.jcustos.bruteforce.CredentialCheckGate;
import eu.jsentinel.jcustos.bruteforce.InMemoryLoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptLimits;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.credential.password.CredentialVerificationUnavailableException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The login pattern the {@link RestThrottleResponses} Javadoc shows gives every credential-check
 * permit back. The example of the first 00.84.00 snapshots tested
 * {@code gate.enter() instanceof Deferred} and dropped an {@code Entered} admission without
 * closing it: with one permit, every login after the first was deferred until restart. The
 * pattern below is the one of the Javadoc, run against a real {@link InMemoryLoginAttemptPolicy}
 * with a gate of one permit that never waits; the Javadoc itself is pinned as well.
 */
@DisplayName("RestThrottleResponses - the documented login pattern gives the gate permit back")
class RestThrottleResponsesLoginPatternTest {

  private static final Path SOURCE =
      Path.of("src/main/java/eu/jsentinel/jcustos/rest/RestThrottleResponses.java");

  /** Records what a handler writes. */
  private static final class RecordingResponse implements RestResponse {
    int status;

    @Override public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override public void body(String body) {
    }

    @Override public void header(String name, String value) {
    }
  }

  private static InMemoryLoginAttemptPolicy onePermitPolicy() {
    return new InMemoryLoginAttemptPolicy(LoginAttemptLimits.defaults()
        .withMaxConcurrentCredentialChecks(1)
        .withGateWait(Duration.ZERO), Clock.systemUTC(), NoopJCustosAuditService.INSTANCE);
  }

  /**
   * The login of the Javadoc example; {@code check} stands for the credential check.
   *
   * @return the status the handler answered with
   */
  private static int login(LoginAttemptPolicy policy, String user, BooleanSupplier check) {
    RecordingResponse response = new RecordingResponse();
    LoginAttemptContext attempt = LoginAttemptContext.now(user, "192.0.2.10", null);
    CredentialCheckGate gate = policy.credentialCheckGate();
    if (policy.beforeAttempt(attempt) instanceof LoginAttemptDecision.LockedOut lockout) {
      RestThrottleResponses.tooManyRequests(response, lockout.remaining());
      return response.status;
    }
    CredentialCheckGate.Admission.Entered permit;
    switch (gate.enter()) {
      case CredentialCheckGate.Admission.Deferred deferred -> {
        policy.abandonAttempt(attempt);
        RestThrottleResponses.tooManyRequests(response, deferred.retryAfter());
        return response.status;
      }
      case CredentialCheckGate.Admission.Entered entered -> permit = entered;
    }
    boolean valid;
    try {
      valid = check.getAsBoolean();
    } catch (CredentialVerificationUnavailableException shed) {
      policy.abandonAttempt(attempt);
      return HttpStatus.SERVICE_UNAVAILABLE.code();
    } catch (RuntimeException checkFailed) {
      policy.recordFailure(attempt, "Credential check failed");
      return HttpStatus.UNAUTHORIZED.code();
    } finally {
      permit.close();
    }
    if (!valid) {
      policy.recordFailure(attempt);
      return HttpStatus.UNAUTHORIZED.code();
    }
    if (policy.confirmSuccess(attempt) instanceof LoginAttemptDecision.LockedOut lockout) {
      RestThrottleResponses.tooManyRequests(response, lockout.remaining());
      return response.status;
    }
    return HttpStatus.OK.code();
  }

  @Test
  @DisplayName("two logins in a row on a one-permit gate are both evaluated; no permit is left in use")
  void twoLoginsInARowAreBothAdmitted() {
    InMemoryLoginAttemptPolicy policy = onePermitPolicy();
    CredentialCheckGate gate = policy.credentialCheckGate();

    assertEquals(HttpStatus.OK.code(), login(policy, "alice", () -> true));
    assertEquals(0, gate.inUse(), "the first login gave its permit back");
    assertEquals(HttpStatus.OK.code(), login(policy, "bob", () -> true),
        "the second login is Entered, not Deferred");
    assertEquals(0, gate.inUse());
    assertEquals(0, gate.deferredCount(), "nothing was deferred");
  }

  @Test
  @DisplayName("a wrong password, a shed verification and a throwing check give the permit back as well")
  void everyOutcomeGivesThePermitBack() {
    InMemoryLoginAttemptPolicy policy = onePermitPolicy();
    CredentialCheckGate gate = policy.credentialCheckGate();

    assertEquals(HttpStatus.UNAUTHORIZED.code(), login(policy, "carol", () -> false));
    assertEquals(HttpStatus.SERVICE_UNAVAILABLE.code(), login(policy, "dave", () -> {
      throw new CredentialVerificationUnavailableException();
    }));
    assertEquals(HttpStatus.UNAUTHORIZED.code(), login(policy, "erin", () -> {
      throw new IllegalStateException("the directory failed");
    }));

    assertEquals(0, gate.inUse());
    assertEquals(HttpStatus.OK.code(), login(policy, "frank", () -> true));
    assertEquals(0, gate.deferredCount());
  }

  @Test
  @DisplayName("the Javadoc example closes the permit in a finally block and never drops an Entered admission")
  void javadocExampleClosesThePermit() throws IOException {
    String source = Files.readString(SOURCE, StandardCharsets.UTF_8);
    int start = source.indexOf("<pre>{@code");
    int end = source.indexOf("}</pre>", start);
    assertTrue(start > 0 && end > start, "the class comment carries the example");
    // without the comment's leading asterisks, on one line
    String example = source.substring(start, end)
        .replaceAll("(?m)^\\s*\\* ?", "")
        .replaceAll("\\s+", " ");

    assertTrue(example.contains("switch (gate.enter())"), example);
    assertTrue(example.contains("} finally { permit.close();"), example);
    assertFalse(example.contains("enter() instanceof"),
        "an instanceof test on enter() drops the Entered admission: " + example);
  }
}
